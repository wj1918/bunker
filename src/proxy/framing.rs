//! HTTP/1.1 message framing for a *proxy* — the security-critical subset.
//!
//! A forward proxy is a relay: it doesn't interpret most of HTTP, but it MUST
//! answer one question precisely, in both directions — "where does this message
//! end?" — or it desyncs keep-alive connections and opens request-smuggling
//! holes. This module isolates exactly that logic as pure, I/O-free functions so
//! it can be fuzzed/unit-tested to death *before* any io_uring runtime is built
//! around it. It does NOT decode bodies (chunked payloads pass through verbatim);
//! it only determines framing and message boundaries.
//!
//! Rules follow RFC 7230 §3.3.3. The headline defense: Content-Length together
//! with Transfer-Encoding is rejected (CL.TE / TE.CL smuggling), matching the
//! behavior bunker advertises today.
#![allow(dead_code)] // wired into the io_uring proxy spike, not the tokio binary

/// How a message body is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body, or an explicit Content-Length: 0.
    None,
    /// Fixed-length body of exactly N bytes.
    ContentLength(u64),
    /// Chunked transfer-encoding (final coding is `chunked`).
    Chunked,
}

/// Why a message's framing was rejected. Each variant is a distinct attack/edge
/// the proxy must refuse rather than guess at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// Both Content-Length and Transfer-Encoding present — the classic
    /// CL.TE/TE.CL desync vector. RFC 7230 §3.3.3: MUST be treated as an error.
    ClTeConflict,
    /// Conflicting Content-Length values (multiple headers, or a comma list,
    /// with more than one distinct value).
    ConflictingContentLength,
    /// A Content-Length value that isn't a valid non-negative integer.
    InvalidContentLength,
    /// Transfer-Encoding present but the final coding isn't `chunked`, so the
    /// body length can't be determined — refuse rather than guess.
    UnframeableTransferEncoding,
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FramingError::ClTeConflict => "Content-Length and Transfer-Encoding both present",
            FramingError::ConflictingContentLength => "conflicting Content-Length values",
            FramingError::InvalidContentLength => "invalid Content-Length value",
            FramingError::UnframeableTransferEncoding => {
                "Transfer-Encoding final coding is not chunked"
            }
        };
        f.write_str(s)
    }
}

fn eq_ignore_ascii_case_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Trim leading/trailing HTTP optional whitespace (SP/HTAB).
fn trim_ows(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map(|i| i + 1)
        .unwrap_or(start);
    &b[start..end]
}

/// Decide body framing from a message's headers (name, value) pairs, applying
/// RFC 7230 §3.3.3 in precedence order. This is the smuggling-defense core.
///
/// Header names are matched case-insensitively. Values are raw bytes. Multiple
/// Content-Length / Transfer-Encoding headers are combined as if comma-joined.
pub fn analyze_framing(headers: &[(&[u8], &[u8])]) -> Result<BodyFraming, FramingError> {
    let mut has_cl = false;
    let mut has_te = false;
    for (name, _) in headers {
        if eq_ignore_ascii_case_bytes(name, b"content-length") {
            has_cl = true;
        } else if eq_ignore_ascii_case_bytes(name, b"transfer-encoding") {
            has_te = true;
        }
    }

    // (1) CL + TE together => smuggling. Highest precedence — reject outright.
    if has_cl && has_te {
        return Err(FramingError::ClTeConflict);
    }

    // (2) Transfer-Encoding: framing is chunked iff the final coding is chunked.
    if has_te {
        // Gather all codings across all TE headers, in order.
        let mut codings: Vec<Vec<u8>> = Vec::new();
        for (name, value) in headers {
            if eq_ignore_ascii_case_bytes(name, b"transfer-encoding") {
                for token in value.split(|&c| c == b',') {
                    let t = trim_ows(token);
                    if !t.is_empty() {
                        codings.push(t.to_ascii_lowercase());
                    }
                }
            }
        }
        // Final coding must be chunked, and chunked must appear exactly once
        // (a second "chunked" anywhere is an obfuscation vector).
        let chunked_count = codings
            .iter()
            .filter(|c| c.as_slice() == b"chunked")
            .count();
        let final_is_chunked = codings
            .last()
            .map(|c| c.as_slice() == b"chunked")
            .unwrap_or(false);
        if final_is_chunked && chunked_count == 1 {
            return Ok(BodyFraming::Chunked);
        }
        return Err(FramingError::UnframeableTransferEncoding);
    }

    // (3) Content-Length: all values (across headers and comma lists) must agree.
    if has_cl {
        let mut seen: Option<u64> = None;
        for (name, value) in headers {
            if !eq_ignore_ascii_case_bytes(name, b"content-length") {
                continue;
            }
            for part in value.split(|&c| c == b',') {
                let p = trim_ows(part);
                let n = parse_u64_strict(p).ok_or(FramingError::InvalidContentLength)?;
                match seen {
                    Some(prev) if prev != n => return Err(FramingError::ConflictingContentLength),
                    _ => seen = Some(n),
                }
            }
        }
        return match seen {
            Some(0) => Ok(BodyFraming::None),
            Some(n) => Ok(BodyFraming::ContentLength(n)),
            None => Err(FramingError::InvalidContentLength),
        };
    }

    // (4) Neither => no body (request) / connection-close-delimited (response,
    // caller's concern). The proxy treats absence as no body to forward.
    Ok(BodyFraming::None)
}

/// Parse a non-negative integer from exactly these ASCII digits — no sign, no
/// `0x`, no whitespace (caller trims OWS), no empty string, no overflow.
fn parse_u64_strict(b: &[u8]) -> Option<u64> {
    if b.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(acc)
}

/// Result of scanning a (possibly partial) chunked body for its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkScan {
    /// A complete chunked body occupies the first N bytes of the buffer.
    Complete(usize),
    /// Need more bytes to determine the end.
    Incomplete,
    /// Malformed framing — reject the message.
    Malformed,
}

/// Find the end of a chunked body without decoding it (pass-through proxying).
/// `buf` must start at the first chunk-size line. Returns how many bytes form
/// the complete body (including the terminating `0\r\n` + trailers + final CRLF).
///
/// Guards the bug-prone bits: hex chunk sizes, chunk extensions (`;name=val`),
/// the zero-length terminator, trailer lines, and the mandatory CRLFs.
pub fn scan_chunked(buf: &[u8]) -> ChunkScan {
    let mut pos = 0usize;
    loop {
        // chunk-size line: hex size, optional ;extensions, then CRLF.
        let line_len = match find(&buf[pos..], b"\r\n") {
            Some(i) => i,
            None => return ChunkScan::Incomplete,
        };
        let size_field = {
            let line = &buf[pos..pos + line_len];
            if !is_clean_chunk_line(line) {
                return ChunkScan::Malformed;
            }
            // strip chunk extensions after ';'
            line.split(|&c| c == b';').next().unwrap_or(line)
        };
        let size = match parse_hex_strict(trim_ows(size_field)) {
            Some(s) => s,
            None => return ChunkScan::Malformed,
        };
        pos += line_len + 2; // consume size line + CRLF

        if size == 0 {
            // Last chunk: optional trailer lines, then a final CRLF (blank line).
            return scan_trailers(buf, pos);
        }

        // size bytes of data, then a CRLF.
        let size = size as usize;
        let need = pos.checked_add(size).and_then(|p| p.checked_add(2));
        let need = match need {
            Some(n) => n,
            None => return ChunkScan::Malformed,
        };
        if buf.len() < need {
            return ChunkScan::Incomplete;
        }
        if &buf[pos + size..pos + size + 2] != b"\r\n" {
            return ChunkScan::Malformed; // data not CRLF-terminated
        }
        pos = need;
    }
}

/// After the terminating `0\r\n`, consume optional trailer header lines until a
/// blank line (CRLF). Returns Complete at the byte past the final CRLF.
fn scan_trailers(buf: &[u8], mut pos: usize) -> ChunkScan {
    loop {
        let line_len = match find(&buf[pos..], b"\r\n") {
            Some(i) => i,
            None => return ChunkScan::Incomplete,
        };
        if line_len == 0 {
            // Blank line: end of trailers (and of the chunked body).
            return ChunkScan::Complete(pos + 2);
        }
        if !is_clean_chunk_line(&buf[pos..pos + line_len]) {
            return ChunkScan::Malformed;
        }
        // A trailer line — consume it and continue.
        pos += line_len + 2;
    }
}

/// A chunk-size line (size + extensions) or trailer line may hold visible
/// characters, spaces and tabs only.
///
/// These lines are relayed exactly as received, and we split them at CRLF. A
/// peer that also accepts a bare LF (or CR) as a line ending would split
/// `5;a=b\nfoo` into two lines where we saw one, and from there disagree with
/// us about where every later chunk — and so the message — ends. That
/// disagreement is what request smuggling is built on, so such a line is
/// rejected rather than passed on.
fn is_clean_chunk_line(line: &[u8]) -> bool {
    line.iter().all(|&c| c == b'\t' || (c >= 0x20 && c != 0x7f))
}

fn parse_hex_strict(b: &[u8]) -> Option<u64> {
    if b.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &c in b {
        let d = match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' => (c - b'a' + 10) as u64,
            b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => return None,
        };
        acc = acc.checked_mul(16)?.checked_add(d)?;
    }
    Some(acc)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Max header bytes / count we'll parse before rejecting (slowloris / resource
/// guard). A real proxy tunes these; these are sane defaults for the spike.
pub const MAX_HEADERS: usize = 100;

/// Routing metadata extracted in the *same* httparse pass that
/// `scan_message_with_metadata` uses for framing. All ranges are byte offsets
/// into the original buffer, so the caller can later slice `buf[range]` to
/// recover method / path / header bytes without re-parsing. This is what makes
/// "parse-once" work: the engine pulls this out of the framing pass and hands
/// it to `rewrite_forward_with_metadata`, which then skips its own httparse
/// call.
///
/// Only populated for requests (`is_request == true`). Responses get `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMetadata {
    pub method: std::ops::Range<usize>,
    pub path: std::ops::Range<usize>,
    /// HTTP minor version (httparse: 1 for HTTP/1.1, 0 for HTTP/1.0).
    pub version: u8,
    pub headers: Vec<HeaderRange>,
    /// Byte offset just past the head's CRLFCRLF terminator. The body (if any)
    /// occupies `head_end..total` in the message buffer.
    pub head_end: usize,
}

/// One header's name + value as byte-ranges into the original buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRange {
    pub name: std::ops::Range<usize>,
    pub value: std::ops::Range<usize>,
}

/// Compute the byte range a `slice` occupies inside `buf`. Caller is
/// responsible for ensuring `slice` is actually a subslice of `buf` (httparse
/// guarantees this for fields parsed out of its input).
#[inline]
fn range_of(buf: &[u8], slice: &[u8]) -> std::ops::Range<usize> {
    let base = buf.as_ptr() as usize;
    let start = slice.as_ptr() as usize - base;
    start..start + slice.len()
}

/// Result of scanning a buffer for one complete HTTP/1 message (head + body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageScan {
    /// A complete message occupies the first `total` bytes; `head` of those are
    /// the start line + headers (up to and including CRLFCRLF), the rest is body.
    Complete {
        head: usize,
        total: usize,
        framing: BodyFraming,
    },
    /// Need more bytes.
    Incomplete,
    /// Malformed head or rejected framing (e.g. smuggling).
    Error(MessageError),
}

/// Why a message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// The start line or headers couldn't be parsed.
    BadHead,
    /// Too many headers.
    TooManyHeaders,
    /// Framing was rejected (smuggling / unframeable). Carries the reason.
    Framing(FramingError),
    /// A chunked body was malformed.
    BadChunked,
    /// Declared Content-Length exceeds the configured body-size limit.
    BodyTooLarge,
}

/// Scan `buf` for exactly one complete HTTP/1 message (no body-size limit).
pub fn scan_message(buf: &[u8], is_request: bool) -> MessageScan {
    scan_message_limited(buf, is_request, 0)
}

/// Like `scan_message`, but rejects bodies larger than `max_body` (0 =
/// unlimited) with `BodyTooLarge`. For Content-Length the check fires as soon
/// as the head is parsed (before buffering the oversized body — the primary
/// resource-exhaustion guard); for chunked the check fires when the body is
/// found complete (`scan_chunked` returns the total length without decoding),
/// so an oversized chunked upload is rejected at message-end rather than
/// mid-stream. Either way, the engine sees `BodyTooLarge` and returns 413
/// before relaying upstream.
///
/// `is_request` selects the request vs response start-line grammar. Pure and
/// incremental: safe to call repeatedly as bytes arrive (returns `Incomplete`
/// until a full message — head + body — is present).
///
/// Thin wrapper over `scan_message_with_metadata` for callers that don't need
/// the routing metadata (responses, tests). The engine's request loop uses
/// the metadata-returning variant directly so `rewrite_forward` can skip a
/// second httparse pass.
pub fn scan_message_limited(buf: &[u8], is_request: bool, max_body: u64) -> MessageScan {
    scan_message_with_metadata(buf, is_request, max_body).0
}

/// Like `scan_message_limited`, but additionally returns `MessageMetadata`
/// (method/path/header byte-ranges + head_end) extracted in the same httparse
/// pass. Returns `(scan, Some(metadata))` for valid requests and
/// `(scan, None)` for responses or any error path. The engine threads this
/// metadata into `rewrite_forward_with_metadata` to avoid parsing the head twice.
pub fn scan_message_with_metadata(
    buf: &[u8],
    is_request: bool,
    max_body: u64,
) -> (MessageScan, Option<MessageMetadata>) {
    // 1. Head must be terminated by CRLFCRLF.
    let head_end = match find(buf, b"\r\n\r\n") {
        Some(i) => i + 4,
        None => return (MessageScan::Incomplete, None),
    };

    // 2. Parse the head with httparse to extract headers for framing.
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut metadata: Option<MessageMetadata> = None;
    let pairs: Vec<(&[u8], &[u8])> = if is_request {
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(buf) {
            Ok(httparse::Status::Complete(n)) => {
                debug_assert_eq!(n, head_end);
                // Build the metadata once, alongside the pairs Vec that
                // analyze_framing needs — both come from the same httparse
                // output, so this is the single source of truth per request.
                let method_str = req.method.unwrap_or("");
                let path_str = req.path.unwrap_or("");
                let header_ranges: Vec<HeaderRange> = req
                    .headers
                    .iter()
                    .map(|h| HeaderRange {
                        name: range_of(buf, h.name.as_bytes()),
                        value: range_of(buf, h.value),
                    })
                    .collect();
                metadata = Some(MessageMetadata {
                    method: range_of(buf, method_str.as_bytes()),
                    path: range_of(buf, path_str.as_bytes()),
                    version: req.version.unwrap_or(1),
                    headers: header_ranges,
                    head_end,
                });
                req.headers
                    .iter()
                    .map(|h| (h.name.as_bytes(), h.value))
                    .collect()
            }
            Ok(httparse::Status::Partial) => return (MessageScan::Incomplete, None),
            Err(httparse::Error::TooManyHeaders) => {
                return (MessageScan::Error(MessageError::TooManyHeaders), None)
            }
            Err(_) => return (MessageScan::Error(MessageError::BadHead), None),
        }
    } else {
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(buf) {
            Ok(httparse::Status::Complete(n)) => {
                debug_assert_eq!(n, head_end);
                resp.headers
                    .iter()
                    .map(|h| (h.name.as_bytes(), h.value))
                    .collect()
            }
            Ok(httparse::Status::Partial) => return (MessageScan::Incomplete, None),
            Err(httparse::Error::TooManyHeaders) => {
                return (MessageScan::Error(MessageError::TooManyHeaders), None)
            }
            Err(_) => return (MessageScan::Error(MessageError::BadHead), None),
        }
    };

    // 3. Decide framing (rejects smuggling).
    let framing = match analyze_framing(&pairs) {
        Ok(f) => f,
        Err(e) => return (MessageScan::Error(MessageError::Framing(e)), None),
    };

    // 4. Locate the body end.
    let scan = match framing {
        BodyFraming::None => MessageScan::Complete {
            head: head_end,
            total: head_end,
            framing,
        },
        BodyFraming::ContentLength(n) => {
            // Reject oversized bodies up front, before buffering them.
            if max_body > 0 && n > max_body {
                return (MessageScan::Error(MessageError::BodyTooLarge), None);
            }
            let total = match head_end.checked_add(n as usize) {
                Some(t) => t,
                None => return (MessageScan::Error(MessageError::BadHead), None),
            };
            if buf.len() < total {
                MessageScan::Incomplete
            } else {
                MessageScan::Complete {
                    head: head_end,
                    total,
                    framing,
                }
            }
        }
        BodyFraming::Chunked => match scan_chunked(&buf[head_end..]) {
            ChunkScan::Complete(body_len) => {
                // Enforce the same body-size cap on chunked uploads. Unlike
                // Content-Length we can only check at message-end (the size
                // isn't declared up front), and the comparison is against the
                // *wire-encoded* chunked length (chunk-size headers + CRLFs +
                // trailers), which is a slightly conservative bound vs the
                // decoded payload — fine for a resource-exhaustion guard.
                // Engines that observe BodyTooLarge return 413 and tear the
                // connection; they don't relay the buffered bytes upstream.
                if max_body > 0 && body_len as u64 > max_body {
                    return (MessageScan::Error(MessageError::BodyTooLarge), None);
                }
                MessageScan::Complete {
                    head: head_end,
                    total: head_end + body_len,
                    framing,
                }
            }
            ChunkScan::Incomplete => MessageScan::Incomplete,
            ChunkScan::Malformed => MessageScan::Error(MessageError::BadChunked),
        },
    };
    // For valid Complete-request scans, metadata is Some (set above). For
    // responses or any non-Complete scan, it's None (left at the initial value
    // or an early return). Pair them up.
    (scan, metadata)
}

/// How the body of the request whose complete head is `head` is framed, or
/// `None` if the head does not parse or its framing is rejected (the full
/// scanner reports why). Lets a reader wait for the rest of a body by length,
/// without parsing the head again on every read.
pub fn request_body_framing(head: &[u8]) -> Option<BodyFraming> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return None,
    }
    let pairs: Vec<(&[u8], &[u8])> = req
        .headers
        .iter()
        .map(|h| (h.name.as_bytes(), h.value))
        .collect();
    analyze_framing(&pairs).ok()
}

/// How the body of a response is delimited (RFC 7230 §3.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseBody {
    /// No body: the response ends at its head.
    None,
    /// Exactly this many bytes follow the head.
    Length(u64),
    /// A chunked body follows (track its end with `ChunkedTracker`).
    Chunked,
    /// No declared length: the body runs until the upstream closes.
    UntilClose,
}

/// Result of scanning a buffer for the head of one HTTP/1 *response*. Response
/// framing, unlike request framing, depends on the request method and the
/// status code, and allows a body delimited by connection close.
///
/// Only the head is examined, so a caller can start relaying the body as it
/// arrives instead of buffering the whole response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseHead {
    /// The head occupies the first `head` bytes.
    Complete {
        head: usize,
        /// A 1xx interim response (other than 101): NOT the answer to the
        /// request — the final response follows on the same connection.
        interim: bool,
        /// Whether the upstream connection may carry another request after
        /// this response (HTTP/1.1 without `Connection: close`, or HTTP/1.0
        /// with `Connection: keep-alive`). Never true for `UntilClose`.
        keep_alive: bool,
        body: ResponseBody,
    },
    /// Need more bytes.
    Incomplete,
    /// Malformed head or rejected framing.
    Error(MessageError),
}

/// True if any `Connection` header in `pairs` lists `token` (case-insensitive).
fn connection_has_token(pairs: &[(&[u8], &[u8])], token: &[u8]) -> bool {
    pairs
        .iter()
        .filter(|(name, _)| eq_ignore_ascii_case_bytes(name, b"connection"))
        .flat_map(|(_, value)| value.split(|&c| c == b','))
        .any(|t| eq_ignore_ascii_case_bytes(trim_ows(t), token))
}

/// Scan `buf` for the head of one HTTP/1 response. `head_request` says whether
/// the request this answers was a HEAD (its response never has a body,
/// whatever Content-Length / Transfer-Encoding claim).
///
/// Rules, in RFC 7230 §3.3.3 order:
///   1. HEAD responses, 1xx, 204 and 304 end at the head.
///   2. Transfer-Encoding with final coding `chunked` => chunked body.
///      (Content-Length together with Transfer-Encoding, or an unframeable
///      Transfer-Encoding, is rejected — same strictness as for requests.)
///   3. Content-Length => that many bytes.
///   4. Neither => the body runs until the upstream closes the connection.
pub fn scan_response_head(buf: &[u8], head_request: bool) -> ResponseHead {
    let head_end = match find(buf, b"\r\n\r\n") {
        Some(i) => i + 4,
        None => return ResponseHead::Incomplete,
    };
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => debug_assert_eq!(n, head_end),
        Ok(httparse::Status::Partial) => return ResponseHead::Incomplete,
        Err(httparse::Error::TooManyHeaders) => {
            return ResponseHead::Error(MessageError::TooManyHeaders)
        }
        Err(_) => return ResponseHead::Error(MessageError::BadHead),
    }
    let code = resp.code.unwrap_or(0);
    let http10 = resp.version == Some(0);
    let pairs: Vec<(&[u8], &[u8])> = resp
        .headers
        .iter()
        .map(|h| (h.name.as_bytes(), h.value))
        .collect();

    let keep_alive = if http10 {
        connection_has_token(&pairs, b"keep-alive")
    } else {
        !connection_has_token(&pairs, b"close")
    };
    let complete = |interim: bool, keep_alive: bool, body: ResponseBody| ResponseHead::Complete {
        head: head_end,
        interim,
        keep_alive,
        body,
    };

    // (1) Responses that never carry a body.
    if (100..200).contains(&code) {
        // 101 Switching Protocols ends HTTP on this connection: it is final,
        // and the connection can't carry another request.
        let interim = code != 101;
        return complete(interim, interim && keep_alive, ResponseBody::None);
    }
    if head_request || code == 204 || code == 304 {
        return complete(false, keep_alive, ResponseBody::None);
    }

    // (2)-(4) Framing from the headers.
    let has_length_header = pairs.iter().any(|(name, _)| {
        eq_ignore_ascii_case_bytes(name, b"content-length")
            || eq_ignore_ascii_case_bytes(name, b"transfer-encoding")
    });
    if !has_length_header {
        return complete(false, false, ResponseBody::UntilClose);
    }
    match analyze_framing(&pairs) {
        Err(e) => ResponseHead::Error(MessageError::Framing(e)),
        Ok(BodyFraming::None) => complete(false, keep_alive, ResponseBody::None),
        Ok(BodyFraming::ContentLength(0)) => complete(false, keep_alive, ResponseBody::None),
        Ok(BodyFraming::ContentLength(n)) => complete(false, keep_alive, ResponseBody::Length(n)),
        Ok(BodyFraming::Chunked) => complete(false, keep_alive, ResponseBody::Chunked),
    }
}

/// Longest chunk-size line (size + extensions) or trailer line accepted while
/// streaming, and the most trailer bytes in total. Without a bound, a peer
/// that never sends the line terminator would make us buffer forever.
const MAX_CHUNK_LINE: usize = 8 * 1024;
const MAX_TRAILER_BYTES: usize = 32 * 1024;

/// What `ChunkedTracker::advance` learned from the bytes it was shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkProgress {
    /// The first N bytes belong to the body and can be passed on; the body
    /// continues. Any bytes after N are an unfinished line: show them again,
    /// with more data appended, on the next call.
    More(usize),
    /// The body ends after the first N bytes.
    Done(usize),
    /// Malformed framing — abandon the message.
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// At the start of a chunk-size line.
    SizeLine,
    /// Inside chunk data, with this many bytes still to come.
    Data(u64),
    /// After chunk data, with this many bytes of its CRLF still to come.
    DataEnd(u8),
    /// After the last chunk, at the start of a trailer line or the final CRLF.
    Trailers,
    Done,
}

/// Finds the end of a chunked body that arrives in pieces, without decoding it
/// and without looking at any byte twice. The streaming counterpart of
/// `scan_chunked`, with the same framing rules.
#[derive(Debug)]
pub struct ChunkedTracker {
    state: ChunkState,
    trailer_bytes: usize,
}

impl Default for ChunkedTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedTracker {
    pub fn new() -> Self {
        ChunkedTracker {
            state: ChunkState::SizeLine,
            trailer_bytes: 0,
        }
    }

    /// Advance over `buf`, which must start where the previous call's consumed
    /// bytes ended.
    pub fn advance(&mut self, buf: &[u8]) -> ChunkProgress {
        let mut pos = 0usize;
        loop {
            match self.state {
                ChunkState::SizeLine => {
                    let rest = &buf[pos..];
                    let Some(line_len) = find(rest, b"\r\n") else {
                        if rest.len() > MAX_CHUNK_LINE {
                            return ChunkProgress::Malformed;
                        }
                        return ChunkProgress::More(pos);
                    };
                    let line = &rest[..line_len];
                    if !is_clean_chunk_line(line) {
                        return ChunkProgress::Malformed;
                    }
                    let size_field = line.split(|&c| c == b';').next().unwrap_or(line);
                    let Some(size) = parse_hex_strict(trim_ows(size_field)) else {
                        return ChunkProgress::Malformed;
                    };
                    pos += line_len + 2;
                    self.state = if size == 0 {
                        ChunkState::Trailers
                    } else {
                        ChunkState::Data(size)
                    };
                }
                ChunkState::Data(remaining) => {
                    let available = (buf.len() - pos) as u64;
                    if available < remaining {
                        self.state = ChunkState::Data(remaining - available);
                        return ChunkProgress::More(buf.len());
                    }
                    pos += remaining as usize;
                    self.state = ChunkState::DataEnd(2);
                }
                ChunkState::DataEnd(left) => {
                    let Some(&byte) = buf.get(pos) else {
                        return ChunkProgress::More(pos);
                    };
                    let expected = if left == 2 { b'\r' } else { b'\n' };
                    if byte != expected {
                        return ChunkProgress::Malformed; // data not CRLF-terminated
                    }
                    pos += 1;
                    self.state = if left == 2 {
                        ChunkState::DataEnd(1)
                    } else {
                        ChunkState::SizeLine
                    };
                }
                ChunkState::Trailers => {
                    let rest = &buf[pos..];
                    let Some(line_len) = find(rest, b"\r\n") else {
                        if rest.len() > MAX_CHUNK_LINE {
                            return ChunkProgress::Malformed;
                        }
                        return ChunkProgress::More(pos);
                    };
                    if !is_clean_chunk_line(&rest[..line_len]) {
                        return ChunkProgress::Malformed;
                    }
                    pos += line_len + 2;
                    if line_len == 0 {
                        self.state = ChunkState::Done;
                        return ChunkProgress::Done(pos);
                    }
                    self.trailer_bytes += line_len + 2;
                    if self.trailer_bytes > MAX_TRAILER_BYTES {
                        return ChunkProgress::Malformed;
                    }
                }
                ChunkState::Done => return ChunkProgress::Done(pos),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&'static str, &'static str)]) -> Vec<(&'static [u8], &'static [u8])> {
        pairs
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect()
    }

    // ---- analyze_framing: no body ----
    #[test]
    fn no_headers_is_no_body() {
        assert_eq!(analyze_framing(&[]), Ok(BodyFraming::None));
    }
    #[test]
    fn unrelated_headers_no_body() {
        let hs = h(&[("Host", "x"), ("Accept", "*/*")]);
        assert_eq!(analyze_framing(&hs), Ok(BodyFraming::None));
    }

    // ---- Content-Length ----
    #[test]
    fn content_length_basic() {
        let hs = h(&[("Content-Length", "42")]);
        assert_eq!(analyze_framing(&hs), Ok(BodyFraming::ContentLength(42)));
    }
    #[test]
    fn content_length_zero_is_none() {
        let hs = h(&[("Content-Length", "0")]);
        assert_eq!(analyze_framing(&hs), Ok(BodyFraming::None));
    }
    #[test]
    fn content_length_case_insensitive_name() {
        let hs = h(&[("CONTENT-LENGTH", "7")]);
        assert_eq!(analyze_framing(&hs), Ok(BodyFraming::ContentLength(7)));
    }
    #[test]
    fn content_length_ows_trimmed() {
        let hs = h(&[("Content-Length", "  5  ")]);
        assert_eq!(analyze_framing(&hs), Ok(BodyFraming::ContentLength(5)));
    }
    #[test]
    fn content_length_duplicate_identical_ok() {
        let hs = h(&[("Content-Length", "5"), ("Content-Length", "5")]);
        assert_eq!(analyze_framing(&hs), Ok(BodyFraming::ContentLength(5)));
    }
    #[test]
    fn content_length_duplicate_differing_rejected() {
        let hs = h(&[("Content-Length", "5"), ("Content-Length", "6")]);
        assert_eq!(
            analyze_framing(&hs),
            Err(FramingError::ConflictingContentLength)
        );
    }
    #[test]
    fn content_length_comma_list_same_ok() {
        let hs = h(&[("Content-Length", "5, 5")]);
        assert_eq!(analyze_framing(&hs), Ok(BodyFraming::ContentLength(5)));
    }
    #[test]
    fn content_length_comma_list_differing_rejected() {
        let hs = h(&[("Content-Length", "5, 6")]);
        assert_eq!(
            analyze_framing(&hs),
            Err(FramingError::ConflictingContentLength)
        );
    }
    #[test]
    fn content_length_non_numeric_rejected() {
        assert_eq!(
            analyze_framing(&h(&[("Content-Length", "abc")])),
            Err(FramingError::InvalidContentLength)
        );
    }
    #[test]
    fn content_length_negative_rejected() {
        assert_eq!(
            analyze_framing(&h(&[("Content-Length", "-1")])),
            Err(FramingError::InvalidContentLength)
        );
    }
    #[test]
    fn content_length_hex_rejected() {
        assert_eq!(
            analyze_framing(&h(&[("Content-Length", "0x10")])),
            Err(FramingError::InvalidContentLength)
        );
    }
    #[test]
    fn content_length_plus_rejected() {
        assert_eq!(
            analyze_framing(&h(&[("Content-Length", "+5")])),
            Err(FramingError::InvalidContentLength)
        );
    }
    #[test]
    fn content_length_overflow_rejected() {
        assert_eq!(
            analyze_framing(&h(&[("Content-Length", "99999999999999999999999999")])),
            Err(FramingError::InvalidContentLength)
        );
    }

    // ---- Transfer-Encoding ----
    #[test]
    fn te_chunked() {
        assert_eq!(
            analyze_framing(&h(&[("Transfer-Encoding", "chunked")])),
            Ok(BodyFraming::Chunked)
        );
    }
    #[test]
    fn te_chunked_case_insensitive() {
        assert_eq!(
            analyze_framing(&h(&[("TRANSFER-ENCODING", "Chunked")])),
            Ok(BodyFraming::Chunked)
        );
    }
    #[test]
    fn te_gzip_then_chunked_ok() {
        assert_eq!(
            analyze_framing(&h(&[("Transfer-Encoding", "gzip, chunked")])),
            Ok(BodyFraming::Chunked)
        );
    }
    #[test]
    fn te_chunked_not_final_rejected() {
        assert_eq!(
            analyze_framing(&h(&[("Transfer-Encoding", "chunked, gzip")])),
            Err(FramingError::UnframeableTransferEncoding)
        );
    }
    #[test]
    fn te_without_chunked_rejected() {
        assert_eq!(
            analyze_framing(&h(&[("Transfer-Encoding", "gzip")])),
            Err(FramingError::UnframeableTransferEncoding)
        );
    }
    #[test]
    fn te_substring_not_chunked() {
        // "xchunked" must not be treated as chunked.
        assert_eq!(
            analyze_framing(&h(&[("Transfer-Encoding", "xchunked")])),
            Err(FramingError::UnframeableTransferEncoding)
        );
    }
    #[test]
    fn te_double_chunked_rejected() {
        // Obfuscation: chunked twice.
        assert_eq!(
            analyze_framing(&h(&[("Transfer-Encoding", "chunked, chunked")])),
            Err(FramingError::UnframeableTransferEncoding)
        );
    }
    #[test]
    fn te_split_across_headers_final_not_chunked() {
        let hs = h(&[
            ("Transfer-Encoding", "chunked"),
            ("Transfer-Encoding", "identity"),
        ]);
        assert_eq!(
            analyze_framing(&hs),
            Err(FramingError::UnframeableTransferEncoding)
        );
    }

    // ---- the headline smuggling defense ----
    #[test]
    fn cl_and_te_together_rejected() {
        let hs = h(&[("Content-Length", "10"), ("Transfer-Encoding", "chunked")]);
        assert_eq!(analyze_framing(&hs), Err(FramingError::ClTeConflict));
    }
    #[test]
    fn te_and_cl_reverse_order_rejected() {
        let hs = h(&[("Transfer-Encoding", "chunked"), ("Content-Length", "10")]);
        assert_eq!(analyze_framing(&hs), Err(FramingError::ClTeConflict));
    }
    #[test]
    fn cl_te_conflict_beats_invalid_cl() {
        // CL.TE check has precedence even if the CL value is also invalid.
        let hs = h(&[("Content-Length", "bad"), ("Transfer-Encoding", "chunked")]);
        assert_eq!(analyze_framing(&hs), Err(FramingError::ClTeConflict));
    }

    // ---- scan_chunked ----
    #[test]
    fn chunked_single() {
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(scan_chunked(body), ChunkScan::Complete(body.len()));
    }
    #[test]
    fn chunked_empty_body() {
        let body = b"0\r\n\r\n";
        assert_eq!(scan_chunked(body), ChunkScan::Complete(body.len()));
    }
    #[test]
    fn chunked_multi() {
        let body = b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(scan_chunked(body), ChunkScan::Complete(body.len()));
    }
    #[test]
    fn chunked_hex_size() {
        // 0x1a = 26 bytes
        let data = "a".repeat(26);
        let body = format!("1a\r\n{}\r\n0\r\n\r\n", data).into_bytes();
        assert_eq!(scan_chunked(&body), ChunkScan::Complete(body.len()));
    }
    #[test]
    fn chunked_with_extension() {
        let body = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        assert_eq!(scan_chunked(body), ChunkScan::Complete(body.len()));
    }
    #[test]
    fn chunked_with_trailers() {
        let body = b"5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n";
        assert_eq!(scan_chunked(body), ChunkScan::Complete(body.len()));
    }
    #[test]
    fn chunked_incomplete_data() {
        assert_eq!(scan_chunked(b"5\r\nhel"), ChunkScan::Incomplete);
    }
    #[test]
    fn chunked_incomplete_no_terminator() {
        assert_eq!(scan_chunked(b"5\r\nhello\r\n"), ChunkScan::Incomplete);
    }
    #[test]
    fn chunked_incomplete_size_line() {
        assert_eq!(scan_chunked(b"5"), ChunkScan::Incomplete);
    }
    #[test]
    fn chunked_bad_hex() {
        assert_eq!(
            scan_chunked(b"zz\r\nhello\r\n0\r\n\r\n"),
            ChunkScan::Malformed
        );
    }
    #[test]
    fn chunked_data_not_crlf_terminated() {
        // declared 5 bytes then "helloXX" instead of "hello\r\n"
        assert_eq!(scan_chunked(b"5\r\nhelloXX0\r\n\r\n"), ChunkScan::Malformed);
    }
    #[test]
    fn chunked_trailing_bytes_after_complete() {
        // a complete body plus the start of the next request — Complete points
        // only at the body's end, leaving the rest for the next parse.
        // body = "5\r\nhello\r\n0\r\n\r\n" = 15 bytes; the rest belongs to the next request.
        let next = b"5\r\nhello\r\n0\r\n\r\nGET / HTTP/1.1\r\n";
        assert_eq!(scan_chunked(next), ChunkScan::Complete(15));
    }

    // ---- robustness: incremental feed must never false-Malformed ----
    #[test]
    fn chunked_every_prefix_of_valid_is_incomplete_until_end() {
        // As bytes arrive on the socket, every short prefix of a valid body must
        // read as Incomplete (never Malformed/panic); only the full body is
        // Complete. This is what makes the scanner safe to call on partial reads.
        let body: &[u8] = b"3\r\nabc\r\n1a\r\n0123456789abcdef0123456789\r\n0\r\nX-T: v\r\n\r\n";
        for n in 0..body.len() {
            assert_eq!(
                scan_chunked(&body[..n]),
                ChunkScan::Incomplete,
                "prefix len {n}"
            );
        }
        assert_eq!(scan_chunked(body), ChunkScan::Complete(body.len()));
    }

    // ---- robustness: never panic on arbitrary input (deterministic fuzz) ----
    #[test]
    fn scan_chunked_never_panics() {
        // Deterministic LCG so any failure is reproducible. We don't assert the
        // verdict — only that scanning arbitrary bytes can't panic (no OOB index,
        // no overflow). This is the property a hostile client tests for us.
        let mut state: u32 = 0x1234_5678;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 16) as u8
        };
        for _ in 0..20_000 {
            let len = (next() % 40) as usize;
            // Bias bytes toward the framing alphabet so we exercise real paths.
            let alphabet = b"0123456789abcdefABCDEF\r\n; \t";
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    if next() % 3 == 0 {
                        next() // raw byte
                    } else {
                        alphabet[(next() as usize) % alphabet.len()]
                    }
                })
                .collect();
            let _ = scan_chunked(&buf); // must not panic
        }
    }

    #[test]
    fn analyze_framing_never_panics() {
        let mut state: u32 = 0x9e37_79b9;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 16) as u8
        };
        let cl_vals: [&[u8]; 6] = [b"", b"5", b"5,5", b"5, 6", b"-1", b"0x5"];
        let te_vals: [&[u8]; 5] = [
            b"",
            b"chunked",
            b"gzip, chunked",
            b"chunked, gzip",
            b"identity",
        ];
        for _ in 0..5_000 {
            let mut hs: Vec<(&[u8], &[u8])> = Vec::new();
            if next() % 2 == 0 {
                hs.push((
                    b"Content-Length",
                    cl_vals[(next() as usize) % cl_vals.len()],
                ));
            }
            if next() % 2 == 0 {
                hs.push((
                    b"Transfer-Encoding",
                    te_vals[(next() as usize) % te_vals.len()],
                ));
            }
            if next() % 2 == 0 {
                hs.push((b"Host", b"example.com"));
            }
            let _ = analyze_framing(&hs); // must not panic
        }
    }

    // ---- scan_message: requests ----
    #[test]
    fn msg_get_no_body() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(
            scan_message(buf, true),
            MessageScan::Complete {
                head: buf.len(),
                total: buf.len(),
                framing: BodyFraming::None
            }
        );
    }
    #[test]
    fn msg_post_content_length() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        let head = buf.len() - 5;
        assert_eq!(
            scan_message(buf, true),
            MessageScan::Complete {
                head,
                total: buf.len(),
                framing: BodyFraming::ContentLength(5)
            }
        );
    }
    #[test]
    fn msg_post_body_incomplete() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhel";
        assert_eq!(scan_message(buf, true), MessageScan::Incomplete);
    }
    #[test]
    fn msg_head_incomplete() {
        assert_eq!(
            scan_message(b"GET / HTTP/1.1\r\nHost: ", true),
            MessageScan::Incomplete
        );
    }
    #[test]
    fn msg_chunked_request() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        match scan_message(buf, true) {
            MessageScan::Complete {
                total,
                framing: BodyFraming::Chunked,
                ..
            } => {
                assert_eq!(total, buf.len())
            }
            other => panic!("expected chunked complete, got {other:?}"),
        }
    }
    #[test]
    fn msg_smuggling_rejected() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
        assert_eq!(
            scan_message(buf, true),
            MessageScan::Error(MessageError::Framing(FramingError::ClTeConflict))
        );
    }
    #[test]
    fn msg_bad_head_rejected() {
        // garbage start line
        let buf = b"!!!not http!!!\r\n\r\n";
        assert_eq!(
            scan_message(buf, true),
            MessageScan::Error(MessageError::BadHead)
        );
    }

    // ---- scan_message: responses ----
    #[test]
    fn msg_response_content_length() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!";
        let head = buf.len() - 13;
        assert_eq!(
            scan_message(buf, false),
            MessageScan::Complete {
                head,
                total: buf.len(),
                framing: BodyFraming::ContentLength(13)
            }
        );
    }
    #[test]
    fn msg_response_chunked() {
        let buf = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        match scan_message(buf, false) {
            MessageScan::Complete {
                total,
                framing: BodyFraming::Chunked,
                ..
            } => {
                assert_eq!(total, buf.len())
            }
            other => panic!("expected chunked complete, got {other:?}"),
        }
    }

    // ---- scan_message: incremental safety + pipelining ----
    #[test]
    fn msg_every_prefix_safe() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        for n in 0..buf.len() {
            // Every prefix must be Incomplete (never panic / false Error).
            assert_eq!(
                scan_message(&buf[..n], true),
                MessageScan::Incomplete,
                "prefix {n}"
            );
        }
        assert!(matches!(
            scan_message(buf, true),
            MessageScan::Complete { .. }
        ));
    }
    #[test]
    fn msg_body_too_large_rejected_early() {
        // Head declares CL 100 but only part of the body is present; with a
        // limit of 10 it must reject immediately (not wait for the body).
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nhello";
        assert_eq!(
            scan_message_limited(buf, true, 10),
            MessageScan::Error(MessageError::BodyTooLarge)
        );
    }
    #[test]
    fn msg_body_within_limit_ok() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        assert!(matches!(
            scan_message_limited(buf, true, 10),
            MessageScan::Complete {
                framing: BodyFraming::ContentLength(5),
                ..
            }
        ));
    }
    #[test]
    fn msg_body_limit_zero_is_unlimited() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        assert!(matches!(
            scan_message_limited(buf, true, 0),
            MessageScan::Complete { .. }
        ));
    }

    #[test]
    fn msg_pipelined_returns_first_only() {
        // Two requests back-to-back: scan must frame only the first.
        let buf = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n";
        let first = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n".len();
        assert_eq!(
            scan_message(buf, true),
            MessageScan::Complete {
                head: first,
                total: first,
                framing: BodyFraming::None
            }
        );
    }

    // ---- max_body enforcement on chunked bodies ----
    #[test]
    fn chunked_body_under_limit_accepted() {
        // chunked body wire length = 15 ("5\r\nhello\r\n0\r\n\r\n"), limit 100 — passes.
        // The cap is against the wire-encoded chunked length, not the decoded
        // payload (which is 5 bytes here): conservative-but-correct.
        let req: Vec<u8> = [
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"5\r\nhello\r\n0\r\n\r\n",
        ]
        .concat();
        match scan_message_limited(&req, true, 100) {
            MessageScan::Complete {
                framing: BodyFraming::Chunked,
                ..
            } => {}
            other => panic!("expected Complete chunked, got {:?}", other),
        }
    }

    #[test]
    fn chunked_body_over_limit_rejected() {
        // 5-byte chunked body, limit 4 — must reject as oversized. Prior
        // behavior allowed any chunked body regardless of max_body, since the
        // size check fired only on declared Content-Length.
        let req: Vec<u8> = [
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"5\r\nhello\r\n0\r\n\r\n",
        ]
        .concat();
        assert_eq!(
            scan_message_limited(&req, true, 4),
            MessageScan::Error(MessageError::BodyTooLarge)
        );
    }

    #[test]
    fn chunked_body_unlimited_when_max_zero() {
        // max_body=0 means "unlimited" — chunked passes through even if huge.
        let big = "a".repeat(10_000);
        let req: Vec<u8> = [
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            format!("2710\r\n{}\r\n0\r\n\r\n", big).as_bytes(), // 0x2710 = 10000
        ]
        .concat();
        match scan_message_limited(&req, true, 0) {
            MessageScan::Complete {
                framing: BodyFraming::Chunked,
                ..
            } => {}
            other => panic!("expected Complete chunked, got {:?}", other),
        }
    }

    // ---- scan_response: RFC 7230 §3.3.3 response rules ----

    /// Whole-buffer view of a response, built from the two streaming pieces
    /// (`scan_response_head` + the chunked scanner) the engine uses.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ResponseScan {
        Complete {
            head: usize,
            total: usize,
            interim: bool,
            keep_alive: bool,
        },
        UntilClose {
            head: usize,
        },
        Incomplete,
        Error(MessageError),
    }

    fn scan_response(buf: &[u8], head_request: bool) -> ResponseScan {
        let (head, interim, keep_alive, body) = match scan_response_head(buf, head_request) {
            ResponseHead::Incomplete => return ResponseScan::Incomplete,
            ResponseHead::Error(e) => return ResponseScan::Error(e),
            ResponseHead::Complete {
                head,
                interim,
                keep_alive,
                body,
            } => (head, interim, keep_alive, body),
        };
        let body_len = match body {
            ResponseBody::None => 0,
            ResponseBody::Length(n) => n as usize,
            ResponseBody::UntilClose => {
                assert!(!keep_alive, "a close-delimited response can't keep alive");
                return ResponseScan::UntilClose { head };
            }
            ResponseBody::Chunked => {
                // The streaming tracker must agree with the one-shot scanner.
                let one_shot = scan_chunked(&buf[head..]);
                let streamed = ChunkedTracker::new().advance(&buf[head..]);
                match (one_shot, streamed) {
                    (ChunkScan::Complete(n), ChunkProgress::Done(m)) => {
                        assert_eq!(n, m);
                        n
                    }
                    (ChunkScan::Incomplete, ChunkProgress::More(_)) => {
                        return ResponseScan::Incomplete
                    }
                    (ChunkScan::Malformed, ChunkProgress::Malformed) => {
                        return ResponseScan::Error(MessageError::BadChunked)
                    }
                    other => panic!("chunk scanners disagree: {other:?}"),
                }
            }
        };
        if buf.len() < head + body_len {
            return ResponseScan::Incomplete;
        }
        ResponseScan::Complete {
            head,
            total: head + body_len,
            interim,
            keep_alive,
        }
    }

    fn complete(head: usize, total: usize, keep_alive: bool) -> ResponseScan {
        ResponseScan::Complete {
            head,
            total,
            interim: false,
            keep_alive,
        }
    }

    #[test]
    fn response_content_length_body() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let head = r.len() - 5;
        assert_eq!(scan_response(r, false), complete(head, r.len(), true));
        // Body not all here yet.
        assert_eq!(
            scan_response(&r[..r.len() - 1], false),
            ResponseScan::Incomplete
        );
    }

    #[test]
    fn response_to_head_has_no_body_despite_content_length() {
        // The origin describes the body a GET would return but sends none.
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 1256\r\n\r\n";
        assert_eq!(scan_response(r, true), complete(r.len(), r.len(), true));
        // The same bytes answering a GET are an unfinished response.
        assert_eq!(scan_response(r, false), ResponseScan::Incomplete);
    }

    #[test]
    fn response_to_head_has_no_body_despite_chunked() {
        let r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(scan_response(r, true), complete(r.len(), r.len(), true));
    }

    #[test]
    fn response_204_and_304_have_no_body() {
        for status in ["204 No Content", "304 Not Modified"] {
            let r = format!("HTTP/1.1 {status}\r\nContent-Length: 10\r\n\r\n");
            assert_eq!(
                scan_response(r.as_bytes(), false),
                complete(r.len(), r.len(), true),
                "{status}"
            );
        }
    }

    #[test]
    fn response_1xx_is_interim_and_ends_at_head() {
        let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
        let mut buf = interim.to_vec();
        buf.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        assert_eq!(
            scan_response(&buf, false),
            ResponseScan::Complete {
                head: interim.len(),
                total: interim.len(),
                interim: true,
                keep_alive: true,
            }
        );
        // 103 Early Hints carries headers but is still interim and bodiless.
        let hints = b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n";
        assert!(matches!(
            scan_response(hints, false),
            ResponseScan::Complete { interim: true, total, .. } if total == hints.len()
        ));
    }

    #[test]
    fn response_101_is_final_and_not_reusable() {
        let r = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(scan_response(r, false), complete(r.len(), r.len(), false));
    }

    #[test]
    fn response_without_length_runs_until_close() {
        let r = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html>";
        let head = r.len() - 6;
        assert_eq!(scan_response(r, false), ResponseScan::UntilClose { head });
        // HTTP/1.1 without a length is close-delimited too.
        let r11 = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npartial";
        assert!(matches!(
            scan_response(r11, false),
            ResponseScan::UntilClose { .. }
        ));
    }

    #[test]
    fn response_explicit_zero_length_is_complete_not_until_close() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(scan_response(r, false), complete(r.len(), r.len(), true));
    }

    #[test]
    fn response_chunked_body() {
        let r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let head = find(r, b"\r\n\r\n").unwrap() + 4;
        assert_eq!(scan_response(r, false), complete(head, r.len(), true));
        assert_eq!(
            scan_response(&r[..r.len() - 2], false),
            ResponseScan::Incomplete
        );
    }

    #[test]
    fn response_keep_alive_follows_version_and_connection_header() {
        let ka = |r: &[u8]| match scan_response(r, false) {
            ResponseScan::Complete { keep_alive, .. } => keep_alive,
            other => panic!("expected Complete, got {:?}", other),
        };
        assert!(ka(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
        assert!(!ka(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ));
        assert!(!ka(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: foo, Close\r\n\r\n"
        ));
        // HTTP/1.0 closes by default...
        assert!(!ka(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"));
        // ...unless it opts in.
        assert!(ka(
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
        ));
    }

    #[test]
    fn response_rejects_conflicting_framing_and_bad_heads() {
        assert_eq!(
            scan_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
                false
            ),
            ResponseScan::Error(MessageError::Framing(FramingError::ClTeConflict))
        );
        assert_eq!(
            scan_response(b"NOT-HTTP garbage\r\n\r\n", false),
            ResponseScan::Error(MessageError::BadHead)
        );
        assert_eq!(
            scan_response(b"HTTP/1.1 200 OK\r\nContent-Le", false),
            ResponseScan::Incomplete
        );
    }

    #[test]
    fn scan_response_never_panics_on_truncation() {
        let r =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX: y\r\n\r\n";
        for head_request in [false, true] {
            for n in 0..=r.len() {
                let _ = scan_response(&r[..n], head_request);
            }
        }
    }

    // ---- ChunkedTracker: streaming chunked framing ----

    /// Feed `body` to a tracker in pieces of `step` bytes, the way a relay
    /// loop does (unconsumed bytes are shown again with more appended).
    /// Returns the body length found, or `None` if it never completed.
    fn track_in_steps(body: &[u8], step: usize) -> Result<Option<usize>, ()> {
        let mut tracker = ChunkedTracker::new();
        let mut pending: Vec<u8> = Vec::new();
        let mut passed = 0usize;
        for piece in body.chunks(step) {
            pending.extend_from_slice(piece);
            match tracker.advance(&pending) {
                ChunkProgress::More(n) => {
                    passed += n;
                    pending.drain(..n);
                }
                ChunkProgress::Done(n) => return Ok(Some(passed + n)),
                ChunkProgress::Malformed => return Err(()),
            }
        }
        Ok(None)
    }

    #[test]
    fn chunked_tracker_agrees_with_one_shot_scan_at_every_split() {
        let bodies: [&[u8]; 6] = [
            b"0\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            b"5;ext=1\r\nhello\r\nA\r\n0123456789\r\n0\r\n\r\n",
            b"3\r\nabc\r\n0\r\nX-Trailer: 1\r\nY: 2\r\n\r\n",
            // CRLF inside chunk data must not be read as framing.
            b"6\r\n\r\n\r\n\r\n\r\n0\r\n\r\n",
            b"1\r\nx\r\n1\r\ny\r\n1\r\nz\r\n0\r\n\r\n",
        ];
        for body in bodies {
            assert_eq!(scan_chunked(body), ChunkScan::Complete(body.len()));
            // Trailing bytes after the body are not part of it.
            let mut with_extra = body.to_vec();
            with_extra.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
            for step in 1..=with_extra.len() {
                assert_eq!(
                    track_in_steps(&with_extra, step),
                    Ok(Some(body.len())),
                    "step {step} over {:?}",
                    String::from_utf8_lossy(body)
                );
            }
            // Every strict prefix is unfinished, never complete or malformed.
            for cut in 0..body.len() {
                assert_eq!(track_in_steps(&body[..cut], 3), Ok(None), "cut {cut}");
            }
        }
    }

    #[test]
    fn chunked_tracker_rejects_what_the_one_shot_scan_rejects() {
        let bad: [&[u8]; 5] = [
            b"zz\r\nhello\r\n0\r\n\r\n",    // not hex
            b"5\r\nhelloXX0\r\n\r\n",       // data not CRLF-terminated
            b"5\r\nhello\rX0\r\n\r\n",      // CR without LF
            b"\r\n5\r\nhello\r\n0\r\n\r\n", // empty size line
            b"-1\r\n\r\n",                  // signed size
        ];
        for body in bad {
            assert_eq!(scan_chunked(body), ChunkScan::Malformed);
            for step in 1..=body.len() {
                assert_eq!(track_in_steps(body, step), Err(()), "step {step}");
            }
        }
    }

    /// Regression: a bare LF or CR inside a chunk-size line or trailer was
    /// relayed as part of one line. A peer that treats it as a line ending
    /// would frame the body differently (request smuggling). Both scanners
    /// reject it, at every way the bytes can be split across reads.
    #[test]
    fn control_characters_in_chunk_lines_are_rejected() {
        let bad: [&[u8]; 6] = [
            b"5;a=b\nfoo\r\nhello\r\n0\r\n\r\n", // bare LF in an extension
            b"5;a=b\rfoo\r\nhello\r\n0\r\n\r\n", // bare CR in an extension
            b"5\n\r\nhello\r\n0\r\n\r\n",        // bare LF after the size
            b"5;a=\x00\r\nhello\r\n0\r\n\r\n",   // NUL
            b"0\r\nX-T: a\nInjected: 1\r\n\r\n", // bare LF in a trailer
            b"0\r\nX-T: a\x7f\r\n\r\n",          // DEL in a trailer
        ];
        for body in bad {
            assert_eq!(scan_chunked(body), ChunkScan::Malformed, "{body:?}");
            for step in 1..=body.len() {
                assert_eq!(
                    track_in_steps(body, step),
                    Err(()),
                    "step {step} of {body:?}"
                );
            }
        }
        // Ordinary extensions and trailers, tabs included, still pass.
        let good: &[u8] = b"5;name=\"a b\";\tflag\r\nhello\r\n0\r\nX-T: a\tb\r\n\r\n";
        assert_eq!(scan_chunked(good), ChunkScan::Complete(good.len()));
        assert_eq!(track_in_steps(good, 3), Ok(Some(good.len())));
    }

    #[test]
    fn chunked_tracker_passes_data_through_without_waiting_for_the_chunk_end() {
        let mut tracker = ChunkedTracker::new();
        // Size line plus the first 4 of 0x10000 data bytes: all of it is body.
        assert_eq!(tracker.advance(b"10000\r\nabcd"), ChunkProgress::More(11));
        // A partial size line is held back until its CRLF arrives.
        let mut tracker = ChunkedTracker::new();
        assert_eq!(tracker.advance(b"1\r\nx\r\n1"), ChunkProgress::More(6));
        assert_eq!(tracker.advance(b"1"), ChunkProgress::More(0));
        assert_eq!(tracker.advance(b"1\r\n"), ChunkProgress::More(3));
    }

    #[test]
    fn chunked_tracker_bounds_unterminated_lines_and_trailers() {
        // A size line that never ends.
        let mut tracker = ChunkedTracker::new();
        assert_eq!(
            tracker.advance(&vec![b'1'; MAX_CHUNK_LINE + 1]),
            ChunkProgress::Malformed
        );
        // Endless trailers.
        let mut tracker = ChunkedTracker::new();
        assert_eq!(tracker.advance(b"0\r\n"), ChunkProgress::More(3));
        let line = b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
        let mut outcome = ChunkProgress::More(0);
        for _ in 0..=(MAX_TRAILER_BYTES / line.len()) {
            outcome = tracker.advance(line);
            if outcome == ChunkProgress::Malformed {
                break;
            }
        }
        assert_eq!(outcome, ChunkProgress::Malformed);
    }
}
