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
        // A trailer line — consume it and continue.
        pos += line_len + 2;
    }
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
}
