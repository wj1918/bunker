//! Forward-proxy request rewriting (pure, I/O-free). A forward proxy receives
//! absolute-form request lines (`GET http://host:port/path HTTP/1.1`) and must
//! rewrite them to origin-form (`GET /path HTTP/1.1`) before sending upstream,
//! strip hop-by-hop headers, set `Host` to the routed target, and (unless
//! switched off) set `X-Forwarded-For` to the client's address. This module does exactly
//! that on raw bytes so it's reusable by any runtime backend and unit-testable.
//!
//! Like framing.rs, the dangerous parsing reuses httparse; the rewriting and
//! target extraction are the new logic, pinned by tests.

use crate::proxy::framing::MessageMetadata;
use crate::security::split_host_port;
use bytes::Bytes;
use std::net::IpAddr;

const MAX_HEADERS: usize = 100;

/// RFC 7230 hop-by-hop headers — must not be forwarded to the upstream.
///
/// `Transfer-Encoding` is deliberately NOT stripped, although it is hop-by-hop:
/// the body is relayed undecoded, so a chunked body must keep the header that
/// frames it. Dropping it would hand the origin a request with no body length,
/// followed by raw chunk bytes it would parse as a second request (request
/// smuggling / connection desync). The framing pass has already rejected any
/// Transfer-Encoding whose final coding isn't a single `chunked`, and any
/// request carrying both Transfer-Encoding and Content-Length.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Headers of the client's request that are not copied to the upstream:
/// hop-by-hop headers, plus two the proxy writes itself.
///
/// * `Host` — re-emitted from the target the request is actually routed to
///   (see `push_host_header`). Forwarding the client's own value would let
///   `GET http://allowed.example/` with `Host: blocked.example` pass the
///   blocklist on the URL while a shared server routes by the header.
/// * `X-Forwarded-For` — replaced by the real peer address, or dropped when
///   the proxy is configured not to send one. Copying the client's would put
///   a forged address first in the list, where origins that trust the header
///   read it. (The hyper path drops it for the same reason.)
fn is_dropped_request_header(name: &str) -> bool {
    is_hop_by_hop(name)
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("x-forwarded-for")
}

/// Headers that say where the body ends. A client must not be able to remove
/// these by naming them in `Connection` (see `is_nominated`): the body is
/// relayed as received, so the origin would be left to guess its length.
fn is_framing_header(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"content-length") || name.eq_ignore_ascii_case(b"transfer-encoding")
}

/// True if `name` is listed in one of the request's `Connection` headers.
/// RFC 7230 §6.1: a header named there is meant for this hop only and must be
/// removed before forwarding.
fn is_nominated(name: &[u8], headers: &[(&[u8], &[u8])]) -> bool {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(b"connection"))
        .flat_map(|(_, value)| value.split(|&c| c == b','))
        .any(|token| token.trim_ascii().eq_ignore_ascii_case(name))
}

/// Append `Host: <target>` for the host the request is routed to. The port is
/// omitted when it is the default for `http`; IPv6 literals get their brackets
/// back (`split_host_port` strips them).
fn push_host_header(out: &mut Vec<u8>, host: &str, port: u16) {
    out.extend_from_slice(b"Host: ");
    if host.contains(':') {
        out.push(b'[');
        out.extend_from_slice(host.as_bytes());
        out.push(b']');
    } else {
        out.extend_from_slice(host.as_bytes());
    }
    if port != 80 {
        out.push(b':');
        out.extend_from_slice(port.to_string().as_bytes());
    }
    out.extend_from_slice(b"\r\n");
}

/// The resolved upstream target of a forward-proxy request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Why a forward request couldn't be rewritten/routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardError {
    /// Malformed request head.
    BadRequest,
    /// No usable target (neither absolute-form URI nor Host header).
    NoTarget,
    /// CONNECT / authority-form — handled by the tunnel path, not here.
    IsConnect,
    /// An `https://` URL in a plain proxy request. This proxy does not
    /// originate TLS, so forwarding it would send a request the client meant
    /// to be encrypted — URL, cookies, credentials — to the origin in clear
    /// text. HTTPS must come through a CONNECT tunnel, which every ordinary
    /// client uses.
    HttpsNotTunnelled,
}

/// Parse a forward-proxy request (full message bytes: head + body) and produce
/// the upstream `Target` plus the rewritten message to send upstream (origin-form
/// request line, hop-by-hop stripped, X-Forwarded-For appended, body preserved).
///
/// Parses the head itself; the engine uses `rewrite_forward_with_metadata`,
/// which reuses the parse the framing pass already did. Outside tests this
/// wrapper has no caller.
#[allow(dead_code)]
pub fn rewrite_forward(
    req: &Bytes,
    client_ip: IpAddr,
) -> Result<(Target, Bytes, Bytes), ForwardError> {
    rewrite_forward_with_metadata(req, Some(client_ip), None)
}

/// Rewrite a forward-proxy request for the upstream.
///
/// `forwarded_for` is the address to announce in `X-Forwarded-For`, or `None`
/// to send no such header. If `meta` is `Some(_)` the head is not parsed again:
/// method, target and headers are read from the byte ranges the framing pass
/// (`scan_message_with_metadata`, on this same `req`) already extracted.
///
/// Returns `(Target, head, body)` where `head` is the freshly-built rewritten
/// header bytes and `body` is a zero-copy `Bytes::slice` into `req`. The
/// caller can send both to the upstream via `write_all_vectored(head, body)`
/// without any body copy — the body never gets memcpy'd between `req` arrival
/// and upstream send.
pub fn rewrite_forward_with_metadata(
    req: &Bytes,
    forwarded_for: Option<IpAddr>,
    meta: Option<&MessageMetadata>,
) -> Result<(Target, Bytes, Bytes), ForwardError> {
    if let Some(m) = meta {
        let method =
            std::str::from_utf8(&req[m.method.clone()]).map_err(|_| ForwardError::BadRequest)?;
        let request_target =
            std::str::from_utf8(&req[m.path.clone()]).map_err(|_| ForwardError::BadRequest)?;
        let headers: Vec<(&[u8], &[u8])> = m
            .headers
            .iter()
            .map(|h| (&req[h.name.clone()], &req[h.value.clone()]))
            .collect();
        return rewrite(
            req,
            method,
            request_target,
            &headers,
            m.head_end,
            forwarded_for,
        );
    }
    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut storage);
    let head_len = match parsed.parse(&req[..]) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) | Err(_) => return Err(ForwardError::BadRequest),
    };
    let method = parsed.method.ok_or(ForwardError::BadRequest)?;
    let request_target = parsed.path.ok_or(ForwardError::BadRequest)?;
    let headers: Vec<(&[u8], &[u8])> = parsed
        .headers
        .iter()
        .map(|h| (h.name.as_bytes(), h.value))
        .collect();
    rewrite(
        req,
        method,
        request_target,
        &headers,
        head_len,
        forwarded_for,
    )
}

/// The one implementation behind both entry points, so a request is routed
/// and rewritten identically whether or not its head was pre-parsed.
fn rewrite(
    req: &Bytes,
    method: &str,
    request_target: &str,
    headers: &[(&[u8], &[u8])],
    head_len: usize,
    forwarded_for: Option<IpAddr>,
) -> Result<(Target, Bytes, Bytes), ForwardError> {
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(ForwardError::IsConnect);
    }

    // Determine (host, port, origin-form path) from the request target.
    let (host, port, origin_path): (&str, u16, &str) = match strip_scheme(request_target) {
        Some((Scheme::Https, _)) => return Err(ForwardError::HttpsNotTunnelled),
        Some((Scheme::Http, rest)) => {
            // absolute-form: http://authority[/path]
            let slash = rest.find('/').unwrap_or(rest.len());
            let path = if slash < rest.len() {
                &rest[slash..]
            } else {
                "/"
            };
            let (h, p) = split_host_port(&rest[..slash]);
            (h, p.filter(|&p| p != 0).unwrap_or(80), path)
        }
        None if request_target.starts_with('/') => {
            // origin-form: route via the Host header.
            let host_hdr = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(b"host"))
                .and_then(|(_, value)| std::str::from_utf8(value).ok())
                .ok_or(ForwardError::NoTarget)?;
            let (h, p) = split_host_port(host_hdr.trim());
            (h, p.filter(|&p| p != 0).unwrap_or(80), request_target)
        }
        None => return Err(ForwardError::NoTarget),
    };
    if host.is_empty() {
        return Err(ForwardError::NoTarget);
    }

    // Build the rewritten head: origin-form line, Host, filtered headers, XFF.
    let mut out = Vec::with_capacity(head_len + 48);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(origin_path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    push_host_header(&mut out, host, port);
    for (name, value) in headers {
        // httparse only yields token (ASCII) names; anything else is skipped.
        let Ok(name_str) = std::str::from_utf8(name) else {
            continue;
        };
        if is_dropped_request_header(name_str) {
            continue;
        }
        if !is_framing_header(name) && is_nominated(name, headers) {
            continue;
        }
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    if let Some(client_ip) = forwarded_for {
        out.extend_from_slice(b"X-Forwarded-For: ");
        out.extend_from_slice(client_ip.to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    // Zero-copy body: a refcounted slice into `req`, no memcpy. The caller
    // writes head + body via write_all_vectored.
    let body = req.slice(head_len..);
    let target = Target {
        host: host.to_string(),
        port,
    };
    Ok((target, Bytes::from(out), body))
}

/// Parse a CONNECT request and return its tunnel target. CONNECT uses
/// authority-form (`CONNECT host:port HTTP/1.1`); the port is mandatory.
/// Returns None if it isn't a well-formed CONNECT with an explicit port.
pub fn parse_connect_target(req: &[u8]) -> Option<Target> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    parsed.parse(req).ok()?;
    let method = parsed.method?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let (host, port) = split_host_port(parsed.path?);
    let port = port.filter(|&p| p != 0)?; // CONNECT requires an explicit port
    if host.is_empty() {
        return None;
    }
    Some(Target {
        host: host.to_string(),
        port,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

/// Split a leading `http://` or `https://` (any case) off an absolute-form
/// target, returning the scheme and the rest (authority + path).
fn strip_scheme(target: &str) -> Option<(Scheme, &str)> {
    let rest_after = |prefix: &str| {
        let head = target.get(..prefix.len())?;
        head.eq_ignore_ascii_case(prefix)
            .then(|| &target[prefix.len()..])
    };
    if let Some(rest) = rest_after("http://") {
        Some((Scheme::Http, rest))
    } else {
        rest_after("https://").map(|rest| (Scheme::Https, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))
    }

    fn rewrite(req: &str) -> Result<(Target, String), ForwardError> {
        let req_bytes = Bytes::from(req.as_bytes().to_vec());
        rewrite_forward(&req_bytes, ip()).map(|(t, head, body)| {
            let mut combined = Vec::with_capacity(head.len() + body.len());
            combined.extend_from_slice(&head);
            combined.extend_from_slice(&body);
            (t, String::from_utf8(combined).unwrap())
        })
    }

    #[test]
    fn absolute_form_default_port() {
        let (t, out) =
            rewrite("GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .unwrap();
        assert_eq!(
            t,
            Target {
                host: "example.com".into(),
                port: 80
            }
        );
        assert!(
            out.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
            "got: {out:?}"
        );
        assert!(out.contains("X-Forwarded-For: 10.0.0.7\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn absolute_form_explicit_port() {
        let (t, out) =
            rewrite("GET http://127.0.0.1:8080/ HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n").unwrap();
        assert_eq!(
            t,
            Target {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert!(out.starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn absolute_form_no_path_becomes_slash() {
        let (t, out) =
            rewrite("GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(t.host, "example.com");
        assert!(out.starts_with("GET / HTTP/1.1\r\n"));
    }

    /// Regression: `GET https://host/...` on the proxy port was forwarded to
    /// port 443 without TLS, putting a request the client meant to be
    /// encrypted on the wire in clear text. It is refused on both parse paths.
    #[test]
    fn https_absolute_form_is_refused_not_sent_in_clear() {
        for raw in [
            "GET https://example.com/x HTTP/1.1\r\nHost: example.com\r\nCookie: s=1\r\n\r\n",
            "GET HTTPS://example.com:8443/ HTTP/1.1\r\n\r\n",
            "POST https://example.com/ HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi",
        ] {
            let req = Bytes::from(raw.as_bytes().to_vec());
            let ip: IpAddr = "10.0.0.7".parse().unwrap();
            let (_, meta) = crate::proxy::framing::scan_message_with_metadata(&req, true, 0);
            assert!(meta.is_some());
            for meta in [None, meta.as_ref()] {
                assert_eq!(
                    rewrite_forward_with_metadata(&req, Some(ip), meta).unwrap_err(),
                    ForwardError::HttpsNotTunnelled,
                    "{raw}"
                );
            }
        }
        // A path that merely contains the text is still plain http.
        assert!(rewrite("GET http://example.com/https://x HTTP/1.1\r\n\r\n").is_ok());
    }

    #[test]
    fn origin_form_uses_host_header() {
        let (t, out) =
            rewrite("GET /index.html HTTP/1.1\r\nHost: example.com:8443\r\n\r\n").unwrap();
        assert_eq!(
            t,
            Target {
                host: "example.com".into(),
                port: 8443
            }
        );
        assert!(out.starts_with("GET /index.html HTTP/1.1\r\n"));
    }

    #[test]
    fn hop_by_hop_stripped() {
        let (_, out) = rewrite(
            "GET http://x.com/ HTTP/1.1\r\nHost: x.com\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert!(!out.to_lowercase().contains("connection: keep-alive"));
        assert!(!out.to_lowercase().contains("proxy-connection"));
        assert!(out.contains("Accept: */*\r\n")); // end-to-end header preserved
    }

    #[test]
    fn body_preserved() {
        let (_, out) =
            rewrite("POST http://x.com/ HTTP/1.1\r\nHost: x.com\r\nContent-Length: 5\r\n\r\nhello")
                .unwrap();
        assert!(out.ends_with("\r\n\r\nhello"));
        assert!(out.contains("Content-Length: 5\r\n"));
    }

    #[test]
    fn connect_is_rejected_here() {
        let req = Bytes::from(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec(),
        );
        assert_eq!(
            rewrite_forward(&req, ip()).map(|_| ()),
            Err(ForwardError::IsConnect)
        );
    }

    #[test]
    fn origin_form_without_host_no_target() {
        let req = Bytes::from(b"GET /x HTTP/1.1\r\n\r\n".to_vec());
        assert_eq!(
            rewrite_forward(&req, ip()).map(|_| ()),
            Err(ForwardError::NoTarget)
        );
    }

    #[test]
    fn connect_target_parsed() {
        assert_eq!(
            parse_connect_target(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
            ),
            Some(Target {
                host: "example.com".into(),
                port: 443
            })
        );
    }

    #[test]
    fn connect_ipv6_target() {
        assert_eq!(
            parse_connect_target(b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n"),
            Some(Target {
                host: "::1".into(),
                port: 8443
            })
        );
    }

    #[test]
    fn connect_without_port_rejected() {
        assert_eq!(
            parse_connect_target(b"CONNECT example.com HTTP/1.1\r\n\r\n"),
            None
        );
    }

    #[test]
    fn non_connect_is_none() {
        assert_eq!(
            parse_connect_target(b"GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n"),
            None
        );
    }

    #[test]
    fn ipv6_absolute_form() {
        let (t, out) =
            rewrite("GET http://[::1]:8080/p HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n").unwrap();
        assert_eq!(
            t,
            Target {
                host: "::1".into(),
                port: 8080
            }
        );
        assert!(out.starts_with("GET /p HTTP/1.1\r\n"));
    }

    /// Regression: the chunked body is relayed undecoded, so the header that
    /// frames it must survive the rewrite on both the slow and the fast path.
    #[test]
    fn chunked_request_keeps_transfer_encoding() {
        let raw = "POST http://example.com/up HTTP/1.1\r\nHost: example.com\r\n\
                   Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n\
                   5\r\nhello\r\n0\r\n\r\n";
        let req = Bytes::from(raw.as_bytes().to_vec());
        let ip: IpAddr = "10.0.0.7".parse().unwrap();

        let (scan, meta) = crate::proxy::framing::scan_message_with_metadata(&req, true, 0);
        assert!(matches!(
            scan,
            crate::proxy::framing::MessageScan::Complete { .. }
        ));

        let slow = rewrite_forward_with_metadata(&req, Some(ip), None).unwrap();
        let fast = rewrite_forward_with_metadata(&req, Some(ip), meta.as_ref()).unwrap();
        assert_eq!(slow, fast, "fast path must match the slow path");

        let (_, head, body) = slow;
        let head = String::from_utf8(head.to_vec()).unwrap();
        assert!(head.contains("Transfer-Encoding: chunked\r\n"), "{head}");
        // Real hop-by-hop headers are still stripped.
        assert!(!head.to_ascii_lowercase().contains("connection:"), "{head}");
        assert_eq!(&body[..], b"5\r\nhello\r\n0\r\n\r\n");
    }

    /// Rewrite on both paths and insist they agree; return the upstream head.
    fn rewritten_head(raw: &str) -> String {
        let req = Bytes::from(raw.as_bytes().to_vec());
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        let (_, meta) = crate::proxy::framing::scan_message_with_metadata(&req, true, 0);
        let slow = rewrite_forward_with_metadata(&req, Some(ip), None).unwrap();
        let fast = rewrite_forward_with_metadata(&req, Some(ip), meta.as_ref()).unwrap();
        assert_eq!(slow, fast, "fast path must match the slow path");
        String::from_utf8(slow.1.to_vec()).unwrap()
    }

    /// Regression: the client's Host header was forwarded as-is, so it could
    /// name a different (blocked) site than the URL the checks ran on.
    #[test]
    fn host_header_is_rewritten_to_the_routed_target() {
        let head = rewritten_head(
            "GET http://allowed.example/x HTTP/1.1\r\nHost: blocked.example\r\nAccept: */*\r\n\r\n",
        );
        assert_eq!(
            head,
            "GET /x HTTP/1.1\r\nHost: allowed.example\r\nAccept: */*\r\n\
             X-Forwarded-For: 10.0.0.7\r\n\r\n"
        );
    }

    #[test]
    fn host_header_is_added_when_the_client_sent_none() {
        let head = rewritten_head("GET http://example.com/ HTTP/1.1\r\n\r\n");
        assert!(head.contains("\r\nHost: example.com\r\n"), "{head}");
    }

    #[test]
    fn host_header_keeps_non_default_port_and_ipv6_brackets() {
        let h = |raw| rewritten_head(raw);
        assert!(h("GET http://example.com:8080/ HTTP/1.1\r\n\r\n")
            .contains("\r\nHost: example.com:8080\r\n"));
        assert!(
            h("GET http://example.com:80/ HTTP/1.1\r\n\r\n").contains("\r\nHost: example.com\r\n")
        );
        // 443 is not the default for http://, so it must be spelled out.
        assert!(h("GET http://example.com:443/ HTTP/1.1\r\n\r\n")
            .contains("\r\nHost: example.com:443\r\n"));
        assert!(h("GET http://[2001:db8::1]:8080/ HTTP/1.1\r\n\r\n")
            .contains("\r\nHost: [2001:db8::1]:8080\r\n"));
        assert!(
            h("GET http://[2001:db8::1]/ HTTP/1.1\r\n\r\n").contains("\r\nHost: [2001:db8::1]\r\n")
        );
        // origin-form: routed by Host, which is re-emitted in canonical form.
        assert!(h("GET /p HTTP/1.1\r\nhOsT: example.com:8443\r\n\r\n")
            .contains("\r\nHost: example.com:8443\r\n"));
    }

    /// Regression: a header named in `Connection` is for this hop only, but
    /// was forwarded. Framing headers are the exception: a client must not be
    /// able to make the proxy drop the header that delimits the body.
    #[test]
    fn headers_named_in_connection_are_not_forwarded() {
        let head = rewritten_head(
            "GET http://example.com/ HTTP/1.1\r\nConnection: close, X-Internal\r\n\
             connection: x-other\r\nX-Internal: 1\r\nX-Other: 2\r\nX-Kept: 3\r\n\r\n",
        );
        assert!(!head.contains("X-Internal"), "{head}");
        assert!(!head.contains("X-Other"), "{head}");
        assert!(head.contains("X-Kept: 3\r\n"), "{head}");

        let head = rewritten_head(
            "POST http://example.com/ HTTP/1.1\r\nConnection: Content-Length\r\n\
             Content-Length: 2\r\n\r\nhi",
        );
        assert!(head.contains("Content-Length: 2\r\n"), "{head}");
        let head = rewritten_head(
            "POST http://example.com/ HTTP/1.1\r\nConnection: transfer-encoding\r\n\
             Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        );
        assert!(head.contains("Transfer-Encoding: chunked\r\n"), "{head}");
    }

    /// With forwarding of the client address switched off, no
    /// X-Forwarded-For is sent at all — not the proxy's, not the client's.
    #[test]
    fn x_forwarded_for_can_be_switched_off() {
        let raw =
            "GET http://example.com/ HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4\r\nAccept: */*\r\n\r\n";
        let req = Bytes::from(raw.as_bytes().to_vec());
        let (_, meta) = crate::proxy::framing::scan_message_with_metadata(&req, true, 0);
        for meta in [None, meta.as_ref()] {
            let (_, head, _) = rewrite_forward_with_metadata(&req, None, meta).unwrap();
            let head = String::from_utf8(head.to_vec()).unwrap();
            assert!(
                !head.to_ascii_lowercase().contains("x-forwarded-for"),
                "{head}"
            );
            assert!(head.ends_with("Accept: */*\r\n\r\n"), "{head}");
        }
    }

    /// Regression: a client-supplied X-Forwarded-For was forwarded ahead of
    /// the proxy's, letting the client forge the address origins trust.
    #[test]
    fn client_supplied_x_forwarded_for_is_dropped() {
        let head = rewritten_head(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\
             X-Forwarded-For: 10.0.0.1\r\nx-forwarded-for: 192.168.0.9, 8.8.8.8\r\n\r\n",
        );
        assert_eq!(
            head.to_ascii_lowercase().matches("x-forwarded-for").count(),
            1
        );
        assert!(
            head.ends_with("X-Forwarded-For: 10.0.0.7\r\n\r\n"),
            "{head}"
        );
        assert_eq!(head.matches("Host:").count(), 1);
    }
}
