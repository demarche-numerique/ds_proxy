mod helpers;
pub use helpers::*;

// Path traversal patterns are forwarded to the upstream storage as-is.
// The proxy's role is routing, not path enforcement — the storage
// handles its own access control.

// SSRF is structurally eliminated: create_upstream_url uses string
// concatenation instead of Url::join(), so the host is never replaced
// regardless of the request path.

/// Scheme-relative URL (//evil.com) is forwarded as a path, not interpreted as a host.
/// With Url::join(), "//evil.com" would replace the host (RFC 3986 §4.2).
#[actix_rt::test]
async fn awc_forwards_scheme_relative_url_as_path() {
    let path = awc_raw_path("/jail/cell///evil.com:8080/secret").await;
    assert_eq!(path, "/jail/cell///evil.com:8080/secret");
}

/// Sends a URL through awc and captures the raw HTTP request line on the wire
/// using a TCP server (no HTTP framework — just a socket).
/// Returns the path component from "GET <path> HTTP/1.1".
async fn awc_raw_path(url_path: &str) -> String {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        let request_line = reader.lines().next().unwrap().unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        request_line
    });

    let client = awc::Client::default();
    let url = format!("http://127.0.0.1:{}{}", port, url_path);
    let _ = client.get(&url).send().await;

    let request_line = server.join().unwrap();
    request_line.split_whitespace().nth(1).unwrap().to_string()
}

/// Proves that awc does NOT normalize ".." in paths.
/// A raw TCP server captures what actually goes on the wire.
#[actix_rt::test]
async fn awc_forwards_dotdot_literally() {
    let path = awc_raw_path("/jail/cell/../escape").await;
    assert_eq!(path, "/jail/cell/../escape");
}

/// Multiple consecutive ".." segments are preserved.
#[actix_rt::test]
async fn awc_forwards_multiple_dotdot_literally() {
    let path = awc_raw_path("/jail/cell/../../etc/passwd").await;
    assert_eq!(path, "/jail/cell/../../etc/passwd");
}

/// Percent-encoded dots (%2e%2e) are not decoded or resolved by awc.
#[actix_rt::test]
async fn awc_forwards_percent_encoded_dotdot_literally() {
    let path = awc_raw_path("/jail/cell/%2e%2e/escape").await;
    assert_eq!(path, "/jail/cell/%2e%2e/escape");
}

/// Mixed encoding (%2e.) is preserved as-is.
#[actix_rt::test]
async fn awc_forwards_mixed_encoded_dotdot_literally() {
    let path = awc_raw_path("/jail/cell/%2e./escape").await;
    assert_eq!(path, "/jail/cell/%2e./escape");
}

/// Backslash-based traversal (Windows-style) is preserved as-is.
#[actix_rt::test]
async fn awc_forwards_backslash_traversal_literally() {
    let path = awc_raw_path("/jail/cell/..%5c..%5cescape").await;
    assert_eq!(path, "/jail/cell/..%5c..%5cescape");
}

/// Double URL encoding (%252e%252e) is preserved as-is.
#[actix_rt::test]
async fn awc_forwards_double_encoded_dotdot_literally() {
    let path = awc_raw_path("/jail/cell/%252e%252e/escape").await;
    assert_eq!(path, "/jail/cell/%252e%252e/escape");
}
