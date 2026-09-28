use assert_fs::prelude::*;
use ds_proxy::crypto::header::*;

mod helpers;
pub use helpers::*;

#[test]
#[serial(servers)]
fn upload_and_download() {
    /*
    This test:
     - spawns a node server that stores uploaded files in tests/fixtures/server-static/uploads/
     - spawns a ds proxy that uses the node proxy as a storage backend
     - uploads a file using curl via the DS proxy and check correct uploaded md5
     - checks amz headers
     - checks that said file is encrypted
     - decrypt the uploaded file by the decrypted command and check the result
     - downloads the uploaded file via the proxy, and checks that its content matches the initial content
    */
    let uploaded_path = "tests/fixtures/server-static/uploads/jail/cell/victory";

    let temp = assert_fs::TempDir::new().unwrap();
    let decrypted_file = temp.child("computer.dec.svg");
    let decrypted_path = decrypted_file.path();

    ensure_is_absent(uploaded_path);

    let _proxy_node_and_redis = ProxyAndNode::start();

    curl_put(COMPUTER_SVG_PATH, "localhost:4444/upstream/victory");
    assert_eq!(returned_header("etag"), COMPUTER_SVG_MD5_ETAG);

    assert_eq!(
        node_received_header("x-amz-meta-original-content-length"),
        Some(format!("\"{}\"", COMPUTER_SVG_BYTES.len()))
    );
    assert!(node_received_header("x-amz-date").is_some());
    assert!(node_received_header("authorization").is_some());
    assert!(node_received_header("content-md5").is_none());

    let uploaded_bytes = std::fs::read(uploaded_path).expect("uploaded should exist !");
    assert_eq!(&uploaded_bytes[0..PREFIX_SIZE], PREFIX);

    assert_eq!(
        "\"UNSIGNED-PAYLOAD\"",
        node_received_header("x-amz-content-sha256").unwrap()
    );

    decrypt(uploaded_path, decrypted_path);
    let decrypted_bytes = std::fs::read(decrypted_path).unwrap();
    assert_eq!(decrypted_bytes, COMPUTER_SVG_BYTES);

    let curl_head = curl_head("localhost:4444/upstream/victory");
    let text = String::from_utf8_lossy(&curl_head.stdout);
    let text = text
        .lines()
        .find(|line| line.starts_with("content-length"))
        .unwrap();
    assert_eq!(
        text,
        format!("content-length: {}", COMPUTER_SVG_BYTES.len())
    );

    let curl_download = curl_get("localhost:4444/upstream/victory");
    assert_eq!(curl_download.stdout, COMPUTER_SVG_BYTES);

    let curl_range_download = curl_range_get("localhost:4444/upstream/victory", 0, 10);
    assert_eq!(curl_range_download.stdout, &COMPUTER_SVG_BYTES[0..11]);

    let curl_socket_download = curl_socket_get("localhost:4444/upstream/victory");
    assert_eq!(curl_socket_download.stdout, COMPUTER_SVG_BYTES);

    let curl_chunked_download = curl_get("localhost:4444/upstream/victory?chunked=true");
    assert_eq!(curl_chunked_download.stdout, COMPUTER_SVG_BYTES);

    temp.close().unwrap();
}

#[test]
#[serial(servers)]
fn check_s3_signature() {
    let _proxy_node_and_redis =
        ProxyAndNode::start_with_options(None, None, PrintServerLogs::No, None, true);

    let put = curl_put(COMPUTER_SVG_PATH, "localhost:4444/upstream/victory");
    assert!(put.status.success());
    assert_eq!(
        String::from_utf8_lossy(&put.stdout),
        "Invalid S3 signature".to_string()
    );
}

#[test]
#[serial(servers)]
fn a_served_range_is_a_partial_response() {
    /*
    A range is extracted from the stream ds_proxy decrypts, not from the upstream, which
    never sees the header. The response must still say what it is: outside 206 and 416,
    `Content-Range` has no defined meaning (RFC 9110 §14.4), so a shared cache is free to
    store this slice as the whole representation of an URL others read in full.
    */
    let uploaded_path = "tests/fixtures/server-static/uploads/jail/cell/partial";

    ensure_is_absent(uploaded_path);

    let _proxy_node_and_redis = ProxyAndNode::start();

    curl_put(COMPUTER_SVG_PATH, "localhost:4444/upstream/partial");

    let headers = curl_range_headers("localhost:4444/upstream/partial", "bytes=0-10");
    assert!(
        headers.contains("http/1.1 206 partial content"),
        "expected a 206, got:\n{}",
        headers
    );
    assert!(
        headers.contains(&format!(
            "content-range: bytes 0-10/{}",
            COMPUTER_SVG_BYTES.len()
        )),
        "expected a content-range over the cleartext length, got:\n{}",
        headers
    );
    assert!(
        headers.contains("content-length: 11"),
        "expected the length of the slice, got:\n{}",
        headers
    );

    // an upstream that did not answer 200 is relayed whole: an error page is not a slice,
    // and carries no content-range to pretend otherwise
    let missing = curl_range_headers("localhost:4444/upstream/never_uploaded", "bytes=0-10");
    assert!(
        missing.contains("http/1.1 404"),
        "expected the upstream status, got:\n{}",
        missing
    );
    assert!(
        !missing.contains("content-range"),
        "an error page is not a range, got:\n{}",
        missing
    );
    let missing_body = curl_range_get("localhost:4444/upstream/never_uploaded", 0, 10);
    assert!(
        missing_body.stdout.len() > 11,
        "the error page must be relayed whole, got {} bytes",
        missing_body.stdout.len()
    );

    // a range over an object stored in the clear is served the same way
    let plain_path = "tests/fixtures/server-static/uploads/jail/cell/plain";
    std::fs::write(plain_path, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
    let plain = curl_range_headers("localhost:4444/upstream/plain", "bytes=5-9");
    assert!(
        plain.contains("http/1.1 206 partial content")
            && plain.contains("content-range: bytes 5-9/26"),
        "expected a 206 over the plaintext object, got:\n{}",
        plain
    );
    assert_eq!(
        curl_range_get("localhost:4444/upstream/plain", 5, 9).stdout,
        b"FGHIJ"
    );

    // A range designating no byte is no range at all, and must not take the extracting
    // path: `HttpRange` yields an empty vec for a header it cannot use, and a zero-length
    // range for a suffix range over an empty object — both of which used to reach the
    // subtraction and the `first().unwrap()` below it.
    let unusable = curl_range_headers("localhost:4444/upstream/partial", "bytes=");
    assert!(
        unusable.contains("http/1.1 200 ok") && !unusable.contains("content-range"),
        "expected an untouched 200, got:\n{}",
        unusable
    );

    let empty_path = "tests/fixtures/server-static/uploads/jail/cell/empty";
    std::fs::write(empty_path, b"").unwrap();
    let empty = curl_range_headers("localhost:4444/upstream/empty", "bytes=-5");
    assert!(
        empty.contains("http/1.1 200 ok") && !empty.contains("content-range"),
        "expected an untouched 200, got:\n{}",
        empty
    );
}
