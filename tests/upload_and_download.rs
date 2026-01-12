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
        Some(format!("\"{}\"", COMPUTER_SVG_BYTES.len().to_string()))
    );
    assert!(node_received_header("x-amz-date").is_some());
    assert!(node_received_header("authorization").is_some());

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
        ProxyAndNode::start_with_options(None, PrintServerLogs::No, None, true);

    let put = curl_put(COMPUTER_SVG_PATH, "localhost:4444/upstream/victory");
    assert_eq!(put.status.success(), true);
    assert_eq!(
        String::from_utf8_lossy(&put.stdout),
        "Invalid S3 signature".to_string()
    );
}
