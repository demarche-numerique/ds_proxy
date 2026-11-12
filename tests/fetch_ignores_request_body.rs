use std::process::Command;

mod helpers;
pub use helpers::*;

#[test]
#[serial(servers)]
fn fetch_ignores_the_request_body() {
    let uploaded_path = "tests/fixtures/server-static/uploads/jail/cell/computer.svg.enc";

    std::fs::copy(ENCRYPTED_COMPUTER_SVG_PATH, uploaded_path).expect("copy failed");

    let _proxy_node_and_redis = ProxyAndNode::start();

    let curl_download = Command::new("curl")
        .arg("-XGET")
        .arg("localhost:4444/upstream/computer.svg.enc")
        .arg("-H")
        .arg("Content-Encoding: gzip")
        .arg("--data-binary")
        .arg("not gzip")
        .arg("--fail")
        .output()
        .expect("failed to perform download");

    assert!(curl_download.status.success());
    assert_eq!(curl_download.stdout, COMPUTER_SVG_BYTES);
}
