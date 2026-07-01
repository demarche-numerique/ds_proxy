mod helpers;
pub use helpers::*;

#[test]
#[serial(servers)]
fn connect_url_routes_the_connection_but_signs_for_upstream() {
    /*
    This test proves the --s3-connect-url mechanism end to end:
     - the upstream is set to an unreachable host (a reserved `.test` TLD on a
       dead port): if --s3-connect-url were ignored, the request could never reach
       any backend
     - --s3-connect-url redirects the actual TCP connection to the node backend
       (localhost:3333), while the signature and the Host header must stay on the
       upstream

    We then check that:
     - the node really stored the uploaded file => the connection was routed to
       the connect target
     - the Host header the node received is the upstream, NOT the connect target
       => signature/Host decoupling works
    */
    let uploaded_path = "tests/fixtures/server-static/uploads/jail/cell/victory";
    ensure_is_absent(uploaded_path);

    let _servers = ProxyAndNode::start_with_connect_url(
        "http://my-upstream.test:9999/jail/cell",
        "http://localhost:3333",
    );

    // curl_put panics if the upload does not succeed.
    curl_put(COMPUTER_SVG_PATH, "localhost:4444/upstream/victory");

    // The node received and stored the file: the connection reached the connect
    // target even though the upstream host is unreachable.
    let uploaded_bytes = std::fs::read(uploaded_path).expect("uploaded file should exist");
    assert!(!uploaded_bytes.is_empty());

    // The Host seen by the node is the upstream authority, not localhost:3333.
    assert_eq!(
        node_received_header("host").unwrap(),
        "\"my-upstream.test:9999\""
    );
}
