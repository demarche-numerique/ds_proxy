use std::path::Path;

mod helpers;
pub use helpers::*;

// The node backend answers 307 under `redirect/`, pointing at a real object
// path. The proxy must neither follow it (the body would be resent empty,
// storing an empty object with a 200) nor relay it (the client would go to
// the upstream directly). It answers 502 and nothing is stored.
#[test]
#[serial(servers)]
fn an_upstream_redirect_is_refused() {
    let redirected_path = "tests/fixtures/server-static/uploads/jail/cell/redirected/victory";
    ensure_is_absent(redirected_path);

    let _proxy_node_and_redis = ProxyAndNode::start();

    let status = curl_put_status(
        COMPUTER_SVG_PATH,
        "localhost:4444/upstream/redirect/victory",
    );
    assert_eq!(status, "502");
    assert!(
        !Path::new(redirected_path).exists(),
        "the redirect must not have been followed"
    );

    let status = curl_get_status("localhost:4444/upstream/redirect/victory");
    assert_eq!(status, "502");

    let headers = curl_get_headers("localhost:4444/upstream/redirect/victory");
    assert!(
        !headers.to_lowercase().contains("location:"),
        "the upstream Location must not be relayed, got: {}",
        headers
    );
}

// 304 is a 3xx too, but not a redirect: a conditional GET must still get it.
#[test]
#[serial(servers)]
fn a_not_modified_answer_is_relayed() {
    let uploaded_path = "tests/fixtures/server-static/uploads/jail/cell/victory";
    ensure_is_absent(uploaded_path);

    let _proxy_node_and_redis = ProxyAndNode::start();

    curl_put(COMPUTER_SVG_PATH, "localhost:4444/upstream/victory");

    let status = curl_get_status_with_headers(
        "localhost:4444/upstream/victory",
        &["If-Modified-Since: Sat, 01 Jan 2050 00:00:00 GMT"],
    );
    assert_eq!(status, "304");
}
