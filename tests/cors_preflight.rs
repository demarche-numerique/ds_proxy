mod helpers;
pub use helpers::*;

use serde_json::Value;
use std::collections::HashMap;

// A browser's CORS preflight carries no credential, and the signature check
// lets it through. The proxy must relay it as it came, without lending it
// the proxy's own S3 signature.
#[test]
#[serial(servers)]
fn a_preflight_is_relayed_unsigned() {
    let _proxy_node_and_redis = ProxyAndNode::start();

    let status = curl_preflight_status("localhost:4444/upstream/bucket/key?X-Amz-Signature=abc");
    assert_eq!(status, "204");

    let received = curl_get("localhost:3333/last_options_headers").stdout;
    let headers: HashMap<String, Value> =
        serde_json::from_str(&String::from_utf8_lossy(&received)).unwrap();

    assert!(
        headers.contains_key("origin"),
        "the preflight should have reached the upstream, got: {:?}",
        headers
    );
    for signed in ["authorization", "x-amz-date", "x-amz-content-sha256"] {
        assert!(
            !headers.contains_key(signed),
            "the preflight must not carry the proxy's signature, got {}: {:?}",
            signed,
            headers
        );
    }

    // The upstream must see its own name, not the public one the browser
    // used: a bucket resolved by virtual host would otherwise not be found.
    assert_eq!(
        headers.get("host").and_then(|h| h.as_str()),
        Some("localhost:3333"),
        "the preflight must carry the upstream Host, got: {:?}",
        headers
    );
}
