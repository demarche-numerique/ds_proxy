mod helpers;
pub use helpers::*;

#[test]
#[serial(servers)]
fn dual_routes_s3_and_swift_to_their_own_upstream() {
    /*
    This test proves dual mode routes each request to the right backend:
     - the proxy runs in dual mode with an S3 upstream on :3333 and a Swift
       upstream on :3334 (signature check bypassed so we don't have to forge a
       valid inbound SigV4, only the AWS4 marker matters for detection)
     - a request carrying an `Authorization: AWS4-HMAC-SHA256 …` header is
       detected as S3: it must land on the S3 backend, re-signed by the proxy
     - a request carrying only an `X-Auth-Token` header is detected as Swift: it
       must land on the Swift backend, relayed as-is (token preserved, no S3
       signature added)
    */
    let _servers = DualServers::start(
        "http://localhost:3333/jail/cell",
        "http://localhost:3334/jail/cell",
    );

    // S3 request: the marker is a dummy AWS4 Authorization header; the proxy
    // strips it and re-signs before forwarding.
    curl_put_with_headers(
        COMPUTER_SVG_PATH,
        "localhost:4444/upstream/s3_object",
        &["Authorization: AWS4-HMAC-SHA256 Credential=whatever, SignedHeaders=host, Signature=00"],
    );

    // The S3 backend received it, re-signed by the proxy (real signature).
    let s3_auth = node_received_header_on_port(3333, "authorization");
    assert!(
        s3_auth
            .as_deref()
            .is_some_and(|a| a.contains("AWS4-HMAC-SHA256")),
        "S3 backend should have received a re-signed request, got: {:?}",
        s3_auth
    );
    // The Swift backend saw no PUT at all.
    assert!(node_received_header_on_port(3334, "host").is_none());

    // Swift request: only a token, no AWS marker.
    curl_put_with_headers(
        COMPUTER_SVG_PATH,
        "localhost:4444/upstream/swift_object",
        &["X-Auth-Token: token123"],
    );

    // The Swift backend received it with the token relayed verbatim...
    assert_eq!(
        node_received_header_on_port(3334, "x-auth-token").as_deref(),
        Some("\"token123\""),
    );
    // ...and it was NOT S3-signed.
    assert!(
        node_received_header_on_port(3334, "authorization").is_none(),
        "Swift request must not be S3-signed"
    );
}
