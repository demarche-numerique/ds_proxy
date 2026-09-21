use std::path::Path;
use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest};
use ds_proxy::s3_config::S3Config;
use url::Url;

mod helpers;
pub use helpers::*;

const UPLOADED_PATH: &str = "tests/fixtures/server-static/uploads/jail/cell/victory";
const UNSIGNED_HEADERS_ERROR: &str =
    "There were headers present in the request which were not signed";

// Presigned URL for the proxy, the way an application hands one to a browser:
// signed with the proxy credentials, over the host header only.
fn presign(method: &str, url: &str) -> String {
    presign_with_headers(method, url, &[])
}

// Same, with extra headers pinned by the signature, like an application
// presigning a PUT together with its x-amz-acl.
fn presign_with_headers(method: &str, url: &str, headers: &[(&str, &str)]) -> String {
    let s3_config = S3Config::new(
        Credentials::new("key", "secret", None, None, "test"),
        "region".to_string(),
        false,
        None,
    );

    let signable = SignableRequest::new(
        method,
        url,
        std::iter::once(("host", "localhost:4444")).chain(headers.iter().copied()),
        SignableBody::UnsignedPayload,
    )
    .unwrap();

    let (instructions, _) =
        s3_config.sign(SystemTime::now(), signable, Some(Duration::from_secs(60)));

    let mut presigned = Url::parse(url).unwrap();
    for (name, value) in instructions.params() {
        presigned.query_pairs_mut().append_pair(name, value);
    }

    presigned.to_string()
}

// A presigned PUT vouches for the host header only. Smuggling an unsigned
// x-amz- header (here a CopyObject source) must be refused before the proxy
// re-signs the request with its own credentials.
#[test]
#[serial(servers)]
fn an_unsigned_x_amz_header_is_refused() {
    ensure_is_absent(UPLOADED_PATH);

    let _proxy_node_and_redis =
        ProxyAndNode::start_with_options(None, None, PrintServerLogs::No, None, true);

    let url = presign("PUT", "http://localhost:4444/upstream/victory");
    let put = curl_put_with_headers(
        COMPUTER_SVG_PATH,
        &url,
        &["x-amz-copy-source: /jail/cell/someone-else"],
    );

    assert_eq!(
        String::from_utf8_lossy(&put.stdout),
        UNSIGNED_HEADERS_ERROR.to_string()
    );
    assert!(!Path::new(UPLOADED_PATH).exists());
}

// A signed header sent twice must not validate: the signature covered one
// value, and the proxy would have forwarded the other.
#[test]
#[serial(servers)]
fn a_signed_header_sent_twice_is_refused() {
    ensure_is_absent(UPLOADED_PATH);

    let _proxy_node_and_redis =
        ProxyAndNode::start_with_options(None, None, PrintServerLogs::No, None, true);

    let url = presign_with_headers(
        "PUT",
        "http://localhost:4444/upstream/victory",
        &[("x-amz-acl", "private")],
    );

    // the signed value alone goes through
    let put = curl_put_with_headers(COMPUTER_SVG_PATH, &url, &["x-amz-acl: private"]);
    assert_ne!(
        String::from_utf8_lossy(&put.stdout),
        "Invalid S3 signature".to_string()
    );
    assert!(Path::new(UPLOADED_PATH).exists());
    ensure_is_absent(UPLOADED_PATH);

    // the same header twice, in either order, does not
    for headers in [
        ["x-amz-acl: public-read", "x-amz-acl: private"],
        ["x-amz-acl: private", "x-amz-acl: public-read"],
    ] {
        let put = curl_put_with_headers(COMPUTER_SVG_PATH, &url, &headers);
        assert_eq!(
            String::from_utf8_lossy(&put.stdout),
            "Invalid S3 signature".to_string(),
            "headers {:?} must be refused",
            headers
        );
        assert!(!Path::new(UPLOADED_PATH).exists());
    }
}

// Headers outside the x-amz- prefix are not covered by the rule, including
// x-amzn-trace-id which the AWS SDKs leave unsigned on purpose.
#[test]
#[serial(servers)]
fn unsigned_headers_outside_x_amz_are_accepted() {
    ensure_is_absent(UPLOADED_PATH);

    let _proxy_node_and_redis =
        ProxyAndNode::start_with_options(None, None, PrintServerLogs::No, None, true);

    let url = presign("PUT", "http://localhost:4444/upstream/victory");
    let put = curl_put_with_headers(
        COMPUTER_SVG_PATH,
        &url,
        &[
            "x-amzn-trace-id: Root=1-5759e988-bd862e3fe1be46a994272793",
            "content-type: image/svg+xml",
        ],
    );

    assert_ne!(
        String::from_utf8_lossy(&put.stdout),
        UNSIGNED_HEADERS_ERROR.to_string()
    );
    assert!(Path::new(UPLOADED_PATH).exists());

    let url = presign("GET", "http://localhost:4444/upstream/victory");
    let get = curl_get(&url);
    assert_eq!(get.stdout, COMPUTER_SVG_BYTES);
}
