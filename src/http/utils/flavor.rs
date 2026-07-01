// Wired into the middleware and handlers in a later commit; until then the
// items are only exercised by unit tests.
#![allow(dead_code)]

use actix_web::HttpRequest;

/// Which storage API a given request speaks.
///
/// The proxy can serve S3 and Swift backends at the same time (dual mode). For
/// each request we need to tell them apart: S3 clients authenticate with AWS
/// SigV4 (either an `Authorization: AWS4-HMAC-SHA256 …` header or a presigned
/// URL carrying an `x-amz-signature` query param). Anything else — Swift token
/// auth, Swift TempURL, or no auth at all — is treated as Swift, whose auth is
/// delegated to the upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    S3,
    Swift,
}

/// Detect whether a request carries an S3 SigV4 signature.
///
/// Note: SigV2 presigned URLs (`AWSAccessKeyId`/`Signature`/`Expires`) are not
/// supported and are therefore seen as Swift.
pub fn detect_flavor(req: &HttpRequest) -> Flavor {
    if is_s3_signed(req) {
        Flavor::S3
    } else {
        Flavor::Swift
    }
}

fn is_s3_signed(req: &HttpRequest) -> bool {
    let signed_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256"));

    let presigned = req
        .uri()
        .query()
        .is_some_and(|q| q.to_ascii_lowercase().contains("x-amz-signature"));

    signed_header || presigned
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn authorization_header_is_s3() {
        let req = TestRequest::get()
            .uri("/upstream/bucket/key")
            .insert_header((
                "authorization",
                "AWS4-HMAC-SHA256 Credential=key/20251130/eu-west-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature=deadbeef",
            ))
            .to_http_request();

        assert_eq!(detect_flavor(&req), Flavor::S3);
    }

    #[test]
    fn presigned_query_param_is_s3() {
        let req = TestRequest::put()
            .uri("/upstream/bucket/key?x-amz-algorithm=AWS4-HMAC-SHA256&x-amz-signature=abc123")
            .to_http_request();

        assert_eq!(detect_flavor(&req), Flavor::S3);
    }

    #[test]
    fn presigned_query_param_is_case_insensitive() {
        let req = TestRequest::put()
            .uri("/upstream/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc123")
            .to_http_request();

        assert_eq!(detect_flavor(&req), Flavor::S3);
    }

    #[test]
    fn swift_token_is_swift() {
        let req = TestRequest::get()
            .uri("/upstream/v1/AUTH_project/container/object")
            .insert_header(("x-auth-token", "gAAAAABmtoken"))
            .to_http_request();

        assert_eq!(detect_flavor(&req), Flavor::Swift);
    }

    #[test]
    fn swift_tempurl_is_swift() {
        let req = TestRequest::get()
            .uri("/upstream/v1/AUTH_project/container/object?temp_url_sig=abcdef&temp_url_expires=1700000000")
            .to_http_request();

        assert_eq!(detect_flavor(&req), Flavor::Swift);
    }

    #[test]
    fn unsigned_request_is_swift() {
        let req = TestRequest::get()
            .uri("/upstream/bucket/key")
            .to_http_request();

        assert_eq!(detect_flavor(&req), Flavor::Swift);
    }

    // A SigV2 presigned URL is not S3-signed as far as this proxy is concerned.
    #[test]
    fn sigv2_presigned_is_swift() {
        let req = TestRequest::get()
            .uri("/upstream/bucket/key?AWSAccessKeyId=key&Signature=abc%3D&Expires=1700000000")
            .to_http_request();

        assert_eq!(detect_flavor(&req), Flavor::Swift);
    }
}
