use awc::ClientRequest;
use aws_sigv4::http_request::{SignableBody, SignableRequest};
use std::time::SystemTime;
use url::Url;

use crate::s3_config::S3Config;

const S3_SIGNATURE_RELATED_KEYS: [&str; 18] = [
    "awsaccesskeyid",
    "signature",
    "expires",
    "authorization",
    "x-amz-algorithm",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-crc64nvme",
    "x-amz-checksum-mode",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-expires",
    "x-amz-sdk-checksum-algorithm",
    "x-amz-security-token",
    "x-amz-signedheaders",
    "x-amz-signature",
];

pub fn sign_request(req: ClientRequest, s3_config: S3Config) -> ClientRequest {
    sign_request_with_time(req, s3_config, SystemTime::now())
}

fn sign_request_with_time(
    mut req: ClientRequest,
    s3_config: S3Config,
    time: SystemTime,
) -> ClientRequest {
    let url = Url::parse(&req.get_uri().to_string()).unwrap();
    req = req.uri(remove_s3_signature_params(url));

    for key in S3_SIGNATURE_RELATED_KEYS.iter() {
        req.headers_mut().remove(*key);
    }

    let uri = req.get_uri();
    let mut host = uri.host().unwrap_or_default().to_string();
    let port = uri.port();

    if port.is_some() {
        host = format!("{}:{}", host, port.unwrap().as_str());
    }

    req = req
        .insert_header(("x-amz-content-sha256", "UNSIGNED-PAYLOAD"))
        .insert_header(("host", host));

    let s3_headers = req
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str().to_lowercase().starts_with("x-amz"))
        .map(|(k, v)| (k.as_str(), v.to_str().unwrap_or("")));

    let signable_request = SignableRequest::new(
        req.get_method().as_str(),
        req.get_uri().to_string(),
        s3_headers,
        SignableBody::UnsignedPayload,
    )
    .unwrap();

    let (signing_instructions, _signature) = s3_config.sign(time, signable_request, None);

    for (name, value) in signing_instructions.headers() {
        req = req.insert_header((name, value));
    }

    log::debug!("Signed request {:?}", req);

    req
}

pub fn remove_s3_signature_params(url: Url) -> String {
    let mut cleaned_url = url.clone();
    cleaned_url.set_query(None);

    let kept_pairs = url
        .query_pairs()
        .filter(|(k, _)| !S3_SIGNATURE_RELATED_KEYS.contains(&k.as_ref().to_lowercase().as_str()));
    for (k, v) in kept_pairs {
        cleaned_url.query_pairs_mut().append_pair(&k, &v);
    }

    cleaned_url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::config::Credentials;
    use chrono::{DateTime, NaiveDateTime, Utc};

    fn config() -> S3Config {
        S3Config::new(
            Credentials::new("an_access_key", "a_secret_key", None, None, "test"),
            "eu-west-1".to_string(),
            true,
        )
    }

    #[test]
    fn test_sign_request_removes_interfering_s3_params() {
        let uri = "https://s3-eu-west-1.amazonaws.com/plop?q=p&X-Amz-Algorithm=AWS4-HMAC-SHA256&AWSAccessKeyId=an_access_key&Signature=5Vo1RnSRALE3f9K8CJFOIOBAPbQ%3D&x-amz-acl=private&Expires=1764714247";
        let request = awc::Client::new()
            .get(uri)
            .insert_header(("X-Amz-Security-Token", "some_token"))
            .insert_header(("host", "localhost"));

        let signed = sign_request(request, config());

        assert_eq!(
            signed.get_uri().to_string(),
            "https://s3-eu-west-1.amazonaws.com/plop?q=p&x-amz-acl=private"
        );
        assert!(signed.headers().get("x-amz-security-token").is_none());
        assert_eq!(
            signed.headers().get("host"),
            Some(&"s3-eu-west-1.amazonaws.com".parse().unwrap())
        );
    }

    #[test]
    fn test_sign_request_with_port() {
        let uri = "https://s3-eu-west-1.amazonaws.com:1234/plop?q=p&X-Amz-Algorithm=AWS4-HMAC-SHA256&AWSAccessKeyId=an_access_key&Signature=5Vo1RnSRALE3f9K8CJFOIOBAPbQ%3D&x-amz-acl=private&Expires=1764714247";
        let request = awc::Client::new()
            .get(uri)
            .insert_header(("X-Amz-Security-Token", "some_token"))
            .insert_header(("host", "s3-eu-west-1.amazonaws.com:1234"));

        let signed = sign_request(request, config());

        assert_eq!(
            signed.get_uri().to_string(),
            "https://s3-eu-west-1.amazonaws.com:1234/plop?q=p&x-amz-acl=private"
        );
        assert!(signed.headers().get("x-amz-security-token").is_none());
        assert_eq!(
            signed.headers().get("host"),
            Some(&"s3-eu-west-1.amazonaws.com:1234".parse().unwrap())
        );
    }

    #[test]
    fn test_sign_request() {
        let uri = "https://s3-eu-west-1.amazonaws.com/drive-media-storage/item/12c3368f-884b-4bee-9779-10412cf05586/une%20image.png";

        let request = awc::Client::new()
            .get(uri)
            .insert_header(("header_which", "should_not_be_signed"));
        let date_str = "20251201T145423Z";

        let naive = NaiveDateTime::parse_from_str(date_str, "%Y%m%dT%H%M%SZ").unwrap();
        let time_now: SystemTime = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc).into();

        let signed = sign_request_with_time(request, config(), time_now);

        assert_eq!(
            signed.headers().get("x-amz-content-sha256").unwrap(),
            "UNSIGNED-PAYLOAD"
        );
        assert_eq!(signed.headers().get("authorization").unwrap(), "AWS4-HMAC-SHA256 Credential=an_access_key/20251201/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=7d6f290a9a6c9f298c13978e0521168756fe07e105de79238f24e40879e704f0");
    }

    #[test]
    fn test_sign_presigned_url() {
        let uri = "https://s3-eu-west-1.amazonaws.com/drive-media-storage/plop?AWSAccessKeyId=an_access_key&Signature=5Vo1RnSRALE3f9K8CJFOIOBAPbQ%3D&x-amz-acl=private&Expires=1764714247";

        let request = awc::Client::new()
            .get(uri)
            .insert_header(("host", "s3-eu-west-1.amazonaws.com"))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .insert_header(("user-agent", "curl/8.17.0"))
            .insert_header(("accept", "*/*"));

        let date_str = "20251201T145423Z";
        let naive = NaiveDateTime::parse_from_str(date_str, "%Y%m%dT%H%M%SZ").unwrap();
        let time_now: SystemTime = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc).into();

        let signed = sign_request_with_time(request, config(), time_now);

        assert_eq!(signed.headers().get("authorization").unwrap(), "AWS4-HMAC-SHA256 Credential=an_access_key/20251201/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=9d0c8b45db94e946687e2ff747c9e352e1468140a5bd6de9ee772f94317c7ec2");
    }
}
