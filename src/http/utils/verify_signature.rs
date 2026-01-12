use actix_web::HttpRequest;
use aws_sigv4::http_request::SignableBody;
use aws_sigv4::http_request::SignableRequest;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::HashMap;
use std::time::Duration;

use crate::http::utils::s3_helper::remove_s3_signature_params;
use crate::s3_config::S3Config;

pub fn is_signature_valid(request: &HttpRequest, s3_config: S3Config) -> bool {
    is_signature_valid_with_date(request, s3_config, Utc::now())
}

fn is_signature_valid_with_date(
    request: &HttpRequest,
    s3_config: S3Config,
    now: DateTime<Utc>,
) -> bool {
    log::info!("Verifying signature for request: {:?}", &request);

    let all_params = extract_query_and_header_params(request);

    let provided_signature = match extract_signature(&all_params) {
        Some(sig) => sig,
        None => {
            log::warn!("No signature found in request");
            return false;
        }
    };
    let expires_in = extract_expires_in(&all_params);
    let s3_date = extract_s3_date(&all_params);
    let signed_pairs = extract_signed_pairs(&all_params);

    if !s3_date_is_valid(now, s3_date, expires_in) {
        log::warn!("S3 date is invalid or too far in the past/future");
        return false;
    }

    let body = if let Some(sha) = all_params.get("x-amz-content-sha256") {
        SignableBody::Precomputed(sha.to_string())
    } else {
        SignableBody::UnsignedPayload
    };

    let url_without_signature = remove_s3_signature_params(request.full_url());

    log::debug!("method: {}", request.method());
    log::debug!("Full URL: {}", request.full_url());
    log::debug!("URL without_signature: {}", url_without_signature);
    log::debug!("Signed params: {:?}", signed_pairs);
    log::debug!("Body for signing: {:?}", body);

    let signable = SignableRequest::new(
        request.method().as_str(),
        url_without_signature,
        signed_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        body,
    )
    .unwrap();

    let (_, expected_signature) = s3_config.sign(s3_date.into(), signable, expires_in);

    log::debug!("Expected signature: {}", expected_signature);
    log::debug!("Provided signature: {}", provided_signature);

    expected_signature == provided_signature
}

fn s3_date_is_valid(
    now: DateTime<Utc>,
    s3_date: DateTime<Utc>,
    expires_in: Option<Duration>,
) -> bool {
    if s3_date + expires_in.unwrap_or_default() < now - Duration::from_mins(15) {
        return false;
    }

    if s3_date > now + Duration::from_mins(15) {
        return false;
    }

    true
}

fn extract_s3_date(all_params: &HashMap<String, String>) -> DateTime<Utc> {
    let amz_date = all_params.get("x-amz-date").expect("Missing x-amz-date");
    //  it must be in the ISO 8601 basic YYYYMMDD'T'HHMMSS'Z' format. Z stands for UTC time.
    let naive = NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ")
        .expect("Invalid x-amz-date format");
    DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
}

fn extract_expires_in(all_params: &HashMap<String, String>) -> Option<Duration> {
    all_params
        .get("x-amz-expires")
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn extract_query_and_header_params(request: &HttpRequest) -> HashMap<String, String> {
    let mut params: HashMap<String, String> = request
        .full_url()
        .query_pairs()
        .map(|(k, v)| (k.to_lowercase(), v.to_string()))
        .collect();

    request.headers().iter().for_each(|(k, v)| {
        params.insert(
            k.as_str().to_lowercase(),
            v.to_str().unwrap_or("").to_string(),
        );
    });

    params
}

fn presigned_url(all_params: &HashMap<String, String>) -> bool {
    all_params.contains_key("x-amz-signature")
}

fn extract_signed_pairs(all_params: &HashMap<String, String>) -> Vec<(String, String)> {
    let header_list = if presigned_url(all_params) {
        all_params
            .get("x-amz-signedheaders")
            .expect("Missing x-amz-signedheaders")
            .as_str()
    } else {
        all_params
            .get("authorization")
            .expect("Missing Authorization header")
            .split(',')
            .find(|part| part.trim().starts_with("SignedHeaders="))
            .expect("Missing SignedHeaders in Authorization header")
            .trim()
            .trim_start_matches("SignedHeaders=")
    };

    header_list
        .split(';')
        .filter_map(|h| all_params.get(h).map(|v| (h.to_string(), v.clone())))
        .collect()
}

fn extract_signature(s3_params: &HashMap<String, String>) -> Option<String> {
    if presigned_url(s3_params) {
        s3_params.get("x-amz-signature").map(|s| s.to_string())
    } else {
        let authorization = s3_params.get("authorization")?;

        authorization
            .split(',')
            .map(|part| part.trim())
            .find(|part| part.starts_with("Signature="))
            .map(|sig| sig.trim_start_matches("Signature=").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use aws_sdk_s3::config::Credentials;

    fn to_utc_datetime(s: &str) -> DateTime<Utc> {
        let naive = NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%SZ").unwrap();
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    }

    #[test]
    fn date_inside_a_15min_window_is_valid() {
        let now = Utc::now();

        let s3_date = now + chrono::Duration::minutes(10);
        assert!(s3_date_is_valid(now, s3_date, None));

        let s3_date = now - chrono::Duration::minutes(10);
        assert!(s3_date_is_valid(now, s3_date, None));

        let s3_date = now + chrono::Duration::minutes(16);
        assert!(!s3_date_is_valid(now, s3_date, None));

        let s3_date = now - chrono::Duration::minutes(16);
        assert!(!s3_date_is_valid(now, s3_date, None));

        let s3_date = now - chrono::Duration::minutes(16);
        let expires_in = Some(Duration::from_mins(2));
        assert!(s3_date_is_valid(now, s3_date, expires_in));
    }

    fn config() -> S3Config {
        S3Config::new(
            Credentials::new("an_access_key", "a_secret_key", None, None, "test"),
            "eu-west-1".to_string(),
            true,
        )
    }
    #[test]
    fn presigned_put() {
        env_logger::init();

        let uri = "/upstream/drive-media-storage/item/2b5a76ad-4bfb-4f32-9b6d-ebdd999d3711/test.txt?x-amz-algorithm=AWS4-HMAC-SHA256&x-amz-signature=1695606b1548dc5e8819c3a0276951ac12fb3ef58861d3f31d05c8359a06b1ef&x-amz-credential=an_access_key%2F20251113%2Feu-west-1%2Fs3%2Faws4_request&x-amz-date=20251113T155445Z&x-amz-expires=60&x-amz-signedheaders=host%3Bx-amz-acl";

        let request = TestRequest::put()
            .uri(uri)
            .insert_header(("host", "localhost:4444"))
            .insert_header(("x-amz-acl", "private"))
            .to_http_request();

        let now = to_utc_datetime("20251113T155445Z");

        assert!(is_signature_valid_with_date(&request, config(), now));
    }

    #[test]
    fn query_params_and_authorization_header() {
        let uri = "/upstream/drive-media-storage?list-type=2&encoding-type=url";

        let request = TestRequest::get()
            .uri(uri)
            .insert_header(("host", "localhost:4444"))
            .insert_header(("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
            .insert_header(("x-amz-date", "20251130T111327Z"))
            .insert_header(("authorization", "AWS4-HMAC-SHA256 Credential=an_access_key/20251130/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=a493bc79221f7402ed31bc65a23f1c4b4398e9c97d234d0c298f9822496b6a20"))
            .to_http_request();

        let now = to_utc_datetime("20251130T111327Z");
        assert!(is_signature_valid_with_date(&request, config(), now));
    }

    #[test]
    fn authorization_header() {
        let uri = "/upstream/drive-media-storage/item/29f00a79-b2ff-49a4-b0d5-814863d21ea8/18-11-2025-a-18h35.ics";

        let request = TestRequest::get()
            .uri(uri)
            .insert_header(("host", "937d7186e461.ngrok-free.app"))
            .insert_header(("authorization", "AWS4-HMAC-SHA256 Credential=an_access_key/20251117/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=e09656ef6781f03e8eacd0c5a98c18c4a884254982b8a0043201aa6838e8792c"))
            .insert_header(("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
            .insert_header(("x-amz-date", "20251117T151958Z"))
            .to_http_request();

        let now = to_utc_datetime("20251117T151958Z");

        assert!(is_signature_valid_with_date(&request, config(), now));
    }

    #[test]
    fn multiple_signed_headers() {
        let uri =
            "/upstream/drive-media-storage/item/969fd250-d647-48d7-a0b9-705f2cf4069c/test.txt";

        let request = TestRequest::get()
            .uri(uri)
            .insert_header(("authorization", "AWS4-HMAC-SHA256 Credential=an_access_key/20251118/eu-west-1/s3/aws4_request, SignedHeaders=host;range;x-amz-checksum-mode;x-amz-content-sha256;x-amz-date, Signature=df8a2df04aea3cec93826f42a38e55a13f74b63680fada05d5203cb05df9fbef"))
            .insert_header(("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
            .insert_header(("x-amz-checksum-mode", "ENABLED"))
            .insert_header(("range", "bytes=0-2047"))
            .insert_header(("x-amz-date", "20251118T135750Z"))
            .insert_header(("host", "c0f16bdf2fc8.ngrok-free.app"))
            .to_http_request();

        let now = to_utc_datetime("20251118T135750Z");

        assert!(is_signature_valid_with_date(&request, config(), now));
    }

    #[test]
    fn put_image_and_authorization_header() {
        let uri = "/upstream/coucou/image";

        let request = TestRequest::put()
            .uri(uri)
            .insert_header(("x-amz-checksum-crc32", "8Lrrxw=="))
            .insert_header(("x-amz-content-sha256", "110812f67fa1e1f0117f6f3d70241c1a42a7b07711a93c2477cc516d9042f9db"))
            .insert_header(("x-amz-date", "20251201T073220Z"))
            .insert_header(("x-amz-sdk-checksum-algorithm", "CRC32"))
            .insert_header(("authorization", "AWS4-HMAC-SHA256 Credential=an_access_key/20251201/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-checksum-crc32;x-amz-content-sha256;x-amz-date;x-amz-sdk-checksum-algorithm, Signature=3d6ec6fbb42c50e044607308f04b11d8d98fd402c9ccf9f997d172251b819a74"))
            .insert_header(("host", "localhost:4444"))
            .to_http_request();

        let now = to_utc_datetime("20251201T073220Z");

        assert!(is_signature_valid_with_date(&request, config(), now));
    }

    #[test]
    fn put_image_with_space_in_name_and_authorization_header() {
        let uri = "/upstream/coucou/une%20image";

        let request = TestRequest::put()
            .uri(uri)
            .insert_header(("x-amz-checksum-crc32", "8Lrrxw=="))
            .insert_header(("x-amz-content-sha256", "110812f67fa1e1f0117f6f3d70241c1a42a7b07711a93c2477cc516d9042f9db"))
            .insert_header(("x-amz-date", "20251201T073226Z"))
            .insert_header(("x-amz-sdk-checksum-algorithm", "CRC32"))
            .insert_header(("authorization", "AWS4-HMAC-SHA256 Credential=an_access_key/20251201/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-checksum-crc32;x-amz-content-sha256;x-amz-date;x-amz-sdk-checksum-algorithm, Signature=846cd81b55eede5c7dfce5523f968997ec99e6b7ff963334ae5fadfee7df6ce1"))
            .insert_header(("host", "localhost:4444"))
            .to_http_request();

        let now = to_utc_datetime("20251201T073226Z");

        assert!(is_signature_valid_with_date(&request, config(), now));
    }
}
