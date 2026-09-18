//! Presigned S3 URLs and Swift TempURLs carry their credential in the query
//! string. That is what makes a request user-facing, and what the write-once
//! guard keys on.
//!
//! Keys are read percent-decoded and lowercased, the same way the signature
//! check and the upstream read them: a spelling that they accept must be
//! seen here too.

use std::collections::HashMap;
use url::form_urlencoded;

const PRESIGNED_KEYS: [&str; 4] = [
    "x-amz-signature",
    "x-amz-expires",
    "temp_url_sig",
    "temp_url_expires",
];

pub struct PresignedQuery {
    params: HashMap<String, String>,
}

impl PresignedQuery {
    pub fn parse(query: Option<&str>) -> Self {
        let params = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.to_lowercase(), v.into_owned()))
            .collect();

        PresignedQuery { params }
    }

    /// True when the query carries an S3 presigned signature/expiry or a
    /// Swift TempURL signature/expiry.
    pub fn is_presigned(&self) -> bool {
        PRESIGNED_KEYS
            .iter()
            .any(|key| self.params.contains_key(*key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presigned(query: &str) -> bool {
        PresignedQuery::parse(Some(query)).is_presigned()
    }

    #[test]
    fn s3_presigned_urls_are_detected() {
        assert!(presigned(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60&X-Amz-Signature=abc"
        ));
        assert!(presigned("x-amz-expires=60&x-amz-signature=abc"));
        assert!(presigned("X-Amz-Signature=abc"));
    }

    #[test]
    fn swift_tempurls_are_detected() {
        assert!(presigned("temp_url_sig=abc&temp_url_expires=1700000000"));
        assert!(presigned("temp_url_sig=abc"));
    }

    #[test]
    fn percent_encoded_key_spellings_are_detected() {
        assert!(presigned("X-Amz%2DExpires=60&X-Amz-Signature=abc"));
        assert!(presigned("X-Amz%2DSignature=abc&X-Amz%2DExpires=60"));
        assert!(presigned("x%2Damz%2Dexpires=60"));
        assert!(presigned(
            "temp_url%5Fexpires=1700000000&temp_url%5Fsig=abc"
        ));
        assert!(presigned("%74emp_url_sig=abc"));
    }

    #[test]
    fn application_requests_are_not_presigned() {
        assert!(!presigned(""));
        assert!(!PresignedQuery::parse(None).is_presigned());
        assert!(!presigned("list-type=2&encoding-type=url"));
        assert!(!presigned("partNumber=1&uploadId=abc"));
        // a value is not a key
        assert!(!presigned("q=x-amz-signature"));
    }
}
