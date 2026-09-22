//! Presigned S3 URLs and Swift TempURLs carry their credential in the query
//! string. That is what makes a request user-facing, and what the write-once
//! guard keys on.
//!
//! Keys are read percent-decoded and lowercased, the same way the signature
//! check and the upstream read them: a spelling that they accept must be
//! seen here too.

use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::HashMap;
use std::time::Duration;
use url::form_urlencoded;

use crate::http::utils::verify_signature::SIGNATURE_GRACE;
use crate::write_once_service::DEFAULT_LOCK_DURATION;

const PRESIGNED_KEYS: [&str; 4] = [
    "x-amz-signature",
    "x-amz-expires",
    "temp_url_sig",
    "temp_url_expires",
];

/// Longest lock ever taken, so that a credential with an absurd expiry
/// cannot make Redis refuse the SET. A year is far beyond the seven days
/// AWS allows a presigned URL to live.
const MAX_LOCK_DURATION: Duration = Duration::from_secs(365 * 24 * 3600);

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

    /// How long a write-once lock must hold for this credential: until it
    /// can no longer be replayed, and never less than the default.
    pub fn lock_duration(&self, now: DateTime<Utc>) -> Duration {
        let remaining = self
            .expires_at()
            .and_then(|end| (end - now).to_std().ok())
            .unwrap_or_default();

        remaining.max(DEFAULT_LOCK_DURATION).min(MAX_LOCK_DURATION)
    }

    /// When the credential stops being accepted, if it can be read: S3
    /// `x-amz-date + x-amz-expires`, Swift `temp_url_expires` (unix
    /// timestamp or ISO 8601), both extended by the clock skew the
    /// signature check tolerates.
    fn expires_at(&self) -> Option<DateTime<Utc>> {
        let end = if let Some(expires) = self.params.get("temp_url_expires") {
            parse_swift_expiry(expires)?
        } else {
            let date = self.params.get("x-amz-date")?;
            let expires_in: u64 = self.params.get("x-amz-expires")?.parse().ok()?;
            let naive = NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ").ok()?;
            let date = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
            date.checked_add_signed(chrono::TimeDelta::seconds(i64::try_from(expires_in).ok()?))?
        };

        end.checked_add_signed(chrono::TimeDelta::from_std(SIGNATURE_GRACE).ok()?)
    }
}

fn parse_swift_expiry(value: &str) -> Option<DateTime<Utc>> {
    if let Ok(timestamp) = value.parse::<i64>() {
        return DateTime::<Utc>::from_timestamp(timestamp, 0);
    }

    let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%SZ").ok()?;
    Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
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

    fn at(s: &str) -> DateTime<Utc> {
        let naive = NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%SZ").unwrap();
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    }

    fn lock_duration(query: &str, now: &str) -> Duration {
        PresignedQuery::parse(Some(query)).lock_duration(at(now))
    }

    #[test]
    fn s3_lock_holds_until_expiry_plus_grace() {
        // valid for 7 days from 12:00, asked at 12:00 → 7 days + 15 min
        let query = "X-Amz-Date=20260918T120000Z&X-Amz-Expires=604800&X-Amz-Signature=abc";
        assert_eq!(
            lock_duration(query, "20260918T120000Z"),
            Duration::from_secs(604800 + 900)
        );
        // asked one day in: six days + 15 min left
        assert_eq!(
            lock_duration(query, "20260919T120000Z"),
            Duration::from_secs(518400 + 900)
        );
    }

    #[test]
    fn swift_lock_holds_until_expiry_plus_grace() {
        // 1789120000 is 2026-09-11T09:46:40Z; asked two hours earlier
        let query = "temp_url_sig=abc&temp_url_expires=1789120000";
        assert_eq!(
            lock_duration(query, "20260911T074640Z"),
            Duration::from_secs(2 * 3600 + 900)
        );

        let query = "temp_url_sig=abc&temp_url_expires=2026-09-11T09:46:40Z";
        assert_eq!(
            lock_duration(query, "20260911T074640Z"),
            Duration::from_secs(2 * 3600 + 900)
        );
    }

    #[test]
    fn short_or_unreadable_expiry_falls_back_to_the_default() {
        // 60 seconds left: the default hour is longer
        let query = "X-Amz-Date=20260918T120000Z&X-Amz-Expires=60&X-Amz-Signature=abc";
        assert_eq!(
            lock_duration(query, "20260918T120000Z"),
            DEFAULT_LOCK_DURATION
        );
        // already expired
        assert_eq!(
            lock_duration(query, "20260918T130000Z"),
            DEFAULT_LOCK_DURATION
        );
        // no expiry at all, or garbage
        assert_eq!(
            lock_duration("X-Amz-Signature=abc", "20260918T120000Z"),
            DEFAULT_LOCK_DURATION
        );
        assert_eq!(
            lock_duration(
                "X-Amz-Date=yesterday&X-Amz-Expires=soon&X-Amz-Signature=abc",
                "20260918T120000Z"
            ),
            DEFAULT_LOCK_DURATION
        );
        assert_eq!(
            lock_duration(
                "temp_url_sig=abc&temp_url_expires=never",
                "20260918T120000Z"
            ),
            DEFAULT_LOCK_DURATION
        );
    }

    #[test]
    fn absurd_expiry_is_capped() {
        let query = "temp_url_sig=abc&temp_url_expires=9999999999";
        assert_eq!(lock_duration(query, "20260918T120000Z"), MAX_LOCK_DURATION);
        let query = "temp_url_sig=abc&temp_url_expires=99999999999999999999";
        assert_eq!(
            lock_duration(query, "20260918T120000Z"),
            DEFAULT_LOCK_DURATION
        );
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
