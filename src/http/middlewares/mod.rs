use super::super::config::HttpConfig;
use super::utils::flavor::{Flavor, detect_flavor};
use super::utils::presigned::PresignedQuery;
use super::utils::verify_signature::{is_signature_valid, unsigned_amz_headers};
use crate::write_once_service::WriteOnceService;
use actix_web::http::{Method, Uri};
use actix_web::{
    Error,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error::{ErrorForbidden, ErrorUnauthorized},
    middleware::Next,
    web,
};
use chrono::Utc;
use percent_encoding::percent_decode_str;
use url::Url;

pub async fn ensure_write_once(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let uri = req.uri();

    // Only guard presigned/user-facing writes: Swift TempURLs and S3
    // presigned URLs, recognised on decoded query keys. Both flavors are
    // covered so write-once holds in dual mode too.
    let presigned = PresignedQuery::parse(uri.query());
    if !presigned.is_presigned() {
        return next.call(req).await;
    }

    // The lock must outlive the credential, or the URL becomes replayable
    // again once the lock expires.
    let lock_duration = presigned.lock_duration(Utc::now());

    let write_once_service = req
        .app_data::<web::Data<WriteOnceService>>()
        .unwrap()
        .clone();

    let path = normalized_path(uri);

    // key was set before, early return and deny access because we only write once
    let locked = match write_once_service.lock(&path, lock_duration).await {
        Ok(true) => true,
        Ok(false) => {
            log::warn!("Access denied: Redis key already exists: {:?}", path);
            return Err(ErrorForbidden("Access denied"));
        }
        // Redis unavailable: the request goes through unguarded. Say so
        // loudly, since write-once is silently suspended for as long as
        // this lasts.
        Err(err) => {
            log::error!(
                "write-once lock unavailable, letting {:?} through unguarded: {}",
                path,
                err
            );
            false
        }
    };

    // proceed with the request
    let result = next.call(req).await;

    // Only a successful upstream answer consumes the lock. Anything else
    // (upstream refusal, proxy error) stored nothing, so the credential
    // must stay usable.
    let succeeded = matches!(&result, Ok(response) if response.status().is_success());
    if locked
        && !succeeded
        && let Err(err) = write_once_service.unlock(&path).await
    {
        log::error!("Failed to release write-once lock on {:?}: {}", path, err);
    }

    result
}

// The lock must hold on the object the request actually addresses. Swift
// decodes the path before it checks a TempURL and before it resolves the
// object, so every percent-encoded spelling of a name passes the same
// signature: key the lock on the decoded path, `%2F` included, decoded once.
// Dot segments are resolved before decoding, by url::Url, where an encoded
// slash does not separate segments. The key is decoded, so it is logged with
// `{:?}`: a decoded control character must not reach the log as is.
fn normalized_path(uri: &Uri) -> String {
    let path = Url::parse(&format!("http://ds-proxy{}", uri.path()))
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|_| uri.path().to_owned());
    percent_decode_str(&path).decode_utf8_lossy().into_owned()
}

pub async fn verify_s3_signature(
    service_request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    if service_request.method() == Method::OPTIONS {
        return next.call(service_request).await;
    }

    let config = service_request.app_data::<web::Data<HttpConfig>>().unwrap();

    // In dual mode only S3-flavored requests are signature-checked; Swift
    // requests delegate auth to the upstream. In single mode every request is
    // treated as S3 when credentials are configured (unchanged behavior).
    let is_s3_request = !config.dual || detect_flavor(service_request.request()) == Flavor::S3;

    if let Some(s3_config) = &config.s3_config
        && is_s3_request
        && !s3_config.bypass_signature_check
    {
        if !is_signature_valid(service_request.request(), s3_config) {
            log::warn!(
                "Invalid S3 signature for {} {}",
                service_request.method(),
                service_request.path()
            );
            return Err(ErrorUnauthorized("Invalid S3 signature"));
        }

        // The signature only vouches for the headers the client signed.
        // Every other x-amz- header would be re-signed by the proxy with
        // its own credentials, so refuse them like S3 does.
        let unsigned = unsigned_amz_headers(service_request.request());
        if !unsigned.is_empty() {
            log::warn!(
                "Unsigned x-amz- headers {:?} for {} {}",
                unsigned,
                service_request.method(),
                service_request.path()
            );
            return Err(ErrorForbidden(
                "There were headers present in the request which were not signed",
            ));
        }
    }

    next.call(service_request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_key(path: &str) -> String {
        normalized_path(&path.parse::<Uri>().unwrap())
    }

    #[test]
    fn every_encoded_spelling_of_an_object_shares_one_write_once_lock() {
        for spelling in [
            "/upstream/v1/AUTH_project/container/folder/document.pdf",
            "/upstream/v1/AUTH_project/container/folder/d%6Fcument.pdf",
            "/upstream/v1/AUTH_project/container/folder/d%6fcument.pdf",
            "/upstream/v1/AUTH_project/container/folder%2Fdocument.pdf",
        ] {
            assert_eq!(
                lock_key(spelling),
                "/upstream/v1/AUTH_project/container/folder/document.pdf",
                "{} has its own lock",
                spelling
            );
        }
    }

    #[test]
    fn the_lock_path_is_decoded_once_after_dot_segments() {
        assert_eq!(
            lock_key("/upstream/v1/AUTH_project/container/100%2525.pdf"),
            "/upstream/v1/AUTH_project/container/100%25.pdf"
        );
        assert_eq!(
            lock_key("/upstream/v1/AUTH_project/container/x%2F..%2Fdocument.pdf"),
            "/upstream/v1/AUTH_project/container/x/../document.pdf"
        );
    }
}
