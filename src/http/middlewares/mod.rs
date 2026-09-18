use super::super::config::HttpConfig;
use super::utils::flavor::{detect_flavor, Flavor};
use super::utils::presigned::PresignedQuery;
use super::utils::verify_signature::{is_signature_valid, unsigned_amz_headers};
use crate::write_once_service::WriteOnceService;
use actix_web::http::{Method, Uri};
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error::{ErrorForbidden, ErrorUnauthorized},
    middleware::Next,
    web, Error,
};
use std::path::Path;
use url::Url;

pub async fn ensure_write_once(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let uri = req.uri();

    // Only guard presigned/user-facing writes: Swift TempURLs and S3
    // presigned URLs, recognised on decoded query keys. Both flavors are
    // covered so write-once holds in dual mode too.
    if !PresignedQuery::parse(uri.query()).is_presigned() {
        return next.call(req).await;
    }

    let write_once_service = req
        .app_data::<web::Data<WriteOnceService>>()
        .unwrap()
        .clone();

    let path = normalized_path(uri);

    // key was set before, early return and deny access because we only write once
    match write_once_service.lock(&path).await {
        Ok(true) => {}
        Ok(false) => {
            log::warn!("Access denied: Redis key already exists: {}", path);
            return Err(ErrorForbidden("Access denied"));
        }
        // Redis unavailable: the request goes through unguarded. Say so
        // loudly, since write-once is silently suspended for as long as
        // this lasts.
        Err(err) => {
            log::error!(
                "write-once lock unavailable, letting {} through unguarded: {}",
                path,
                err
            );
        }
    }

    // proceed with the request
    let result = next.call(req).await;
    if let Ok(ref response) = result {
        if !response.status().is_success() {
            if let Err(err) = write_once_service.unlock(&path).await {
                log::error!(
                    "Failed to mark as locked with expiration: {}. Error: {}",
                    path,
                    err
                );
            }
        }
    }

    result
}

// The lock must hold on the object the request actually addresses. Both the
// signature check (HttpRequest::full_url) and the upstream URL go through
// url::Url, which resolves `.` and `..` segments, percent-encoded or not. Key
// the lock on that same resolved path, so that every spelling of a path
// shares one lock. Any other path comes out unchanged.
fn normalized_path(uri: &Uri) -> String {
    Url::parse(&format!("http://ds-proxy{}", uri.path()))
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|_| uri.path().to_owned())
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

    if let Some(s3_config) = config.s3_config.clone() {
        if is_s3_request && !s3_config.bypass_signature_check {
            if !is_signature_valid(service_request.request(), s3_config) {
                log::warn!(
                    "Invalid S3 signature for request: {}",
                    service_request.uri()
                );
                return Err(ErrorUnauthorized("Invalid S3 signature"));
            }

            // The signature only vouches for the headers the client signed.
            // Every other x-amz- header would be re-signed by the proxy with
            // its own credentials, so refuse them like S3 does.
            let unsigned = unsigned_amz_headers(service_request.request());
            if !unsigned.is_empty() {
                log::warn!(
                    "Unsigned x-amz- headers {:?} for request: {}",
                    unsigned,
                    service_request.uri()
                );
                return Err(ErrorForbidden(
                    "There were headers present in the request which were not signed",
                ));
            }
        }
    }

    next.call(service_request).await
}

pub fn erase_file(res: Result<ServiceResponse, Error>) -> Result<ServiceResponse, Error> {
    let response = res.unwrap();
    let request = response.request();

    let filepath = request
        .app_data::<web::Data<HttpConfig>>()
        .unwrap()
        .local_encryption_path_for(request)
        .unwrap();

    if Path::new(&filepath).exists() {
        std::fs::remove_file(filepath).unwrap();
    }

    Ok(response)
}
