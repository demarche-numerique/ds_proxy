use super::super::config::HttpConfig;
use super::utils::verify_signature::is_signature_valid;
use crate::write_once_service::WriteOnceService;
use actix_http::Method;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error::{ErrorBadRequest, ErrorForbidden, ErrorUnauthorized},
    middleware::Next,
    web, Error,
};
use std::path::Path;

pub async fn ensure_write_once(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let uri_string = req.uri().to_string();
    let uri: &str = uri_string.as_str();

    let user_facing_uri = req
        .uri()
        .query()
        .is_some_and(|query| query.contains("temp_url_expires"));

    if !user_facing_uri {
        return next.call(req).await;
    }

    let write_once_service = req
        .app_data::<web::Data<WriteOnceService>>()
        .unwrap()
        .clone();

    // key was set before, early return and deny access because we only write once
    match write_once_service.lock(uri).await {
        Ok(true) => {}
        Ok(false) => {
            log::warn!("Access denied: Redis key already exists: {}", uri);
            return Err(ErrorForbidden("Access denied"));
        }
        Err(_) => {} // don't mind about redis errors
    }

    // proceed with the request
    let result = next.call(req).await;
    if let Ok(ref response) = result {
        if !response.status().is_success() {
            if let Err(err) = write_once_service.unlock(uri).await {
                log::error!(
                    "Failed to mark as locked with expiration: {}. Error: {}",
                    uri,
                    err
                );
            }
        }
    }

    result
}

// Path validation adapted from actix-files v0.6.10 (PathBufWrap::parse_path)
// Copyright (c) actix contributors — MIT OR Apache-2.0
// https://github.com/actix/actix-web/tree/master/actix-files
pub async fn reject_path_traversal(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let raw_path = req.uri().path();

    if let Err(reason) = validate_path(raw_path) {
        log::warn!("Path traversal/SSRF rejected: {} — {}", raw_path, reason);
        return Err(ErrorBadRequest("Bad request"));
    }

    next.call(req).await
}

fn validate_path(raw_path: &str) -> Result<(), &'static str> {
    let slash_count_before = raw_path.matches('/').count();

    if raw_path.contains("//") {
        return Err("consecutive slashes");
    }

    let decoded = percent_encoding::percent_decode_str(raw_path)
        .decode_utf8()
        .map_err(|_| "invalid utf-8")?;

    if decoded.matches('/').count() != slash_count_before {
        return Err("encoded slash");
    }

    let double_decoded = percent_encoding::percent_decode_str(&decoded)
        .decode_utf8()
        .map_err(|_| "invalid utf-8")?;

    if double_decoded.matches('/').count() != slash_count_before {
        return Err("double-encoded slash");
    }

    for segment in decoded.split('/') {
        if segment == ".." {
            return Err("dot-dot segment");
        }
    }

    Ok(())
}

pub async fn verify_s3_signature(
    service_request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    if service_request.method() == Method::OPTIONS {
        return next.call(service_request).await;
    }

    let config = service_request.app_data::<web::Data<HttpConfig>>().unwrap();

    if let Some(config) = config.s3_config.clone() {
        if !config.bypass_signature_check && !is_signature_valid(service_request.request(), config)
        {
            log::warn!(
                "Invalid S3 signature for request: {}",
                service_request.uri()
            );
            return Err(ErrorUnauthorized("Invalid S3 signature"));
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

#[cfg(test)]
mod tests {
    use super::validate_path;

    #[test]
    fn valid_paths() {
        assert!(validate_path("/upstream/file.txt").is_ok());
        assert!(validate_path("/upstream/sub/dir/file.txt").is_ok());
        assert!(validate_path("/upstream/plop%20plop.png").is_ok());
    }

    #[test]
    fn rejects_dot_dot_segments() {
        assert!(validate_path("/upstream/../../etc/passwd").is_err());
        assert!(validate_path("/upstream/../escape").is_err());
    }

    #[test]
    fn rejects_encoded_slashes() {
        assert!(validate_path("/upstream/..%2f..%2fout.txt").is_err());
        assert!(validate_path("/upstream/..%2F..%2Fout.txt").is_err());
    }

    #[test]
    fn rejects_double_encoded_slashes() {
        assert!(validate_path("/upstream/..%252f..%252fout.txt").is_err());
    }

    #[test]
    fn rejects_encoded_dots() {
        assert!(validate_path("/upstream/%2e%2e/%2e%2e/out.txt").is_err());
    }

    #[test]
    fn rejects_consecutive_slashes_ssrf() {
        assert!(validate_path("/upstream///127.0.0.1:9002/secret").is_err());
        assert!(validate_path("/upstream///evil.com/steal").is_err());
    }

    #[test]
    fn rejects_mixed_encoding() {
        assert!(validate_path("/upstream/..%2f../../out.txt").is_err());
    }
}
