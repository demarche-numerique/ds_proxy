use super::super::config::HttpConfig;
use super::utils::verify_signature::is_signature_valid;
use crate::write_once_service::WriteOnceService;
use actix_http::Method;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error::{ErrorForbidden, ErrorUnauthorized},
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
