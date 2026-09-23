mod encrypt_to_file;
mod fetch;
mod fetch_file;
mod forward;
mod ping;
mod simple_proxy;

pub use encrypt_to_file::encrypt_to_file;
pub use fetch::fetch;
pub use fetch_file::fetch_file;
pub use forward::forward;
pub use ping::ping;
pub use simple_proxy::simple_proxy;

// shared import between handlers
use super::super::config::HttpConfig;
use super::super::crypto::*;
use super::utils::flavor::Flavor;
use super::utils::s3_helper::sign_request;
use super::utils::*;
use actix_web::http::{StatusCode, header};
use actix_web::{Error, HttpRequest, HttpResponse, HttpResponseBuilder, web};
use awc::error::SendRequestError;
use awc::{Client, ClientRequest, ClientResponse};
use futures::TryStreamExt;
use log::{error, trace};

pub static FETCH_RESPONSE_HEADERS_TO_REMOVE: [header::HeaderName; 3] = [
    // Connection settings (keepalived) must not be resend
    header::CONNECTION,
    // Encryption changes the length of the content
    // and we use chunk transfert-encoding
    header::CONTENT_LENGTH,
    // Encryption change the data and thus the etag
    // which is often used as a md5
    header::ETAG,
];

pub static FETCH_REQUEST_HEADERS_TO_REMOVE: [header::HeaderName; 2] = [
    // Connection settings (keepalived) must not be resend
    header::CONNECTION,
    header::RANGE,
];

// An S3 request goes out signed with the proxy's credentials, towards the
// connect target if one is configured. A Swift request goes out as is.
pub fn sign_for_upstream(config: &HttpConfig, flavor: Flavor, req: ClientRequest) -> ClientRequest {
    match (flavor, &config.s3_config) {
        (Flavor::S3, Some(s3_config)) => config.apply_s3_connect_url(sign_request(req, s3_config)),
        _ => req,
    }
}

pub fn upstream_error(req: &HttpRequest, e: SendRequestError) -> Error {
    error!("upstream error {:?} for {} {}", e, req.method(), req.path());
    match e {
        SendRequestError::Timeout => actix_web::error::ErrorGatewayTimeout(e),
        _ => actix_web::error::ErrorBadGateway(e),
    }
}

// The response to the client starts as the upstream's: same status, same
// headers but the ones the handler has to drop.
pub fn client_response<S>(
    req: &HttpRequest,
    res: &ClientResponse<S>,
    headers_to_remove: &[header::HeaderName],
) -> HttpResponseBuilder {
    if res.status().is_client_error() || res.status().is_server_error() {
        error!(
            "upstream status error {} for {} {}",
            res.status(),
            req.method(),
            req.path()
        );
    }

    let mut client_resp = HttpResponse::build(res.status());

    for header in res
        .headers()
        .iter()
        .filter(|(h, _)| !headers_to_remove.contains(h))
    {
        client_resp.append_header(header);
    }

    client_resp
}

// An upstream redirect on an encrypting path (fetch, forward) is neither
// followed nor relayed. Following it would resend the body empty or turn
// the request into a GET; relaying its Location would send the client to
// the upstream directly, around the encryption. Nothing was stored, so
// answer 502 and say so in the logs. simple_proxy transforms nothing and
// relays a redirect like any other answer.
//
// Only the statuses that carry a Location count: 304 Not Modified is also
// a 3xx, and a conditional GET must still get it.
pub fn refuse_redirect(req: &HttpRequest, status: StatusCode) -> Result<(), Error> {
    let is_redirect = matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    );

    if is_redirect {
        error!(
            "upstream redirect {} for {} {}, refused",
            status,
            req.method(),
            req.path()
        );
        return Err(actix_web::error::ErrorBadGateway("upstream redirect"));
    }

    Ok(())
}
