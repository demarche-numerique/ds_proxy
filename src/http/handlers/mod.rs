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
use super::utils::*;
use actix_web::http::header;
use actix_web::{web, Error, HttpRequest, HttpResponse};
use awc::Client;
use futures::TryStreamExt;
use futures_core::stream::Stream;
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
