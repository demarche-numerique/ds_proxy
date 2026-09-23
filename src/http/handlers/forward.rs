use crate::config::DEFAULT_CHUNK_SIZE;
use crate::http::utils::flavor::{Flavor, route};
use crate::http::utils::s3_helper::sign_request;

use super::*;
use futures::StreamExt;
use md5::{Digest, Md5};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

const UPLOAD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

static FORWARD_REQUEST_HEADERS_TO_REMOVE: [header::HeaderName; 5] = [
    // Connection settings (keepalived) must not be resend
    header::CONNECTION,
    // Encryption changes the length of the content
    header::CONTENT_LENGTH,
    // The Content-MD5 sent by the client is the checksum of the cleartext
    // data, it does not match the encrypted body forwarded to the storage
    header::HeaderName::from_static("content-md5"),
    // Openstack checks the ETAG header as a md5 checksum of the data
    // the encryption change the data and thus the etag
    header::ETAG,
    // The awc client does not handle expect header
    // https://github.com/actix/actix-web/issues/1775
    header::EXPECT,
];

static FORWARD_RESPONSE_HEADERS_TO_REMOVE: [header::HeaderName; 1] = [
    // Connection settings (keepalived) must not be resend
    header::CONNECTION,
];

pub async fn forward(
    req: HttpRequest,
    payload: web::Payload,
    client: web::Data<Client>,
    config: web::Data<HttpConfig>,
) -> Result<HttpResponse, Error> {
    let (flavor, base) = route(&config, &req);
    let put_url = config.create_upstream_url(&req, base);

    let mut forwarded_req = client
        .request_from(put_url.clone(), req.head())
        .force_close()
        .timeout(UPLOAD_TIMEOUT);

    if let Some(length) = content_length(req.headers())
        && flavor == Flavor::S3
    {
        log::info!(
            "Adding x-amz-meta-original-content-length header with length {}",
            length
        );
        forwarded_req =
            forwarded_req.insert_header(("x-amz-meta-original-content-length", length.to_string()));
    }

    for header in &FORWARD_REQUEST_HEADERS_TO_REMOVE {
        forwarded_req.headers_mut().remove(header);
    }

    let (key_id, key) = config
        .keyring
        .get_last_key()
        .expect("no key avalaible for encryption");

    // The etag we answer is the md5 of the cleartext the client sent, so the
    // payload is hashed on its way into the encoder, not inside it.
    let md5_hasher = Rc::new(RefCell::new(Md5::new()));
    let hasher = Rc::clone(&md5_hasher);
    let hashed_payload = payload
        .map(|item| item.map_err(Error::from))
        .inspect_ok(move |bytes| hasher.borrow_mut().update(bytes));

    let encrypted_body = encrypted_body(
        key,
        key_id,
        DEFAULT_CHUNK_SIZE,
        content_length(req.headers()),
        hashed_payload,
    );

    let final_req = match (flavor, config.s3_config.clone()) {
        (Flavor::S3, Some(s3_config)) => {
            config.apply_s3_connect_url(sign_request(forwarded_req, s3_config))
        }
        _ => forwarded_req,
    };

    let mut res = final_req.send_body(encrypted_body).await.map_err(|e| {
        error!(
            "forward fwk error {:?} for {} {}",
            e,
            req.method(),
            req.path()
        );
        actix_web::error::ErrorBadGateway(e)
    })?;

    trace!("backend response for PUT {:?} : {:?}", put_url, res);

    refuse_redirect(&req, res.status())?;

    if res.status().is_client_error() || res.status().is_server_error() {
        error!(
            "forward status error {} for {} {}",
            res.status(),
            req.method(),
            req.path()
        );
    }

    let mut client_resp = HttpResponse::build(res.status());

    for header in res
        .headers()
        .iter()
        .filter(|(h, _)| !FORWARD_RESPONSE_HEADERS_TO_REMOVE.contains(h))
    {
        client_resp.append_header(header);
    }

    let etag = hex::encode(md5_hasher.borrow().clone().finalize());

    client_resp.insert_header(("etag", format!("\"{}\"", etag)));

    Ok(client_resp.body(res.body().await?))
}
