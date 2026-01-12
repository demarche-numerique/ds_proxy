use crate::http::utils::s3_helper::sign_request;

use super::*;
use actix_web::body::SizedStream;
use futures::StreamExt;
use std::time::Duration;

const UPLOAD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

static FORWARD_REQUEST_HEADERS_TO_REMOVE: [header::HeaderName; 4] = [
    // Connection settings (keepalived) must not be resend
    header::CONNECTION,
    // Encryption changes the length of the content
    header::CONTENT_LENGTH,
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
    let Some(put_url) = config.create_upstream_url(&req) else {
        return not_found();
    };

    let mut forwarded_req = client
        .request_from(put_url.clone(), req.head())
        .force_close()
        .timeout(UPLOAD_TIMEOUT);

    if let Some(length) = content_length(req.headers()) {
        if config.s3_config.is_some() {
            log::info!(
                "Adding x-amz-meta-original-content-length header with length {}",
                length
            );
            forwarded_req = forwarded_req
                .insert_header(("x-amz-meta-original-content-length", length.to_string()));
        }
    }

    let forward_length: Option<usize> = content_length(req.headers())
        .map(|content_length| encrypted_content_length(content_length, config.chunk_size));

    for header in &FORWARD_REQUEST_HEADERS_TO_REMOVE {
        forwarded_req.headers_mut().remove(header);
    }

    let (key_id, key) = config
        .keyring
        .get_last_key()
        .expect("no key avalaible for encryption");

    let convert_payload = payload.map(|item| item.map_err(|e| Error::from(e)));
    let encrypted_stream = Encoder::<Error>::new(key, key_id, config.chunk_size, Box::new(convert_payload));

    let final_req = if let Some(s3_config) = config.s3_config.clone() {
        sign_request(forwarded_req, s3_config)
    } else {
        forwarded_req
    };

    let res_e = if let Some(length) = forward_length {
        final_req
            .send_body(SizedStream::new(length as u64, encrypted_stream))
            .await
    } else {
        final_req.send_stream(encrypted_stream).await
    };

    let mut res = res_e.map_err(|e| {
        error!("forward fwk error {:?}, {:?}", e, req);
        actix_web::error::ErrorBadGateway(e)
    })?;

    trace!("backend response for PUT {:?} : {:?}", put_url, res);

    if res.status().is_client_error() || res.status().is_server_error() {
        error!("forward status error {:?} {:?}", req, res);
    }

    let mut client_resp = HttpResponse::build(res.status());

    for header in res
        .headers()
        .iter()
        .filter(|(h, _)| !FORWARD_RESPONSE_HEADERS_TO_REMOVE.contains(h))
    {
        client_resp.append_header(header);
    }

    // let etag = encrypted_stream.input_md5();

    // client_resp.insert_header(("etag", format!("\"{}\"", etag)));

    Ok(client_resp.body(res.body().await?))
}
