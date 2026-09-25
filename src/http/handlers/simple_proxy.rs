use actix_web::http::Method;

use crate::http::utils::flavor::{Flavor, route};
use crate::http::utils::s3_helper::upstream_host;

use super::*;

pub async fn simple_proxy(
    req: HttpRequest,
    payload: web::Payload,
    client: web::Data<Client>,
    config: web::Data<HttpConfig>,
) -> Result<HttpResponse, Error> {
    let (flavor, url) = route(&config, &req);

    let mut proxied_req = client.request_from(url, req.head()).force_close();

    for header in &FETCH_REQUEST_HEADERS_TO_REMOVE {
        proxied_req.headers_mut().remove(header);
    }

    // A CORS preflight carries no credential by design, and the upstream
    // evaluates it against the bucket's CORS policy without one. Relay it
    // unsigned: signing it would lend the proxy's credentials to a request
    // nobody authenticated (the signature check skips OPTIONS). It still
    // needs the upstream's Host, which sign_request would otherwise have set.
    let req_to_send = match (flavor, &config.s3_config) {
        (Flavor::S3, Some(_)) if req.method() == Method::OPTIONS => {
            let host = upstream_host(proxied_req.get_uri());
            config.apply_s3_connect_url(proxied_req.insert_header(("host", host)))
        }
        _ => sign_for_upstream(&config, flavor, proxied_req),
    };

    let res = req_to_send
        .send_stream(payload)
        .await
        .map_err(|e| upstream_error(&req, e))?;

    let mut client_resp = client_response(&req, &res, &FETCH_RESPONSE_HEADERS_TO_REMOVE);

    if req.method() == Method::HEAD
        && let Some(content_length) = res.headers().get("x-amz-meta-original-content-length")
    {
        client_resp.insert_header(("content-length", content_length.clone()));
    }

    Ok(client_resp.streaming(res))
}
