use actix_http::Method;

use crate::http::utils::s3_helper::sign_request;

use super::*;

pub async fn simple_proxy(
    req: HttpRequest,
    payload: web::Payload,
    client: web::Data<Client>,
    config: web::Data<HttpConfig>,
) -> Result<HttpResponse, Error> {
    let url = config.create_upstream_url(&req);

    if url.is_none() {
        return not_found();
    }

    let mut proxied_req = client.request_from(url.unwrap(), req.head()).force_close();

    for header in &FETCH_REQUEST_HEADERS_TO_REMOVE {
        proxied_req.headers_mut().remove(header);
    }

    let req_to_send = if let Some(s3_config) = config.s3_config.clone() {
        sign_request(proxied_req, s3_config)
    } else {
        proxied_req
    };

    req_to_send
        .send_stream(payload)
        .await
        .map_err(|e| {
            error!("simple proxy fwk error {:?}, {:?}", e, req);
            actix_web::error::ErrorBadGateway(e)
        })
        .map(|res| {
            if res.status().is_client_error() || res.status().is_server_error() {
                error!("simple proxy status error {:?} {:?}", req, res);
            }

            let mut client_resp = HttpResponse::build(res.status());

            for header in res
                .headers()
                .iter()
                .filter(|(h, _)| !FETCH_RESPONSE_HEADERS_TO_REMOVE.contains(h))
            {
                client_resp.append_header(header);
            }

            if req.method() == Method::HEAD {
                if let Some(content_length) =
                    res.headers().get("x-amz-meta-original-content-length")
                {
                    client_resp.insert_header(("content-length", content_length.clone()));
                }
            }

            client_resp.streaming(res)
        })
}
