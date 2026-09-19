use super::*;
use crate::http::utils::{
    flavor::{Flavor, route},
    partial_extractor::*,
    s3_helper::sign_request,
};
use actix_files::HttpRange;
use actix_web::http::StatusCode;
use actix_web::web::Bytes;
use std::pin::Pin;

pub async fn fetch(
    req: HttpRequest,
    body: web::Bytes,
    client: web::Data<Client>,
    config: web::Data<HttpConfig>,
) -> Result<HttpResponse, Error> {
    let (flavor, base) = route(&config, &req);
    let get_url = config.create_upstream_url(&req, base);

    let mut fetch_req = client
        .request_from(get_url.clone(), req.head())
        .force_close();

    let raw_range = req
        .headers()
        .get(header::RANGE)
        .and_then(|l| l.to_str().ok());

    for header in &FETCH_REQUEST_HEADERS_TO_REMOVE {
        fetch_req.headers_mut().remove(header);
    }

    let req_to_send = match (flavor, config.s3_config.clone()) {
        (Flavor::S3, Some(s3_config)) => {
            config.apply_s3_connect_url(sign_request(fetch_req, s3_config))
        }
        _ => fetch_req,
    };

    let res = req_to_send.send_body(body).await.map_err(|e| {
        error!("fetch error {:?} for {} {}", e, req.method(), req.path());
        match e {
            awc::error::SendRequestError::Timeout => actix_web::error::ErrorGatewayTimeout(e),
            _ => actix_web::error::ErrorBadGateway(e),
        }
    })?;

    trace!("backend response for GET {:?} : {:?}", get_url, res);

    refuse_redirect(&req, res.status())?;

    if res.status().is_client_error() || res.status().is_server_error() {
        error!(
            "fetch status error {} for {} {}",
            res.status(),
            req.method(),
            req.path()
        );
    }

    let upstream_status = res.status();

    let mut client_resp = HttpResponse::build(upstream_status);

    for header in res
        .headers()
        .iter()
        .filter(|(h, _)| !FETCH_RESPONSE_HEADERS_TO_REMOVE.contains(h))
    {
        client_resp.append_header(header);
    }

    let original_length = content_length(res.headers());

    let mut boxy: Box<dyn Stream<Item = Result<Bytes, _>> + Unpin> = Box::new(res);
    let (cypher_type, buff) = read_ds_header(&mut boxy).await;

    let fetch_length =
        original_length.map(|content_length| decrypted_content_length(content_length, cypher_type));

    let decoder: Pin<Box<dyn Stream<Item = Result<Bytes, _>>>> =
        Box::pin(decode(config.keyring.clone(), boxy, cypher_type, buff));

    if let Some(length) = fetch_length {
        let range = raw_range.map(|r| HttpRange::parse(r, length.try_into().unwrap()));

        let served_range = match (upstream_status, range) {
            (StatusCode::OK, Some(Ok(v))) => v.first().copied().filter(|r| r.length > 0),
            _ => None,
        };

        match served_range {
            Some(r) => {
                let range_start = r.start.try_into().unwrap();
                let range_end = (r.start + r.length - 1).try_into().unwrap();

                let pe = PartialExtractor::new(decoder, range_start, range_end);

                client_resp.append_header((
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", range_start, range_end, length),
                ));

                // What we hand back is a slice, and only a 206 says so
                client_resp.status(StatusCode::PARTIAL_CONTENT);

                Ok(client_resp.no_chunking(r.length).streaming(pe))
            }
            None => Ok(client_resp.no_chunking(length as u64).streaming(decoder)),
        }
    } else {
        Ok(client_resp.streaming(decoder))
    }
}
