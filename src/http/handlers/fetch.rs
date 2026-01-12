use super::*;
use crate::http::utils::{partial_extractor::*, s3_helper::sign_request};
use actix_files::HttpRange;
use actix_web::web::Bytes;

pub async fn fetch(
    req: HttpRequest,
    body: web::Bytes,
    client: web::Data<Client>,
    config: web::Data<HttpConfig>,
) -> Result<HttpResponse, Error> {
    let get_url = config.create_upstream_url(&req);

    if get_url.is_none() {
        return not_found();
    }

    let get_url = get_url.unwrap();

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

    let req_to_send = if let Some(s3_config) = config.s3_config.clone() {
        sign_request(fetch_req, s3_config)
    } else {
        fetch_req
    };

    let res = req_to_send.send_body(body).await.map_err(|e| {
        error!("fetch error {:?}, {:?}", e, req);
        match e {
            awc::error::SendRequestError::Timeout => actix_web::error::ErrorGatewayTimeout(e),
            _ => actix_web::error::ErrorBadGateway(e),
        }
    })?;

    trace!("backend response for GET {:?} : {:?}", get_url, res);

    if res.status().is_client_error() || res.status().is_server_error() {
        error!("fetch status error {:?} {:?}", req, res);
    }

    let mut client_resp = HttpResponse::build(res.status());

    for header in res
        .headers()
        .iter()
        .filter(|(h, _)| !FETCH_RESPONSE_HEADERS_TO_REMOVE.contains(h))
    {
        client_resp.append_header(header);
    }

    let original_length = content_length(res.headers());

    let mut boxy: Box<dyn Stream<Item = Result<Bytes, _>> + Unpin> = Box::new(res);
    let header_decoder = HeaderDecoder::new(&mut boxy);
    let (cypher_type, buff) = header_decoder.await;
    let fetch_length =
        original_length.map(|content_length| decrypted_content_length(content_length, cypher_type));

    let decoder =
        Decoder::new_from_cypher_and_buffer(config.keyring.clone(), boxy, cypher_type, buff);

    if let Some(length) = fetch_length {
        use std::convert::TryInto;

        let range = raw_range.map(|r| HttpRange::parse(r, length.try_into().unwrap()));

        match range {
            Some(Ok(v)) => {
                let r = v.first().unwrap();

                let range_start = r.start.try_into().unwrap();
                let range_end = (r.start + r.length - 1).try_into().unwrap();

                let pe = PartialExtractor::new(Box::new(decoder), range_start, range_end);

                client_resp.append_header((
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", range_start, range_end, length),
                ));

                Ok(client_resp.no_chunking(r.length).streaming(pe))
            }
            _ => Ok(client_resp.no_chunking(length as u64).streaming(decoder)),
        }
    } else {
        Ok(client_resp.streaming(decoder))
    }
}
