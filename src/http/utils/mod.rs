use actix_web::http::{header, header::HeaderMap};

pub mod memory_or_file_buffer;
pub mod partial_extractor;
pub mod s3_helper;
pub mod verify_signature;

pub fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|l| l.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
}
