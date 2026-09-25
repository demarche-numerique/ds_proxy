use super::*;

// The file is served once: it is removed as soon as it is open, the response
// streams it from the open descriptor.
pub async fn fetch_file(req: HttpRequest, config: web::Data<HttpConfig>) -> HttpResponse {
    let filepath = config.local_encryption_path_for(&req).unwrap();

    match actix_files::NamedFile::open(&filepath) {
        Ok(named_file) => {
            std::fs::remove_file(&filepath).unwrap();
            named_file.into_response(&req)
        }
        _ => HttpResponse::NotFound().finish(),
    }
}
