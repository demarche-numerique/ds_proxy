use tokio::{fs::OpenOptions, io::AsyncWriteExt};

use super::*;

pub async fn encrypt_to_file(
    req: HttpRequest,
    config: web::Data<HttpConfig>,
    payload: web::Payload,
) -> HttpResponse {
    let filepath = config.local_encryption_path_for(&req).unwrap();

    let (id, key) = config
        .keyring
        .get_last_key()
        .expect("no key avalaible for encryption");

    let mut encrypted_stream = Encoder::new(key, id, config.chunk_size, Box::new(payload), None);

    log::info!("Encrypting to file: {}", filepath.display());

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(filepath)
        .await
        .unwrap();

    while let Ok(Some(chunk)) = encrypted_stream.try_next().await {
        f.write_all(&chunk).await.unwrap();
    }

    f.sync_all().await.unwrap();

    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .body("{}")
}
