use ds_proxy::{config::DEFAULT_CHUNK_SIZE, crypto::header::*};
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{ABYTES, HEADERBYTES};
use std::fs::File;
use std::io::Write;

mod helpers;
pub use helpers::*;

#[actix_rt::test]
#[serial(servers)]
async fn content_length_and_transfert_encoding() {
    let _proxy_node_and_redis = ProxyAndNode::start();

    let tmp_dir = assert_fs::TempDir::new().unwrap();

    // multiple of chunk size
    let nb_chunk = 2;
    let original_length = nb_chunk * DEFAULT_CHUNK_SIZE;
    let content = vec![0; original_length];

    let expected_encrypted_length =
        HEADER_V2_SIZE + HEADERBYTES + nb_chunk * (ABYTES + DEFAULT_CHUNK_SIZE);

    let (uploaded_length, downloaded_length) =
        uploaded_and_downloaded_content_length(&content).await;

    assert_eq!(expected_encrypted_length, uploaded_length);
    assert_eq!(original_length, downloaded_length);

    // not a multiple of chunk size
    let nb_chunk = 2;
    let original_length = nb_chunk * DEFAULT_CHUNK_SIZE + 1;
    let content = vec![0; original_length];

    let expected_encrypted_length =
        HEADER_V2_SIZE + HEADERBYTES + nb_chunk * (ABYTES + DEFAULT_CHUNK_SIZE) + ABYTES + 1;

    let (uploaded_length, downloaded_length) =
        uploaded_and_downloaded_content_length(&content).await;

    assert_eq!(expected_encrypted_length, uploaded_length);
    assert_eq!(original_length, downloaded_length);

    tmp_dir.close().unwrap();
}

async fn uploaded_and_downloaded_content_length(content: &[u8]) -> (usize, usize) {
    let mut f = File::create("/tmp/foo").expect("Unable to create file");
    f.write_all(content).expect("Unable to write data");

    curl_put("/tmp/foo", "localhost:4444/upstream/file");

    let last_put_headers = curl_get("localhost:3333/last_put_headers").stdout;

    let deserialized: TestHeaders = serde_json::from_slice(&last_put_headers).unwrap();

    (
        deserialized.content_length.parse::<usize>().unwrap(),
        curl_get_content_length_header("http://localhost:4444/upstream/file"),
    )
}

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug)]
struct TestHeaders {
    #[serde(rename = "content-length")]
    content_length: String,
}
