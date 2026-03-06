use std::convert::TryInto;

use assert_fs::prelude::*;
use ds_proxy::crypto::header;

mod helpers;
pub use helpers::*;

#[test]
#[serial(servers)]
fn multiple_keys() {
    /* this tests encrypt 3 files with 3 differents keys
     * ensure the right key_id is written in the file
     * and then download and decrypt the differnts files
     */

    let temp = assert_fs::TempDir::new().unwrap();
    let keyring_file = temp.child("keyring");
    let keyring_path = keyring_file.path().to_str().unwrap();
    println!("{:?}", keyring_path);

    let password = init_keyring(keyring_path);

    for i in 0..3u64 {
        add_a_key(keyring_path, &password);

        let upload_url = format!("localhost:4444/upstream/victory_{}", i);
        let upload_path = format!(
            "tests/fixtures/server-static/uploads/jail/cell/victory_{}",
            i
        );
        ensure_is_absent(&upload_path);

        let _proxy_node_and_redis = ProxyAndNode::start_with_keyring_path(keyring_path, &password);
        curl_put(COMPUTER_SVG_PATH, &upload_url);

        assert_eq!(key_id(&upload_path), i + 1);
    }

    let _proxy_node_and_redis = ProxyAndNode::start_with_keyring_path(keyring_path, &password);

    for i in 0..3 {
        let download_url = format!("localhost:4444/upstream/victory_{}", i);
        let curl_download = curl_get(&download_url);
        assert_eq!(curl_download.stdout, COMPUTER_SVG_BYTES);
    }

    temp.close().unwrap();
}

fn key_id(uploaded_path: &str) -> u64 {
    let uploaded_bytes = std::fs::read(uploaded_path).expect("uploaded should exist !");

    u64::from_le_bytes(
        uploaded_bytes[header::HEADER_SIZE..header::HEADER_V2_SIZE]
            .try_into()
            .unwrap(),
    )
}
