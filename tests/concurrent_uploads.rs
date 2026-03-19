use assert_fs::prelude::*;
use ds_proxy::crypto::header::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

mod helpers;
pub use helpers::*;

#[test]
#[serial(servers)]
fn concurent_uploads() {
    /*
    This test:
     - spawns a node server that stores uploaded files in tests/fixtures/server-static/uploads/
     - spawns a ds proxy that uses the node proxy as a storage backend
     - attempts to store many files concurently files, while the server has a high latency

    For large number of threads, you may need to increase the open files limit before this works.
    For instance:
        ulimit -n 2048
    */

    const THREADS_COUNT: u16 = 20;
    const DELAY_BETWEEN_TREADS: Duration = Duration::from_millis(10);
    const SERVER_LATENCY: Duration = Duration::from_millis(100);

    let _proxy_node_and_redis = ProxyAndNode::start_with_options(
        None,
        Some(SERVER_LATENCY),
        PrintServerLogs::No,
        None,
        false,
    );

    // Spawn threads (with a slight delay between each)
    let mut child_threads = vec![];
    let counter = Arc::new(Mutex::new(0));

    for _ in 0..THREADS_COUNT {
        thread::sleep(DELAY_BETWEEN_TREADS);

        let counter = Arc::clone(&counter);

        let name = format!("thread {}", child_threads.len());
        let child_thread = thread::Builder::new()
            .name(name)
            .spawn(move || {
                {
                    let mut threads_count = counter.lock().unwrap();
                    *threads_count += 1;
                    println!("Number of threads: {}", threads_count);
                }

                let stored_filename = Uuid::new_v4();
                let stored_file_url = format!("localhost:4444/upstream/{}", stored_filename);
                let uploaded_path = format!(
                    "tests/fixtures/server-static/uploads/jail/cell/{}",
                    stored_filename
                );

                let temp = assert_fs::TempDir::new().unwrap();
                let decrypted_file = temp.child("computer.dec.svg");
                let decrypted_path = decrypted_file.path();

                curl_put(COMPUTER_SVG_PATH, &stored_file_url);

                let uploaded_bytes =
                    std::fs::read(&uploaded_path).expect("uploaded should exist !");
                assert!(!uploaded_bytes.is_empty());
                assert_eq!(&uploaded_bytes[0..PREFIX_SIZE], PREFIX);

                decrypt(&uploaded_path, decrypted_path);
                let decrypted_bytes = std::fs::read(decrypted_path).unwrap();
                assert_eq!(COMPUTER_SVG_BYTES.len(), decrypted_bytes.len());
                assert_eq!(COMPUTER_SVG_BYTES, decrypted_bytes);

                let curl_download = curl_get(&stored_file_url);
                assert_eq!(curl_download.stdout.len(), COMPUTER_SVG_BYTES.len());
                assert_eq!(curl_download.stdout, COMPUTER_SVG_BYTES);

                let curl_socket_download = curl_socket_get(&stored_file_url);
                assert_eq!(curl_socket_download.stdout.len(), COMPUTER_SVG_BYTES.len());
                assert_eq!(curl_socket_download.stdout, COMPUTER_SVG_BYTES);

                let curl_chunked_download = curl_get(&format!(
                    "localhost:4444/upstream/{}?chunked=true",
                    stored_filename
                ));
                assert_eq!(curl_chunked_download.stdout.len(), COMPUTER_SVG_BYTES.len());
                assert_eq!(curl_chunked_download.stdout, COMPUTER_SVG_BYTES);

                // Cleanup
                temp.close().unwrap();
                ensure_is_absent(&uploaded_path);

                {
                    let mut threads_count = counter.lock().unwrap();
                    *threads_count -= 1;
                    println!("Number of threads: {}", threads_count);
                }
            })
            .unwrap();
        child_threads.push(child_thread);
    }

    // Wait for all threads to have successfully finished
    // (or panic if a child thread panicked.)
    for child_thread in child_threads {
        child_thread.join().expect("A child thread panicked");
    }
}
