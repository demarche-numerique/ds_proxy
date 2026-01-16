use assert_cmd::cargo;
pub use serial_test::serial;

use actix_web::web::{BufMut, Bytes, BytesMut};
use actix_web::Error;
use assert_cmd::prelude::*;
use futures::executor::{block_on, block_on_stream};
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;
use std::{thread, time};

use ds_proxy::crypto::*;
use ds_proxy::keyring_utils::load_keyring;

mod curl;
pub use curl::*;

pub const PASSWORD: &str = "plop";
pub const DS_KEYRING: &str = "tests/fixtures/keyring.toml";

pub const COMPUTER_SVG_PATH: &str = "tests/fixtures/computer.svg";
pub static COMPUTER_SVG_BYTES: Bytes =
    Bytes::from_static(include_bytes!("../fixtures/computer.svg"));
pub const COMPUTER_SVG_MD5_ETAG: &str = "\"12ed2469072ced7b2d0e3141f0ef01f5\"";

pub const ENCRYPTED_COMPUTER_SVG_PATH: &str = "tests/fixtures/computer.svg.enc";
pub static ENCRYPTED_COMPUTER_SVG_BYTES: Bytes =
    Bytes::from_static(include_bytes!("../fixtures/computer.svg.enc"));

#[allow(dead_code)]
pub struct ProxyAndNode {
    proxy: ChildGuard,
    node: ChildGuard,
    redis: ChildGuard,
}

impl ProxyAndNode {
    pub fn start() -> ProxyAndNode {
        ProxyAndNode::start_with_options(None, PrintServerLogs::No, None, false)
    }

    pub fn start_with_keyring_path(keyring_path: &str) -> ProxyAndNode {
        ProxyAndNode::start_with_options(None, PrintServerLogs::No, Some(keyring_path), false)
    }

    pub fn start_with_options(
        latency: Option<Duration>,
        log: PrintServerLogs,
        keyring_path: Option<&str>,
        enable_s3_signature_check: bool,
    ) -> ProxyAndNode {
        let proxy = launch_proxy(log, keyring_path, enable_s3_signature_check);
        let node = launch_node_with_latency(latency, log);
        let redis = launch_redis(log);
        thread::sleep(time::Duration::from_secs(4));
        ProxyAndNode { proxy, node, redis }
    }
}

pub fn launch_redis(log: PrintServerLogs) -> ChildGuard {
    let mut command = Command::new("redis-server");
    command.arg("--port").arg("5555");

    match log {
        PrintServerLogs::Yes => {
            command.env("RUST_LOG", "trace");
        }
        PrintServerLogs::No => (),
    }
    let child = command.spawn().expect("failed to execute redis-server");

    ChildGuard {
        child,
        description: "redis",
    }
}

pub fn launch_proxy(
    log: PrintServerLogs,
    keyring_path: Option<&str>,
    enable_s3_signature_check: bool,
) -> ChildGuard {
    let keyring = if let Some(file) = keyring_path {
        file
    } else {
        DS_KEYRING
    };

    let mut command = Command::new(cargo::cargo_bin!("ds_proxy"));
    command
        .arg("proxy")
        .arg("--address=localhost:4444")
        .arg("--upstream-url=http://localhost:3333/jail/cell")
        .arg("--s3-access-key=key")
        .arg("--s3-secret-key=secret")
        .arg("--s3-region=region")
        .env("DS_KEYRING", keyring)
        .env("DS_PASSWORD", PASSWORD);

    if !enable_s3_signature_check {
        command.arg("--bypass-s3-signature-check");
    }

    match log {
        PrintServerLogs::Yes => {
            command.env("RUST_LOG", "trace");
        }
        PrintServerLogs::No => (),
    }

    let child = command.spawn().expect("failed to execute ds_proxy");
    ChildGuard {
        child,
        description: "ds_proxy",
    }
}

pub fn launch_node_with_latency(latency: Option<Duration>, log: PrintServerLogs) -> ChildGuard {
    let mut command = Command::new("node");
    command.arg("tests/fixtures/server-static/server.js");

    match log {
        PrintServerLogs::Yes => {
            command.env("DEBUG", "express:*");
        }
        PrintServerLogs::No => (),
    }

    if let Some(l) = latency {
        command.arg(format!("--latency={}", l.as_millis()));
    }

    let child = command.spawn().expect("failed to execute node");
    ChildGuard {
        child,
        description: "node",
    }
}

pub struct ChildGuard {
    pub child: Child,
    description: &'static str,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        match self.child.kill() {
            Err(e) => println!(
                "ChildGuard: could not kill out-of-scope '{}' process: {}",
                self.description, e
            ),
            Ok(_) => println!(
                "ChildGuard: successfully killed out-of-scope '{}' process",
                self.description
            ),
        }
    }
}

#[derive(Clone, Copy)]
pub enum PrintServerLogs {
    Yes,
    No,
}

pub fn decrypt(
    encrypted_path: &str,
    decrypted_path: &std::path::Path,
) -> assert_cmd::assert::Assert {
    Command::new(cargo::cargo_bin!("ds_proxy"))
        .arg("decrypt")
        .arg(encrypted_path)
        .arg(decrypted_path)
        .env("DS_KEYRING", DS_KEYRING)
        .env("DS_PASSWORD", PASSWORD)
        .assert()
        .success()
}

pub fn decrypt_bytes(input: Bytes) -> BytesMut {
    let source: Result<Bytes, Error> = Ok(input);
    let source_stream = futures::stream::once(Box::pin(async { source }));
    let mut boxy: Box<dyn futures::Stream<Item = Result<Bytes, _>> + Unpin> =
        Box::new(source_stream);

    let header_decoder = HeaderDecoder::new(&mut boxy);
    let (cypher_type, buff) = block_on(header_decoder);

    let keyring = load_keyring(DS_KEYRING, PASSWORD.to_string());

    let decoder = Decoder::new_from_cypher_and_buffer(keyring, boxy, cypher_type, buff);

    block_on_stream(decoder)
        .map(|r| r.unwrap())
        .fold(BytesMut::with_capacity(64), |mut acc, x| {
            acc.put(x);
            acc
        })
}

pub fn ensure_is_absent(file_path: &str) {
    if Path::new(file_path).exists() {
        std::fs::remove_file(file_path)
            .unwrap_or_else(|_| panic!("Unable to remove {} !", file_path));
    }
}

pub fn add_a_key(keyring_path: &str) -> assert_cmd::assert::Assert {
    Command::new(cargo::cargo_bin!("ds_proxy"))
        .arg("add-key")
        .env("DS_KEYRING", keyring_path)
        .env("DS_PASSWORD", PASSWORD)
        .assert()
        .success()
}

pub fn compute_sha256(file_path: &str) -> String {
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};
    use std::{fs, io};

    let mut file = fs::File::open(file_path).unwrap();
    let mut hasher = Sha256::new();
    let _n = io::copy(&mut file, &mut hasher).unwrap();
    HEXLOWER.encode(&hasher.finalize()[..])
}
