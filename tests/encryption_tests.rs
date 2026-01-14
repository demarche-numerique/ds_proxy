extern crate ds_proxy;

use ds_proxy::crypto::*;
use ds_proxy::keyring::Keyring;
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{Key, KEYBYTES};
use std::collections::HashMap;

use actix_web::web::{BufMut, Bytes, BytesMut};
use actix_web::Error;
use futures::executor::{block_on, block_on_stream};

use proptest::prelude::*;

mod helpers;
pub use helpers::*;

#[test]
fn decrypt_clear_stream() {
    let clear: &[u8] = b"something not encrypted";

    let buf = decrypt_bytes(Bytes::from(clear));

    assert_eq!(clear, &buf[..]);
}

#[test]
fn encoding_then_decoding_returns_source_data() {
    let keyring: Keyring = build_keyring();

    proptest!(|(source_bytes: Vec<u8>, chunk_size in 1usize..10000)| {
        let source : Result<Bytes, Error> = Ok(Bytes::from(source_bytes.clone()));
        let source_stream  = futures::stream::once(Box::pin(async { source }));

        let (key_id, key) = keyring.get_last_key().unwrap();

        let encoder = Encoder::new(key, key_id, chunk_size, Box::new(source_stream), None);

        let mut boxy: Box<dyn futures::Stream<Item = Result<Bytes, _>> + Unpin> = Box::new(encoder);

        let header_decoder = HeaderDecoder::new(&mut boxy);
        let (cypher_type, buff) = block_on(header_decoder);

        let decoder =
        Decoder::new_from_cypher_and_buffer(keyring.clone(), boxy, cypher_type, buff);

        let buf = block_on_stream(decoder)
            .map(|r| r.unwrap())
            .fold(BytesMut::with_capacity(64), |mut acc, x| { acc.put(x); acc });

        assert_eq!(source_bytes, &buf[..]);
    });
}

#[test]
fn decrypting_plaintext_returns_plaintext() {
    let keyring: Keyring = build_keyring();

    proptest!(|(clear: Vec<u8>)| {
        let source : Result<Bytes, Error> = Ok(Bytes::from(clear.clone()));
        let source_stream  = futures::stream::once(Box::pin(async { source }));

        let mut boxy: Box<dyn futures::Stream<Item = Result<Bytes, _>> + Unpin> = Box::new(source_stream);

        let header_decoder = HeaderDecoder::new(&mut boxy);
        let (cypher_type, buff) = block_on(header_decoder);

        let decoder =
        Decoder::new_from_cypher_and_buffer(keyring.clone(), boxy, cypher_type, buff);

        let buf = block_on_stream(decoder)
            .map(|r| r.unwrap())
            .fold(BytesMut::with_capacity(64), |mut acc, x| { acc.put(x); acc });

        assert_eq!(clear, &buf[..]);
    });
}

fn build_keyring() -> Keyring {
    let key: [u8; KEYBYTES] = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8,
    ];

    let mut hash = HashMap::new();
    hash.insert(0, Key::from_bytes(&key).expect("Invalid key"));

    Keyring::new(hash)
}
