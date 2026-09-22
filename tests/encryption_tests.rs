extern crate ds_proxy;

use ds_proxy::crypto::*;
use ds_proxy::keyring::Keyring;
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{KEYBYTES, Key};
use std::collections::HashMap;

use actix_web::Error;
use actix_web::body::{BodyStream, to_bytes};
use actix_web::web::Bytes;
use futures::executor::block_on;
use std::pin::pin;

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
        let source_stream = futures::stream::iter([source]);

        let (key_id, key) = keyring.get_last_key().unwrap();

        let mut encrypted = pin!(encode(key, key_id, chunk_size, source_stream));

        let (cypher_type, buff) = block_on(read_ds_header(&mut encrypted));

        let decoder = decode(keyring.clone(), encrypted, cypher_type, buff);

        let buf = block_on(to_bytes(BodyStream::new(decoder))).unwrap();

        assert_eq!(source_bytes, &buf[..]);
    });
}

#[test]
fn decoding_does_not_depend_on_how_the_ciphertext_is_split() {
    let keyring: Keyring = build_keyring();

    proptest!(|(source_bytes: Vec<u8>, chunk_size in 1usize..1000, piece_size in 1usize..100)| {
        let (key_id, key) = keyring.get_last_key().unwrap();

        let source: Result<Bytes, Error> = Ok(Bytes::from(source_bytes.clone()));
        let source_stream = futures::stream::iter([source]);
        let encoder = encode(key, key_id, chunk_size, source_stream);
        let encrypted = block_on(to_bytes(BodyStream::new(encoder))).unwrap();

        // The encoder hands out whole chunks, upstream storage does not: split
        // the ciphertext again so that the decoder sees partial chunks.
        let pieces: Vec<Result<Bytes, Error>> = encrypted
            .chunks(piece_size)
            .map(|piece| Ok(Bytes::copy_from_slice(piece)))
            .collect();

        let mut encrypted = futures::stream::iter(pieces);

        let (cypher_type, buff) = block_on(read_ds_header(&mut encrypted));
        let decoder = decode(keyring.clone(), encrypted, cypher_type, buff);
        let decrypted = block_on(to_bytes(BodyStream::new(decoder))).unwrap();

        prop_assert_eq!(&source_bytes[..], &decrypted[..]);
    });
}

#[test]
fn encrypting_an_empty_source_produces_nothing() {
    let keyring: Keyring = build_keyring();
    let (key_id, key) = keyring.get_last_key().unwrap();

    let source: Result<Bytes, Error> = Ok(Bytes::new());
    let source_stream = futures::stream::iter([source]);

    let encoder = encode(key, key_id, 16, source_stream);
    let encrypted = block_on(to_bytes(BodyStream::new(encoder))).unwrap();

    // Not even a header: an empty object stays empty, which is what
    // encrypted_content_length announces to the storage.
    assert_eq!(0, encrypted.len());
    assert_eq!(encrypted_content_length(0, 16), encrypted.len());
}

#[test]
fn the_encrypted_length_matches_the_announced_one() {
    let keyring: Keyring = build_keyring();

    proptest!(|(source_bytes: Vec<u8>, chunk_size in 1usize..1000, piece_size in 1usize..100)| {
        let (key_id, key) = keyring.get_last_key().unwrap();

        // Feeding the source in pieces of their own size exercises the chunk
        // boundaries, where the announced length is easiest to get wrong.
        let pieces: Vec<Result<Bytes, Error>> = source_bytes
            .chunks(piece_size)
            .map(|piece| Ok(Bytes::copy_from_slice(piece)))
            .collect();

        let encoder = encode(key, key_id, chunk_size, futures::stream::iter(pieces));
        let encrypted = block_on(to_bytes(BodyStream::new(encoder))).unwrap();

        prop_assert_eq!(
            encrypted_content_length(source_bytes.len(), chunk_size),
            encrypted.len()
        );
    });
}

#[test]
fn decrypting_plaintext_returns_plaintext() {
    let keyring: Keyring = build_keyring();

    proptest!(|(clear: Vec<u8>)| {
        let source : Result<Bytes, Error> = Ok(Bytes::from(clear.clone()));
        let mut source_stream = futures::stream::iter([source]);

        let (cypher_type, buff) = block_on(read_ds_header(&mut source_stream));

        let decoder = decode(keyring.clone(), source_stream, cypher_type, buff);

        let buf = block_on(to_bytes(BodyStream::new(decoder))).unwrap();

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
