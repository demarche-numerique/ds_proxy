use super::super::keyring::Keyring;
use super::decipher_type::DecipherType;
use actix_web::web::{Bytes, BytesMut};
use async_stream::try_stream;
use futures::TryStreamExt;
use futures::stream::Stream;
use libsodium_rs::crypto_secretstream::{PullState, xchacha20poly1305};
use log::trace;
use std::pin::pin;

pub fn decode<E>(
    keyring: Keyring,
    input: impl Stream<Item = Result<Bytes, E>>,
    decipher_type: DecipherType,
    buffer: BytesMut,
) -> impl Stream<Item = Result<Bytes, E>> {
    try_stream! {
        let mut input = pin!(input);
        let mut buffer = buffer;

        match decipher_type {
            DecipherType::Plaintext => {
                if !buffer.is_empty() {
                    yield buffer.split().freeze();
                }

                while let Some(bytes) = input.try_next().await? {
                    yield bytes;
                }
            }

            DecipherType::Encrypted { chunk_size, key_id, .. } => {
                let key = keyring
                    .get_key_by_id(&key_id)
                    .unwrap_or_else(|| panic!("Key {} not found !", key_id));

                while buffer.len() < xchacha20poly1305::HEADERBYTES {
                    trace!("not enough data to decrypt the header");
                    match input.try_next().await? {
                        Some(bytes) => buffer.extend_from_slice(&bytes),
                        // TODO: throw error
                        None => break,
                    }
                }

                if xchacha20poly1305::HEADERBYTES <= buffer.len() {
                    trace!("decrypting the header");

                    let header: [u8; xchacha20poly1305::HEADERBYTES] = buffer
                        .split_to(xchacha20poly1305::HEADERBYTES)
                        .as_ref()
                        .try_into()
                        .expect("slice with incorrect length");

                    let mut decryptor = PullState::init_pull(&header, &key)
                        .expect("Failed to initialize pull state");

                    let encrypted_chunk_size = xchacha20poly1305::ABYTES + chunk_size;

                    loop {
                        while encrypted_chunk_size <= buffer.len() {
                            trace!("decoding a whole chunk");
                            yield pull(&mut decryptor, buffer.split_to(encrypted_chunk_size));
                        }

                        match input.try_next().await? {
                            Some(bytes) => buffer.extend_from_slice(&bytes),
                            None => break,
                        }
                    }

                    // The stream is over: what is left is the last, shorter
                    // chunk. It is absent when the object stopped on a chunk
                    // boundary.
                    if !buffer.is_empty() {
                        trace!("inner stream over, decrypting whats left");
                        yield pull(&mut decryptor, buffer.split());
                    }
                }
            }
        }
    }
}

fn pull(decryptor: &mut PullState, encrypted_chunk: BytesMut) -> Bytes {
    decryptor
        .pull(&encrypted_chunk, None)
        .expect("Unable to decrypt chunk")
        .0
        .into()
}
