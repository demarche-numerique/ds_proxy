use super::super::keyring::Keyring;
use super::decipher_type::DecipherType;
use actix_web::web::{Bytes, BytesMut};
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_core::stream::Stream;
use libsodium_rs::crypto_secretstream::{xchacha20poly1305, Key, PullState};
use log::{error, trace};
use std::convert::TryInto;

pub struct Decoder<E> {
    inner: Box<dyn Stream<Item = Result<Bytes, E>> + Unpin>,
    inner_ended: bool,
    decipher_type: DecipherType,
    stream_decoder: Option<PullState>,
    buffer: BytesMut,
    keyring: Keyring,
}

impl<E> Decoder<E> {
    pub fn new_from_cypher_and_buffer(
        keyring: Keyring,
        s: Box<dyn Stream<Item = Result<Bytes, E>> + Unpin>,
        decipher_type: DecipherType,
        b: Option<BytesMut>,
    ) -> Decoder<E> {
        Decoder {
            inner: s,
            inner_ended: false,
            decipher_type,
            stream_decoder: None,
            buffer: b.unwrap_or_default(),
            keyring,
        }
    }

    fn decrypt_buffer(&mut self, cx: &mut Context) -> Poll<Option<Result<Bytes, E>>> {
        if self.inner_ended && self.buffer.is_empty() {
            trace!("buffer empty and stream ended, stop");
            Poll::Ready(None)
        } else {
            match self.decipher_type {
                DecipherType::Encrypted {
                    chunk_size, key_id, ..
                } => {
                    if let Some(key) = self.keyring.get_key_by_id(&key_id) {
                        self.decrypt(cx, &chunk_size, key)
                    } else {
                        panic!("Key {} not found !", key_id)
                    }
                }

                DecipherType::Plaintext => Poll::Ready(Some(Ok(self.buffer.split().freeze()))),
            }
        }
    }

    fn decrypt(
        &mut self,
        cx: &mut Context,
        chunk_size: &usize,
        key: Key,
    ) -> Poll<Option<Result<Bytes, E>>> {
        match self.stream_decoder {
            None => {
                trace!("no stream_decoder");

                if xchacha20poly1305::HEADERBYTES <= self.buffer.len() {
                    trace!("decrypting the header");

                    let header_array: [u8; xchacha20poly1305::HEADERBYTES] = self
                        .buffer
                        .split_to(xchacha20poly1305::HEADERBYTES)
                        .as_ref()
                        .try_into()
                        .expect("slice with incorrect length");

                    let pull_state = PullState::init_pull(&header_array, &key)
                        .expect("Failed to initialize pull state");

                    self.stream_decoder = Some(pull_state);

                    self.decrypt_buffer(cx)
                } else {
                    trace!("not enough data to decrypt the header");
                    if self.inner_ended {
                        // TODO: throw error
                        Poll::Ready(None)
                    } else {
                        // waiting for more data
                        Pin::new(self).poll_next(cx)
                    }
                }
            }

            Some(ref mut stream) => {
                trace!("stream_decoder present !");
                trace!("self.buffer.len() : {:?}", self.buffer.len());

                let mut chunks = self
                    .buffer
                    .chunks_exact(xchacha20poly1305::ABYTES + chunk_size);

                let decrypted: Bytes = chunks
                    .by_ref()
                    .flat_map(|encrypted_chunk| {
                        stream
                            .pull(encrypted_chunk, None)
                            .expect("Unable to decrypt chunk")
                            .0
                    })
                    .collect();

                self.buffer = chunks.remainder().into();

                if !decrypted.is_empty() {
                    Poll::Ready(Some(Ok(decrypted)))
                } else if self.inner_ended {
                    trace!("inner stream over, decrypting whats left");

                    let decrypted = stream
                        .pull(&self.buffer.split(), None)
                        .expect("Unable to decrypt last chunk")
                        .0;

                    Poll::Ready(Some(Ok(decrypted.into())))
                } else {
                    trace!("waiting for more data");

                    Pin::new(self).poll_next(cx)
                }
            }
        }
    }
}

impl<E> Stream for Decoder<E> {
    type Item = Result<Bytes, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let decoder = self.get_mut();

        match Pin::new(decoder.inner.as_mut()).poll_next(cx) {
            Poll::Pending => {
                trace!("poll: not ready");
                Poll::Pending
            }
            Poll::Ready(Some(Ok(bytes))) => {
                trace!("poll: bytes, + {:?}", bytes.len());
                decoder.buffer.extend(bytes);
                decoder.decrypt_buffer(cx)
            }
            Poll::Ready(None) => {
                trace!("poll: over");
                decoder.inner_ended = true;
                decoder.decrypt_buffer(cx)
            }
            Poll::Ready(Some(Err(e))) => {
                error!("poll: error");
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}
