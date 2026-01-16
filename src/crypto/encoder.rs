use super::header::{Header, HEADER_SIZE};
use actix_web::web::{Bytes, BytesMut};
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_core::stream::Stream;
use libsodium_rs::crypto_secretstream::{xchacha20poly1305::TAG_MESSAGE, Key, PushState};
use log::trace;
use md5::digest::DynDigest;
use std::cell::RefCell;
use std::rc::Rc;

pub struct Encoder<E> {
    inner: Box<dyn Stream<Item = Result<Bytes, E>> + Unpin>,
    inner_ended: bool,
    stream_encoder: Option<PushState>,
    buffer: BytesMut,
    chunk_size: usize,
    key: Key,
    key_id: u64,
    maybe_hasher: Option<Rc<RefCell<Box<dyn DynDigest>>>>,
}

impl<E> Encoder<E> {
    pub fn new(
        key: Key,
        key_id: u64,
        chunk_size: usize,
        s: Box<dyn Stream<Item = Result<Bytes, E>> + Unpin>,
        maybe_hasher: Option<Rc<RefCell<Box<dyn DynDigest>>>>,
    ) -> Encoder<E> {
        Encoder {
            inner: s,
            inner_ended: false,
            stream_encoder: None,
            buffer: BytesMut::with_capacity(chunk_size),
            chunk_size,
            key,
            key_id,
            maybe_hasher,
        }
    }

    fn encrypt_buffer(&mut self, cx: &mut Context) -> Poll<Option<Result<Bytes, E>>> {
        if self.buffer.is_empty() {
            trace!("buffer empty, stop");
            Poll::Ready(None)
        } else {
            trace!("buffer not empty");
            match self.stream_encoder {
                None => {
                    trace!("no stream encoder");
                    let (enc_stream, encryption_header) =
                        PushState::init_push(&self.key).expect("Failed to initialize push state");

                    self.stream_encoder = Some(enc_stream);

                    let encryption_header_bytes =
                        Bytes::copy_from_slice(encryption_header.as_ref());

                    let mut buf =
                        BytesMut::with_capacity(HEADER_SIZE + encryption_header_bytes.len());

                    let ds_header = Header::new(self.chunk_size, self.key_id);
                    let ds_header_bytes: Vec<u8> = ds_header.into();
                    buf.extend(&ds_header_bytes[..]);
                    buf.extend(encryption_header_bytes);

                    Poll::Ready(Some(Ok(buf.freeze())))
                }

                Some(ref mut stream) => {
                    trace!("stream encoder present !");
                    if self.chunk_size <= self.buffer.len() {
                        let mut encoded_buff = BytesMut::with_capacity(self.buffer.len());

                        while self.chunk_size <= self.buffer.len() {
                            trace!("encoding a whole chunk");

                            let encoded_message = stream
                                .push(&self.buffer.split_to(self.chunk_size), None, TAG_MESSAGE)
                                .unwrap();

                            encoded_buff.extend_from_slice(&encoded_message);
                        }

                        Poll::Ready(Some(Ok(encoded_buff.freeze())))
                    } else {
                        trace!("the chunk is not complete");
                        if self.inner_ended {
                            trace!("the stream is closed, encoding whats left");
                            let rest = self.buffer.len();
                            let encoded = stream
                                .push(&self.buffer.split_to(rest), None, TAG_MESSAGE)
                                .unwrap();
                            Poll::Ready(Some(Ok(Bytes::from(encoded))))
                        } else {
                            trace!("waiting for more data");
                            Pin::new(self).poll_next(cx)
                        }
                    }
                }
            }
        }
    }
}

impl<E> Stream for Encoder<E> {
    type Item = Result<Bytes, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let encoder = self.get_mut();

        match Pin::new(encoder.inner.as_mut()).poll_next(cx) {
            Poll::Pending => {
                trace!("poll: not ready");
                Poll::Pending
            }
            Poll::Ready(Some(Ok(bytes))) => {
                trace!("poll: bytes");
                if let Some(ref hasher_rc) = encoder.maybe_hasher {
                    hasher_rc.borrow_mut().update(&bytes);
                }
                encoder.buffer.extend_from_slice(&bytes);
                encoder.encrypt_buffer(cx)
            }
            Poll::Ready(Some(Err(e))) => {
                trace!("poll: error");
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                trace!("poll: over");
                encoder.inner_ended = true;
                encoder.encrypt_buffer(cx)
            }
        }
    }
}
