use super::header::Header;
use actix_web::web::{Bytes, BytesMut};
use async_stream::try_stream;
use futures::TryStreamExt;
use futures::stream::Stream;
use libsodium_rs::crypto_secretstream::{Key, PushState, xchacha20poly1305::TAG_MESSAGE};
use log::trace;
use std::pin::pin;

pub fn encode<E>(
    key: Key,
    key_id: u64,
    chunk_size: usize,
    input: impl Stream<Item = Result<Bytes, E>>,
) -> impl Stream<Item = Result<Bytes, E>> {
    try_stream! {
        let mut input = pin!(input);
        let mut buffer = BytesMut::with_capacity(chunk_size);
        let mut encryptor: Option<PushState> = None;

        while let Some(bytes) = input.try_next().await? {
            buffer.extend_from_slice(&bytes);

            if encryptor.is_none() && !buffer.is_empty() {
                trace!("writing the headers");

                let (state, encryption_header) =
                    PushState::init_push(&key).expect("Failed to initialize push state");
                encryptor = Some(state);

                let ds_header: Vec<u8> = Header::new(chunk_size, key_id).into();
                yield Bytes::from([&ds_header[..], encryption_header.as_ref()].concat());
            }

            while chunk_size <= buffer.len() {
                trace!("encoding a whole chunk");
                yield push(encryptor.as_mut().unwrap(), buffer.split_to(chunk_size));
            }
        }

        if let Some(state) = encryptor.as_mut()
            && !buffer.is_empty()
        {
            trace!("the stream is closed, encoding whats left");
            yield push(state, buffer.split());
        }
    }
}

fn push(encryptor: &mut PushState, clear_chunk: BytesMut) -> Bytes {
    encryptor
        .push(&clear_chunk, None, TAG_MESSAGE)
        .expect("Unable to encrypt chunk")
        .into()
}
