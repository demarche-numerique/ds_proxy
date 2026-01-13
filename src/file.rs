use super::config::*;
use super::crypto::*;
use actix_web::web::{BufMut, Bytes, BytesMut};
use actix_web::Error;
use futures::executor::block_on;
use futures::executor::block_on_stream;

pub fn encrypt(config: EncryptConfig) {
    let input: Vec<u8> = std::fs::read(config.input_file).unwrap();

    let source: Result<Bytes, Error> = Ok(Bytes::from(input));
    let source_stream = futures::stream::once(Box::pin(async { source }));

    let (key_id, key) = config
        .keyring
        .get_last_key()
        .expect("no key avalaible for encryption");

    let encoder = Encoder::new(
        key,
        key_id,
        config.chunk_size,
        Box::new(source_stream),
        None,
    );

    let buf = block_on_stream(encoder).map(|r| r.unwrap()).fold(
        BytesMut::with_capacity(64),
        |mut acc, x| {
            acc.put(x);
            acc
        },
    );

    std::fs::write(config.output_file, &buf[..]).unwrap();
}

pub fn decrypt(config: DecryptConfig) {
    let input: Vec<u8> = std::fs::read(config.input_file).unwrap();

    let source: Result<Bytes, Error> = Ok(Bytes::from(input));
    let source_stream = futures::stream::once(Box::pin(async { source }));
    let mut boxy: Box<dyn futures::Stream<Item = Result<Bytes, _>> + Unpin> =
        Box::new(source_stream);

    let header_decoder = HeaderDecoder::new(&mut boxy);
    let (cypher_type, buff) = block_on(header_decoder);

    let decoder =
        Decoder::new_from_cypher_and_buffer(config.keyring.clone(), boxy, cypher_type, buff);

    let buf = block_on_stream(decoder).map(|r| r.unwrap()).fold(
        BytesMut::with_capacity(64),
        |mut acc, x| {
            acc.put(x);
            acc
        },
    );

    std::fs::write(config.output_file, &buf[..]).unwrap();
}
