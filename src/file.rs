use super::config::*;
use super::crypto::*;
use actix_web::web::Bytes;
use futures::executor::block_on;
use futures::executor::block_on_stream;
use futures::stream::Stream;
use std::fs::File;
use std::io::{self, Read, Write};

pub fn encrypt(config: EncryptConfig) {
    let (key_id, key) = config
        .keyring
        .get_last_key()
        .expect("no key avalaible for encryption");

    let input = read_in_blocks(File::open(config.input_file).unwrap());
    let encoder = Encoder::new(key, key_id, DEFAULT_CHUNK_SIZE, Box::new(input), None);

    let mut output = File::create(config.output_file).unwrap();
    for chunk in block_on_stream(encoder) {
        output.write_all(&chunk.unwrap()).unwrap();
    }
}

pub fn decrypt(config: DecryptConfig) {
    let mut boxy: Box<dyn Stream<Item = io::Result<Bytes>> + Unpin> =
        Box::new(read_in_blocks(File::open(config.input_file).unwrap()));

    let header_decoder = HeaderDecoder::new(&mut boxy);
    let (cypher_type, buff) = block_on(header_decoder);

    let decoder =
        Decoder::new_from_cypher_and_buffer(config.keyring.clone(), boxy, cypher_type, buff);

    let mut output = File::create(config.output_file).unwrap();
    for chunk in block_on_stream(decoder) {
        output.write_all(&chunk.unwrap()).unwrap();
    }
}

fn read_in_blocks(mut file: File) -> impl Stream<Item = io::Result<Bytes>> + Unpin {
    futures::stream::iter(std::iter::from_fn(move || {
        let mut block = vec![0; DEFAULT_CHUNK_SIZE];
        match file.read(&mut block) {
            Ok(0) => None,
            Ok(n) => {
                block.truncate(n);
                Some(Ok(Bytes::from(block)))
            }
            Err(e) => Some(Err(e)),
        }
    }))
}
