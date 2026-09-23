use super::config::*;
use super::crypto::*;
use actix_web::web::Bytes;
use futures::executor::block_on;
use futures::future::ready;
use futures::stream::{Stream, TryStreamExt};
use std::fs::File;
use std::io::{self, Read, Write};

pub fn encrypt(config: EncryptConfig) {
    let (key_id, key) = config
        .keyring
        .get_last_key()
        .expect("no key avalaible for encryption");

    let input = read_in_blocks(File::open(config.input_file).unwrap());
    let mut output = File::create(config.output_file).unwrap();

    block_on(
        encode(key, key_id, DEFAULT_CHUNK_SIZE, input)
            .try_for_each(|chunk| ready(output.write_all(&chunk))),
    )
    .unwrap();
}

pub fn decrypt(config: DecryptConfig) {
    let mut input = read_in_blocks(File::open(config.input_file).unwrap());

    let (cypher_type, buff) = block_on(read_ds_header(&mut input));

    let mut output = File::create(config.output_file).unwrap();

    block_on(
        decode(config.keyring.clone(), input, cypher_type, buff)
            .try_for_each(|chunk| ready(output.write_all(&chunk))),
    )
    .unwrap();
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
