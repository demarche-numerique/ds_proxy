mod decipher_type;
mod decoder;
mod encoder;
pub mod header;
mod header_decoder;

pub use self::decoder::decode;
pub use self::encoder::encode;
pub use self::header::Header;
pub use self::header_decoder::read_ds_header;

use actix_web::Error;
use actix_web::body::{BodyStream, EitherBody, MessageBody, SizedStream};
use actix_web::web::Bytes;
use decipher_type::DecipherType;
use futures::stream::Stream;
use header::*;
use libsodium_rs::crypto_secretstream::Key;
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{ABYTES, HEADERBYTES};

pub fn encrypted_body(
    key: Key,
    key_id: u64,
    chunk_size: usize,
    clear_length: Option<usize>,
    input: impl Stream<Item = Result<Bytes, Error>> + 'static,
) -> impl MessageBody {
    let encrypted = encode(key, key_id, chunk_size, input);

    match clear_length {
        Some(length) => EitherBody::left(SizedStream::new(
            encrypted_content_length(length, chunk_size) as u64,
            encrypted,
        )),
        None => EitherBody::right(BodyStream::new(encrypted)),
    }
}

pub fn encrypted_content_length(clear_length: usize, chunk_size: usize) -> usize {
    if clear_length == 0 {
        return 0;
    }

    // Every chunk, including the last partial one, carries its own ABYTES tag.
    HEADER_V2_SIZE + HEADERBYTES + clear_length + ABYTES * clear_length.div_ceil(chunk_size)
}

pub fn decrypted_content_length(encrypted_length: usize, decipher: DecipherType) -> usize {
    if encrypted_length == 0 {
        return 0;
    }

    match decipher {
        DecipherType::Encrypted {
            chunk_size,
            header_size,
            ..
        } => {
            // The inverse of encrypted_content_length: a body of n full chunks
            // plus an optional remainder holds exactly div_ceil tags, since a
            // remainder is shorter than a full chunk.
            let body = encrypted_length - header_size - HEADERBYTES;
            body - ABYTES * body.div_ceil(ABYTES + chunk_size)
        }

        DecipherType::Plaintext => encrypted_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn decrypted_content_length_inverts_encrypted_content_length() {
        proptest!(|(clear_length in 0usize..100_000, chunk_size in 1usize..10_000)| {
            let encrypted_length = encrypted_content_length(clear_length, chunk_size);

            prop_assert_eq!(
                clear_length,
                decrypted_content_length(
                    encrypted_length,
                    DecipherType::Encrypted {
                        chunk_size,
                        key_id: 0,
                        header_size: HEADER_V2_SIZE,
                    },
                )
            );
        });
    }

    #[test]
    fn test_decrypt_content_length_from_0() {
        let original_length = 0;
        let chunk_size = 16;
        let encrypted_length = 0;

        let decrypted_length = decrypted_content_length(
            encrypted_length,
            DecipherType::Encrypted {
                chunk_size,
                key_id: 0,
                header_size: header::HEADER_SIZE,
            },
        );

        assert_eq!(original_length, decrypted_length);
    }

    #[test]
    fn test_decrypt_content_length_without_remainder() {
        let original_length = 32;
        let chunk_size = 16;
        let nb_chunk = 32 / 16;
        let encrypted_length = HEADER_SIZE + HEADERBYTES + nb_chunk * (ABYTES + chunk_size);

        let decrypted_length = decrypted_content_length(
            encrypted_length,
            DecipherType::Encrypted {
                chunk_size,
                key_id: 0,
                header_size: header::HEADER_SIZE,
            },
        );

        assert_eq!(original_length, decrypted_length);
    }

    #[test]
    fn test_decrypt_content_length_with_remainder() {
        let original_length = 33;
        let chunk_size = 16;
        let nb_chunk = 32 / 16;
        let encrypted_length =
            HEADER_SIZE + HEADERBYTES + nb_chunk * (ABYTES + chunk_size) + (ABYTES + 1);

        let decrypted_length = decrypted_content_length(
            encrypted_length,
            DecipherType::Encrypted {
                chunk_size,
                key_id: 0,
                header_size: header::HEADER_SIZE,
            },
        );

        assert_eq!(original_length, decrypted_length);
    }

    #[test]
    fn test_decrypt_content_length_with_another_exemple() {
        let original_length = 5882;
        let encrypted_length = 6345;

        let decrypted_length = decrypted_content_length(
            encrypted_length,
            DecipherType::Encrypted {
                chunk_size: 256,
                key_id: 0,
                header_size: header::HEADER_SIZE,
            },
        );

        assert_eq!(original_length, decrypted_length);
    }

    #[test]
    fn test_encrypted_content_length_from_0() {
        let original_length = 0;
        let chunk_size = 16;
        let encrypted_length = 0;

        assert_eq!(
            encrypted_length,
            encrypted_content_length(original_length, chunk_size)
        );
    }

    #[test]
    fn test_encrypted_content_length_without_remainder() {
        let original_length = 32;
        let chunk_size = 16;
        let nb_chunk = 32 / 16;
        let encrypted_length = HEADER_V2_SIZE + HEADERBYTES + nb_chunk * (ABYTES + chunk_size);

        assert_eq!(
            encrypted_length,
            encrypted_content_length(original_length, chunk_size)
        );
    }

    #[test]
    fn test_encrypted_content_length_with_remainder() {
        let original_length = 33;
        let chunk_size = 16;
        let nb_chunk = 32 / 16;
        let encrypted_length =
            HEADER_V2_SIZE + HEADERBYTES + nb_chunk * (ABYTES + chunk_size) + (ABYTES + 1);

        assert_eq!(
            encrypted_length,
            encrypted_content_length(original_length, chunk_size)
        );
    }

    #[test]
    fn test_encrypted_content_length_with_another_exemple() {
        let original_length = 5882;
        let encrypted_length = 6353;
        let chunk_size = 256;

        assert_eq!(
            encrypted_length,
            encrypted_content_length(original_length, chunk_size)
        );
    }
}
