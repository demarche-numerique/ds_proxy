mod decipher_type;
mod decoder;
mod encoder;
pub mod header;
mod header_decoder;

pub use self::decoder::Decoder;
pub use self::encoder::Encoder;
pub use self::header::Header;
pub use self::header_decoder::HeaderDecoder;

use decipher_type::DecipherType;
use header::*;
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{ABYTES, HEADERBYTES};

pub fn encrypted_content_length(clear_length: usize, chunk_size: usize) -> usize {
    if clear_length == 0 {
        return 0;
    }

    let nb_chunk = clear_length / chunk_size;
    let remainder = clear_length % chunk_size;

    if remainder == 0 {
        HEADER_V2_SIZE + HEADERBYTES + nb_chunk * (ABYTES + chunk_size)
    } else {
        HEADER_V2_SIZE + HEADERBYTES + nb_chunk * (ABYTES + chunk_size) + ABYTES + remainder
    }
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
            // encrypted = header_ds + header_crypto + n ( abytes + chunk ) + a (abytes + remainder)
            // with remainder < chunk and a = 0 if remainder = 0, a = 1 otherwise
            //
            //  encrypted - header_ds - header_crypto = n ( abytes + chunk ) + a (abytes + remainder)
            //
            //  integer_part ((encrypted - header_ds - header_crypto) / ( abytes + chunk ))
            //    = integer_part ( n + a (abytes + remainder) / (abytes + chunk) )
            //    = n

            let nb_chunk = (encrypted_length - header_size - HEADERBYTES) / (ABYTES + chunk_size);
            let remainder_exists =
                !(encrypted_length - header_size - HEADERBYTES).is_multiple_of(ABYTES + chunk_size);

            if remainder_exists {
                encrypted_length - header_size - HEADERBYTES - (nb_chunk + 1) * ABYTES
            } else {
                encrypted_length - header_size - HEADERBYTES - nb_chunk * ABYTES
            }
        }

        DecipherType::Plaintext => encrypted_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
