use super::decipher_type::DecipherType;
use super::header;
use actix_web::web::{Bytes, BytesMut};
use futures::stream::{Stream, StreamExt};
use log::{error, trace};
use std::fmt::Debug;

/// Reads just enough of `input` to tell whether it is a ds file and, if so,
/// how it was encrypted. The ds header is consumed; the bytes read past it
/// are handed back so that the caller can go on decoding without losing them.
pub async fn read_ds_header<S, E>(input: &mut S) -> (DecipherType, BytesMut)
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Debug,
{
    let mut buffer = BytesMut::new();

    while let Some(item) = input.next().await {
        match item {
            Err(e) => {
                error!("poll: error {:?}", e);
                return (DecipherType::Plaintext, BytesMut::new());
            }
            Ok(bytes) => {
                trace!("poll: bytes, + {:?}", bytes.len());
                buffer.extend(bytes);

                if let ParseHeaderResponse::DecipherType(d) = parse_header(&mut buffer) {
                    return (d, buffer);
                }

                trace!("not enough byte to decide decypher type");
            }
        }
    }

    trace!("poll: over");
    (DecipherType::Plaintext, buffer)
}

/// Consumes the ds header from `buffer` and describes what follows it. A
/// buffer that does not start with the ds prefix is left untouched and read
/// as plaintext.
fn parse_header(buffer: &mut BytesMut) -> ParseHeaderResponse {
    if buffer.len() < header::HEADER_SIZE {
        return ParseHeaderResponse::MissingBytes;
    }

    if &buffer[..header::PREFIX_SIZE] != header::PREFIX {
        return ParseHeaderResponse::DecipherType(DecipherType::Plaintext);
    }

    let version = usize::from_le_bytes(
        buffer[header::PREFIX_SIZE..header::PREFIX_SIZE + header::VERSION_NB_SIZE]
            .try_into()
            .unwrap(),
    );

    let chunk_size = usize::from_le_bytes(
        buffer[header::PREFIX_SIZE + header::VERSION_NB_SIZE..header::HEADER_SIZE]
            .try_into()
            .unwrap(),
    );

    if version == 1 {
        let _ = buffer.split_to(header::HEADER_SIZE);
        trace!(
            "header version: {:?}, chunk_size: {:?}, key_id: {:?}",
            version, chunk_size, 0
        );
        return ParseHeaderResponse::DecipherType(DecipherType::Encrypted {
            chunk_size,
            key_id: 0,
            header_size: header::HEADER_SIZE,
        });
    } else if buffer.len() < header::HEADER_V2_SIZE {
        return ParseHeaderResponse::MissingBytes;
    }

    let key_id = u64::from_le_bytes(
        buffer[header::HEADER_SIZE..header::HEADER_V2_SIZE]
            .try_into()
            .unwrap(),
    );

    trace!(
        "header version: {:?}, chunk_size: {:?}, key_id: {:?}",
        version, chunk_size, key_id
    );

    let _ = buffer.split_to(header::HEADER_V2_SIZE);
    ParseHeaderResponse::DecipherType(DecipherType::Encrypted {
        chunk_size,
        key_id,
        header_size: header::HEADER_V2_SIZE,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ParseHeaderResponse {
    DecipherType(DecipherType),
    MissingBytes,
}

#[cfg(test)]
mod tests {
    use header::Header;

    use super::*;

    #[test]
    fn test_parse_header() {
        let empty: [u8; 0] = [];
        let mut buffer = BytesMut::from(&empty[..]);

        assert_eq!(ParseHeaderResponse::MissingBytes, parse_header(&mut buffer));
        assert_eq!(empty, buffer[..]);

        let plain_text = [0u8; header::HEADER_SIZE];
        let mut buffer = BytesMut::from(&plain_text[..]);

        assert_eq!(
            ParseHeaderResponse::DecipherType(DecipherType::Plaintext),
            parse_header(&mut buffer)
        );
        assert_eq!(plain_text, buffer[..]);

        let v1_header: Vec<u8> = [
            header::PREFIX,
            &1_usize.to_le_bytes(),
            &10_usize.to_le_bytes(),
        ]
        .concat();
        let mut buffer = BytesMut::from(&v1_header[..]);

        assert_eq!(
            ParseHeaderResponse::DecipherType(DecipherType::Encrypted {
                chunk_size: 10,
                key_id: 0,
                header_size: header::HEADER_SIZE
            }),
            parse_header(&mut buffer)
        );
        assert_eq!(empty, buffer[..]);

        let header_bytes_2: Vec<u8> = Header::new(13, 15).into();
        let mut buffer = BytesMut::from(&header_bytes_2[..]);
        assert_eq!(
            ParseHeaderResponse::DecipherType(DecipherType::Encrypted {
                chunk_size: 13,
                key_id: 15,
                header_size: header::HEADER_V2_SIZE
            }),
            parse_header(&mut buffer)
        );
        assert_eq!(empty, buffer[..]);
    }

    #[test]
    fn plaintext_stream_is_read_as_plaintext() {
        use actix_web::Error;

        let clear: &[u8] = b"something not encrypted";

        let source: Result<Bytes, Error> = Ok(Bytes::from(clear));
        let mut source_stream = futures::stream::once(Box::pin(async { source }));

        let (cypher_type, buff) = futures::executor::block_on(read_ds_header(&mut source_stream));

        assert_eq!(DecipherType::Plaintext, cypher_type);
        assert_eq!(BytesMut::from(clear), buff);
    }
}
