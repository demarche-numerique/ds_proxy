use super::decipher_type::DecipherType;
use super::header;
use actix_web::web::{Bytes, BytesMut};
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::future::Future;
use futures::stream::Stream;
use log::{error, trace};
use std::convert::TryInto;
use std::fmt::Debug;

pub struct HeaderDecoder<'a, E> {
    inner: Option<&'a mut Box<dyn Stream<Item = Result<Bytes, E>> + Unpin>>,
    buffer: BytesMut,
}

impl<E> HeaderDecoder<'_, E> {
    pub fn new(s: &mut Box<dyn Stream<Item = Result<Bytes, E>> + Unpin>) -> HeaderDecoder<'_, E> {
        HeaderDecoder {
            inner: Some(s),
            buffer: BytesMut::new(),
        }
    }

    pub fn parse_header(&mut self) -> ParseHeaderResponse {
        if self.buffer.len() < header::HEADER_SIZE {
            return ParseHeaderResponse::MissingBytes;
        }

        if &self.buffer[..header::PREFIX_SIZE] != header::PREFIX {
            return ParseHeaderResponse::DecipherType(DecipherType::Plaintext);
        }

        let version = usize::from_le_bytes(
            self.buffer[header::PREFIX_SIZE..header::PREFIX_SIZE + header::VERSION_NB_SIZE]
                .try_into()
                .unwrap(),
        );

        let chunk_size = usize::from_le_bytes(
            self.buffer[header::PREFIX_SIZE + header::VERSION_NB_SIZE..header::HEADER_SIZE]
                .try_into()
                .unwrap(),
        );

        if version == 1 {
            let _ = self.buffer.split_to(header::HEADER_SIZE);
            trace!(
                "header version: {:?}, chunk_size: {:?}, key_id: {:?}",
                version, chunk_size, 0
            );
            return ParseHeaderResponse::DecipherType(DecipherType::Encrypted {
                chunk_size,
                key_id: 0,
                header_size: header::HEADER_SIZE,
            });
        } else if self.buffer.len() < header::HEADER_V2_SIZE {
            return ParseHeaderResponse::MissingBytes;
        }

        let key_id = u64::from_le_bytes(
            self.buffer[header::HEADER_SIZE..header::HEADER_V2_SIZE]
                .try_into()
                .unwrap(),
        );

        trace!(
            "header version: {:?}, chunk_size: {:?}, key_id: {:?}",
            version, chunk_size, key_id
        );

        let _ = self.buffer.split_to(header::HEADER_V2_SIZE);
        ParseHeaderResponse::DecipherType(DecipherType::Encrypted {
            chunk_size,
            key_id,
            header_size: header::HEADER_V2_SIZE,
        })
    }
}

impl<E> Future for HeaderDecoder<'_, E>
where
    E: Debug,
{
    type Output = (DecipherType, Option<BytesMut>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let decoder = self.get_mut();

        match Pin::new((decoder.inner.as_mut()).unwrap()).poll_next(cx) {
            Poll::Pending => {
                trace!("poll: not ready");
                Poll::Pending
            }
            Poll::Ready(None) => {
                trace!("poll: over");
                Poll::Ready((DecipherType::Plaintext, Some(decoder.buffer.clone())))
            }
            Poll::Ready(Some(Err(e))) => {
                error!("poll: error {:?}", e);
                Poll::Ready((DecipherType::Plaintext, None))
            }
            Poll::Ready(Some(Ok(bytes))) => {
                trace!("poll: bytes, + {:?}", bytes.len());
                decoder.buffer.extend(bytes);

                match decoder.parse_header() {
                    ParseHeaderResponse::MissingBytes => {
                        trace!("not enough byte to decide decypher type");
                        Pin::new(decoder).poll(cx)
                    }
                    ParseHeaderResponse::DecipherType(d) => {
                        Poll::Ready((d, Some(decoder.buffer.clone())))
                    }
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseHeaderResponse {
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
        let mut decoder = build_decoder(&empty);

        assert_eq!(ParseHeaderResponse::MissingBytes, decoder.parse_header());
        assert_eq!(empty, decoder.buffer[..]);

        let plain_text = [0u8; header::HEADER_SIZE];
        let mut decoder = build_decoder(&plain_text);

        assert_eq!(
            ParseHeaderResponse::DecipherType(DecipherType::Plaintext),
            decoder.parse_header()
        );
        assert_eq!(plain_text, decoder.buffer[..]);

        let v1_header: Vec<u8> = [
            header::PREFIX,
            &1_usize.to_le_bytes(),
            &10_usize.to_le_bytes(),
        ]
        .concat();
        let mut decoder = build_decoder(&v1_header);

        assert_eq!(
            ParseHeaderResponse::DecipherType(DecipherType::Encrypted {
                chunk_size: 10,
                key_id: 0,
                header_size: header::HEADER_SIZE
            }),
            decoder.parse_header()
        );
        assert_eq!(empty, decoder.buffer[..]);

        let header_bytes_2: Vec<u8> = Header::new(13, 15).into();
        let mut decoder = build_decoder(&header_bytes_2);
        assert_eq!(
            ParseHeaderResponse::DecipherType(DecipherType::Encrypted {
                chunk_size: 13,
                key_id: 15,
                header_size: header::HEADER_V2_SIZE
            }),
            decoder.parse_header()
        );
        assert_eq!(empty, decoder.buffer[..]);
    }

    fn build_decoder(slice: &[u8]) -> HeaderDecoder<'_, String> {
        HeaderDecoder {
            buffer: BytesMut::from(slice),
            inner: None,
        }
    }

    #[test]
    fn header_decoder() {
        use actix_web::Error;

        let clear: &[u8] = b"something not encrypted";

        let source: Result<Bytes, Error> = Ok(Bytes::from(clear));
        let source_stream = futures::stream::once(Box::pin(async { source }));

        let mut boxy: Box<dyn Stream<Item = Result<Bytes, _>> + Unpin> = Box::new(source_stream);

        let (cypher_type, buff) = futures::executor::block_on(HeaderDecoder::new(&mut boxy));

        assert_eq!(DecipherType::Plaintext, cypher_type);
        assert_eq!(Some(BytesMut::from(clear)), buff);
    }
}
