use actix_web::web::{Buf, Bytes};
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::stream::Stream;
use log::trace;

pub struct PartialExtractor<E> {
    inner: Box<dyn Stream<Item = Result<Bytes, E>> + Unpin>,
    start: usize,
    end: usize,
    position: usize,
}

impl<E> PartialExtractor<E> {
    pub fn new(
        s: Box<dyn Stream<Item = Result<Bytes, E>> + Unpin>,
        start: usize,
        end: usize,
    ) -> PartialExtractor<E> {
        PartialExtractor {
            inner: s,
            start,
            end,
            position: 0,
        }
    }
}

impl<E> Stream for PartialExtractor<E> {
    type Item = Result<Bytes, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let extractor = self.get_mut();

        match Pin::new(extractor.inner.as_mut()).poll_next(cx) {
            Poll::Ready(Some(Ok(mut bytes))) => {
                let bytes_len = bytes.len();

                trace!(
                    "start {:?}, end {:?}, position {:?}",
                    extractor.start, extractor.end, extractor.position
                );

                if extractor.position + bytes_len < extractor.start {
                    extractor.position += bytes_len;
                    return Pin::new(extractor).poll_next(cx);
                }

                if extractor.end < extractor.position {
                    return Poll::Ready(None);
                }

                bytes.truncate(extractor.end - extractor.position + 1);

                if extractor.position < extractor.start {
                    bytes.advance(extractor.start - extractor.position);
                }

                extractor.position += bytes_len;
                Poll::Ready(Some(Ok(bytes)))
            }
            p => p,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        Error,
        web::{BufMut, BytesMut},
    };
    use futures::executor::block_on_stream;
    use futures::stream::{self, Iter};
    use std::vec::IntoIter;
    use stream::iter;

    #[test]
    fn extract_with_borne() {
        let t: Vec<&[u8]> = vec![b"0", b"12", b"3", b"45", b"6"];
        let start = 1;
        let end = 5;
        let expected = Bytes::from_static(b"12345");

        let s = make_stream(t);
        let pe = PartialExtractor::new(s, start, end);
        let result = extract(pe);

        assert_eq!(expected, result);
    }

    #[test]
    fn extract_n_without_borne() {
        let t: Vec<&[u8]> = vec![b"0", b"12", b"3", b"45", b"6"];
        let start = 2;
        let end = 4;
        let expected = Bytes::from_static(b"234");

        let s = make_stream(t);
        let pe = PartialExtractor::new(s, start, end);
        let result = extract(pe);

        assert_eq!(expected, result);
    }

    #[test]
    fn extract_from_1_chunk() {
        let t: Vec<&[u8]> = vec![b"012345"];
        let start = 1;
        let end = 4;
        let expected = Bytes::from_static(b"1234");

        let s = make_stream(t);
        let pe = PartialExtractor::new(s, start, end);
        let result = extract(pe);

        assert_eq!(expected, result);
    }

    fn make_stream(v: Vec<&[u8]>) -> Box<Iter<IntoIter<Result<Bytes, Error>>>> {
        let t = v
            .iter()
            .map(|b| Ok(Bytes::copy_from_slice(b)))
            .collect::<Vec<Result<Bytes, Error>>>();

        Box::new(iter(t))
    }

    fn extract(pe: PartialExtractor<Error>) -> BytesMut {
        block_on_stream(pe)
            .map(|r| r.unwrap())
            .fold(BytesMut::with_capacity(64), |mut acc, x| {
                acc.put(x);
                acc
            })
    }
}
