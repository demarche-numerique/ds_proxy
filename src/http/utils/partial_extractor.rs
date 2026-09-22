use actix_web::web::{Buf, Bytes};
use async_stream::try_stream;
use futures::TryStreamExt;
use futures::stream::Stream;
use log::trace;
use std::pin::pin;

pub fn extract_range<E>(
    input: impl Stream<Item = Result<Bytes, E>>,
    start: usize,
    end: usize,
) -> impl Stream<Item = Result<Bytes, E>> {
    try_stream! {
        let mut input = pin!(input);
        let mut position = 0;

        while let Some(mut bytes) = input.try_next().await? {
            trace!("start {:?}, end {:?}, position {:?}", start, end, position);

            let next_position = position + bytes.len();

            if start < next_position {
                bytes.truncate(end + 1 - position);
                bytes.advance(start.saturating_sub(position));
                yield bytes;
            }

            if end < next_position {
                break;
            }

            position = next_position;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::Error;
    use actix_web::body::{BodyStream, to_bytes};
    use futures::executor::block_on;
    use futures::stream::iter;

    #[test]
    fn extract_with_borne() {
        let t: Vec<&[u8]> = vec![b"0", b"12", b"3", b"45", b"6"];
        let start = 1;
        let end = 5;
        let expected = Bytes::from_static(b"12345");

        let s = make_stream(t);
        let pe = extract_range(s, start, end);
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
        let pe = extract_range(s, start, end);
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
        let pe = extract_range(s, start, end);
        let result = extract(pe);

        assert_eq!(expected, result);
    }

    #[test]
    fn extracts_the_same_bytes_as_a_slice() {
        use proptest::prelude::*;

        proptest!(|(data in proptest::collection::vec(any::<u8>(), 1..300), piece_size in 1usize..50, a: usize, b: usize)| {
            let start = a % data.len();
            let end = start + b % (data.len() - start);

            let pieces: Vec<&[u8]> = data.chunks(piece_size).collect();
            let pe = extract_range(make_stream(pieces), start, end);

            prop_assert_eq!(&data[start..=end], &extract(pe)[..]);
        });
    }

    fn make_stream(v: Vec<&[u8]>) -> impl Stream<Item = Result<Bytes, Error>> {
        let items: Vec<Result<Bytes, Error>> =
            v.iter().map(|b| Ok(Bytes::copy_from_slice(b))).collect();

        iter(items)
    }

    fn extract(pe: impl Stream<Item = Result<Bytes, Error>>) -> Bytes {
        block_on(to_bytes(BodyStream::new(pe))).unwrap()
    }
}
