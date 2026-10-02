use ctaes_rs::{Error, Padding, Pkcs7, ZeroPadding};

fn check_zero_block_size<P: Padding>() {
    for &length in &[0, 1, 16, usize::MAX] {
        assert!(matches!(P::padded_buffer_length(length, 0), Err(Error::InvalidBlockSize)));
        let mut buffer = [0xa5; 32];
        assert!(matches!(P::pad(&mut buffer, length, 0), Err(Error::InvalidBlockSize)));
        assert_eq!(buffer, [0xa5; 32]);
    }
}

#[test]
fn zero_block_size_returns_errors() {
    check_zero_block_size::<ZeroPadding>();
    check_zero_block_size::<Pkcs7>();
}

#[test]
fn pkcs7_rejects_unrepresentable_block_sizes() {
    for &size in &[256, usize::MAX] {
        assert!(matches!(Pkcs7::padded_buffer_length(0, size), Err(Error::InvalidBlockSize)));
        let mut buffer = [0xa5; 512];
        assert!(matches!(Pkcs7::pad(&mut buffer, 0, size), Err(Error::InvalidBlockSize)));
        assert_eq!(buffer, [0xa5; 512]);
    }
}

fn check_overflow<P: Padding>() {
    assert!(matches!(P::padded_buffer_length(usize::MAX, 16), Err(Error::PaddedLengthOverflow)));
    let mut buffer = [0xa5; 16];
    assert!(matches!(P::pad(&mut buffer, usize::MAX, 16), Err(Error::PaddedLengthOverflow)));
    assert_eq!(buffer, [0xa5; 16]);
}

#[test]
fn padded_length_overflow_returns_errors() {
    check_overflow::<ZeroPadding>();
    check_overflow::<Pkcs7>();
    // Zero padding need not grow an already aligned buffer.
    assert_eq!(ZeroPadding::padded_buffer_length(usize::MAX, 1).unwrap(), usize::MAX);
    assert!(matches!(Pkcs7::padded_buffer_length(usize::MAX, 1), Err(Error::PaddedLengthOverflow)));
}

#[test]
fn valid_lengths_keep_padding_semantics() {
    for size in 1..=255 {
        for length in 0..=2 * size {
            let zero = ZeroPadding::padded_buffer_length(length, size).unwrap();
            let pkcs7 = Pkcs7::padded_buffer_length(length, size).unwrap();
            assert_eq!(zero % size, 0);
            assert!(zero >= length && zero - length < size);
            assert_eq!(pkcs7 % size, 0);
            assert!(pkcs7 > length && pkcs7 - length <= size);
        }
    }
    assert_eq!(ZeroPadding::padded_buffer_length(1, usize::MAX).unwrap(), usize::MAX);
}
