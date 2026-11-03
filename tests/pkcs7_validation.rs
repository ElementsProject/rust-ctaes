use ctaes_rs::{Error, Padding, Pkcs7};

fn assert_invalid(result: Result<&[u8], Error>) {
    match result {
        Err(Error::UnpadError(message)) => assert_eq!(message, "Invalid PKCS7 padding"),
        other => panic!("expected uniform padding error, got {:?}", other),
    }
}

#[test]
fn aes_padding_lengths_and_corrupted_suffixes() {
    for padding in 1..=16 {
        let mut buffer = [0x42; 32];
        buffer[32 - padding..].fill(padding as u8);
        assert_eq!(Pkcs7::unpad_with_block_size(&buffer, 16).unwrap(), &buffer[..32 - padding]);
        assert_eq!(Pkcs7::unpad(&buffer).unwrap(), &buffer[..32 - padding]);

        // Corrupt each claimed padding byte except the length byte. A changed
        // length byte can describe a different, legitimately valid suffix.
        for position in 32 - padding..31 {
            for replacement in 0..=255u8 {
                if replacement == padding as u8 {
                    continue;
                }
                let mut corrupted = buffer;
                corrupted[position] = replacement;
                assert_invalid(Pkcs7::unpad_with_block_size(&corrupted, 16));
                assert_invalid(Pkcs7::unpad(&corrupted));
            }
        }
    }
}

#[test]
fn invalid_lengths_and_block_sizes() {
    assert_invalid(Pkcs7::unpad(&[]));
    assert_invalid(Pkcs7::unpad(&[0]));
    assert_invalid(Pkcs7::unpad(&[2]));
    assert_invalid(Pkcs7::unpad_with_block_size(&[], 16));
    for size in &[0, 256, usize::MAX] {
        assert_invalid(Pkcs7::unpad_with_block_size(&[16; 16], *size));
    }
    for length in 1..32 {
        if length % 16 != 0 {
            assert_invalid(Pkcs7::unpad_with_block_size(&vec![1; length], 16));
        }
    }
    for last in 0..=255u8 {
        if last == 0 || last > 16 {
            let mut buffer = [0; 32];
            buffer[31] = last;
            assert_invalid(Pkcs7::unpad_with_block_size(&buffer, 16));
        }
    }
    // Even a matching suffix is invalid when it exceeds the AES block size.
    assert_invalid(Pkcs7::unpad_with_block_size(&[32; 32], 16));
}

#[test]
fn generic_block_sizes_and_full_padding_blocks() {
    for size in 1..=255 {
        let mut buffer = vec![0x42; 2 * size];
        Pkcs7::pad(&mut buffer, size, size).unwrap();
        assert_eq!(Pkcs7::unpad_with_block_size(&buffer, size).unwrap(), &buffer[..size]);
        if size == 16 {
            assert_eq!(Pkcs7::unpad(&buffer).unwrap(), &buffer[..size]);
        }
        assert_eq!(Pkcs7::unpad_with_block_size(&buffer[size..], size).unwrap(), &[]);
    }
}

#[test]
fn maximum_padding_checks_entire_suffix() {
    let mut buffer = [0x42; 510];
    buffer[255..].fill(255);
    for position in 255..509 {
        buffer[position] = 0;
        assert_invalid(Pkcs7::unpad_with_block_size(&buffer, 255));
        buffer[position] = 255;
    }
}

#[test]
fn data_before_padding_is_preserved() {
    // Padding validates only the suffix, not the authenticity or meaning of data.
    for padding in 1..=16 {
        let mut buffer = [0; 32];
        buffer[32 - padding..].fill(padding as u8);
        for value in 0..=255u8 {
            buffer[31 - padding] = value;
            assert_eq!(Pkcs7::unpad(&buffer).unwrap(), &buffer[..32 - padding]);
            assert_eq!(Pkcs7::unpad_with_block_size(&buffer, 16).unwrap(), &buffer[..32 - padding]);
        }
    }
}

#[test]
fn default_unpad_rejects_padding_larger_than_aes_block() {
    assert_invalid(Pkcs7::unpad(&[32; 32]));
    // Matching suffix bytes must not bypass the AES padding-length limit.
    for padding in 17..=255 {
        let mut buffer = [0x42; 256];
        buffer[256 - padding..].fill(padding as u8);
        assert_invalid(Pkcs7::unpad(&buffer));
    }
}

#[test]
fn default_unpad_requires_aes_block_alignment() {
    for length in 1..32 {
        if length % 16 != 0 {
            assert_invalid(Pkcs7::unpad(&vec![1; length]));
        }
    }
    assert_eq!(Pkcs7::unpad(&[16; 16]).unwrap(), &[]);
}
