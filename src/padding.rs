// Copyright (c) 2023 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

use crate::constant_time::{ConstantTimeEq, ConstantTimeLess};
use crate::{Error, AES_BLOCK_SIZE};

/// Trait defining interface for a Padding implementation
pub trait Padding {
    /// Given a length of data and block_size return the minimum size of a buffer required to hold
    /// the padded data
    fn padded_buffer_length(data_length: usize, block_size: usize) -> Result<usize, Error>;
    /// Take a buffer containing data of specified length and based on the blocksize apply the padding
    /// to the buffer. The returned slice will reference the slice of padded data in the buffer
    fn pad(buffer: &mut [u8], data_length: usize, block_size: usize) -> Result<&[u8], Error>;
    /// Given a buffer of padded data, attempt to provide a slice that references
    /// the unpadded data
    fn unpad(buffer: &[u8]) -> Result<&[u8], Error>;
}

/// Implementation of basic Zero Padding. May not be reversible if the original data ends with one
/// or more zero bytes. Does not add an extra block of padding if the data length is already a
/// multiple of the block size
pub enum ZeroPadding {}

impl Padding for ZeroPadding {
    fn padded_buffer_length(data_length: usize, block_size: usize) -> Result<usize, Error> {
        if block_size == 0 {
            return Err(Error::InvalidBlockSize);
        }
        let remainder = data_length % block_size;
        let padding_length = if remainder == 0 { 0 } else { block_size - remainder };
        data_length.checked_add(padding_length).ok_or(Error::PaddedLengthOverflow)
    }

    fn pad(buffer: &mut [u8], data_length: usize, block_size: usize) -> Result<&[u8], Error> {
        let padded_length = Self::padded_buffer_length(data_length, block_size)?;
        if buffer.len() < padded_length {
            return Err(Error::PaddedBufferTooSmall);
        }

        if data_length < padded_length {
            buffer[data_length..padded_length].fill(0u8);
        }

        Ok(&buffer[0..padded_length])
    }

    /// Remove trailing zero padding. Empty input returns an unpadding error.
    fn unpad(buffer: &[u8]) -> Result<&[u8], Error> {
        if buffer.is_empty() {
            return Err(Error::UnpadError("Buffer to unpad is empty".to_string()));
        }

        let mut end = buffer.len();
        while end > 0 && buffer[end - 1] == 0 {
            end -= 1;
        }
        Ok(&buffer[..end])
    }
}

/// Implementation of the PKCS7 padding scheme.
///
/// Padding validation does not authenticate a message. Verify its MAC before
/// decrypting or unpadding, and never expose padding validity for unauthenticated
/// input. `Padding::unpad` enforces the AES block size (16 bytes); use
/// `unpad_with_block_size` for other block sizes.
pub enum Pkcs7 {}

impl Pkcs7 {
    /// Validate PKCS7 padding, including block alignment and padding length bounds.
    ///
    /// For AES, pass 16. The block size must be in 1..=255.
    /// All bytes in the final block are checked using constant-time comparisons
    /// before returning padding validity. This is not a substitute for a MAC.
    pub fn unpad_with_block_size(buffer: &[u8], block_size: usize) -> Result<&[u8], Error> {
        if block_size == 0
            || block_size > 255
            || buffer.is_empty()
            || buffer.len() % block_size != 0
        {
            return Err(Self::invalid_padding());
        }
        Self::validate_suffix(buffer, block_size)
    }

    fn invalid_padding() -> Error {
        Error::UnpadError("Invalid PKCS7 padding".to_string())
    }

    fn validate_suffix(buffer: &[u8], scan_length: usize) -> Result<&[u8], Error> {
        if buffer.is_empty() {
            return Err(Self::invalid_padding());
        }
        let padding_length = buffer[buffer.len() - 1];
        let pad = u16::from(padding_length);
        // The padding length must be nonzero and must not exceed the scan length.
        let mut valid = !padding_length.ct_eq(&0) & !(scan_length as u16).ct_lt(&pad);

        // The scan length and addresses depend only on public buffer/block sizes.
        // Accumulate all mismatches without branching on decrypted byte values.
        for (offset, byte) in buffer.iter().rev().take(scan_length).enumerate() {
            let is_padding = (offset as u16).ct_lt(&pad);
            valid &= !is_padding | byte.ct_eq(&padding_length);
        }

        // Only the final validity decision and returned length depend on padding.
        if bool::from(valid) {
            Ok(&buffer[..buffer.len() - padding_length as usize])
        } else {
            Err(Self::invalid_padding())
        }
    }
}

impl Padding for Pkcs7 {
    fn padded_buffer_length(data_length: usize, block_size: usize) -> Result<usize, Error> {
        if block_size == 0 || block_size > 255 {
            return Err(Error::InvalidBlockSize);
        }
        let padding_length = block_size - data_length % block_size;
        data_length.checked_add(padding_length).ok_or(Error::PaddedLengthOverflow)
    }

    fn pad(buffer: &mut [u8], data_length: usize, block_size: usize) -> Result<&[u8], Error> {
        let padded_length = Self::padded_buffer_length(data_length, block_size)?;
        if buffer.len() < padded_length {
            return Err(Error::PaddedBufferTooSmall);
        }

        let padding_length = padded_length - data_length;

        buffer[data_length..padded_length].fill(padding_length as u8);
        Ok(&buffer[0..padded_length])
    }

    /// Validate and remove PKCS7 padding for AES's 16-byte block size.
    ///
    /// Requires nonempty, block-aligned input and 1..=16 matching padding bytes.
    /// For data padded with another block size, use `unpad_with_block_size`.
    fn unpad(buffer: &[u8]) -> Result<&[u8], Error> {
        Self::unpad_with_block_size(buffer, AES_BLOCK_SIZE)
    }
}

#[cfg(test)]
mod test {
    use crate::padding::{Padding, Pkcs7, ZeroPadding};
    use crate::Error;

    #[test]
    fn test_zero_padding_unpad_empty() {
        assert!(matches!(ZeroPadding::unpad(&[]), Err(Error::UnpadError(_))));
    }

    #[test]
    fn test_zero_padding_unpad_boundaries() {
        for length in 1..=32 {
            let mut buffer = vec![0; length];
            assert_eq!(ZeroPadding::unpad(&buffer).unwrap(), &[]);

            // Preserve the last nonzero byte at every possible position,
            // including the first byte and a buffer with no trailing padding.
            for position in 0..length {
                buffer[position] = 0x42;
                assert_eq!(ZeroPadding::unpad(&buffer).unwrap(), &buffer[..position + 1]);
                buffer[position] = 0;
            }
        }
    }

    #[test]
    fn test_zero_padding() {
        const BLOCK_SIZE: usize = 16;
        assert_eq!(ZeroPadding::padded_buffer_length(20, BLOCK_SIZE).unwrap(), 2 * BLOCK_SIZE);
        assert_eq!(
            ZeroPadding::padded_buffer_length(2 * BLOCK_SIZE, BLOCK_SIZE).unwrap(),
            2 * BLOCK_SIZE
        );

        const DATA_LENGTH: usize = 22;
        let mut buffer = [2u8; 2 * BLOCK_SIZE + 1];

        buffer[0..2 * BLOCK_SIZE].fill(1u8);

        let padded_buffer =
            ZeroPadding::pad(buffer.as_mut_slice(), DATA_LENGTH, BLOCK_SIZE).unwrap();

        assert_eq!(&padded_buffer[0..DATA_LENGTH], [1u8; DATA_LENGTH].as_slice());

        assert_eq!(
            &padded_buffer[DATA_LENGTH..],
            vec![0u8; padded_buffer.len() - DATA_LENGTH].as_slice()
        );

        let unpadded_padded_buffer = ZeroPadding::unpad(padded_buffer).unwrap();
        assert_eq!(unpadded_padded_buffer, [1u8; DATA_LENGTH].as_slice());

        assert_eq!(buffer[2 * BLOCK_SIZE], 2u8);

        assert!(matches!(
            ZeroPadding::pad(buffer.as_mut_slice(), 2 * BLOCK_SIZE + 1, BLOCK_SIZE),
            Err(Error::PaddedBufferTooSmall)
        ));
    }

    #[test]
    fn test_pkcs7_unpad_invalid() {
        let is_invalid = |buffer: &[u8]| matches!(Pkcs7::unpad(buffer), Err(Error::UnpadError(_)));
        let mut buffer = [0u8; 16];
        // Zero padding length
        assert!(is_invalid(&buffer));
        // Padding length larger than block size
        buffer[15] = 17;
        assert!(is_invalid(&buffer));
        // Mismatched padding byte
        buffer[12..].fill(4);
        buffer[12] = 3;
        assert!(is_invalid(&buffer));
        // Valid padding of every length
        for padding_length in 1..=16u8 {
            buffer.fill(0xaa);
            buffer[16 - padding_length as usize..].fill(padding_length);
            assert_eq!(Pkcs7::unpad(&buffer).unwrap().len(), 16 - padding_length as usize);
        }
    }

    #[test]
    fn test_pkcs7_padding() {
        const BLOCK_SIZE: usize = 16;
        assert_eq!(Pkcs7::padded_buffer_length(20, BLOCK_SIZE).unwrap(), 2 * BLOCK_SIZE);
        assert_eq!(
            Pkcs7::padded_buffer_length(2 * BLOCK_SIZE, BLOCK_SIZE).unwrap(),
            3 * BLOCK_SIZE
        );

        const DATA_LENGTH: usize = 22;
        let mut buffer = [2u8; 2 * BLOCK_SIZE + 1];

        buffer[0..2 * BLOCK_SIZE].fill(1u8);

        let padded_buffer = Pkcs7::pad(buffer.as_mut_slice(), DATA_LENGTH, BLOCK_SIZE).unwrap();

        assert_eq!(&padded_buffer[0..DATA_LENGTH], [1u8; DATA_LENGTH].as_slice());

        assert_eq!(
            &padded_buffer[DATA_LENGTH..],
            vec![10u8; padded_buffer.len() - DATA_LENGTH].as_slice()
        );

        let unpadded_padded_buffer = Pkcs7::unpad(padded_buffer).unwrap();
        assert_eq!(unpadded_padded_buffer, [1u8; DATA_LENGTH].as_slice());

        assert_eq!(buffer[2 * BLOCK_SIZE], 2u8);

        assert!(matches!(
            Pkcs7::pad(buffer.as_mut_slice(), 2 * BLOCK_SIZE + 1, BLOCK_SIZE),
            Err(Error::PaddedBufferTooSmall)
        ));
    }
}
