// Copyright (c) 2023 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

use crate::Error;

/// Trait defining interface for a Padding implementation
pub trait Padding {
    /// Given a length of data and block_size return the minimum size of a buffer required to hold
    /// the padded data
    fn padded_buffer_length(data_length: usize, block_size: usize) -> usize;
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
    fn padded_buffer_length(data_length: usize, block_size: usize) -> usize {
        if data_length % block_size == 0 {
            data_length
        } else {
            block_size + block_size * (data_length / block_size)
        }
    }

    fn pad(buffer: &mut [u8], data_length: usize, block_size: usize) -> Result<&[u8], Error> {
        let padded_length = Self::padded_buffer_length(data_length, block_size);
        if buffer.len() < padded_length {
            return Err(Error::PaddedBufferTooSmall);
        }

        if data_length < padded_length {
            buffer[data_length..padded_length].fill(0u8);
        }

        Ok(&buffer[0..padded_length])
    }

    fn unpad(buffer: &[u8]) -> Result<&[u8], Error> {
        let mut n = buffer.len() - 1;
        while n > 0 {
            if buffer[n] != 0 {
                break;
            }
            n -= 1;
        }
        Ok(&buffer[0..=n])
    }
}

/// Implementation of the PKCS7 padding scheme
pub enum Pkcs7 {}

impl Padding for Pkcs7 {
    fn padded_buffer_length(data_length: usize, block_size: usize) -> usize {
        block_size + block_size * (data_length / block_size)
    }

    fn pad(buffer: &mut [u8], data_length: usize, block_size: usize) -> Result<&[u8], Error> {
        let padded_length = Self::padded_buffer_length(data_length, block_size);
        if buffer.len() < padded_length {
            return Err(Error::PaddedBufferTooSmall);
        }

        let padding_length = padded_length - data_length;

        buffer[data_length..padded_length].fill(padding_length as u8);
        Ok(&buffer[0..padded_length])
    }

    fn unpad(buffer: &[u8]) -> Result<&[u8], Error> {
        let padding_length = match buffer.last() {
            None => return Err(Error::UnpadError("Buffer to unpad is empty".to_string())),
            Some(l) => *l,
        };
        if buffer.len() < padding_length as usize {
            return Err(Error::UnpadError(
                "Buffer smaller than PKCS7 recorded padded length".to_string(),
            ));
        }
        if padding_length == 0 {
            return Err(Error::UnpadError("PKCS7 padding length can't be zero".to_string()));
        }

        Ok(&buffer[0..buffer.len() - padding_length as usize])
    }
}

#[cfg(test)]
mod test {
    use crate::padding::{Padding, Pkcs7, ZeroPadding};
    use crate::Error;

    #[test]
    fn test_zero_padding() {
        const BLOCK_SIZE: usize = 16;
        assert_eq!(ZeroPadding::padded_buffer_length(20, BLOCK_SIZE), 2 * BLOCK_SIZE);
        assert_eq!(ZeroPadding::padded_buffer_length(2 * BLOCK_SIZE, BLOCK_SIZE), 2 * BLOCK_SIZE);

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
    fn test_pkcs7_padding() {
        const BLOCK_SIZE: usize = 16;
        assert_eq!(Pkcs7::padded_buffer_length(20, BLOCK_SIZE), 2 * BLOCK_SIZE);
        assert_eq!(Pkcs7::padded_buffer_length(2 * BLOCK_SIZE, BLOCK_SIZE), 3 * BLOCK_SIZE);

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
