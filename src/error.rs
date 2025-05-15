// Copyright (c) 2023 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

use thiserror::Error;

/// The errors that can be encountered using this crate
#[derive(Debug, Clone, Error)]
pub enum Error {
    #[error("Key must be '{0}' bytes long")]
    KeyIncorrectLength(usize),
    #[error("IV must be 16 bytes long")]
    IvIncorrectLength,
    #[error("Buffer not multiple of block size")]
    NonBlockSizeAlignedBuffer,
    #[error("Output buffer is not big enough to hold the result of processing input")]
    InsufficientBufferSize,
    #[error("Buffer not large enough to accomodate padded buffer")]
    PaddedBufferTooSmall,
    #[error("Unable to unpad buffer: {0}")]
    UnpadError(String),
}
