// Copyright (c) 2023 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

//! Rust bindings and API for CTAES (constant-time AES implementation from Bitcoin Core found at
//! https://github.com/bitcoin-core/ctaes)
//!
//! The CTAES Library provides a constant time implementation of the AES algorithm. For completeness
//! this crate provides the interface to the AES-ECB methods, but they should not be used. Rather,
//! use the AES-CBC methods.
//!
//! The crate also provides a Padding utility implementation to help the user prepare, pad and unpad
//! buffers. Zero Padding and PKCS7 padding implementations are provided
//!
//! # Security
//!
//! CBC provides no authentication. Callers MUST authenticate the IV and ciphertext
//! (and any protocol metadata) before decryption or unpadding. Use encrypt-then-MAC
//! with independent encryption and MAC keys, or an authenticated-encryption library.
//! Never expose padding results for unauthenticated input; even constant-time
//! padding validation still reveals validity through its return value.
//!
//! # Examples
//!
//! ```
//! use hex_conservative::FromHex;
//! use ctaes_rs::{Padding, Pkcs7, AesCbcBlockCipher, Aes128Cbc};
//!
//! let key = <[u8; 16]>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
//! let iv = <[u8; 16]>::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
//! let message = <Vec<u8>>::from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
//!
//! let padded_buffer_length = Pkcs7::padded_buffer_length(message.len(), 16).unwrap();
//! let mut plaintext = vec![0u8; padded_buffer_length];
//! plaintext[0..message.len()].copy_from_slice(message.as_slice());
//! Pkcs7::pad(plaintext.as_mut_slice(), message.len(), 16).unwrap();
//! let mut ciphertext = vec![0u8; padded_buffer_length];
//!
//! let mut cipher = Aes128Cbc::new(key.as_slice(), iv.as_slice()).unwrap();
//! cipher.encrypt(plaintext.as_slice(), ciphertext.as_mut_slice()).unwrap();
//!
//! let mut deciphered = vec![0u8; padded_buffer_length];
//! let mut decipher = Aes128Cbc::new(key.as_slice(), iv.as_slice()).unwrap();
//! decipher.decrypt(ciphertext.as_slice(), deciphered.as_mut_slice()).unwrap();
//! let unpadded_result = Pkcs7::unpad_with_block_size(deciphered.as_slice(), 16).unwrap();
//! assert_eq!(message.as_slice(), unpadded_result);
//! ```
//!

extern crate thiserror;
extern crate zeroize;

mod constant_time;
#[allow(non_snake_case)]
mod ctaes_ffi;
mod error;
mod padding;

use ctaes_ffi::{
    AES128_CBC_ctx, AES128_CBC_decrypt, AES128_CBC_encrypt, AES128_CBC_init, AES128_ctx,
    AES128_decrypt, AES128_encrypt, AES128_init, AES192_CBC_ctx, AES192_CBC_decrypt,
    AES192_CBC_encrypt, AES192_CBC_init, AES192_ctx, AES192_decrypt, AES192_encrypt, AES192_init,
    AES256_CBC_ctx, AES256_CBC_decrypt, AES256_CBC_encrypt, AES256_CBC_init, AES256_ctx,
    AES256_decrypt, AES256_encrypt, AES256_init, FfiAesCbcCipher, FfiAesCipher,
};
pub use error::Error;
pub use padding::{Padding, Pkcs7, ZeroPadding};

pub const AES128_KEY_LENGTH: usize = 16;
pub const AES192_KEY_LENGTH: usize = 24;
pub const AES256_KEY_LENGTH: usize = 32;
pub const AES_BLOCK_SIZE: usize = 16;

/// Trait that implements the common `encrypt` and `decrypt` methods for all AES ciphers
pub trait AesBlockCipher: FfiAesCipher {
    /// Encrypt the contents of `plaintext` and place the result in the `ciphertext` out parameter
    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), Error> {
        if plaintext.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::NonBlockSizeAlignedBuffer);
        }
        if plaintext.len() > ciphertext.len() {
            return Err(Error::InsufficientBufferSize);
        }

        let num_blocks = plaintext.len() / AES_BLOCK_SIZE;
        self.ffi_encrypt(num_blocks, ciphertext, plaintext);

        Ok(())
    }

    /// Decrypt the contents of `ciphertext` and place the result in the `plaintext` out parameter
    ///
    /// `ciphertext` must contain whole AES blocks. `plaintext` must be at least as long
    /// as `ciphertext`; any remaining bytes in `plaintext` are left unchanged.
    fn decrypt(&self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), Error> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::NonBlockSizeAlignedBuffer);
        }
        if plaintext.len() < ciphertext.len() {
            return Err(Error::InsufficientBufferSize);
        }

        let num_blocks = ciphertext.len() / AES_BLOCK_SIZE;
        self.ffi_decrypt(num_blocks, plaintext, ciphertext);

        Ok(())
    }
}

/// 128-bit AES-ECB cipher
#[derive(Default)]
pub struct Aes128 {
    context: AES128_ctx,
}

impl FfiAesCipher for Aes128 {
    fn ffi_init(&mut self, key: &[u8]) {
        unsafe {
            AES128_init(&mut self.context, key.as_ptr());
        }
    }

    fn ffi_decrypt(&self, num_blocks: usize, plaintext: &mut [u8], ciphertext: &[u8]) {
        unsafe {
            AES128_decrypt(&self.context, num_blocks, plaintext.as_mut_ptr(), ciphertext.as_ptr());
        }
    }

    fn ffi_encrypt(&self, num_blocks: usize, ciphertext: &mut [u8], plaintext: &[u8]) {
        unsafe {
            AES128_encrypt(&self.context, num_blocks, ciphertext.as_mut_ptr(), plaintext.as_ptr());
        }
    }
}

impl Aes128 {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != AES128_KEY_LENGTH {
            return Err(Error::KeyIncorrectLength(AES128_KEY_LENGTH));
        }

        let context = AES128_ctx::default();
        let mut cipher = Aes128 { context };
        cipher.ffi_init(key);

        Ok(cipher)
    }
}

impl AesBlockCipher for Aes128 {}

/// 192-bit AES-ECB cipher
#[derive(Default)]
pub struct Aes192 {
    context: AES192_ctx,
}

impl FfiAesCipher for Aes192 {
    fn ffi_init(&mut self, key: &[u8]) {
        unsafe {
            AES192_init(&mut self.context, key.as_ptr());
        }
    }

    fn ffi_decrypt(&self, num_blocks: usize, plaintext: &mut [u8], ciphertext: &[u8]) {
        unsafe {
            AES192_decrypt(&self.context, num_blocks, plaintext.as_mut_ptr(), ciphertext.as_ptr());
        }
    }

    fn ffi_encrypt(&self, num_blocks: usize, ciphertext: &mut [u8], plaintext: &[u8]) {
        unsafe {
            AES192_encrypt(&self.context, num_blocks, ciphertext.as_mut_ptr(), plaintext.as_ptr());
        }
    }
}

impl Aes192 {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != AES192_KEY_LENGTH {
            return Err(Error::KeyIncorrectLength(AES192_KEY_LENGTH));
        }

        let context = AES192_ctx::default();
        let mut cipher = Aes192 { context };
        cipher.ffi_init(key);

        Ok(cipher)
    }
}

impl AesBlockCipher for Aes192 {}

/// 256-bit AES-ECB cipher
#[derive(Default)]
pub struct Aes256 {
    context: AES256_ctx,
}

impl FfiAesCipher for Aes256 {
    fn ffi_init(&mut self, key: &[u8]) {
        unsafe {
            AES256_init(&mut self.context, key.as_ptr());
        }
    }

    fn ffi_decrypt(&self, num_blocks: usize, plaintext: &mut [u8], ciphertext: &[u8]) {
        unsafe {
            AES256_decrypt(&self.context, num_blocks, plaintext.as_mut_ptr(), ciphertext.as_ptr());
        }
    }

    fn ffi_encrypt(&self, num_blocks: usize, ciphertext: &mut [u8], plaintext: &[u8]) {
        unsafe {
            AES256_encrypt(&self.context, num_blocks, ciphertext.as_mut_ptr(), plaintext.as_ptr());
        }
    }
}

impl Aes256 {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != AES256_KEY_LENGTH {
            return Err(Error::KeyIncorrectLength(AES256_KEY_LENGTH));
        }

        let context = AES256_ctx::default();
        let mut cipher = Aes256 { context };
        cipher.ffi_init(key);

        Ok(cipher)
    }
}

impl AesBlockCipher for Aes256 {}

/// Trait that implements the common `encrypt` and `decrypt` methods for all AES-CBC ciphers
///
/// This is unauthenticated encryption. Callers MUST verify a MAC over the IV,
/// ciphertext, and relevant metadata before decrypting or unpadding.
///
/// Each instance holds one CBC chain. Successful calls advance its IV to the last
/// ciphertext block; empty inputs and rejected calls leave the chain unchanged.
/// Use separate instances initialized with the same key and IV for encryption
/// and decryption of a message. For each independent message, create a new
/// instance with a fresh, unpredictable IV; continuing a chain is for chunks of
/// the same message only.
pub trait AesCbcBlockCipher: FfiAesCbcCipher {
    /// Encrypt whole blocks, advancing the CBC chain.
    ///
    /// Output must be at least as long as input; trailing output bytes are unchanged.
    fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), Error> {
        if plaintext.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::NonBlockSizeAlignedBuffer);
        }
        if plaintext.len() > ciphertext.len() {
            return Err(Error::InsufficientBufferSize);
        }

        let num_blocks = plaintext.len() / AES_BLOCK_SIZE;
        self.ffi_encrypt(num_blocks, ciphertext, plaintext);

        Ok(())
    }

    /// Decrypt the contents of `ciphertext` and place the result in `plaintext`.
    ///
    /// `ciphertext` must contain whole AES blocks. `plaintext` must be at least as long
    /// as `ciphertext`; any remaining bytes in `plaintext` are left unchanged.
    fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), Error> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::NonBlockSizeAlignedBuffer);
        }
        if plaintext.len() < ciphertext.len() {
            return Err(Error::InsufficientBufferSize);
        }

        let num_blocks = ciphertext.len() / AES_BLOCK_SIZE;
        self.ffi_decrypt(num_blocks, plaintext, ciphertext);

        Ok(())
    }
}

/// 128-bit AES-CBC cipher
pub struct Aes128Cbc {
    context: AES128_CBC_ctx,
}

impl Aes128Cbc {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, Error> {
        if key.len() != AES128_KEY_LENGTH {
            return Err(Error::KeyIncorrectLength(AES128_KEY_LENGTH));
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(Error::IvIncorrectLength);
        }

        let mut context = AES128_CBC_ctx::default();
        unsafe {
            AES128_CBC_init(&mut context, key.as_ptr(), iv.as_ptr());
        }
        Ok(Self { context })
    }
}

impl FfiAesCbcCipher for Aes128Cbc {
    fn ffi_decrypt(&mut self, num_blocks: usize, plaintext: &mut [u8], ciphertext: &[u8]) {
        unsafe {
            AES128_CBC_decrypt(
                &mut self.context,
                num_blocks,
                plaintext.as_mut_ptr(),
                ciphertext.as_ptr(),
            );
        }
    }

    fn ffi_encrypt(&mut self, num_blocks: usize, ciphertext: &mut [u8], plaintext: &[u8]) {
        unsafe {
            AES128_CBC_encrypt(
                &mut self.context,
                num_blocks,
                ciphertext.as_mut_ptr(),
                plaintext.as_ptr(),
            );
        }
    }
}

impl AesCbcBlockCipher for Aes128Cbc {}

/// 192-bit AES-CBC cipher
pub struct Aes192Cbc {
    context: AES192_CBC_ctx,
}

impl Aes192Cbc {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, Error> {
        if key.len() != AES192_KEY_LENGTH {
            return Err(Error::KeyIncorrectLength(AES192_KEY_LENGTH));
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(Error::IvIncorrectLength);
        }

        let mut context = AES192_CBC_ctx::default();
        unsafe {
            AES192_CBC_init(&mut context, key.as_ptr(), iv.as_ptr());
        }
        Ok(Self { context })
    }
}

impl FfiAesCbcCipher for Aes192Cbc {
    fn ffi_decrypt(&mut self, num_blocks: usize, plaintext: &mut [u8], ciphertext: &[u8]) {
        unsafe {
            AES192_CBC_decrypt(
                &mut self.context,
                num_blocks,
                plaintext.as_mut_ptr(),
                ciphertext.as_ptr(),
            );
        }
    }

    fn ffi_encrypt(&mut self, num_blocks: usize, ciphertext: &mut [u8], plaintext: &[u8]) {
        unsafe {
            AES192_CBC_encrypt(
                &mut self.context,
                num_blocks,
                ciphertext.as_mut_ptr(),
                plaintext.as_ptr(),
            );
        }
    }
}

impl AesCbcBlockCipher for Aes192Cbc {}

/// 256-bit AES-CBC cipher
pub struct Aes256Cbc {
    context: AES256_CBC_ctx,
}

impl Aes256Cbc {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, Error> {
        if key.len() != AES256_KEY_LENGTH {
            return Err(Error::KeyIncorrectLength(AES256_KEY_LENGTH));
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(Error::IvIncorrectLength);
        }

        let mut context = AES256_CBC_ctx::default();
        unsafe {
            AES256_CBC_init(&mut context, key.as_ptr(), iv.as_ptr());
        }
        Ok(Self { context })
    }
}

impl FfiAesCbcCipher for Aes256Cbc {
    fn ffi_decrypt(&mut self, num_blocks: usize, plaintext: &mut [u8], ciphertext: &[u8]) {
        unsafe {
            AES256_CBC_decrypt(
                &mut self.context,
                num_blocks,
                plaintext.as_mut_ptr(),
                ciphertext.as_ptr(),
            );
        }
    }

    fn ffi_encrypt(&mut self, num_blocks: usize, ciphertext: &mut [u8], plaintext: &[u8]) {
        unsafe {
            AES256_CBC_encrypt(
                &mut self.context,
                num_blocks,
                ciphertext.as_mut_ptr(),
                plaintext.as_ptr(),
            );
        }
    }
}

impl AesCbcBlockCipher for Aes256Cbc {}

#[cfg(test)]
mod test {
    use crate::AES128_KEY_LENGTH;
    use crate::AES192_KEY_LENGTH;
    use crate::AES256_KEY_LENGTH;
    use crate::{
        Aes128, Aes128Cbc, Aes192, Aes192Cbc, Aes256, Aes256Cbc, AesBlockCipher, AesCbcBlockCipher,
        Error,
    };

    #[test]
    fn test_buffer_validation() {
        assert!(matches!(
            Aes128::new([0u8; 17].as_slice()),
            Err(Error::KeyIncorrectLength(AES128_KEY_LENGTH))
        ));
        assert!(matches!(
            Aes192::new([0u8; 25].as_slice()),
            Err(Error::KeyIncorrectLength(AES192_KEY_LENGTH))
        ));
        assert!(matches!(
            Aes256::new([0u8; 33].as_slice()),
            Err(Error::KeyIncorrectLength(AES256_KEY_LENGTH))
        ));
        assert!(matches!(
            Aes128Cbc::new([0u8; 17].as_slice(), [0u8; 16].as_slice()),
            Err(Error::KeyIncorrectLength(AES128_KEY_LENGTH))
        ));
        assert!(matches!(
            Aes128Cbc::new([0u8; 16].as_slice(), [0u8; 17].as_slice()),
            Err(Error::IvIncorrectLength)
        ));
        assert!(matches!(
            Aes192Cbc::new([0u8; 25].as_slice(), [0u8; 16].as_slice()),
            Err(Error::KeyIncorrectLength(AES192_KEY_LENGTH))
        ));
        assert!(matches!(
            Aes192Cbc::new([0u8; 24].as_slice(), [0u8; 17].as_slice()),
            Err(Error::IvIncorrectLength)
        ));
        assert!(matches!(
            Aes256Cbc::new([0u8; 33].as_slice(), [0u8; 16].as_slice()),
            Err(Error::KeyIncorrectLength(AES256_KEY_LENGTH))
        ));
        assert!(matches!(
            Aes256Cbc::new([0u8; 32].as_slice(), [0u8; 17].as_slice()),
            Err(Error::IvIncorrectLength)
        ));

        let cipher = Aes128::new([0u8; 16].as_slice()).unwrap();
        assert!(matches!(
            cipher.encrypt([0u8; 33].as_slice(), [0u8; 33].as_mut_slice()),
            Err(Error::NonBlockSizeAlignedBuffer)
        ));
        assert!(matches!(
            cipher.encrypt([0u8; 64].as_slice(), [0u8; 32].as_mut_slice()),
            Err(Error::InsufficientBufferSize)
        ));
        assert!(matches!(
            cipher.decrypt([0u8; 64].as_slice(), [0u8; 32].as_mut_slice()),
            Err(Error::InsufficientBufferSize)
        ));
        assert!(matches!(cipher.decrypt([0u8; 0].as_slice(), [0u8; 32768].as_mut_slice()), Ok(())));
        assert!(matches!(
            cipher.decrypt([0u8; crate::AES_BLOCK_SIZE].as_slice(), [0u8; 32768].as_mut_slice()),
            Ok(())
        ));

        let mut cipher = Aes128Cbc::new([0u8; 16].as_slice(), [0u8; 16].as_slice()).unwrap();
        assert!(matches!(
            cipher.encrypt([0u8; 33].as_slice(), [0u8; 33].as_mut_slice()),
            Err(Error::NonBlockSizeAlignedBuffer)
        ));
        assert!(matches!(
            cipher.encrypt([0u8; 64].as_slice(), [0u8; 32].as_mut_slice()),
            Err(Error::InsufficientBufferSize)
        ));
        assert!(matches!(
            cipher.decrypt([0u8; 64].as_slice(), [0u8; 32].as_mut_slice()),
            Err(Error::InsufficientBufferSize)
        ));
        assert!(matches!(cipher.decrypt([0u8; 0].as_slice(), [0u8; 32768].as_mut_slice()), Ok(())));
        assert!(matches!(
            cipher.decrypt([0u8; crate::AES_BLOCK_SIZE].as_slice(), [0u8; 32768].as_mut_slice()),
            Ok(())
        ));
    }
}
