# ctaes-rs

Rust bindings and API for CTAES (constant-time AES implementation from Bitcoin Core found at
https://github.com/bitcoin-core/ctaes)

The CTAES Library provides a constant time implementation of the AES algorithm. For completeness
this crate provides the interface to the AES-ECB methods, but they should not be used. Rather,
use the AES-CBC methods.

The crate also provides a Padding utility implementation to help the user prepare, pad and unpad
buffers. Zero Padding and PKCS7 padding implementations are provided

Run `cargo doc --nodeps` to generate the documentation of the library.

# Note
This is a low-level encryption library and should be employed in conjunction with a message 
authentication scheme to avoid chosen-ciphertext and chosen-plaintext attacks.

# Compatibility
This crate requires Rust 1.63.0 or later.