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
This is a low-level, unauthenticated encryption library. Callers MUST authenticate
the IV, ciphertext, and relevant protocol metadata before decrypting or unpadding.
Use encrypt-then-MAC with independent encryption and MAC keys, or use an
authenticated-encryption library. Reject invalid tags before calling CBC decrypt;
never expose padding results for unauthenticated ciphertext.

Strict padding checks and constant-time byte comparisons do not eliminate a
padding oracle: success versus failure still reveals padding validity.

For AES padding `Padding::unpad` uses a block size of 16 by default. For any other block size
use `Pkcs7::unpad_with_block_size(buffer, BLOCK_SIZE)`.

CBC instances retain their chaining state across calls. CBC `encrypt` and
`decrypt` require a mutable instance. Use separate instances with the same key
and initial IV to encrypt and decrypt a message. Calls on one instance process
successive block-aligned chunks of that message; they do not start new messages.
For each independent message, construct a new instance with a fresh,
unpredictable IV.

# Compatibility
This crate requires Rust 1.63.0 or later.

# License
This crate is licensed under the MIT license (see `COPYING`), except for
`src/constant_time.rs`, which contains code derived from the
[subtle](https://github.com/dalek-cryptography/subtle) crate and is licensed under
the BSD-3-Clause license reproduced at the top of that file.
