// Copyright (c) 2023 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

// Using Zeroize to zero out the memory used by AES contexts on drop
use zeroize::Zeroize;

// FFI interface to the c ctaes library
#[repr(C)]
#[derive(Default)]
struct AES_state {
    slice: [u16; 8usize],
}

impl Drop for AES_state {
    fn drop(&mut self) {
        self.slice.zeroize()
    }
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AES128_ctx {
    rk: [AES_state; 11usize],
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AES192_ctx {
    rk: [AES_state; 13usize],
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AES256_ctx {
    rk: [AES_state; 15usize],
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AES128_CBC_ctx {
    ctx: AES128_ctx,
    iv: [u8; 16usize],
}

impl Drop for AES128_CBC_ctx {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AES192_CBC_ctx {
    ctx: AES192_ctx,
    iv: [u8; 16usize],
}

impl Drop for AES192_CBC_ctx {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AES256_CBC_ctx {
    ctx: AES256_ctx,
    iv: [u8; 16usize],
}

impl Drop for AES256_CBC_ctx {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

extern "C" {
    pub(crate) fn AES128_init(ctx: *mut AES128_ctx, key16: *const ::std::os::raw::c_uchar);

    pub(crate) fn AES128_encrypt(
        ctx: *const AES128_ctx,
        blocks: usize,
        cipher16: *mut ::std::os::raw::c_uchar,
        plain16: *const ::std::os::raw::c_uchar,
    );
    pub(crate) fn AES128_decrypt(
        ctx: *const AES128_ctx,
        blocks: usize,
        plain16: *mut ::std::os::raw::c_uchar,
        cipher16: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES192_init(ctx: *mut AES192_ctx, key24: *const ::std::os::raw::c_uchar);

    pub(crate) fn AES192_encrypt(
        ctx: *const AES192_ctx,
        blocks: usize,
        cipher16: *mut ::std::os::raw::c_uchar,
        plain16: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES192_decrypt(
        ctx: *const AES192_ctx,
        blocks: usize,
        plain16: *mut ::std::os::raw::c_uchar,
        cipher16: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES256_init(ctx: *mut AES256_ctx, key32: *const ::std::os::raw::c_uchar);

    pub(crate) fn AES256_encrypt(
        ctx: *const AES256_ctx,
        blocks: usize,
        cipher16: *mut ::std::os::raw::c_uchar,
        plain16: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES256_decrypt(
        ctx: *const AES256_ctx,
        blocks: usize,
        plain16: *mut ::std::os::raw::c_uchar,
        cipher16: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES128_CBC_init(
        ctx: *mut AES128_CBC_ctx,
        key16: *const ::std::os::raw::c_uchar,
        iv: *const u8,
    );

    pub(crate) fn AES128_CBC_encrypt(
        ctx: *mut AES128_CBC_ctx,
        blocks: usize,
        encrypted: *mut ::std::os::raw::c_uchar,
        plain: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES128_CBC_decrypt(
        ctx: *mut AES128_CBC_ctx,
        blocks: usize,
        plain: *mut ::std::os::raw::c_uchar,
        encrypted: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES192_CBC_init(
        ctx: *mut AES192_CBC_ctx,
        key16: *const ::std::os::raw::c_uchar,
        iv: *const u8,
    );

    pub(crate) fn AES192_CBC_encrypt(
        ctx: *mut AES192_CBC_ctx,
        blocks: usize,
        encrypted: *mut ::std::os::raw::c_uchar,
        plain: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES192_CBC_decrypt(
        ctx: *mut AES192_CBC_ctx,
        blocks: usize,
        plain: *mut ::std::os::raw::c_uchar,
        encrypted: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES256_CBC_init(
        ctx: *mut AES256_CBC_ctx,
        key16: *const ::std::os::raw::c_uchar,
        iv: *const u8,
    );

    pub(crate) fn AES256_CBC_encrypt(
        ctx: *mut AES256_CBC_ctx,
        blocks: usize,
        encrypted: *mut ::std::os::raw::c_uchar,
        plain: *const ::std::os::raw::c_uchar,
    );

    pub(crate) fn AES256_CBC_decrypt(
        ctx: *mut AES256_CBC_ctx,
        blocks: usize,
        plain: *mut ::std::os::raw::c_uchar,
        encrypted: *const ::std::os::raw::c_uchar,
    );
}

/// A sealed trait defining the interface of an AES cipher
pub trait FfiAesCipher {
    fn ffi_init(&mut self, key: &[u8]);
    fn ffi_decrypt(&self, num_blocks: usize, plaintext: &mut [u8], ciphertext: &[u8]);
    fn ffi_encrypt(&self, num_blocks: usize, ciphertext: &mut [u8], plaintext: &[u8]);
}

/// A sealed trait defining the interface of an AES-CBC cipher
pub trait FfiAesCbcCipher: Sized {
    fn ffi_decrypt(&self, num_blocks: usize, plaintext: &mut [u8], ciphertext: &[u8]);
    fn ffi_encrypt(&self, num_blocks: usize, ciphertext: &mut [u8], plaintext: &[u8]);
}
