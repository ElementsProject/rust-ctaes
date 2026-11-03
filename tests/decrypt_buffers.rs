use ctaes_rs::{
    Aes128, Aes128Cbc, Aes192, Aes192Cbc, Aes256, Aes256Cbc, AesBlockCipher, AesCbcBlockCipher,
    Error, AES_BLOCK_SIZE,
};

fn check_decrypt_buffers<E, D>(encrypt: E, decrypt: D)
where
    E: Fn(&[u8], &mut [u8]) -> Result<(), Error>,
    D: Fn(&[u8], &mut [u8]) -> Result<(), Error>,
{
    const SENTINEL: u8 = 0xa5;

    // Include empty input, the reported one-block input with four blocks of
    // output space, and multiple blocks. Extra output need not be block aligned.
    for &input_len in &[0, AES_BLOCK_SIZE, 2 * AES_BLOCK_SIZE] {
        let expected: Vec<u8> = (0..input_len).map(|i| i as u8).collect();
        let mut ciphertext = vec![0; input_len];
        encrypt(&expected, &mut ciphertext).unwrap();

        for &extra in &[0, 1, AES_BLOCK_SIZE, 3 * AES_BLOCK_SIZE, 1024] {
            let mut plaintext = vec![SENTINEL; input_len + extra];
            decrypt(&ciphertext, &mut plaintext).unwrap();
            assert_eq!(&plaintext[..input_len], expected.as_slice());
            assert!(plaintext[input_len..].iter().all(|&b| b == SENTINEL));
        }
    }

    // XF-05: reject every partial-block length regardless of output capacity,
    // including a one-byte ciphertext with 16-byte and 1024-byte output buffers.
    for input_len in 1..2 * AES_BLOCK_SIZE {
        if input_len % AES_BLOCK_SIZE == 0 {
            continue;
        }
        let ciphertext = vec![0xaa; input_len];
        let rounded_len = (input_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        for &output_len in &[rounded_len, rounded_len + 1, 1024] {
            let mut plaintext = vec![SENTINEL; output_len];
            assert!(matches!(
                decrypt(&ciphertext, &mut plaintext),
                Err(Error::NonBlockSizeAlignedBuffer)
            ));
            assert!(plaintext.iter().all(|&b| b == SENTINEL));
        }
    }

    // Reject undersized output without writing to it, regardless of alignment.
    let ciphertext = [0; 2 * AES_BLOCK_SIZE];
    for &output_len in &[0, 1, AES_BLOCK_SIZE, 2 * AES_BLOCK_SIZE - 1] {
        let mut plaintext = vec![SENTINEL; output_len];
        assert!(matches!(decrypt(&ciphertext, &mut plaintext), Err(Error::InsufficientBufferSize)));
        assert!(plaintext.iter().all(|&b| b == SENTINEL));
    }
}

macro_rules! decrypt_buffer_test {
    ($name:ident, $cipher:expr) => {
        #[test]
        fn $name() {
            check_decrypt_buffers(
                |plaintext, ciphertext| $cipher.unwrap().encrypt(plaintext, ciphertext),
                |ciphertext, plaintext| $cipher.unwrap().decrypt(ciphertext, plaintext),
            );
        }
    };
}

decrypt_buffer_test!(aes128_decrypt_buffers, Aes128::new(&[0; 16]));
decrypt_buffer_test!(aes192_decrypt_buffers, Aes192::new(&[0; 24]));
decrypt_buffer_test!(aes256_decrypt_buffers, Aes256::new(&[0; 32]));
decrypt_buffer_test!(aes128_cbc_decrypt_buffers, Aes128Cbc::new(&[0; 16], &[0; 16]));
decrypt_buffer_test!(aes192_cbc_decrypt_buffers, Aes192Cbc::new(&[0; 24], &[0; 16]));
decrypt_buffer_test!(aes256_cbc_decrypt_buffers, Aes256Cbc::new(&[0; 32], &[0; 16]));
