/*********************************************************************
* Copyright (c) 2023 Blockstream                                     *
* Distributed under the MIT software license, see the accompanying   *
* file COPYING or https://opensource.org/licenses/mit-license.php.   *
**********************************************************************/

extern crate hex_conservative;

use ctaes_rs::Aes192Cbc;
use ctaes_rs::Aes256Cbc;
use ctaes_rs::{Aes128, Aes128Cbc, Aes192, Aes256, AesBlockCipher, AesCbcBlockCipher};
use hex_conservative::FromHex;

struct AesTestVector {
    key: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn aes_test_vectors() -> Vec<AesTestVector> {
    let mut vectors = vec![];

    /* AES test vectors from FIPS 197 via ctaes repo*/
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        plaintext: <Vec<u8>>::from_hex("00112233445566778899aabbccddeeff").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap(),
        plaintext: <Vec<u8>>::from_hex("00112233445566778899aabbccddeeff").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("dda97ca4864cdfe06eaf70a0ec0d7191").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap(),
        plaintext: <Vec<u8>>::from_hex("00112233445566778899aabbccddeeff").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("8ea2b7ca516745bfeafc49904b496089").unwrap(),
    });

    /* AES-ECB test vectors from NIST sp800-38a. */
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap(),
        plaintext: <Vec<u8>>::from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("3ad77bb40d7a3660a89ecaf32466ef97").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap(),
        plaintext: <Vec<u8>>::from_hex("ae2d8a571e03ac9c9eb76fac45af8e51").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("f5d3d58503b9699de785895a96fdbaaf").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap(),
        plaintext: <Vec<u8>>::from_hex("30c81c46a35ce411e5fbc1191a0a52ef").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("43b1cd7f598ece23881b00e3ed030688").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap(),
        plaintext: <Vec<u8>>::from_hex("f69f2445df4f9b17ad2b417be66c3710").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("7b0c785e27e8ad3f8223207104725dd4").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap(),
        plaintext: <Vec<u8>>::from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("bd334f1d6e45f25ff712a214571fa5cc").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap(),
        plaintext: <Vec<u8>>::from_hex("ae2d8a571e03ac9c9eb76fac45af8e51").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("974104846d0ad3ad7734ecb3ecee4eef").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap(),
        plaintext: <Vec<u8>>::from_hex("30c81c46a35ce411e5fbc1191a0a52ef").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("ef7afd2270e2e60adce0ba2face6444e").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap(),
        plaintext: <Vec<u8>>::from_hex("f69f2445df4f9b17ad2b417be66c3710").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("9a4b41ba738d6c72fb16691603c18e0e").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )
        .unwrap(),
        plaintext: <Vec<u8>>::from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("f3eed1bdb5d2a03c064b5a7e3db181f8").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )
        .unwrap(),
        plaintext: <Vec<u8>>::from_hex("ae2d8a571e03ac9c9eb76fac45af8e51").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("591ccb10d410ed26dc5ba74a31362870").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )
        .unwrap(),
        plaintext: <Vec<u8>>::from_hex("30c81c46a35ce411e5fbc1191a0a52ef").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("b6ed21b99ca6f4f9f153e7b1beafed1d").unwrap(),
    });
    vectors.push(AesTestVector {
        key: <Vec<u8>>::from_hex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )
        .unwrap(),
        plaintext: <Vec<u8>>::from_hex("f69f2445df4f9b17ad2b417be66c3710").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("23304b7a39f9f3ff067d8d8f9e24ecc7").unwrap(),
    });

    vectors
}

struct AesCbcTestVector {
    key: Vec<u8>,
    iv: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn aes_cbc_test_vectors() -> Vec<AesCbcTestVector> {
    let mut vectors = vec![];

    vectors.push(AesCbcTestVector {
        key: <Vec<u8>>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap(),
        iv: <Vec<u8>>::from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        plaintext: <Vec<u8>>::from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7").unwrap()
    });
    vectors.push(AesCbcTestVector {
        key: <Vec<u8>>::from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap(),
        iv: <Vec<u8>>::from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        plaintext: <Vec<u8>>::from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd").unwrap()
    });
    vectors.push(AesCbcTestVector {
        key: <Vec<u8>>::from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap(),
        iv: <Vec<u8>>::from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        plaintext: <Vec<u8>>::from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap(),
        ciphertext: <Vec<u8>>::from_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b").unwrap()
    });

    vectors
}

#[test]
fn test_aes_ciphers() {
    for test_vector in aes_test_vectors() {
        match test_vector.key.len() {
            16 => {
                let cipher = Aes128::new(test_vector.key.as_slice()).unwrap();
                test_cipher(cipher, &test_vector.plaintext, &test_vector.ciphertext);
            }
            24 => {
                let cipher = Aes192::new(test_vector.key.as_slice()).unwrap();
                test_cipher(cipher, &test_vector.plaintext, &test_vector.ciphertext);
            }
            32 => {
                let cipher = Aes256::new(test_vector.key.as_slice()).unwrap();
                test_cipher(cipher, &test_vector.plaintext, &test_vector.ciphertext);
            }
            _ => panic!("Invalid key length"),
        };
    }
}

fn test_cipher<T: AesBlockCipher>(cipher: T, plaintext: &Vec<u8>, ciphertext: &Vec<u8>) {
    let mut ciphered = [0u8; 16];
    let mut deciphered = [0u8; 16];

    cipher.encrypt(plaintext.as_slice(), ciphered.as_mut_slice()).unwrap();
    assert_eq!(ciphered.as_slice(), ciphertext.as_slice());

    cipher.decrypt(ciphered.as_slice(), deciphered.as_mut_slice()).unwrap();
    assert_eq!(deciphered.as_slice(), plaintext.as_slice());
}

#[test]
fn test_aes_cbc_ciphers() {
    for test_vector in aes_cbc_test_vectors() {
        match test_vector.key.len() {
            16 => {
                let cipher =
                    Aes128Cbc::new(test_vector.key.as_slice(), test_vector.iv.as_slice()).unwrap();
                test_cbc_cipher(cipher, &test_vector.plaintext, &test_vector.ciphertext);
            }
            24 => {
                let cipher =
                    Aes192Cbc::new(test_vector.key.as_slice(), test_vector.iv.as_slice()).unwrap();
                test_cbc_cipher(cipher, &test_vector.plaintext, &test_vector.ciphertext);
            }
            32 => {
                let cipher =
                    Aes256Cbc::new(test_vector.key.as_slice(), test_vector.iv.as_slice()).unwrap();
                test_cbc_cipher(cipher, &test_vector.plaintext, &test_vector.ciphertext);
            }
            _ => panic!("Invalid key length"),
        };
    }
}

fn test_cbc_cipher<T: AesCbcBlockCipher>(cipher: T, plaintext: &Vec<u8>, ciphertext: &Vec<u8>) {
    let mut ciphered = vec![0u8; plaintext.len()];
    let mut deciphered = vec![0u8; plaintext.len()];

    cipher.encrypt(plaintext.as_slice(), ciphered.as_mut_slice()).unwrap();
    assert_eq!(ciphered.as_slice(), ciphertext.as_slice());

    cipher.decrypt(ciphered.as_slice(), deciphered.as_mut_slice()).unwrap();
    assert_eq!(deciphered.as_slice(), plaintext.as_slice());
}
