use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr64BE;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use std::hint::black_box;

use crate::constants::*;

type Aes256Ctr = Ctr64BE<Aes256>;

pub struct KeyPair {
    pub encryption_key: [u8; KEY_LEN],
    pub mac_key: [u8; KEY_LEN],
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.encryption_key.fill(0);
        self.mac_key.fill(0);
        black_box(&mut self.encryption_key);
        black_box(&mut self.mac_key);
    }
}

pub fn derive_keys(password: &str, salt: &[u8]) -> KeyPair {
    let mut encryption_key = [0u8; KEY_LEN];
    let mut mac_key = [0u8; KEY_LEN];
    let password_bytes = password.as_bytes();

    rayon::join(
        || {
            pbkdf2_hmac::<Sha256>(password_bytes, salt, PBKDF_ITER_MAIN, &mut encryption_key);
        },
        || {
            let mut mac_salt = Vec::with_capacity(salt.len() + MAC_SALT_SUFFIX.len());
            mac_salt.extend_from_slice(salt);
            mac_salt.extend_from_slice(MAC_SALT_SUFFIX);
            pbkdf2_hmac::<Sha256>(password_bytes, &mac_salt, PBKDF_ITER_MAC, &mut mac_key);
            mac_salt.fill(0);
            black_box(mac_salt.as_mut_slice());
        },
    );

    KeyPair {
        encryption_key,
        mac_key,
    }
}

pub fn process_chunk_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    data: &mut [u8],
    byte_offset: u64,
) {
    let block_counter = byte_offset / 16;
    let mut full_nonce = [0u8; 16];

    full_nonce[..NONCE_LEN].copy_from_slice(nonce);
    full_nonce[NONCE_LEN..].copy_from_slice(&block_counter.to_be_bytes());

    let mut cipher = Aes256Ctr::new(key.into(), &full_nonce.into());
    cipher.apply_keystream(data);
}

pub fn process_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    data: &[u8],
    byte_offset: usize,
) -> Vec<u8> {
    let mut result = data.to_vec();
    process_chunk_in_place(key, nonce, &mut result, byte_offset as u64);
    result
}

pub fn compute_mac(mac_key: &[u8; KEY_LEN], data_hash: &[u8]) -> [u8; MAC_LEN] {
    let mut mac_hasher = Sha256::new();

    mac_hasher.update(mac_key);
    mac_hasher.update(data_hash);

    let result = mac_hasher.finalize();
    let mut mac = [0u8; MAC_LEN];

    mac.copy_from_slice(&result);
    mac
}
