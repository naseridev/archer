use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use subtle::ConstantTimeEq;

use crate::constants::*;
use crate::crypto::{compute_mac, derive_keys, process_chunk};
use crate::error::{ArcherError, Result};
use crate::iso;

pub fn decrypt(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    if !input_path.exists() || !input_path.is_file() {
        return Err(ArcherError::FileNotFound(input_path.display().to_string()));
    }

    if output_path.exists() {
        return Err(ArcherError::FileExists(output_path.display().to_string()));
    }

    let file_size = std::fs::metadata(input_path)?.len() as usize;
    if file_size < HEADER_SIZE + 100 {
        return Err(ArcherError::InvalidFormat("Input file too small".into()));
    }

    println!();
    println!("[*] Validating ISO header...");

    let mut input = BufReader::new(File::open(input_path)?);
    let mut header = vec![0u8; HEADER_SIZE];

    input.read_exact(&mut header)?;
    iso::validate_header(&header)?;

    println!("[*] Reading metadata...");

    let mut magic = [0u8; 4];
    input.read_exact(&mut magic)?;

    if magic != MAGIC {
        return Err(ArcherError::InvalidFormat("Invalid magic bytes".into()));
    }

    let mut version_buf = [0u8; 1];
    input.read_exact(&mut version_buf)?;

    if version_buf[0] != VERSION {
        return Err(ArcherError::InvalidFormat(format!(
            "Unsupported version: {}",
            version_buf[0]
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let mut size_buf = [0u8; 8];

    input.read_exact(&mut salt)?;
    input.read_exact(&mut nonce)?;
    input.read_exact(&mut size_buf)?;

    let expected_size = u64::from_le_bytes(size_buf) as usize;

    println!("[*] Deriving keys...");
    let keys = derive_keys(password, &salt);

    let mut hasher = Sha256::new();
    let mut header_data = Vec::new();

    header_data.extend_from_slice(&magic);
    header_data.push(version_buf[0]);
    header_data.extend_from_slice(&salt);
    header_data.extend_from_slice(&nonce);
    header_data.extend_from_slice(&size_buf);
    hasher.update(&header_data);

    println!("[*] Reading encrypted data...");

    let mut encrypted_chunks = Vec::new();
    let mut offset = 0;

    while offset < expected_size {
        let chunk_size = CHUNK_SIZE.min(expected_size - offset);
        let mut buffer = vec![0u8; chunk_size];

        input.read_exact(&mut buffer)?;
        encrypted_chunks.push((buffer, offset));
        offset += chunk_size;
    }

    println!("[*] Decrypting data ({} chunks)...", encrypted_chunks.len());

    let decrypted_chunks: Vec<Vec<u8>> = encrypted_chunks
        .par_iter()
        .map(|(data, offset)| process_chunk(&keys.encryption_key, &nonce, data, *offset))
        .collect();

    println!("[*] Verifying MAC...");

    for (encrypted, _) in &encrypted_chunks {
        hasher.update(encrypted);
    }

    let mut stored_mac = [0u8; MAC_LEN];
    if let Err(e) = input.read_exact(&mut stored_mac) {
        return Err(ArcherError::InvalidFormat(format!("MAC missing: {}", e)));
    }

    let computed_mac = compute_mac(&keys.mac_key, &hasher.finalize());

    let mac_valid: bool = computed_mac.ct_eq(&stored_mac).into();
    if !mac_valid {
        println!("[-] MAC verification failed");
        return Err(ArcherError::MacVerificationFailed);
    }

    println!("[*] Writing decrypted file...");

    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .map_err(ArcherError::Io)?,
    );

    for decrypted in &decrypted_chunks {
        if let Err(e) = output.write_all(decrypted) {
            std::fs::remove_file(output_path).ok();
            return Err(ArcherError::Io(e));
        }
    }

    if let Err(e) = output.flush() {
        std::fs::remove_file(output_path).ok();
        return Err(ArcherError::Io(e));
    }

    println!(
        "[+] Decrypted: {} >> {} ({} bytes)",
        input_path.display(),
        output_path.display(),
        expected_size
    );

    Ok(())
}
