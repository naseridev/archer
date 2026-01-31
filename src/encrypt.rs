use rand::RngCore;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::constants::*;
use crate::crypto::{compute_mac, derive_keys, process_chunk};
use crate::error::{ArcherError, Result};
use crate::iso;

fn get_unique_output_path(base_name: &str) -> PathBuf {
    let mut counter = 1u32;
    loop {
        let path = if counter <= 9999 {
            PathBuf::from(format!("{}-{:04}-x86_64.iso", base_name, counter))
        } else {
            PathBuf::from(format!("{}-{}-x86_64.iso", base_name, counter))
        };

        if !path.exists() {
            return path;
        }

        counter = counter.saturating_add(1);
        if counter == 0 {
            return PathBuf::from(format!("{}-overflow-x86_64.iso", base_name));
        }
    }
}

pub fn encrypt(
    input_path: &Path,
    output_path: Option<&Path>,
    min_size_mb: u64,
    password: &str,
) -> Result<()> {
    if !input_path.exists() || !input_path.is_file() {
        return Err(ArcherError::FileNotFound(input_path.display().to_string()));
    }

    let output_path = output_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let base_name = format!("archlinux-{}", iso::get_version_string());
        get_unique_output_path(&base_name)
    });

    if output_path.exists() {
        return Err(ArcherError::FileExists(output_path.display().to_string()));
    }

    let file_size = std::fs::metadata(input_path)?.len() as usize;

    println!();
    println!("[*] Initializing encryption...");

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];

    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    println!("[*] Deriving encryption keys...");

    let keys = derive_keys(password, &salt);
    let mut header_data = Vec::new();

    header_data.extend_from_slice(MAGIC);
    header_data.push(VERSION);
    header_data.extend_from_slice(&salt);
    header_data.extend_from_slice(&nonce);
    header_data.extend_from_slice(&(file_size as u64).to_le_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&header_data);

    let iso_header = iso::create_header();

    println!("[*] Creating output file...");

    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)?,
    );

    output.write_all(&iso_header)?;
    output.write_all(&header_data)?;

    println!("[*] Reading input file...");

    let mut input = BufReader::new(File::open(input_path)?);
    let mut chunks = Vec::new();
    let mut offset = 0;

    while offset < file_size {
        let chunk_size = CHUNK_SIZE.min(file_size - offset);
        let mut buffer = vec![0u8; chunk_size];
        input.read_exact(&mut buffer)?;
        chunks.push((buffer, offset));
        offset += chunk_size;
    }

    println!("[*] Encrypting data ({} chunks)...", chunks.len());

    let encrypted_chunks: Vec<Vec<u8>> = chunks
        .par_iter()
        .map(|(data, offset)| process_chunk(&keys.encryption_key, &nonce, data, *offset))
        .collect();

    println!("[*] Writing encrypted data...");

    for encrypted in &encrypted_chunks {
        output.write_all(encrypted)?;
        hasher.update(encrypted);
    }

    println!("[*] Computing MAC...");

    let mac = compute_mac(&keys.mac_key, &hasher.finalize());
    output.write_all(&mac)?;

    println!("[*] Applying ISO disguise...");

    let total_before_footer = iso_header.len() + header_data.len() + file_size + MAC_LEN;
    let min_size_bytes = (min_size_mb as usize) * 1024 * 1024;

    iso::write_footer(&mut output, total_before_footer, min_size_bytes)?;
    output.flush()?;

    let final_size = std::fs::metadata(&output_path)?.len();

    println!(
        "[+] Encrypted: {} >> {} ({} bytes, ISO disguised)",
        input_path.display(),
        output_path.display(),
        final_size
    );

    Ok(())
}
