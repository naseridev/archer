use rand::RngCore;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::constants::*;
use crate::crypto::{compute_mac, derive_keys, process_chunk_in_place};
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

        if path.symlink_metadata().is_err() {
            return path;
        }

        match counter.checked_add(1) {
            Some(next) => counter = next,
            None => return PathBuf::from(format!("{}-overflow-x86_64.iso", base_name)),
        }
    }
}

pub fn encrypt(
    input_path: &Path,
    output_path: Option<&Path>,
    min_size_mb: u64,
    password: &str,
) -> Result<()> {
    let metadata = match std::fs::metadata(input_path) {
        Ok(m) if m.is_file() => m,
        _ => return Err(ArcherError::FileNotFound(input_path.display().to_string())),
    };

    let output_path = output_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let base_name = format!("archlinux-{}", iso::get_version_string());
        get_unique_output_path(&base_name)
    });

    if output_path.symlink_metadata().is_ok() {
        return Err(ArcherError::FileExists(output_path.display().to_string()));
    }

    let file_size = metadata.len();
    let mut input = BufReader::new(File::open(input_path)?);

    println!();
    println!("[*] Initializing encryption...");

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let mut rng = rand::thread_rng();

    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    println!("[*] Deriving encryption keys...");

    let keys = derive_keys(password, &salt);
    let mut header_data = [0u8; METADATA_SIZE];

    header_data[..4].copy_from_slice(MAGIC);
    header_data[4] = VERSION;
    header_data[5..5 + SALT_LEN].copy_from_slice(&salt);
    header_data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN].copy_from_slice(&nonce);
    header_data[5 + SALT_LEN + NONCE_LEN..METADATA_SIZE].copy_from_slice(&file_size.to_le_bytes());

    let mut hasher = Sha256::new();
    hasher.update(header_data);

    let iso_header = iso::create_header();

    println!("[*] Creating output file...");

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ArcherError::FileExists(output_path.display().to_string())
            } else {
                ArcherError::Io(e)
            }
        })?;

    let mut output = BufWriter::new(file);

    let encrypt_result: Result<()> = (|| {
        output.write_all(&iso_header)?;
        output.write_all(&header_data)?;

        let total_chunks = file_size.div_ceil(CHUNK_SIZE as u64);
        let batch_cap = (total_chunks as usize).min(BATCH_CHUNKS);
        let mut batch: Vec<(Vec<u8>, u64)> = (0..batch_cap)
            .map(|_| (vec![0u8; CHUNK_SIZE], 0u64))
            .collect();
        let mut offset = 0u64;

        println!(
            "[*] Reading, encrypting, and writing data ({} chunks)...",
            total_chunks
        );

        while offset < file_size {
            let mut count = 0usize;
            while count < batch_cap && offset < file_size {
                let chunk_size = (CHUNK_SIZE as u64).min(file_size - offset) as usize;
                let (ref mut buf, ref mut chunk_offset) = batch[count];
                buf.resize(chunk_size, 0);
                input.read_exact(buf)?;
                *chunk_offset = offset;
                offset += chunk_size as u64;
                count += 1;
            }

            batch[..count]
                .par_iter_mut()
                .for_each(|(data, chunk_offset)| {
                    process_chunk_in_place(&keys.encryption_key, &nonce, data, *chunk_offset);
                });

            for (encrypted, _) in &batch[..count] {
                output.write_all(encrypted)?;
                hasher.update(encrypted);
            }
        }

        println!("[*] Computing MAC...");

        let mac = compute_mac(&keys.mac_key, &hasher.finalize());
        output.write_all(&mac)?;

        println!("[*] Applying ISO disguise...");

        let total_before_footer =
            (iso_header.len() + header_data.len() + MAC_LEN) as u64 + file_size;
        let min_size_bytes = min_size_mb.saturating_mul(1024 * 1024);

        iso::write_footer(
            &mut output,
            total_before_footer as usize,
            min_size_bytes as usize,
        )?;
        output.flush()?;
        Ok(())
    })();

    if let Err(e) = encrypt_result {
        drop(output);
        std::fs::remove_file(&output_path).ok();
        return Err(e);
    }

    let final_size = std::fs::metadata(&output_path)?.len();

    println!(
        "[+] Encrypted: {} >> {} ({} bytes, ISO disguised)",
        input_path.display(),
        output_path.display(),
        final_size
    );

    Ok(())
}
