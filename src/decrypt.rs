use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use subtle::ConstantTimeEq;

use crate::constants::*;
use crate::crypto::{compute_mac, derive_keys, process_chunk_in_place};
use crate::error::{ArcherError, Result};
use crate::iso;

pub fn decrypt(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    let metadata = match std::fs::metadata(input_path) {
        Ok(m) if m.is_file() => m,
        _ => return Err(ArcherError::FileNotFound(input_path.display().to_string())),
    };

    if output_path.symlink_metadata().is_ok() {
        return Err(ArcherError::FileExists(output_path.display().to_string()));
    }

    let file_size = metadata.len();
    let min_file_size = (HEADER_SIZE + METADATA_SIZE + MAC_LEN) as u64;
    if file_size < min_file_size {
        return Err(ArcherError::InvalidFormat("Input file too small".into()));
    }

    println!();
    println!("[*] Validating ISO header...");

    let mut input = BufReader::new(File::open(input_path)?);
    let mut header = vec![0u8; HEADER_SIZE];

    input.read_exact(&mut header)?;
    iso::validate_header(&header)?;
    drop(header);

    println!("[*] Reading metadata...");

    let mut header_data = [0u8; METADATA_SIZE];
    input.read_exact(&mut header_data)?;

    if &header_data[..4] != MAGIC {
        return Err(ArcherError::InvalidFormat("Invalid magic bytes".into()));
    }

    let version = header_data[4];
    if version != VERSION {
        return Err(ArcherError::InvalidFormat(format!(
            "Unsupported version: {}",
            version
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let mut size_buf = [0u8; 8];

    salt.copy_from_slice(&header_data[5..5 + SALT_LEN]);
    nonce.copy_from_slice(&header_data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN]);
    size_buf.copy_from_slice(&header_data[5 + SALT_LEN + NONCE_LEN..METADATA_SIZE]);

    let expected_size = u64::from_le_bytes(size_buf);
    let max_payload_size = file_size - min_file_size;
    if expected_size > max_payload_size {
        return Err(ArcherError::InvalidFormat(
            "Encrypted data size exceeds file size".into(),
        ));
    }

    println!("[*] Deriving keys...");
    let keys = derive_keys(password, &salt);

    let mut hasher = Sha256::new();
    hasher.update(header_data);

    let max_in_memory = (BATCH_CHUNKS * CHUNK_SIZE) as u64;
    let total_chunks = expected_size.div_ceil(CHUNK_SIZE as u64);

    if expected_size <= max_in_memory {
        println!("[*] Reading encrypted data...");

        let mut chunks = Vec::with_capacity(total_chunks as usize);
        let mut offset = 0u64;

        while offset < expected_size {
            let chunk_size = (CHUNK_SIZE as u64).min(expected_size - offset) as usize;
            let mut buffer = vec![0u8; chunk_size];

            input.read_exact(&mut buffer)?;
            hasher.update(&buffer);
            chunks.push((buffer, offset));
            offset += chunk_size as u64;
        }

        println!("[*] Verifying MAC...");

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

        println!("[*] Decrypting data ({} chunks)...", chunks.len());

        chunks.par_iter_mut().for_each(|(data, chunk_offset)| {
            process_chunk_in_place(&keys.encryption_key, &nonce, data, *chunk_offset);
        });

        println!("[*] Writing decrypted file...");

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ArcherError::FileExists(output_path.display().to_string())
                } else {
                    ArcherError::Io(e)
                }
            })?;

        let mut output = BufWriter::new(file);

        for (decrypted, _) in &chunks {
            if let Err(e) = output.write_all(decrypted) {
                drop(output);
                std::fs::remove_file(output_path).ok();
                return Err(ArcherError::Io(e));
            }
        }

        if let Err(e) = output.flush() {
            drop(output);
            std::fs::remove_file(output_path).ok();
            return Err(ArcherError::Io(e));
        }
    } else {
        println!("[*] Reading encrypted data and verifying MAC...");

        let mut hash_buf = vec![0u8; CHUNK_SIZE];
        let mut remaining = expected_size;

        while remaining > 0 {
            let to_read = (CHUNK_SIZE as u64).min(remaining) as usize;
            input.read_exact(&mut hash_buf[..to_read])?;
            hasher.update(&hash_buf[..to_read]);
            remaining -= to_read as u64;
        }
        drop(hash_buf);

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

        input.seek(SeekFrom::Start((HEADER_SIZE + METADATA_SIZE) as u64))?;

        println!(
            "[*] Decrypting and writing data ({} chunks)...",
            total_chunks
        );

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ArcherError::FileExists(output_path.display().to_string())
                } else {
                    ArcherError::Io(e)
                }
            })?;

        let mut output = BufWriter::new(file);
        let mut batch: Vec<(Vec<u8>, u64)> = (0..BATCH_CHUNKS)
            .map(|_| (vec![0u8; CHUNK_SIZE], 0u64))
            .collect();
        let mut offset = 0u64;

        let decrypt_result: Result<()> = (|| {
            while offset < expected_size {
                let mut count = 0usize;
                while count < BATCH_CHUNKS && offset < expected_size {
                    let chunk_size = (CHUNK_SIZE as u64).min(expected_size - offset) as usize;
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

                for (decrypted, _) in &batch[..count] {
                    output.write_all(decrypted)?;
                }
            }
            output.flush()?;
            Ok(())
        })();

        if let Err(e) = decrypt_result {
            drop(output);
            std::fs::remove_file(output_path).ok();
            return Err(e);
        }
    }

    println!(
        "[+] Decrypted: {} >> {} ({} bytes)",
        input_path.display(),
        output_path.display(),
        expected_size
    );

    Ok(())
}
