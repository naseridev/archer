use chrono::{Datelike, Local};

use crate::constants::*;
use crate::error::{ArcherError, Result};

static ZERO_BUFFER: [u8; 65536] = [0u8; 65536];

pub fn get_version_string() -> String {
    let now = Local::now();
    format!("{:04}.{:02}.{:02}", now.year(), now.month(), now.day())
}

pub fn create_header() -> Vec<u8> {
    let version = get_version_string();
    let mut header = vec![0u8; HEADER_SIZE];

    header[32..40].copy_from_slice(b"\x01CD001\x01\x00");

    let system_id = format!("ARCH LINUX {} X86_64", version);
    let system_id_bytes = system_id.as_bytes();
    let copy_len = system_id_bytes.len().min(32);

    header[40..40 + copy_len].copy_from_slice(&system_id_bytes[..copy_len]);
    header[40 + copy_len..128].fill(b' ');

    let mid = HEADER_SIZE / 2;
    header[mid + 13..mid + 17].copy_from_slice(&[0x01, 0x00, 0x00, 0x01]);

    header
}

pub fn write_footer<W: std::io::Write>(
    writer: &mut W,
    current_size: usize,
    min_size: usize,
) -> Result<()> {
    let target_size = current_size.max(min_size);
    let aligned_target = target_size.div_ceil(SECTOR_SIZE) * SECTOR_SIZE;
    let mut remaining = aligned_target.saturating_sub(current_size);

    while remaining > 0 {
        let write_size = remaining.min(ZERO_BUFFER.len());
        writer.write_all(&ZERO_BUFFER[..write_size])?;
        remaining -= write_size;
    }

    Ok(())
}

pub fn validate_header(data: &[u8]) -> Result<()> {
    if data.len() < HEADER_SIZE {
        return Err(ArcherError::InvalidFormat(
            "File too small for ISO header".into(),
        ));
    }

    if &data[32..37] != b"\x01CD00" {
        return Err(ArcherError::InvalidFormat("Invalid ISO signature".into()));
    }

    Ok(())
}
