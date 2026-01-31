# Archer

File encryption tool that disguises encrypted files as Arch Linux ISO images.

## Features

- AES 256 CTR encryption with PBKDF2 key derivation
- HMAC SHA256 authentication
- Encrypted files appear as legitimate ISO images
- Parallel processing for large files
- Secure memory handling with automatic key zeroization

## Installation

```bash
cargo build --release
```

Binary will be in target/release/archer

## Usage

### Encrypt Files

Basic encryption with auto generated filename:
```bash
archer enc input.txt
```

Specify custom output file:
```bash
archer enc input.txt -o custom.iso
```

Set minimum output size in MB:
```bash
archer enc input.txt -s 700
```

Combine options:
```bash
archer enc secret.pdf -o backup.iso -s 1024
```

### Decrypt Files

Basic decryption:
```bash
archer dec encrypted.iso -o output.txt
```

Decrypt to specific location:
```bash
archer dec backup.iso -o /path/to/recovered.pdf
```

### Password Methods

Interactive prompt (default and recommended):
```bash
archer enc file.txt
Password:
Confirm password:
```

Environment variable (less secure):
```bash
ARCHER_KEY=yourpassword archer enc file.txt
```

Windows environment variable:
```bash
set ARCHER_KEY=yourpassword
archer enc file.txt
```

### Examples

Encrypt a document:
```bash
archer enc report.docx
```

Encrypt with specific size:
```bash
archer enc database.sql -s 4096
```

Decrypt a file:
```bash
archer dec archlinux-2025.01.31-0001-x86_64.iso -o report.docx
```

## How It Works

1. Encryption: Generates random salt and nonce, derives keys via PBKDF2, encrypts with AES 256 CTR, computes MAC, wraps in ISO header and footer
2. Decryption: Validates ISO, reads metadata, derives keys, verifies MAC, decrypts data
3. Disguise: Output files contain valid ISO signatures and sector alignment, appearing as bootable images

## Security

- 100000 PBKDF2 iterations for encryption key
- 20000 iterations for MAC key
- Constant time MAC comparison
- Automatic cleanup of sensitive data from memory
- Failed decryption removes partial output files

## File Format

```
ISO Header: 32KB
Magic: ARCH
Version: 1
Salt: 32 bytes
Nonce: 8 bytes
Size: 8 bytes
Encrypted Data
MAC: 32 bytes
ISO Footer Padding
```