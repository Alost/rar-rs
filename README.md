# rar-rs

Pure-Rust RAR5 archive library and tools. Creates, reads, and extracts RAR5
archives with native LZSS+Huffman compression — no external binaries required.

**License:** BSD-2-Clause — see [NOTICE](NOTICE) for legal details.

---

## Features

| Feature                              | Status |
|--------------------------------------|--------|
| Create RAR5 archives                 |   done |
| Extract RAR5 archives                |   done |
| Native LZSS+Huffman compression      |   done |
| Compression levels 0-5               |   done |
| CRC32 integrity verification         |   done |
| Directory entries                    |   done |
| Timestamp preservation               |   done |
| Solid archive decompression          |   done |
| File-level AES-256 encryption        |   done |
| File-level AES-256 decryption        |   done |
| Header-encrypted archive decryption  |   done |
| Multi-volume archive reading         |   done |
| Multi-volume archive creation        |   done |

Archives produced by rar-rs are fully interoperable with WinRAR and unrar.

---

## CLI Tools

### rar

```
rar a [-m0..-m5] [-p<password>] [-v<size>] archive.rar files...   Create archive
rar l archive.rar                          List contents
rar i archive.rar                          Show info
```

The `-v` flag creates multi-volume archives (e.g. `-v1m` for 1 MB volumes, `-v100k` for 100 KB).

### unrar

```
unrar x [-p<password>] archive.rar [dest/]    Extract with full paths
unrar e [-p<password>] archive.rar [dest/]    Extract flat
unrar l [-p<password>] archive.rar            List contents
unrar t [-p<password>] archive.rar            Test integrity
unrar p [-p<password>] archive.rar [file]     Print to stdout
```

---

## Library Usage

```rust
use rar5::RarArchive;

// Create
let mut rar = RarArchive::create("backup.rar")?;
rar.add("src/", 3)?;
rar.add_bytes("notes.txt", b"Some notes", 3)?;
rar.close()?;

// Extract
let mut rar = RarArchive::open("backup.rar")?;
rar.extract_all("/tmp/output/")?;

// Read a single file
let mut rar = RarArchive::open("backup.rar")?;
let data = rar.read("notes.txt")?;

// Create an encrypted archive
let mut rar = RarArchive::create_with_password("secret.rar", "mypassword")?;
rar.add("classified.txt", 3)?;
rar.close()?;

// Open an encrypted archive
let mut rar = RarArchive::open_with_password("secret.rar", "mypassword")?;
let data = rar.read("classified.txt")?;

// Create a multi-volume archive (1 MB per volume)
let mut rar = RarArchive::create_multivolume("backup.rar", 1048576)?;
rar.add("large_file.bin", 3)?;
rar.close()?;

// Open a multi-volume archive (auto-discovers all volumes)
let mut rar = RarArchive::open("backup.part1.rar")?;
rar.extract_all("/tmp/output/")?;
```

---

## Module Layout

```
src/
+-- lib.rs              Public API
+-- archive.rs          RarArchive high-level interface
+-- headers.rs          Block/header structs
+-- compression.rs      Compress/decompress dispatch
+-- encryption.rs       AES-256-CBC + PBKDF2 key derivation
+-- constants.rs        RAR5 format constants
+-- vint.rs             Variable-length integer codec
+-- error.rs            Error types
+-- codec/
|   +-- mod.rs          Codec public API
|   +-- decoder.rs      Block decoder + symbol stream
|   +-- encoder.rs      Block encoder + match finder
|   +-- bitstream.rs    MSB-first bit reader/writer
|   +-- huffman.rs      Canonical Huffman tables
|   +-- window.rs       Sliding window buffer
|   +-- filters.rs      Delta, E8, E8E9, ARM filters
|   +-- lz_match.rs     Hash-chain match finder
|   +-- tables.rs       Symbol/table constants
+-- bin/
    +-- rar.rs          CLI archive creator
    +-- unrar.rs        CLI archive extractor
```

---

## Building

```bash
cargo build --release
```

Binaries are at `target/release/rar` and `target/release/unrar`.

---

## Legal

This is a clean-room implementation for software conservancy and educational
purposes. See [NOTICE](NOTICE) for the full legal notice, including trademark
attribution and scope limitations. Licensed under BSD-2-Clause — see
[LICENSE](LICENSE).
