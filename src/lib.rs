//! # rar5
//!
//! Pure-Rust RAR5 archive library. Creates, reads, and extracts RAR5 archives
//! with native LZSS+Huffman compression — no external binaries required.
//!
//! ## Quick Start
//!
//! ```no_run
//! use rar5::RarArchive;
//!
//! // Create an archive
//! let mut rar = RarArchive::create("backup.rar").unwrap();
//! rar.add("src/", 3).unwrap();
//! rar.add_bytes("notes.txt", b"Some notes", 3).unwrap();
//! rar.close().unwrap();
//!
//! // Extract an archive
//! let mut rar = RarArchive::open("backup.rar").unwrap();
//! rar.extract_all("/tmp/output/").unwrap();
//! ```
//!
//! ## License
//!
//! BSD-2-Clause. See LICENSE for details.

pub mod archive;
pub mod codec;
pub mod compression;
pub mod constants;
pub mod encryption;
pub mod error;
pub mod headers;
pub mod vint;

pub use archive::{ArchiveEntry, RarArchive};
pub use constants::*;
pub use encryption::EncryptionParams;
pub use error::{RarError, RarResult};
