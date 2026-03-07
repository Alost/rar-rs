/// RarArchive — high-level RAR5 archive interface.
///
/// Supports opening existing archives for reading/extraction and creating
/// new archives from scratch.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::codec::DecoderState;
use crate::compression;
use crate::constants::*;
use crate::encryption::{self, parse_archive_encrypt_header};
use crate::error::{RarError, RarResult};
use crate::headers::*;
use crate::vint;

/// A single entry in the archive (public API).
#[derive(Clone, Debug)]
pub struct ArchiveEntry {
    pub header: FileHeader,
}

impl ArchiveEntry {
    pub fn name(&self) -> &str {
        &self.header.name
    }

    pub fn size(&self) -> u64 {
        self.header.unpacked_size
    }

    pub fn compressed_size(&self) -> u64 {
        self.header.packed_size
    }

    pub fn is_dir(&self) -> bool {
        self.header.is_directory
    }

    pub fn crc32(&self) -> Option<u32> {
        self.header.crc32_val
    }

    pub fn method_name(&self) -> &'static str {
        method_name(self.header.comp_method)
    }
}

/// RAR5 archive reader/writer.
pub struct RarArchive {
    path: PathBuf,
    mode: Mode,
    entries: Vec<ArchiveEntry>,
    stream: Option<File>,
    /// Persistent decoder state for solid archive chains.
    solid_state: Option<DecoderState>,
    /// Index of the last file decoded in the solid chain (-1 = none).
    solid_decoded_through: isize,
    /// Password for encrypted archives.
    password: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Read,
    Write,
    Append,
}

impl RarArchive {
    // ── Constructors ───────────────────────────────────────────────────────

    /// Open an existing RAR5 archive for reading.
    pub fn open(path: impl AsRef<Path>) -> RarResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut archive = RarArchive {
            path,
            mode: Mode::Read,
            entries: Vec::new(),
            stream: None,
            solid_state: None,
            solid_decoded_through: -1,
            password: None,
        };
        archive.open_read()?;
        Ok(archive)
    }

    /// Open an existing RAR5 archive with a password for encrypted content.
    pub fn open_with_password(path: impl AsRef<Path>, password: &str) -> RarResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut archive = RarArchive {
            path,
            mode: Mode::Read,
            entries: Vec::new(),
            stream: None,
            solid_state: None,
            solid_decoded_through: -1,
            password: Some(password.to_string()),
        };
        archive.open_read()?;
        Ok(archive)
    }

    /// Set the password for decryption.
    pub fn set_password(&mut self, password: &str) {
        self.password = Some(password.to_string());
    }

    /// Create a new RAR5 archive (overwrites existing file).
    pub fn create(path: impl AsRef<Path>) -> RarResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut archive = RarArchive {
            path,
            mode: Mode::Write,
            entries: Vec::new(),
            stream: None,
            solid_state: None,
            solid_decoded_through: -1,
            password: None,
        };
        archive.open_write()?;
        Ok(archive)
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    fn open_read(&mut self) -> RarResult<()> {
        let f = File::open(&self.path)?;
        self.stream = Some(f);
        self.verify_signature()?;
        self.scan_blocks()?;
        Ok(())
    }

    fn open_write(&mut self) -> RarResult<()> {
        let f = File::create(&self.path)?;
        self.stream = Some(f);
        self.write_signature()?;
        self.write_archive_header()?;
        Ok(())
    }

    /// Finalize the archive (writes end-of-archive block in write mode).
    pub fn close(&mut self) -> RarResult<()> {
        if self.stream.is_some() && (self.mode == Mode::Write || self.mode == Mode::Append) {
            self.write_end_block()?;
            self.mode = Mode::Read; // prevent double-write
        }
        self.stream = None;
        Ok(())
    }

    // ── Signature ──────────────────────────────────────────────────────────

    fn verify_signature(&mut self) -> RarResult<()> {
        let stream = self.stream.as_mut().unwrap();
        let mut sig = [0u8; 8];
        let n = stream.read(&mut sig)?;
        if n < 8 {
            return Err(RarError::Format(format!(
                "file too short to be a RAR archive ({n} bytes read)"
            )));
        }
        if sig[..7] == *RAR4_SIGNATURE && sig != *RAR5_SIGNATURE {
            return Err(RarError::Unsupported(
                "RAR4 format detected; rar-rs only supports RAR5".into(),
            ));
        }
        if sig != *RAR5_SIGNATURE {
            return Err(RarError::Format(format!(
                "not a RAR5 archive (bad signature: {sig:?})"
            )));
        }
        Ok(())
    }

    fn write_signature(&mut self) -> RarResult<()> {
        let stream = self.stream.as_mut().unwrap();
        stream.write_all(RAR5_SIGNATURE)?;
        Ok(())
    }

    // ── Block scanning ─────────────────────────────────────────────────────

    fn scan_blocks(&mut self) -> RarResult<()> {
        self.entries.clear();
        let stream = self.stream.as_mut().unwrap();

        loop {
            let raw = match RawBlock::read_from(stream) {
                Ok(b) => b,
                Err(RarError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };

            let stream_pos = stream.stream_position()?;

            match raw.block_type {
                BLOCK_TYPE_ARCHIVE_HEADER => {
                    let _ah = ArchiveHeader::from_raw(&raw)?;
                }
                BLOCK_TYPE_FILE_HEADER => {
                    let fh = FileHeader::from_raw(&raw, stream_pos)?;
                    self.entries.push(ArchiveEntry { header: fh });
                }
                BLOCK_TYPE_END_ARCHIVE => break,
                BLOCK_TYPE_ENCRYPT_HEADER => {
                    return self.scan_encrypted_blocks(&raw);
                }
                _ => {}
            }

            if raw.data_size > 0 {
                stream.seek(SeekFrom::Start(raw.data_offset + raw.data_size))?;
            }
        }

        Ok(())
    }

    /// Parse the archive-level encryption header and scan all encrypted blocks.
    ///
    /// In header-encrypted archives, each block after the encryption header is:
    /// `[16-byte IV] [AES-256-CBC encrypted header, padded to 16B] [file data if any]`
    fn scan_encrypted_blocks(&mut self, encrypt_raw: &RawBlock) -> RarResult<()> {
        let password = self.password.as_ref().ok_or_else(|| {
            RarError::Encrypted("archive has encrypted headers; provide a password".into())
        })?;

        // Parse the encryption header to get salt, strength, etc.
        let encr_params = parse_archive_encrypt_header(encrypt_raw)?;

        if !encr_params.verify_password(password) {
            return Err(RarError::Encrypted("wrong password".into()));
        }

        let key = encr_params.get_key(password);
        let stream = self.stream.as_mut().unwrap();

        loop {
            // Each encrypted block: [16-byte IV] [encrypted header padded to 16B]
            let mut iv = [0u8; 16];
            match stream.read_exact(&mut iv) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }

            // Read first 16 encrypted bytes to determine header size
            let mut first_block = [0u8; 16];
            stream.read_exact(&mut first_block)?;

            let first_pt = encryption::decrypt_data(&first_block, &key, &iv)?;

            // Parse CRC and header size from decrypted data
            let _crc = u32::from_le_bytes(first_pt[0..4].try_into().unwrap());
            let (hdr_size, vint_len) = vint::decode_from_slice(&first_pt, 4)
                .map_err(|e| RarError::Format(format!("encrypted block vint: {e}")))?;

            if hdr_size == 0 || hdr_size > 2 * 1024 * 1024 {
                return Err(RarError::Format(format!(
                    "implausible encrypted header size: {hdr_size}"
                )));
            }

            // Total raw bytes = CRC(4) + vint + header_body, padded to 16B
            let total_raw = 4 + vint_len + hdr_size as usize;
            let enc_size = ((total_raw + 15) / 16) * 16;

            // Read remaining encrypted blocks (we already have the first 16)
            let mut full_ct = vec![0u8; enc_size];
            full_ct[..16].copy_from_slice(&first_block);
            if enc_size > 16 {
                stream.read_exact(&mut full_ct[16..])?;
            }

            // Decrypt the full header
            let full_pt = encryption::decrypt_data(&full_ct, &key, &iv)?;

            // Extract just the header data (skip CRC + vint)
            let header_data = full_pt[4 + vint_len..4 + vint_len + hdr_size as usize].to_vec();

            // Verify CRC
            let size_bytes = vint::encode(hdr_size);
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&size_bytes);
            hasher.update(&header_data);
            let computed_crc = hasher.finalize();
            if computed_crc != _crc {
                return Err(RarError::Crc {
                    expected: _crc,
                    actual: computed_crc,
                    context: "encrypted block header".into(),
                });
            }

            // Parse block type and flags from header_data
            let mut offset = 0;
            let (block_type, n) = vint::decode_from_slice(&header_data, offset)
                .map_err(|e| RarError::Format(format!("block type: {e}")))?;
            offset += n;
            let (flags, n) = vint::decode_from_slice(&header_data, offset)
                .map_err(|e| RarError::Format(format!("block flags: {e}")))?;
            offset += n;

            let mut _extra_size = 0u64;
            let mut data_size = 0u64;
            if flags & BLOCK_FLAG_EXTRA_DATA != 0 {
                let (v, n) = vint::decode_from_slice(&header_data, offset)
                    .map_err(|e| RarError::Format(format!("extra size: {e}")))?;
                _extra_size = v;
                offset += n;
            }
            if flags & BLOCK_FLAG_DATA_AREA != 0 {
                let (v, n) = vint::decode_from_slice(&header_data, offset)
                    .map_err(|e| RarError::Format(format!("data size: {e}")))?;
                data_size = v;
                offset += n;
            }
            let _ = offset;

            // Build a RawBlock so we can reuse existing header parsers
            let raw = RawBlock {
                header_crc: _crc,
                header_data,
                data_size,
                data_offset: stream.stream_position()?,
                block_type,
                flags,
            };

            match block_type {
                BLOCK_TYPE_ARCHIVE_HEADER => {
                    let _ah = ArchiveHeader::from_raw(&raw)?;
                }
                BLOCK_TYPE_FILE_HEADER => {
                    let fh = FileHeader::from_raw(&raw, raw.data_offset)?;
                    self.entries.push(ArchiveEntry { header: fh });
                }
                BLOCK_TYPE_END_ARCHIVE => break,
                _ => {}
            }

            // Skip file data area if present
            if data_size > 0 {
                stream.seek(SeekFrom::Current(data_size as i64))?;
            }
        }

        Ok(())
    }

    // ── Writing ────────────────────────────────────────────────────────────

    fn write_archive_header(&mut self) -> RarResult<()> {
        let hdr = ArchiveHeader {
            flags: 0,
            extra_data: Vec::new(),
        };
        let stream = self.stream.as_mut().unwrap();
        stream.write_all(&hdr.to_bytes())?;
        Ok(())
    }

    fn write_end_block(&mut self) -> RarResult<()> {
        let eoa = EndOfArchiveHeader { flags: 0 };
        let stream = self.stream.as_mut().unwrap();
        stream.write_all(&eoa.to_bytes())?;
        Ok(())
    }

    // ── Public API: listing ────────────────────────────────────────────────

    /// Return all entries in the archive.
    pub fn list(&self) -> &[ArchiveEntry] {
        &self.entries
    }

    /// Find an entry by name.
    pub fn get_entry(&self, name: &str) -> Option<&ArchiveEntry> {
        self.entries.iter().find(|e| e.name() == name)
    }

    /// Return a list of all entry names.
    pub fn namelist(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name()).collect()
    }

    // ── Public API: reading ────────────────────────────────────────────────

    /// Read and return the uncompressed content of a member.
    pub fn read(&mut self, name: &str) -> RarResult<Vec<u8>> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.name() == name)
            .ok_or_else(|| RarError::Format(format!("member not found: {name:?}")))?
            .clone();
        self.decode_single_file(&entry)
    }

    /// Extract all archive contents to `dest_dir`.
    pub fn extract_all(&mut self, dest_dir: impl AsRef<Path>) -> RarResult<()> {
        let dest = dest_dir.as_ref();
        let entries: Vec<_> = self.entries.clone();
        for entry in &entries {
            self.extract_entry(entry, dest)?;
        }
        Ok(())
    }

    /// Extract a single entry to `dest_dir`.
    pub fn extract(&mut self, name: &str, dest_dir: impl AsRef<Path>) -> RarResult<PathBuf> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.name() == name)
            .ok_or_else(|| RarError::Format(format!("member not found: {name:?}")))?
            .clone();
        self.extract_entry(&entry, dest_dir.as_ref())
    }

    fn extract_entry(&mut self, entry: &ArchiveEntry, dest_dir: &Path) -> RarResult<PathBuf> {
        let dest_path = dest_dir.join(&entry.header.name);

        if entry.is_dir() {
            fs::create_dir_all(&dest_path)?;
            return Ok(dest_path);
        }

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let data = self.decode_single_file(entry)?;
        fs::write(&dest_path, &data)?;

        // Restore mtime (best-effort)
        if entry.header.mtime != 0 {
            let mtime = UNIX_EPOCH + std::time::Duration::from_secs(entry.header.mtime as u64);
            let times = std::fs::FileTimes::new().set_modified(mtime);
            let _ = std::fs::File::options()
                .write(true)
                .open(&dest_path)
                .and_then(|f| f.set_times(times));
        }

        Ok(dest_path)
    }

    fn decode_single_file(&mut self, entry: &ArchiveEntry) -> RarResult<Vec<u8>> {
        // Find the index of this entry
        let target_idx = self
            .entries
            .iter()
            .position(|e| e.header.data_offset == entry.header.data_offset)
            .unwrap_or(0);

        // Check if this entry is part of a solid chain
        if self.is_solid_chain_member(target_idx) {
            return self.decode_solid_through(target_idx);
        }

        self.decode_file_at(target_idx, None)
    }

    /// Check if entry at `idx` is in a solid chain (is solid itself, or
    /// the next entry after it is solid).
    fn is_solid_chain_member(&self, idx: usize) -> bool {
        let hdr = &self.entries[idx].header;
        if hdr.comp_solid {
            return true;
        }
        // First file in a solid group isn't flagged solid but the next one is
        if idx + 1 < self.entries.len() && self.entries[idx + 1].header.comp_solid {
            return true;
        }
        false
    }

    /// Decode all files in the solid chain up through `target_idx`,
    /// returning the data for `target_idx`.
    fn decode_solid_through(&mut self, target_idx: usize) -> RarResult<Vec<u8>> {
        // Find the start of the solid chain (first non-directory file
        // at or before target_idx that isn't solid, followed by solid files)
        let mut chain_start = target_idx;
        for i in (0..target_idx).rev() {
            if self.entries[i].is_dir() {
                continue;
            }
            if self.entries[i].header.comp_solid || self.is_solid_chain_member(i) {
                chain_start = i;
            } else {
                break;
            }
        }

        // If we've already decoded past this point, and it's a forward request, reuse state.
        // If we need to go backwards, reset.
        if self.solid_decoded_through >= chain_start as isize
            && self.solid_decoded_through < target_idx as isize
        {
            // Continue from where we left off
        } else if self.solid_decoded_through >= target_idx as isize {
            // Already decoded this file — but we don't cache the output,
            // so we must restart from the beginning.
            self.solid_state = None;
            self.solid_decoded_through = -1;
        } else {
            // Starting fresh
            self.solid_state = None;
            self.solid_decoded_through = -1;
        }

        // Determine dict_size from the first compressed entry in the chain
        if self.solid_state.is_none() {
            let dict_log = self.entries[chain_start].header.comp_dict_size;
            let dict_log32 = dict_log.max(0) as u32;
            let mut dict_size = 128 * 1024 * (1usize << dict_log32);
            if !dict_size.is_power_of_two() {
                dict_size = dict_size.next_power_of_two();
            }
            self.solid_state = Some(DecoderState::new(dict_size));
        }

        let start_from = (self.solid_decoded_through + 1) as usize;
        let mut target_data = Vec::new();

        for i in start_from..=target_idx {
            let entry = self.entries[i].clone();
            if entry.is_dir() {
                continue;
            }

            // Temporarily take state to satisfy borrow checker
            let mut state = self.solid_state.take().unwrap();
            let data = self.decode_file_at(i, Some(&mut state))?;
            self.solid_state = Some(state);

            self.solid_decoded_through = i as isize;

            if i == target_idx {
                target_data = data;
            }
        }

        Ok(target_data)
    }

    /// Decode a single file, optionally with a shared DecoderState.
    fn decode_file_at(
        &mut self,
        idx: usize,
        state: Option<&mut DecoderState>,
    ) -> RarResult<Vec<u8>> {
        let hdr = &self.entries[idx].header;

        // Empty files / directories
        if hdr.packed_size == 0 && hdr.unpacked_size == 0 {
            return Ok(Vec::new());
        }

        // Check for encryption in extra area
        let encr_params = if !hdr.extra_data.is_empty() {
            encryption::parse_encryption_extra(&hdr.extra_data)?
        } else {
            None
        };

        let is_encrypted = encr_params.is_some();

        if is_encrypted && self.password.is_none() {
            return Err(RarError::Encrypted(format!(
                "{}: encrypted, no password set",
                hdr.name
            )));
        }

        let stream = self.stream.as_mut().unwrap();
        stream.seek(SeekFrom::Start(hdr.data_offset))?;
        let mut packed_data = vec![0u8; hdr.packed_size as usize];
        stream.read_exact(&mut packed_data)?;

        // Decrypt if encrypted
        if let Some(ref params) = encr_params {
            let password = self.password.as_ref().unwrap();
            if !params.verify_password(password) {
                return Err(RarError::Encrypted("wrong password".into()));
            }
            packed_data = params.decrypt(&packed_data, password)?;
        }

        let raw_data = if hdr.comp_method == COMP_METHOD_STORE {
            // For store mode, truncate to unpacked_size (strip zero-fill padding)
            if is_encrypted {
                packed_data.truncate(hdr.unpacked_size as usize);
            }
            packed_data
        } else {
            compression::decompress(
                &packed_data,
                hdr.comp_method,
                hdr.unpacked_size,
                hdr.comp_dict_size,
                state,
            )
            .map_err(|e| RarError::Unsupported(e))?
        };

        // Verify CRC (skip for encrypted files — CRC is password-dependent)
        if !is_encrypted {
            if let Some(expected_crc) = hdr.crc32_val {
                let mut hasher = crc32fast::Hasher::new();
                hasher.update(&raw_data);
                let actual_crc = hasher.finalize();
                if actual_crc != expected_crc {
                    return Err(RarError::Crc {
                        expected: expected_crc,
                        actual: actual_crc,
                        context: hdr.name.clone(),
                    });
                }
            }
        }

        Ok(raw_data)
    }

    // ── Public API: creation ───────────────────────────────────────────────

    /// Add a file from the filesystem to the archive.
    pub fn add(
        &mut self,
        path: impl AsRef<Path>,
        compression_level: u8,
    ) -> RarResult<()> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(RarError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("path not found: {}", path.display()),
            )));
        }

        if path.is_dir() {
            self.add_directory(path, None, true, compression_level)
        } else {
            self.add_file(path, None, compression_level)
        }
    }

    fn add_file(
        &mut self,
        path: &Path,
        arcname: Option<&str>,
        level: u8,
    ) -> RarResult<()> {
        let raw_data = fs::read(path)?;
        let file_crc = {
            let mut h = crc32fast::Hasher::new();
            h.update(&raw_data);
            h.finalize()
        };

        let method = level_to_method(level);
        let (packed_data, actual_method, dict_size_log) = if method == COMP_METHOD_STORE {
            (raw_data.clone(), COMP_METHOD_STORE, 0u8)
        } else {
            let dsl = dict_size_for_data(raw_data.len());
            let compressed = compression::compress(&raw_data, method, dsl)
                .map_err(|e| RarError::Unsupported(e))?;
            if compressed.len() >= raw_data.len() {
                (raw_data.clone(), COMP_METHOD_STORE, 0u8)
            } else {
                (compressed, method, dsl)
            }
        };

        let name = arcname
            .map(|s| s.to_string())
            .unwrap_or_else(|| path.file_name().unwrap().to_string_lossy().into_owned());
        let name = name.replace('\\', "/");

        let meta = fs::metadata(path)?;
        let mtime = meta
            .modified()
            .unwrap_or(SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        #[cfg(unix)]
        let attrs = {
            use std::os::unix::fs::MetadataExt;
            meta.mode() as u64
        };
        #[cfg(not(unix))]
        let attrs = 0o100644u64;

        let fh = FileHeader {
            name: name.clone(),
            unpacked_size: raw_data.len() as u64,
            packed_size: packed_data.len() as u64,
            attributes: attrs,
            mtime,
            crc32_val: Some(file_crc),
            comp_method: actual_method,
            comp_dict_size: dict_size_log,
            host_os: OS_UNIX,
            file_flags: FILE_FLAG_TIME_UNIX | FILE_FLAG_CRC32,
            ..Default::default()
        };

        let stream = self.stream.as_mut().unwrap();
        stream.write_all(&fh.to_bytes())?;
        stream.write_all(&packed_data)?;

        self.entries.push(ArchiveEntry {
            header: FileHeader {
                data_offset: stream.stream_position()? - packed_data.len() as u64,
                ..fh
            },
        });

        Ok(())
    }

    fn add_directory(
        &mut self,
        path: &Path,
        arcname: Option<&str>,
        recursive: bool,
        level: u8,
    ) -> RarResult<()> {
        let name = arcname
            .map(|s| s.to_string())
            .unwrap_or_else(|| path.file_name().unwrap().to_string_lossy().into_owned());
        let name = name.replace('\\', "/").trim_end_matches('/').to_string() + "/";

        let meta = fs::metadata(path)?;
        let mtime = meta
            .modified()
            .unwrap_or(SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        #[cfg(unix)]
        let attrs = {
            use std::os::unix::fs::MetadataExt;
            meta.mode() as u64
        };
        #[cfg(not(unix))]
        let attrs = 0o040755u64;

        let fh = FileHeader {
            name: name.clone(),
            attributes: attrs,
            mtime,
            host_os: OS_UNIX,
            file_flags: FILE_FLAG_TIME_UNIX | FILE_FLAG_DIRECTORY,
            is_directory: true,
            ..Default::default()
        };

        let stream = self.stream.as_mut().unwrap();
        stream.write_all(&fh.to_bytes())?;
        self.entries.push(ArchiveEntry { header: fh });

        if recursive {
            let mut children: Vec<_> = fs::read_dir(path)?
                .filter_map(|e| e.ok())
                .collect();
            children.sort_by_key(|e| e.file_name());

            for child in children {
                let child_path = child.path();
                let child_name = format!("{}{}", name, child.file_name().to_string_lossy());
                if child_path.is_dir() {
                    self.add_directory(&child_path, Some(&child_name), true, level)?;
                } else {
                    self.add_file(&child_path, Some(&child_name), level)?;
                }
            }
        }

        Ok(())
    }

    /// Add raw bytes as a named file in the archive.
    pub fn add_bytes(
        &mut self,
        arcname: &str,
        data: &[u8],
        compression_level: u8,
    ) -> RarResult<()> {
        let file_crc = {
            let mut h = crc32fast::Hasher::new();
            h.update(data);
            h.finalize()
        };

        let method = level_to_method(compression_level);
        let mtime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let (packed_data, actual_method, dict_size_log) = if method == COMP_METHOD_STORE {
            (data.to_vec(), COMP_METHOD_STORE, 0u8)
        } else {
            let dsl = dict_size_for_data(data.len());
            let compressed = compression::compress(data, method, dsl)
                .map_err(|e| RarError::Unsupported(e))?;
            if compressed.len() >= data.len() {
                (data.to_vec(), COMP_METHOD_STORE, 0u8)
            } else {
                (compressed, method, dsl)
            }
        };

        let name = arcname.replace('\\', "/");
        let fh = FileHeader {
            name: name.clone(),
            unpacked_size: data.len() as u64,
            packed_size: packed_data.len() as u64,
            attributes: 0o100644,
            mtime,
            crc32_val: Some(file_crc),
            comp_method: actual_method,
            comp_dict_size: dict_size_log,
            host_os: OS_UNIX,
            file_flags: FILE_FLAG_TIME_UNIX | FILE_FLAG_CRC32,
            ..Default::default()
        };

        let stream = self.stream.as_mut().unwrap();
        stream.write_all(&fh.to_bytes())?;
        stream.write_all(&packed_data)?;

        self.entries.push(ArchiveEntry {
            header: FileHeader {
                data_offset: stream.stream_position()? - packed_data.len() as u64,
                ..fh
            },
        });

        Ok(())
    }
}

impl Drop for RarArchive {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn dict_size_for_data(data_size: usize) -> u8 {
    let base = 128 * 1024;
    let mut log = 0u8;
    while (base << log) < data_size && log < 15 {
        log += 1;
    }
    log
}
