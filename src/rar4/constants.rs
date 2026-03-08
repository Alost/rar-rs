/// RAR4 format constants.
///
/// Based on the header/flag definitions from libarchive's
/// archive_read_support_format_rar.c (BSD-2-Clause).

// ── Header types ──────────────────────────────────────────────────────────

pub const RAR4_HEAD_MARK: u8 = 0x72;
pub const RAR4_HEAD_MAIN: u8 = 0x73;
pub const RAR4_HEAD_FILE: u8 = 0x74;
pub const RAR4_HEAD_COMM: u8 = 0x75;
pub const RAR4_HEAD_AV: u8 = 0x76;
pub const RAR4_HEAD_SUB: u8 = 0x77;
pub const RAR4_HEAD_PROTECT: u8 = 0x78;
pub const RAR4_HEAD_SIGN: u8 = 0x79;
pub const RAR4_HEAD_NEWSUB: u8 = 0x7A;
pub const RAR4_HEAD_ENDARC: u8 = 0x7B;

// ── Common header flags ───────────────────────────────────────────────────

/// Header has ADD_SIZE field (4 bytes of data size after header).
pub const HD_FLAG_ADD_SIZE: u16 = 0x8000;
/// Header spans multiple blocks (skip unknown headers).
pub const HD_FLAG_SKIP_IF_UNKNOWN: u16 = 0x4000;

// ── Main archive header flags (HEAD_MAIN, 0x73) ──────────────────────────

pub const MHD_VOLUME: u16 = 0x0001;
pub const MHD_COMMENT: u16 = 0x0002;
pub const MHD_LOCK: u16 = 0x0004;
pub const MHD_SOLID: u16 = 0x0008;
pub const MHD_NEWNUMBERING: u16 = 0x0010;
pub const MHD_PASSWORD: u16 = 0x0080;
pub const MHD_ENCRYPTVER: u16 = 0x0200;

// ── File header flags (HEAD_FILE, 0x74) ───────────────────────────────────

pub const FHD_SPLIT_BEFORE: u16 = 0x0001;
pub const FHD_SPLIT_AFTER: u16 = 0x0002;
pub const FHD_PASSWORD: u16 = 0x0004;
pub const FHD_COMMENT: u16 = 0x0008;
pub const FHD_SOLID: u16 = 0x0010;
pub const FHD_DIRECTORY: u16 = 0x00E0; // bits 5-7: dictionary size
pub const FHD_LARGE: u16 = 0x0100;
pub const FHD_UNICODE: u16 = 0x0200;
pub const FHD_SALT: u16 = 0x0400;
pub const FHD_EXTTIME: u16 = 0x1000;

// ── File attributes (used to detect directories) ─────────────────────────

pub const RAR4_ATTR_DIRECTORY: u32 = 0x10;
/// Unix symlink attribute (upper word of attr when host_os == Unix).
pub const RAR4_ATTR_UNIX_DIR: u32 = 0o040000;

// ── Compression methods ───────────────────────────────────────────────────

pub const RAR4_METHOD_STORE: u8 = 0x30;
pub const RAR4_METHOD_FASTEST: u8 = 0x31;
pub const RAR4_METHOD_FAST: u8 = 0x32;
pub const RAR4_METHOD_NORMAL: u8 = 0x33;
pub const RAR4_METHOD_GOOD: u8 = 0x34;
pub const RAR4_METHOD_BEST: u8 = 0x35;

// ── Host OS values ────────────────────────────────────────────────────────

pub const RAR4_OS_WINDOWS: u8 = 0;
pub const RAR4_OS_UNIX: u8 = 3;

// ── RAR4 Huffman table sizes ──────────────────────────────────────────────

/// Main codes: 0-255 literals, 256-258 special, 259+ match lengths.
pub const RAR4_NC: usize = 299;
/// Distance codes.
pub const RAR4_DC: usize = 60;
/// Low-distance codes (for close matches).
pub const RAR4_LDC: usize = 17;
/// Repeat/length codes.
pub const RAR4_RC: usize = 28;
/// Bit-count table size (for reading Huffman table definitions).
pub const RAR4_BC: usize = 20;

// ── RAR4 dictionary size ──────────────────────────────────────────────────

/// Default RAR4 dictionary: 4 MB.
pub const RAR4_DEFAULT_DICT_SIZE: usize = 0x400000;

// ── End-of-archive flags ──────────────────────────────────────────────────

pub const ENDARC_NEXT_VOLUME: u16 = 0x0001;
pub const ENDARC_DATACRC: u16 = 0x0002;
pub const ENDARC_REVSPACE: u16 = 0x0004;
