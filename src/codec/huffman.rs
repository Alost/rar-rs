/// RAR5 canonical Huffman codec.
///
/// Two-level decode: quick table for codes up to QUICK_BITS, slower scan
/// for longer codes. Based on the structure used in libarchive's RAR5 reader.

use super::bitstream::{BitReader, BitWriter};
use super::tables::{MAX_CODE_LENGTH, QUICK_BITS, QUICK_SIZE};

// ── Decode Table ───────────────────────────────────────────────────────────

pub struct DecodeTable {
    pub num_symbols: usize,
    pub code_lengths: Vec<u8>,
    decode_len: [u32; MAX_CODE_LENGTH + 2],
    decode_pos: [usize; MAX_CODE_LENGTH + 2],
    decode_num: Vec<u16>,
    quick_len: Vec<u8>,
    quick_num: Vec<u16>,
}

impl DecodeTable {
    pub fn new(code_lengths: &[u8]) -> Self {
        let n = code_lengths.len();

        // Count codes of each length
        let mut len_count = [0u32; MAX_CODE_LENGTH + 2];
        for &cl in code_lengths {
            let cl = cl as usize;
            if cl > 0 && cl <= MAX_CODE_LENGTH {
                len_count[cl] += 1;
            }
        }

        let mut decode_len = [0u32; MAX_CODE_LENGTH + 2];
        let mut decode_pos = [0usize; MAX_CODE_LENGTH + 2];
        let mut decode_num = vec![0u16; n.max(1)];

        let mut code: u32 = 0;
        let mut pos: usize = 0;
        for i in 1..=MAX_CODE_LENGTH {
            code <<= 1;
            decode_len[i - 1] = code << (MAX_CODE_LENGTH - i);
            decode_pos[i] = pos;
            code += len_count[i];
            pos += len_count[i] as usize;
        }
        decode_len[MAX_CODE_LENGTH] = 1 << MAX_CODE_LENGTH;

        // Fill decode_num
        let mut pos_tracker = decode_pos;
        for sym in 0..n {
            let cl = code_lengths[sym] as usize;
            if cl > 0 && cl <= MAX_CODE_LENGTH {
                decode_num[pos_tracker[cl]] = sym as u16;
                pos_tracker[cl] += 1;
            }
        }

        // Build quick lookup table
        let mut quick_len = vec![0u8; QUICK_SIZE];
        let mut quick_num = vec![0u16; QUICK_SIZE];

        let mut code: u32 = 0;
        for cl in 1..=QUICK_BITS {
            let start_pos = decode_pos[cl];
            for j in 0..len_count[cl] as usize {
                let sym = decode_num[start_pos + j];
                let prefix = code << (QUICK_BITS - cl);
                let fill = 1 << (QUICK_BITS - cl);
                for k in 0..fill {
                    let entry = (prefix + k) as usize;
                    if entry < QUICK_SIZE {
                        quick_len[entry] = cl as u8;
                        quick_num[entry] = sym;
                    }
                }
                code += 1;
            }
            code <<= 1;
        }

        DecodeTable {
            num_symbols: n,
            code_lengths: code_lengths.to_vec(),
            decode_len,
            decode_pos,
            decode_num,
            quick_len,
            quick_num,
        }
    }
}

/// Decode one Huffman symbol from the bitstream.
pub fn decode_symbol(table: &DecodeTable, reader: &mut BitReader) -> Result<usize, &'static str> {
    let bits_avail = reader.bits_remaining();
    if bits_avail == 0 {
        return Err("Huffman decode: no bits remaining");
    }

    // Try quick lookup
    let peek_count = (QUICK_BITS).min(bits_avail) as u8;
    let mut prefix = reader.peek_bits(peek_count)?;
    if (peek_count as usize) < QUICK_BITS {
        prefix <<= QUICK_BITS as u32 - peek_count as u32;
    }

    let cl = table.quick_len[prefix as usize];
    if cl > 0 && cl <= peek_count {
        reader.skip_bits(cl as u32);
        return Ok(table.quick_num[prefix as usize] as usize);
    }

    // Slow path
    let peek_count = (MAX_CODE_LENGTH).min(bits_avail) as u8;
    let mut bits = reader.peek_bits(peek_count)?;
    if (peek_count as usize) < MAX_CODE_LENGTH {
        bits <<= MAX_CODE_LENGTH as u32 - peek_count as u32;
    }

    for i in 1..=MAX_CODE_LENGTH {
        if bits < table.decode_len[i] {
            reader.skip_bits(i as u32);
            let prev_boundary = if i > 1 { table.decode_len[i - 1] } else { 0 };
            let offset = ((bits - prev_boundary) >> (MAX_CODE_LENGTH - i)) as usize;
            let idx = table.decode_pos[i] + offset;
            if idx < table.num_symbols {
                return Ok(table.decode_num[idx] as usize);
            }
            break;
        }
    }

    Err("Huffman decode: invalid code")
}

// ── Encode Table ───────────────────────────────────────────────────────────

pub struct EncodeTable {
    pub num_symbols: usize,
    pub codes: Vec<u32>,
    pub lengths: Vec<u8>,
}

impl EncodeTable {
    pub fn new(code_lengths: &[u8]) -> Self {
        let n = code_lengths.len();

        let mut len_count = [0u32; MAX_CODE_LENGTH + 2];
        for &cl in code_lengths {
            let cl = cl as usize;
            if cl > 0 && cl <= MAX_CODE_LENGTH {
                len_count[cl] += 1;
            }
        }

        let mut code: u32 = 0;
        let mut next_code = [0u32; MAX_CODE_LENGTH + 2];
        for bits in 1..=MAX_CODE_LENGTH {
            code <<= 1;
            next_code[bits] = code;
            code += len_count[bits];
        }

        let mut codes = vec![0u32; n];
        for sym in 0..n {
            let cl = code_lengths[sym] as usize;
            if cl > 0 && cl <= MAX_CODE_LENGTH {
                codes[sym] = next_code[cl];
                next_code[cl] += 1;
            }
        }

        EncodeTable {
            num_symbols: n,
            codes,
            lengths: code_lengths.to_vec(),
        }
    }
}

/// Encode one Huffman symbol to the bitstream.
pub fn encode_symbol(table: &EncodeTable, writer: &mut BitWriter, symbol: usize) {
    let cl = table.lengths[symbol];
    debug_assert!(cl > 0, "cannot encode symbol {symbol}: zero length");
    writer.write_bits(table.codes[symbol], cl);
}

/// Build optimal Huffman code lengths from symbol frequencies.
/// Returns a Vec of code bit-lengths (0 for unused symbols).
pub fn build_code_lengths_from_freqs(freqs: &[u32], max_length: usize) -> Vec<u8> {
    let n = freqs.len();
    let active: Vec<(u32, usize)> = freqs
        .iter()
        .enumerate()
        .filter(|(_, f)| **f > 0)
        .map(|(i, &f)| (f, i))
        .collect();

    if active.is_empty() {
        return vec![0; n];
    }
    if active.len() == 1 {
        let mut lengths = vec![0u8; n];
        lengths[active[0].1] = 1;
        return lengths;
    }

    // Build Huffman tree using sorted merge (no BinaryHeap needed for Node)
    // Two-queue approach: one for leaves, one for internal nodes
    let mut leaves: Vec<(u32, usize, Option<(usize, usize)>)> = active
        .iter()
        .map(|&(freq, sym)| (freq, sym, None))
        .collect();
    leaves.sort_by_key(|&(f, s, _)| (f, s));

    // nodes stores: (freq, node_id, children)
    let mut nodes: Vec<(u32, usize, Option<(usize, usize)>)> = Vec::new();
    let mut all_nodes: Vec<(u32, usize, Option<(usize, usize)>)> = Vec::new();
    // Copy leaves into all_nodes
    for &(f, s, _) in &leaves {
        all_nodes.push((f, s, None));
    }

    let mut li = 0; // leaf index
    let mut ni = 0; // internal node index
    let mut counter = n;

    fn pick_min(
        leaves: &[(u32, usize, Option<(usize, usize)>)],
        li: &mut usize,
        nodes: &[(u32, usize, Option<(usize, usize)>)],
        ni: &mut usize,
    ) -> (u32, usize) {
        let have_leaf = *li < leaves.len();
        let have_node = *ni < nodes.len();
        if have_leaf && have_node {
            if leaves[*li].0 <= nodes[*ni].0 {
                let idx = *li;
                *li += 1;
                (leaves[idx].0, idx)
            } else {
                let idx = *ni;
                *ni += 1;
                (nodes[idx].0, leaves.len() + idx)
            }
        } else if have_leaf {
            let idx = *li;
            *li += 1;
            (leaves[idx].0, idx)
        } else {
            let idx = *ni;
            *ni += 1;
            (nodes[idx].0, leaves.len() + idx)
        }
    }

    let total_leaves = leaves.len();
    while (total_leaves - li) + (nodes.len() - ni) > 1 {
        let (f1, id1) = pick_min(&leaves, &mut li, &nodes, &mut ni);
        let (f2, id2) = pick_min(&leaves, &mut li, &nodes, &mut ni);
        counter += 1;
        nodes.push((f1 + f2, counter, Some((id1, id2))));
    }

    // Rebuild all_nodes with internal nodes appended
    for &(f, id, children) in &nodes {
        all_nodes.push((f, id, children));
    }

    let mut lengths = vec![0u8; n];

    // Walk the tree to assign depths
    fn walk(
        all_nodes: &[(u32, usize, Option<(usize, usize)>)],
        node_idx: usize,
        depth: u8,
        total_leaves: usize,
        lengths: &mut Vec<u8>,
    ) {
        if let Some((left, right)) = all_nodes[node_idx].2 {
            walk(all_nodes, left, depth + 1, total_leaves, lengths);
            walk(all_nodes, right, depth + 1, total_leaves, lengths);
        } else {
            // Leaf: all_nodes[node_idx].1 is the original symbol
            let sym = all_nodes[node_idx].1;
            if sym < lengths.len() {
                lengths[sym] = depth;
            }
        }
    }

    let root_idx = all_nodes.len() - 1;
    walk(&all_nodes, root_idx, 0, total_leaves, &mut lengths);

    // Enforce max_length and fix Kraft inequality.
    // Clamping depths > max_length to max_length makes the code overcomplete
    // (Kraft sum > 1). To fix, we lengthen some shorter codes (increase their
    // bit length) which reduces their Kraft contribution.
    let max_len = max_length as u8;
    let mut needs_fix = false;
    for l in &mut lengths {
        if *l > max_len {
            *l = max_len;
            needs_fix = true;
        }
    }

    if needs_fix {
        let kraft_target: u64 = 1u64 << max_len;
        let kraft_sum_fn = |lengths: &[u8]| -> u64 {
            lengths
                .iter()
                .filter(|&&l| l > 0)
                .map(|&l| 1u64 << (max_len - l))
                .sum()
        };

        // Lengthen shortest codes to reduce Kraft sum.
        // Each lengthening of a code from L to L+1 reduces the Kraft sum
        // by 2^(max_len - L - 1).
        while kraft_sum_fn(&lengths) > kraft_target {
            // Find the shortest non-zero, non-max code to lengthen
            let shortest = lengths
                .iter()
                .filter(|&&l| l > 0 && l < max_len)
                .copied()
                .min();
            match shortest {
                Some(s) => {
                    // Lengthen the least-frequent symbol at this length
                    // (last occurrence, which tends to be a less important symbol)
                    for i in (0..n).rev() {
                        if lengths[i] == s {
                            lengths[i] += 1;
                            break;
                        }
                    }
                }
                None => break, // All codes at max_len, can't fix further
            }
        }
    }

    lengths
}
