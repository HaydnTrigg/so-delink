//! DWARF relocation synthesis (M7).
//!
//! The `.debug_info` / `.debug_line` slices we extract from the input `.so`
//! contain absolute VAs and offsets that point into the *original* layout.
//! For the relinked `.so` to have DWARF that tracks the new addresses, we
//! walk each slice and emit ELF relocations on every address- or
//! string-reference field.
//!
//! Scope (v1):
//!  - `.debug_info`: `DW_FORM_addr` attributes → `R_AARCH64_ABS64` against
//!    the function symbol containing the address (addend = offset within
//!    the function if the address is interior to a function).
//!  - `.debug_info`: `DW_FORM_strp` → `R_AARCH64_ABS32` against
//!    `__delink_debug_str_start` (defined by `__shared_data.o`) with
//!    `addend = original_str_offset`. Linker concatenates debug_str and
//!    resolves to the correct final offset.
//!  - `.debug_line`: `DW_LNE_set_address` operand → `R_AARCH64_ABS64`
//!    against the function symbol.
//!
//! Deferred:
//!  - `.debug_ranges` / `.debug_rnglists` / `.debug_loc` / `.debug_loclists`
//!    (M8).
//!  - DWARF 5 `DW_FORM_addrx` / `DW_FORM_strx` / `DW_FORM_line_strp` (M9).
//!  - Cross-unit `DW_FORM_ref_addr` (uncommon in C++ compilers).

use anyhow::{anyhow, bail, Result};
use delink_core::symbols::GlobalSymbols;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum DwarfReloc {
    /// `R_AARCH64_ABS64` at `offset` against `symbol`+addend. Used for
    /// addresses in `.debug_info` (DW_FORM_addr) and `.debug_line`
    /// (DW_LNE_set_address).
    Abs64 {
        offset: u64,
        symbol: String,
        addend: i64,
    },
    /// `R_AARCH64_ABS32` at `offset` against `symbol`+addend. Used for
    /// DW_FORM_strp into the shared debug_str table.
    Abs32 {
        offset: u64,
        symbol: String,
        addend: i64,
    },
}

#[derive(Debug, Default)]
pub struct DwarfRelocDiag {
    pub low_pc_resolved: usize,
    pub low_pc_missing: usize,
    pub strp_emitted: usize,
    pub set_address_resolved: usize,
    pub set_address_missing: usize,
    pub dies_walked: usize,
    pub unknown_forms: usize,
    pub range_pairs_resolved: usize,
    pub range_pairs_missing: usize,
    pub loc_pairs_resolved: usize,
    pub loc_pairs_missing: usize,
}

#[derive(Debug, Clone)]
struct Abbrev {
    #[allow(dead_code)]
    tag: u64,
    #[allow(dead_code)]
    has_children: bool,
    attrs: Vec<AbbrevAttr>,
}

#[derive(Debug, Clone)]
struct AbbrevAttr {
    attr: u64,
    form: u64,
    #[allow(dead_code)]
    implicit_const: Option<i64>,
}

type AbbrevMap = HashMap<u64, Abbrev>;

/// Walk a CU's `.debug_info` slice and emit relocations.
pub fn scan_debug_info(
    slice: &[u8],
    abbrev_slice: &[u8],
    symbols: &GlobalSymbols,
) -> Result<(Vec<DwarfReloc>, DwarfRelocDiag)> {
    let mut relocs = Vec::new();
    let mut diag = DwarfRelocDiag::default();

    let (header_size, addr_size, offset_size) = parse_cu_header(slice)
        .ok_or_else(|| anyhow!("failed to parse CU header"))?;

    let abbrevs = parse_abbrev_table(abbrev_slice)?;
    let mut cursor = header_size;

    while cursor < slice.len() {
        let (code, code_len) = read_uleb128(&slice[cursor..])
            .ok_or_else(|| anyhow!("bad abbrev code ULEB at {cursor}"))?;
        cursor += code_len;
        if code == 0 {
            continue; // null DIE (end of children)
        }
        let Some(abbrev) = abbrevs.get(&code) else {
            bail!("unknown abbrev code {code} at debug_info offset {cursor}");
        };
        diag.dies_walked += 1;

        for attr in &abbrev.attrs {
            let attr_off = cursor;
            let size = form_size(attr.form, addr_size, offset_size, &slice[cursor..]);
            let size = match size {
                Some(s) => s,
                None => {
                    diag.unknown_forms += 1;
                    // If we don't know how to advance, we have to bail —
                    // continuing would desync the parse.
                    return Err(anyhow!(
                        "unknown DW_FORM 0x{:x} at debug_info offset {cursor}",
                        attr.form
                    ));
                }
            };

            match attr.form {
                // DW_FORM_addr
                0x01 => {
                    let addr = read_addr(&slice[cursor..], addr_size);
                    if attr.attr == 0x11 /* DW_AT_low_pc */
                        || attr.attr == 0x12 /* DW_AT_high_pc (as addr: end) */
                        || attr.attr == 0x52 /* DW_AT_entry_pc */
                    {
                        if addr != 0 {
                            match resolve_addr(symbols, addr) {
                                Some((name, addend)) => {
                                    relocs.push(DwarfReloc::Abs64 {
                                        offset: attr_off as u64,
                                        symbol: name,
                                        addend,
                                    });
                                    diag.low_pc_resolved += 1;
                                }
                                None => {
                                    diag.low_pc_missing += 1;
                                }
                            }
                        }
                    }
                }
                // DW_FORM_strp
                0x0e => {
                    let orig = read_offset(&slice[cursor..], offset_size);
                    relocs.push(DwarfReloc::Abs32 {
                        offset: attr_off as u64,
                        symbol: "__delink_debug_str_start".to_string(),
                        addend: orig as i64,
                    });
                    diag.strp_emitted += 1;
                }
                _ => {}
            }

            cursor += size;
        }
    }

    Ok((relocs, diag))
}

/// Walk a line program and emit relocations for `DW_LNE_set_address`
/// extended opcodes. Those are the only byte positions in `.debug_line`
/// that carry absolute VAs we need to rewrite.
pub fn scan_debug_line(
    slice: &[u8],
    symbols: &GlobalSymbols,
) -> Result<(Vec<DwarfReloc>, DwarfRelocDiag)> {
    let mut relocs = Vec::new();
    let mut diag = DwarfRelocDiag::default();

    let header = parse_line_program_header(slice)
        .ok_or_else(|| anyhow!("failed to parse line program header"))?;

    let mut cursor = header.program_start;
    while cursor < slice.len() {
        let opcode = slice[cursor];
        cursor += 1;

        if opcode == 0 {
            // Extended opcode: ULEB length, then sub-opcode, then operands.
            let (len, n) = read_uleb128(&slice[cursor..])
                .ok_or_else(|| anyhow!("bad extended length at {cursor}"))?;
            cursor += n;
            if len == 0 {
                continue;
            }
            let ext_start = cursor;
            let sub = slice[cursor];
            cursor += 1;
            if sub == 0x02 /* DW_LNE_set_address */ {
                let addr = read_addr(&slice[cursor..], header.address_size);
                if addr != 0 {
                    match resolve_addr(symbols, addr) {
                        Some((name, addend)) => {
                            relocs.push(DwarfReloc::Abs64 {
                                offset: cursor as u64,
                                symbol: name,
                                addend,
                            });
                            diag.set_address_resolved += 1;
                        }
                        None => diag.set_address_missing += 1,
                    }
                }
            }
            cursor = ext_start + len as usize;
        } else if (opcode as usize) < header.standard_opcode_lengths.len() + 1 {
            // Standard opcode: consume N ULEB operands per the header.
            let n_operands = header.standard_opcode_lengths[opcode as usize - 1];
            for _ in 0..n_operands {
                let (_, n) = read_uleb128(&slice[cursor..])
                    .ok_or_else(|| anyhow!("bad std-opcode operand at {cursor}"))?;
                cursor += n;
            }
        } else {
            // Special opcode: no operands.
        }
    }

    Ok((relocs, diag))
}

/// Walk `.debug_ranges` (DWARF 2-4 format) and emit R_AARCH64_ABS64 relocs
/// on every non-sentinel address entry.
///
/// Entries are pairs (start: addr, end: addr), each `addr_size` bytes.
/// Sentinels:
///  - `(0, 0)` terminates the current range list.
///  - `(~0, base)` is a base-address selector; in linked binaries we
///    usually don't see these because addresses are already absolute.
pub fn scan_debug_ranges(
    section: &[u8],
    addr_size: u8,
    symbols: &GlobalSymbols,
) -> (Vec<DwarfReloc>, DwarfRelocDiag) {
    let mut relocs = Vec::new();
    let mut diag = DwarfRelocDiag::default();
    let step = addr_size as usize;
    let pair = step * 2;
    if step == 0 || section.len() < pair {
        return (relocs, diag);
    }
    let top = if addr_size == 8 { u64::MAX } else { u32::MAX as u64 };
    let mut cursor = 0usize;
    while cursor + pair <= section.len() {
        let start = read_addr(&section[cursor..], addr_size);
        let end = read_addr(&section[cursor + step..], addr_size);
        // Terminator or base selector → no relocs for this entry.
        if start == 0 && end == 0 {
            cursor += pair;
            continue;
        }
        if start == top {
            cursor += pair;
            continue;
        }
        emit_addr_pair(&mut relocs, &mut diag, symbols, cursor, cursor + step, start, end);
        cursor += pair;
    }
    (relocs, diag)
}

/// Walk `.debug_loc` (DWARF 2-4 format) and emit R_AARCH64_ABS64 relocs on
/// every non-sentinel location entry's `(start, end)` address pair.
///
/// Entry format:
///  - `(start, end, length: u16, expression[length])` — location entry
///  - `(0, 0)` — terminator
///  - `(~0, base)` — base selector (no length/expression)
pub fn scan_debug_loc(
    section: &[u8],
    addr_size: u8,
    symbols: &GlobalSymbols,
) -> (Vec<DwarfReloc>, DwarfRelocDiag) {
    let mut relocs = Vec::new();
    let mut diag = DwarfRelocDiag::default();
    let step = addr_size as usize;
    let pair = step * 2;
    if step == 0 || section.len() < pair {
        return (relocs, diag);
    }
    let top = if addr_size == 8 { u64::MAX } else { u32::MAX as u64 };
    let mut cursor = 0usize;
    while cursor + pair <= section.len() {
        let start = read_addr(&section[cursor..], addr_size);
        let end = read_addr(&section[cursor + step..], addr_size);
        if start == 0 && end == 0 {
            cursor += pair;
            continue;
        }
        if start == top {
            // Base selector: no length follows.
            cursor += pair;
            continue;
        }
        emit_loc_pair(&mut relocs, &mut diag, symbols, cursor, cursor + step, start, end);
        // Skip length + expression.
        if cursor + pair + 2 > section.len() {
            break;
        }
        let len = u16::from_le_bytes(
            section[cursor + pair..cursor + pair + 2]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;
        cursor += pair + 2 + len;
    }
    (relocs, diag)
}

fn emit_addr_pair(
    relocs: &mut Vec<DwarfReloc>,
    diag: &mut DwarfRelocDiag,
    symbols: &GlobalSymbols,
    start_off: usize,
    end_off: usize,
    start: u64,
    end: u64,
) {
    match resolve_addr(symbols, start) {
        Some((name, addend)) => {
            relocs.push(DwarfReloc::Abs64 {
                offset: start_off as u64,
                symbol: name,
                addend,
            });
            diag.range_pairs_resolved += 1;
        }
        None => diag.range_pairs_missing += 1,
    }
    // For the end address, a common case is `start + size` of the same
    // function. Try an interior lookup so we emit the reloc with an
    // appropriate addend into the owning function.
    let end_ref = if end == 0 { None } else { resolve_addr_including_end(symbols, end) };
    if let Some((name, addend)) = end_ref {
        relocs.push(DwarfReloc::Abs64 {
            offset: end_off as u64,
            symbol: name,
            addend,
        });
    } else {
        diag.range_pairs_missing += 1;
    }
}

fn emit_loc_pair(
    relocs: &mut Vec<DwarfReloc>,
    diag: &mut DwarfRelocDiag,
    symbols: &GlobalSymbols,
    start_off: usize,
    end_off: usize,
    start: u64,
    end: u64,
) {
    match resolve_addr(symbols, start) {
        Some((name, addend)) => {
            relocs.push(DwarfReloc::Abs64 {
                offset: start_off as u64,
                symbol: name,
                addend,
            });
            diag.loc_pairs_resolved += 1;
        }
        None => diag.loc_pairs_missing += 1,
    }
    let end_ref = if end == 0 { None } else { resolve_addr_including_end(symbols, end) };
    if let Some((name, addend)) = end_ref {
        relocs.push(DwarfReloc::Abs64 {
            offset: end_off as u64,
            symbol: name,
            addend,
        });
    } else {
        diag.loc_pairs_missing += 1;
    }
}

/// Resolve an address that may point one past the last byte of a function
/// (common for end-of-range markers). Allows `addr == start + size`.
fn resolve_addr_including_end(symbols: &GlobalSymbols, addr: u64) -> Option<(String, i64)> {
    if let Some(f) = symbols.functions.get(&addr) {
        return Some((f.export_name().to_string(), 0));
    }
    if let Some((start, f)) = symbols.functions.range(..=addr).next_back() {
        if addr <= *start + f.size {
            return Some((f.export_name().to_string(), (addr - *start) as i64));
        }
    }
    None
}

#[derive(Debug)]
struct LineProgramHeader {
    address_size: u8,
    standard_opcode_lengths: Vec<u8>,
    program_start: usize,
}

fn parse_line_program_header(slice: &[u8]) -> Option<LineProgramHeader> {
    if slice.len() < 4 {
        return None;
    }
    let initial = u32::from_le_bytes(slice[0..4].try_into().ok()?);
    let (is_64, header_offset_size, after_len) = if initial == 0xffff_ffff {
        (true, 8, 12)
    } else {
        (false, 4, 4)
    };
    if slice.len() < after_len + 2 {
        return None;
    }
    let version = u16::from_le_bytes(slice[after_len..after_len + 2].try_into().ok()?);
    let mut cursor = after_len + 2;

    let address_size: u8 = if version >= 5 {
        if slice.len() < cursor + 2 {
            return None;
        }
        let asize = slice[cursor];
        let _segment_selector = slice[cursor + 1];
        cursor += 2;
        asize
    } else {
        8 // AArch64 default; pre-v5 line programs don't encode it
    };

    // header_length.
    if slice.len() < cursor + header_offset_size {
        return None;
    }
    let header_length = if is_64 {
        u64::from_le_bytes(slice[cursor..cursor + 8].try_into().ok()?) as usize
    } else {
        u32::from_le_bytes(slice[cursor..cursor + 4].try_into().ok()?) as usize
    };
    cursor += header_offset_size;
    let program_start = cursor + header_length;

    // Fixed header fields we need to skip to reach standard_opcode_lengths.
    if slice.len() < cursor + 4 {
        return None;
    }
    let _min_inst_length = slice[cursor];
    cursor += 1;
    if version >= 4 {
        let _max_ops_per_inst = slice[cursor];
        cursor += 1;
    }
    let _default_is_stmt = slice[cursor];
    cursor += 1;
    let _line_base = slice[cursor] as i8;
    cursor += 1;
    let _line_range = slice[cursor];
    cursor += 1;
    let opcode_base = slice[cursor];
    cursor += 1;

    let opcode_count = opcode_base.saturating_sub(1) as usize;
    if slice.len() < cursor + opcode_count {
        return None;
    }
    let standard_opcode_lengths = slice[cursor..cursor + opcode_count].to_vec();

    Some(LineProgramHeader {
        address_size,
        standard_opcode_lengths,
        program_start,
    })
}

fn parse_cu_header(slice: &[u8]) -> Option<(usize, u8, usize)> {
    if slice.len() < 4 {
        return None;
    }
    let initial = u32::from_le_bytes(slice[0..4].try_into().ok()?);
    let (is_64, after_len) = if initial == 0xffff_ffff {
        (true, 12)
    } else {
        (false, 4)
    };
    let offset_size = if is_64 { 8 } else { 4 };
    if slice.len() < after_len + 2 {
        return None;
    }
    let version = u16::from_le_bytes(slice[after_len..after_len + 2].try_into().ok()?);
    let after_version = after_len + 2;

    let (addr_size, header_size) = if version >= 5 {
        if slice.len() < after_version + 2 + offset_size {
            return None;
        }
        let _unit_type = slice[after_version];
        let asize = slice[after_version + 1];
        let header_size = after_version + 2 + offset_size;
        (asize, header_size)
    } else {
        if slice.len() < after_version + offset_size + 1 {
            return None;
        }
        let asize = slice[after_version + offset_size];
        let header_size = after_version + offset_size + 1;
        (asize, header_size)
    };

    Some((header_size, addr_size, offset_size))
}

fn parse_abbrev_table(bytes: &[u8]) -> Result<AbbrevMap> {
    let mut map = HashMap::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let (code, n) = read_uleb128(&bytes[cursor..])
            .ok_or_else(|| anyhow!("bad abbrev code"))?;
        cursor += n;
        if code == 0 {
            break;
        }
        let (tag, n) = read_uleb128(&bytes[cursor..])
            .ok_or_else(|| anyhow!("bad abbrev tag"))?;
        cursor += n;
        if cursor >= bytes.len() {
            bail!("truncated abbrev: missing has_children flag");
        }
        let has_children = bytes[cursor] != 0;
        cursor += 1;
        let mut attrs = Vec::new();
        loop {
            let (attr, n) = read_uleb128(&bytes[cursor..])
                .ok_or_else(|| anyhow!("bad abbrev attr"))?;
            cursor += n;
            let (form, n) = read_uleb128(&bytes[cursor..])
                .ok_or_else(|| anyhow!("bad abbrev form"))?;
            cursor += n;
            if attr == 0 && form == 0 {
                break;
            }
            let implicit_const = if form == 0x21 {
                let (v, n) = read_sleb128(&bytes[cursor..])
                    .ok_or_else(|| anyhow!("bad implicit_const"))?;
                cursor += n;
                Some(v)
            } else {
                None
            };
            attrs.push(AbbrevAttr {
                attr,
                form,
                implicit_const,
            });
        }
        map.insert(
            code,
            Abbrev {
                tag,
                has_children,
                attrs,
            },
        );
    }
    Ok(map)
}

/// Size in bytes of a given DW_FORM, or `None` if we don't recognize it.
/// `bytes` is the remainder of the slice at this attribute's position, used
/// only for variable-length forms (ULEB/SLEB/block/exprloc/string).
fn form_size(form: u64, addr_size: u8, offset_size: usize, bytes: &[u8]) -> Option<usize> {
    match form {
        0x01 => Some(addr_size as usize),          // DW_FORM_addr
        0x03 => {
            // DW_FORM_block2
            if bytes.len() < 2 { return None; }
            let l = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
            Some(2 + l)
        }
        0x04 => {
            // DW_FORM_block4
            if bytes.len() < 4 { return None; }
            let l = u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize;
            Some(4 + l)
        }
        0x05 => Some(2),                            // data2
        0x06 => Some(4),                            // data4
        0x07 => Some(8),                            // data8
        0x08 => {
            // DW_FORM_string (null-terminated C string)
            bytes.iter().position(|&b| b == 0).map(|i| i + 1)
        }
        0x09 => {
            // DW_FORM_block
            let (l, n) = read_uleb128(bytes)?;
            Some(n + l as usize)
        }
        0x0a => {
            // DW_FORM_block1
            if bytes.is_empty() { return None; }
            Some(1 + bytes[0] as usize)
        }
        0x0b => Some(1), // data1
        0x0c => Some(1), // flag
        0x0d => read_sleb128(bytes).map(|(_, n)| n), // sdata
        0x0e => Some(offset_size),                  // strp
        0x0f => read_uleb128(bytes).map(|(_, n)| n), // udata
        0x10 => Some(offset_size),                  // ref_addr
        0x11 => Some(1),                            // ref1
        0x12 => Some(2),                            // ref2
        0x13 => Some(4),                            // ref4
        0x14 => Some(8),                            // ref8
        0x15 => read_uleb128(bytes).map(|(_, n)| n), // ref_udata
        0x16 => {
            // DW_FORM_indirect: form is given inline
            let (inner, n) = read_uleb128(bytes)?;
            let inner_size = form_size(inner, addr_size, offset_size, &bytes[n..])?;
            Some(n + inner_size)
        }
        0x17 => Some(offset_size),                  // sec_offset
        0x18 => {
            // DW_FORM_exprloc
            let (l, n) = read_uleb128(bytes)?;
            Some(n + l as usize)
        }
        0x19 => Some(0),                            // flag_present
        0x1a => read_uleb128(bytes).map(|(_, n)| n), // strx
        0x1b => read_uleb128(bytes).map(|(_, n)| n), // addrx
        0x1c => Some(4),                            // ref_sup4
        0x1d => Some(offset_size),                  // strp_sup
        0x1e => Some(16),                           // data16
        0x1f => Some(offset_size),                  // line_strp
        0x20 => Some(8),                            // ref_sig8
        0x21 => Some(0),                            // implicit_const
        0x22 => read_uleb128(bytes).map(|(_, n)| n), // loclistx
        0x23 => read_uleb128(bytes).map(|(_, n)| n), // rnglistx
        0x24 => Some(8),                            // ref_sup8
        0x25 => Some(1),                            // strx1
        0x26 => Some(2),                            // strx2
        0x27 => Some(3),                            // strx3
        0x28 => Some(4),                            // strx4
        0x29 => Some(1),                            // addrx1
        0x2a => Some(2),                            // addrx2
        0x2b => Some(3),                            // addrx3
        0x2c => Some(4),                            // addrx4
        _ => None,
    }
}

fn resolve_addr(symbols: &GlobalSymbols, addr: u64) -> Option<(String, i64)> {
    if let Some(f) = symbols.functions.get(&addr) {
        return Some((f.export_name().to_string(), 0));
    }
    if let Some((start, f)) = symbols.functions.range(..=addr).next_back() {
        if addr < *start + f.size {
            return Some((f.export_name().to_string(), (addr - *start) as i64));
        }
    }
    None
}

fn read_addr(bytes: &[u8], size: u8) -> u64 {
    match size {
        4 => u32::from_le_bytes(bytes[0..4].try_into().unwrap_or([0; 4])) as u64,
        8 => u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8])),
        _ => 0,
    }
}

fn read_offset(bytes: &[u8], size: usize) -> u64 {
    match size {
        4 => u32::from_le_bytes(bytes[0..4].try_into().unwrap_or([0; 4])) as u64,
        8 => u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8])),
        _ => 0,
    }
}

fn read_uleb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

fn read_sleb128(bytes: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 {
                result |= -1i64 << shift;
            }
            return Some((result, i + 1));
        }
        if shift > 63 {
            return None;
        }
    }
    None
}
