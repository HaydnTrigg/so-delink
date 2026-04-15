//! DWARF compilation unit indexing.
//!
//! Walks every CU in the binary and records:
//!  - CU-level metadata (name, comp_dir, producer, language, address ranges)
//!  - subprograms (functions) with address + size + name
//!  - global variables with their static addresses

use crate::binary::{Binary, DwarfSlice};
use crate::error::Result;
use gimli::{AttributeValue, DebuggingInformationEntry, Dwarf, Operation, Unit};
use std::ops::Range;

#[derive(Debug, Clone)]
pub struct CompilationUnit {
    pub id: usize,
    pub name: String,
    pub comp_dir: Option<String>,
    pub producer: Option<String>,
    pub language: Option<gimli::DwLang>,
    pub ranges: Vec<Range<u64>>,
    pub functions: Vec<Function>,
    pub variables: Vec<Variable>,
    /// Byte range of this CU in `.debug_info` (for DWARF slice extraction).
    pub debug_info_range: Range<usize>,
    /// Byte range of this CU's abbrev table in `.debug_abbrev`.
    pub debug_abbrev_range: Range<usize>,
    /// Byte range of this CU's line program in `.debug_line`, if present.
    pub debug_line_range: Option<Range<usize>>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub linkage_name: Option<String>,
    pub addr: u64,
    pub size: u64,
    pub external: bool,
}

#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub linkage_name: Option<String>,
    pub addr: u64,
    pub external: bool,
}

pub struct CuIndex {
    pub units: Vec<CompilationUnit>,
}

impl CuIndex {
    pub fn build(binary: &Binary<'_>) -> Result<Self> {
        use object::{Object as _, ObjectSection as _};
        let dwarf = &binary.dwarf;
        let abbrev_section: &[u8] = binary
            .elf
            .section_by_name(".debug_abbrev")
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        let line_section: &[u8] = binary
            .elf
            .section_by_name(".debug_line")
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);

        let mut units = Vec::new();
        let mut headers = dwarf.units();
        let mut cu_id = 0usize;
        while let Some(header) = headers.next()? {
            let unit = dwarf.unit(header.clone())?;
            if let Some(cu) = build_unit(
                dwarf,
                header,
                &unit,
                abbrev_section,
                line_section,
                cu_id,
            )? {
                units.push(cu);
                cu_id += 1;
            }
        }
        Ok(Self { units })
    }

    pub fn total_functions(&self) -> usize {
        self.units.iter().map(|u| u.functions.len()).sum()
    }

    pub fn total_variables(&self) -> usize {
        self.units.iter().map(|u| u.variables.len()).sum()
    }
}

fn build_unit<'a>(
    dwarf: &Dwarf<DwarfSlice<'a>>,
    unit_header: gimli::UnitHeader<DwarfSlice<'a>>,
    unit: &Unit<DwarfSlice<'a>>,
    abbrev_section: &[u8],
    line_section: &[u8],
    id: usize,
) -> Result<Option<CompilationUnit>> {
    let mut entries = unit.entries();
    let Some((_, root)) = entries.next_dfs()? else {
        return Ok(None);
    };
    if root.tag() != gimli::DW_TAG_compile_unit {
        return Ok(None);
    }

    let name = attr_string(dwarf, unit, root, gimli::DW_AT_name)?.unwrap_or_else(|| "<anon>".into());
    let comp_dir = attr_string(dwarf, unit, root, gimli::DW_AT_comp_dir)?;
    let producer = attr_string(dwarf, unit, root, gimli::DW_AT_producer)?;
    let language = match root.attr_value(gimli::DW_AT_language)? {
        Some(AttributeValue::Language(l)) => Some(l),
        _ => None,
    };

    let mut ranges = Vec::new();
    let mut range_iter = dwarf.unit_ranges(unit)?;
    while let Some(r) = range_iter.next()? {
        if r.begin < r.end {
            ranges.push(r.begin..r.end);
        }
    }

    let debug_info_range = compute_debug_info_range(&unit_header);
    let debug_abbrev_range =
        compute_debug_abbrev_range(unit_header.debug_abbrev_offset().0 as usize, abbrev_section);
    let debug_line_range = root
        .attr_value(gimli::DW_AT_stmt_list)?
        .and_then(|v| match v {
            AttributeValue::DebugLineRef(off) => Some(off.0 as usize),
            AttributeValue::SecOffset(o) => Some(o as usize),
            _ => None,
        })
        .and_then(|off| compute_debug_line_range(off, line_section));

    let mut functions = Vec::new();
    let mut variables = Vec::new();

    let mut entries = unit.entries();
    while let Some((_, entry)) = entries.next_dfs()? {
        match entry.tag() {
            gimli::DW_TAG_subprogram => {
                if let Some(f) = extract_function(dwarf, unit, entry)? {
                    functions.push(f);
                }
            }
            gimli::DW_TAG_variable => {
                if let Some(v) = extract_variable(dwarf, unit, entry)? {
                    variables.push(v);
                }
            }
            _ => {}
        }
    }

    Ok(Some(CompilationUnit {
        id,
        name,
        comp_dir,
        producer,
        language,
        ranges,
        functions,
        variables,
        debug_info_range,
        debug_abbrev_range,
        debug_line_range,
    }))
}

/// Byte range of this CU header + its DIE tree in `.debug_info`.
fn compute_debug_info_range<'a>(header: &gimli::UnitHeader<DwarfSlice<'a>>) -> Range<usize> {
    let start = header
        .offset()
        .as_debug_info_offset()
        .map(|o| o.0)
        .unwrap_or(0);
    let total = header.length_including_self();
    start..start + total
}

/// Scan forward from `start` in `.debug_abbrev` until the terminating `0`
/// abbrev code that ends this CU's abbrev table. Multiple CUs may share a
/// single abbrev table (same start); the slice is the same for all.
fn compute_debug_abbrev_range(start: usize, section: &[u8]) -> Range<usize> {
    if start >= section.len() {
        return start..start;
    }
    let mut cursor = start;
    loop {
        if cursor >= section.len() {
            break;
        }
        // Read abbreviation code (ULEB128).
        let (code, code_len) = match read_uleb128(&section[cursor..]) {
            Some(v) => v,
            None => break,
        };
        cursor += code_len;
        if code == 0 {
            break;
        }
        // Skip tag (ULEB128).
        let (_, tag_len) = match read_uleb128(&section[cursor..]) {
            Some(v) => v,
            None => break,
        };
        cursor += tag_len;
        if cursor >= section.len() {
            break;
        }
        // Skip has-children flag (1 byte).
        cursor += 1;
        // Read (attr, form) pairs until (0, 0).
        loop {
            let (attr, al) = match read_uleb128(&section[cursor..]) {
                Some(v) => v,
                None => return start..cursor,
            };
            cursor += al;
            let (form, fl) = match read_uleb128(&section[cursor..]) {
                Some(v) => v,
                None => return start..cursor,
            };
            cursor += fl;
            if attr == 0 && form == 0 {
                break;
            }
            // DW_FORM_implicit_const (0x21) carries an additional SLEB128.
            if form == 0x21 {
                let (_, il) = match read_sleb128(&section[cursor..]) {
                    Some(v) => v,
                    None => return start..cursor,
                };
                cursor += il;
            }
        }
    }
    start..cursor
}

/// Byte range of one line program in `.debug_line`, starting at `start`.
/// The line program begins with a `unit_length` header identical in spirit
/// to `.debug_info`'s CU header.
fn compute_debug_line_range(start: usize, section: &[u8]) -> Option<Range<usize>> {
    if start + 4 > section.len() {
        return None;
    }
    let initial = u32::from_le_bytes(section[start..start + 4].try_into().ok()?);
    let (header_size, total) = if initial == 0xffff_ffff {
        if start + 12 > section.len() {
            return None;
        }
        let ext = u64::from_le_bytes(section[start + 4..start + 12].try_into().ok()?) as usize;
        (12, 12 + ext)
    } else {
        (4, 4 + initial as usize)
    };
    let _ = header_size;
    if start + total > section.len() {
        return None;
    }
    Some(start..start + total)
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

fn extract_function<'a>(
    dwarf: &Dwarf<DwarfSlice<'a>>,
    unit: &Unit<DwarfSlice<'a>>,
    entry: &DebuggingInformationEntry<DwarfSlice<'a>>,
) -> Result<Option<Function>> {
    // Skip abstract/inlined-only instances; we want concrete definitions.
    if entry.attr_value(gimli::DW_AT_inline)?.is_some()
        && entry.attr_value(gimli::DW_AT_low_pc)?.is_none()
    {
        return Ok(None);
    }

    let Some(addr) = attr_address(dwarf, unit, entry, gimli::DW_AT_low_pc)? else {
        return Ok(None);
    };
    let size = match entry.attr_value(gimli::DW_AT_high_pc)? {
        Some(AttributeValue::Addr(end)) => end.saturating_sub(addr),
        Some(AttributeValue::Udata(s)) => s,
        Some(AttributeValue::Data1(s)) => s as u64,
        Some(AttributeValue::Data2(s)) => s as u64,
        Some(AttributeValue::Data4(s)) => s as u64,
        Some(AttributeValue::Data8(s)) => s,
        _ => 0,
    };

    // C++ member / inline / out-of-line definitions usually leave DW_AT_name
    // and DW_AT_linkage_name empty on the concrete DIE and point at a
    // declaration DIE via DW_AT_specification. Inline instances use
    // DW_AT_abstract_origin. Follow both to find the real name.
    let (name, linkage_name, external) = resolve_names_with_refs(dwarf, unit, entry)?;
    let name = name.unwrap_or_else(|| "<anon>".into());

    Ok(Some(Function {
        name,
        linkage_name,
        addr,
        size,
        external,
    }))
}

/// Walk `DW_AT_specification` / `DW_AT_abstract_origin` refs to find
/// `DW_AT_name`, `DW_AT_linkage_name`, and `DW_AT_external`. Walks at most
/// a few hops to avoid loops (DWARF doesn't usually produce them but we
/// cap for safety).
fn resolve_names_with_refs<'a>(
    dwarf: &Dwarf<DwarfSlice<'a>>,
    unit: &Unit<DwarfSlice<'a>>,
    entry: &DebuggingInformationEntry<DwarfSlice<'a>>,
) -> Result<(Option<String>, Option<String>, bool)> {
    let mut name = attr_string(dwarf, unit, entry, gimli::DW_AT_name)?;
    let mut linkage = attr_string(dwarf, unit, entry, gimli::DW_AT_linkage_name)?
        .or(attr_string(dwarf, unit, entry, gimli::DW_AT_MIPS_linkage_name)?);
    let mut external = matches!(
        entry.attr_value(gimli::DW_AT_external)?,
        Some(AttributeValue::Flag(true))
    );

    let mut current_offset = match entry.attr_value(gimli::DW_AT_specification)? {
        Some(AttributeValue::UnitRef(o)) => Some(o),
        _ => match entry.attr_value(gimli::DW_AT_abstract_origin)? {
            Some(AttributeValue::UnitRef(o)) => Some(o),
            _ => None,
        },
    };
    let mut hops = 0usize;
    while let Some(off) = current_offset {
        if hops > 4 {
            break;
        }
        hops += 1;
        let Ok(referenced) = unit.entry(off) else {
            break;
        };
        if name.is_none() {
            name = attr_string(dwarf, unit, &referenced, gimli::DW_AT_name)?;
        }
        if linkage.is_none() {
            linkage = attr_string(dwarf, unit, &referenced, gimli::DW_AT_linkage_name)?
                .or(attr_string(dwarf, unit, &referenced, gimli::DW_AT_MIPS_linkage_name)?);
        }
        if !external {
            external = matches!(
                referenced.attr_value(gimli::DW_AT_external)?,
                Some(AttributeValue::Flag(true))
            );
        }
        current_offset = match referenced.attr_value(gimli::DW_AT_specification)? {
            Some(AttributeValue::UnitRef(o)) => Some(o),
            _ => match referenced.attr_value(gimli::DW_AT_abstract_origin)? {
                Some(AttributeValue::UnitRef(o)) => Some(o),
                _ => None,
            },
        };
    }

    Ok((name, linkage, external))
}

fn extract_variable<'a>(
    dwarf: &Dwarf<DwarfSlice<'a>>,
    unit: &Unit<DwarfSlice<'a>>,
    entry: &DebuggingInformationEntry<DwarfSlice<'a>>,
) -> Result<Option<Variable>> {
    let Some(addr) = variable_address(dwarf, unit, entry)? else {
        return Ok(None);
    };
    let name = attr_string(dwarf, unit, entry, gimli::DW_AT_name)?.unwrap_or_else(|| "<anon>".into());
    let linkage_name = attr_string(dwarf, unit, entry, gimli::DW_AT_linkage_name)?;
    let external = matches!(
        entry.attr_value(gimli::DW_AT_external)?,
        Some(AttributeValue::Flag(true))
    );
    Ok(Some(Variable {
        name,
        linkage_name,
        addr,
        external,
    }))
}

fn variable_address<'a>(
    dwarf: &Dwarf<DwarfSlice<'a>>,
    unit: &Unit<DwarfSlice<'a>>,
    entry: &DebuggingInformationEntry<DwarfSlice<'a>>,
) -> Result<Option<u64>> {
    let Some(attr) = entry.attr_value(gimli::DW_AT_location)? else {
        return Ok(None);
    };
    let expr = match attr {
        AttributeValue::Exprloc(e) => e,
        AttributeValue::LocationListsRef(_) => return Ok(None),
        _ => return Ok(None),
    };
    let mut ops = expr.operations(unit.encoding());
    match ops.next()? {
        Some(Operation::Address { address }) => Ok(Some(address)),
        Some(Operation::AddressIndex { index }) => {
            let addr = dwarf.address(unit, index)?;
            Ok(Some(addr))
        }
        _ => Ok(None),
    }
}

fn attr_string<'a>(
    dwarf: &Dwarf<DwarfSlice<'a>>,
    unit: &Unit<DwarfSlice<'a>>,
    entry: &DebuggingInformationEntry<DwarfSlice<'a>>,
    name: gimli::DwAt,
) -> Result<Option<String>> {
    let Some(attr) = entry.attr(name)? else {
        return Ok(None);
    };
    let s = dwarf.attr_string(unit, attr.value())?;
    let owned = s.to_string_lossy().into_owned();
    Ok(Some(owned))
}

fn attr_u64<'a>(
    entry: &DebuggingInformationEntry<DwarfSlice<'a>>,
    name: gimli::DwAt,
) -> Result<Option<u64>> {
    match entry.attr_value(name)? {
        Some(AttributeValue::Udata(v)) => Ok(Some(v)),
        Some(AttributeValue::Data1(v)) => Ok(Some(v as u64)),
        Some(AttributeValue::Data2(v)) => Ok(Some(v as u64)),
        Some(AttributeValue::Data4(v)) => Ok(Some(v as u64)),
        Some(AttributeValue::Data8(v)) => Ok(Some(v)),
        _ => Ok(None),
    }
}

fn attr_address<'a>(
    dwarf: &Dwarf<DwarfSlice<'a>>,
    unit: &Unit<DwarfSlice<'a>>,
    entry: &DebuggingInformationEntry<DwarfSlice<'a>>,
    name: gimli::DwAt,
) -> Result<Option<u64>> {
    match entry.attr_value(name)? {
        Some(AttributeValue::Addr(a)) => Ok(Some(a)),
        Some(AttributeValue::DebugAddrIndex(i)) => Ok(Some(dwarf.address(unit, i)?)),
        _ => Ok(None),
    }
}
