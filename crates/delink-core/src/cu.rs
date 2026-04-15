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
        let dwarf = &binary.dwarf;
        let mut units = Vec::new();
        let mut headers = dwarf.units();
        let mut cu_id = 0usize;
        while let Some(header) = headers.next()? {
            let unit = dwarf.unit(header)?;
            if let Some(cu) = build_unit(dwarf, &unit, cu_id)? {
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
    unit: &Unit<DwarfSlice<'a>>,
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
    }))
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
    let size = attr_u64(entry, gimli::DW_AT_high_pc)?.unwrap_or(0);
    // For DWARF 3+, DW_AT_high_pc is an offset from low_pc when encoded as a constant.
    // If encoded as an address, it's already absolute. We normalize to size.
    let size = match entry.attr_value(gimli::DW_AT_high_pc)? {
        Some(AttributeValue::Addr(end)) => end.saturating_sub(addr),
        Some(AttributeValue::Udata(s)) => s,
        _ => size,
    };

    let name = attr_string(dwarf, unit, entry, gimli::DW_AT_name)?.unwrap_or_else(|| "<anon>".into());
    let linkage_name = attr_string(dwarf, unit, entry, gimli::DW_AT_linkage_name)?
        .or(attr_string(dwarf, unit, entry, gimli::DW_AT_MIPS_linkage_name)?);
    let external = matches!(
        entry.attr_value(gimli::DW_AT_external)?,
        Some(AttributeValue::Flag(true))
    );

    Ok(Some(Function {
        name,
        linkage_name,
        addr,
        size,
        external,
    }))
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
