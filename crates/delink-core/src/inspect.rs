//! Human-readable summary of a loaded `.so`.

use crate::binary::Binary;
use crate::cu::CuIndex;
use crate::error::Result;
use object::read::elf::SectionHeader as _;
use object::{Endianness, Object as _, ObjectSection as _};
use std::fmt::Write as _;

pub struct InspectReport {
    pub arch: String,
    pub sections: Vec<SectionRow>,
    pub dyn_relocs: Vec<(String, usize)>,
    pub cu_rows: Vec<CuRow>,
    pub total_functions: usize,
    pub total_variables: usize,
    pub has_dwarf: bool,
}

pub struct SectionRow {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String,
}

pub struct CuRow {
    pub name: String,
    pub comp_dir: Option<String>,
    pub ranges: usize,
    pub functions: usize,
    pub variables: usize,
    pub coverage: u64,
}

pub fn inspect(binary: &Binary<'_>) -> Result<InspectReport> {
    let arch = "aarch64".to_string();
    let has_dwarf = binary.has_dwarf();

    let mut sections = Vec::new();
    for section in binary.elf.sections() {
        let name = section.name().unwrap_or("<?>").to_string();
        if name.is_empty() {
            continue;
        }
        sections.push(SectionRow {
            name,
            addr: section.address(),
            size: section.size(),
            kind: format!("{:?}", section.kind()),
        });
    }

    let dyn_relocs = count_dyn_relocs(binary);

    let (cu_rows, total_functions, total_variables) = if has_dwarf {
        let idx = CuIndex::build(binary)?;
        let rows = idx
            .units
            .iter()
            .map(|u| CuRow {
                name: u.name.clone(),
                comp_dir: u.comp_dir.clone(),
                ranges: u.ranges.len(),
                functions: u.functions.len(),
                variables: u.variables.len(),
                coverage: u.ranges.iter().map(|r| r.end - r.start).sum(),
            })
            .collect();
        (rows, idx.total_functions(), idx.total_variables())
    } else {
        (Vec::new(), 0, 0)
    };

    Ok(InspectReport {
        arch,
        sections,
        dyn_relocs,
        cu_rows,
        total_functions,
        total_variables,
        has_dwarf,
    })
}

fn count_dyn_relocs(binary: &Binary<'_>) -> Vec<(String, usize)> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    let endian = Endianness::Little;
    for section in binary.elf.sections() {
        let name = section.name().unwrap_or("");
        if !name.starts_with(".rela.") && !name.starts_with(".rel.") {
            continue;
        }
        let Ok(data) = section.data() else { continue };
        let sh = section.elf_section_header();
        let entsize = sh.sh_entsize(endian);
        if entsize == 0 {
            continue;
        }
        let is_rela = sh.sh_type(endian) == object::elf::SHT_RELA;
        let entry_count = data.len() as u64 / entsize;
        for i in 0..entry_count {
            let off = (i * entsize) as usize;
            let r_info = if is_rela {
                read_u64(&data[off + 8..off + 16])
            } else {
                read_u64(&data[off + 8..off + 16])
            };
            let r_type = (r_info & 0xffff_ffff) as u32;
            *counts.entry(r_type).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .map(|(k, v)| (aarch64_reloc_name(k), v))
        .collect()
}

fn read_u64(b: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&b[..8]);
    u64::from_le_bytes(arr)
}

fn aarch64_reloc_name(t: u32) -> String {
    use object::elf::*;
    let name = match t {
        R_AARCH64_NONE => "R_AARCH64_NONE",
        R_AARCH64_ABS64 => "R_AARCH64_ABS64",
        R_AARCH64_ABS32 => "R_AARCH64_ABS32",
        R_AARCH64_ABS16 => "R_AARCH64_ABS16",
        R_AARCH64_PREL64 => "R_AARCH64_PREL64",
        R_AARCH64_PREL32 => "R_AARCH64_PREL32",
        R_AARCH64_PREL16 => "R_AARCH64_PREL16",
        R_AARCH64_ADR_PREL_PG_HI21 => "R_AARCH64_ADR_PREL_PG_HI21",
        R_AARCH64_ADD_ABS_LO12_NC => "R_AARCH64_ADD_ABS_LO12_NC",
        R_AARCH64_CALL26 => "R_AARCH64_CALL26",
        R_AARCH64_JUMP26 => "R_AARCH64_JUMP26",
        R_AARCH64_ADR_GOT_PAGE => "R_AARCH64_ADR_GOT_PAGE",
        R_AARCH64_LD64_GOT_LO12_NC => "R_AARCH64_LD64_GOT_LO12_NC",
        R_AARCH64_COPY => "R_AARCH64_COPY",
        R_AARCH64_GLOB_DAT => "R_AARCH64_GLOB_DAT",
        R_AARCH64_JUMP_SLOT => "R_AARCH64_JUMP_SLOT",
        R_AARCH64_RELATIVE => "R_AARCH64_RELATIVE",
        R_AARCH64_TLS_DTPMOD => "R_AARCH64_TLS_DTPMOD",
        R_AARCH64_TLS_DTPREL => "R_AARCH64_TLS_DTPREL",
        R_AARCH64_TLS_TPREL => "R_AARCH64_TLS_TPREL",
        R_AARCH64_TLSDESC => "R_AARCH64_TLSDESC",
        R_AARCH64_IRELATIVE => "R_AARCH64_IRELATIVE",
        _ => return format!("R_AARCH64_{t}"),
    };
    name.to_string()
}

pub fn format_text(r: &InspectReport) -> String {
    let mut out = String::new();
    writeln!(out, "arch: {}", r.arch).unwrap();
    writeln!(out, "dwarf: {}", if r.has_dwarf { "present" } else { "MISSING" }).unwrap();
    writeln!(out).unwrap();

    writeln!(out, "SECTIONS").unwrap();
    writeln!(out, "  {:<28} {:>16} {:>10}  {}", "name", "addr", "size", "kind").unwrap();
    for s in &r.sections {
        writeln!(
            out,
            "  {:<28} {:016x} {:>10}  {}",
            truncate(&s.name, 28),
            s.addr,
            s.size,
            s.kind
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "DYNAMIC RELOCATIONS").unwrap();
    if r.dyn_relocs.is_empty() {
        writeln!(out, "  (none)").unwrap();
    } else {
        for (name, count) in &r.dyn_relocs {
            writeln!(out, "  {:<40} {:>8}", name, count).unwrap();
        }
    }
    writeln!(out).unwrap();

    writeln!(
        out,
        "COMPILATION UNITS: {} ({} functions, {} variables)",
        r.cu_rows.len(),
        r.total_functions,
        r.total_variables
    )
    .unwrap();
    writeln!(
        out,
        "  {:<50} {:>6} {:>6} {:>6} {:>10}",
        "name", "ranges", "funcs", "vars", "bytes"
    )
    .unwrap();
    for cu in &r.cu_rows {
        writeln!(
            out,
            "  {:<50} {:>6} {:>6} {:>6} {:>10}",
            truncate(&cu.name, 50),
            cu.ranges,
            cu.functions,
            cu.variables,
            cu.coverage
        )
        .unwrap();
    }

    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("…{}", &s[s.len() - (max - 1)..])
    }
}
