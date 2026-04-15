//! Global symbol resolver.
//!
//! Maps every known address in the binary to a symbol: functions and globals
//! from DWARF CUs, plus imported symbols reached through the PLT or GOT. The
//! arch-specific relocation recovery pass consults this when lifting code
//! patterns like `bl <addr>` or `adrp x0, page; ldr x1, [x0, #lo12]`.

use crate::binary::Binary;
use crate::cu::CuIndex;
use crate::error::Result;
use object::read::elf::{ElfFile64, SectionHeader};
#[allow(unused_imports)]
use object::read::elf::FileHeader;
use object::{Endianness, Object as _, ObjectSection as _};
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

#[derive(Debug, Clone)]
pub struct FunctionRef {
    pub cu_id: usize,
    pub name: String,
    pub linkage_name: Option<String>,
    pub size: u64,
    pub external: bool,
}

impl FunctionRef {
    pub fn export_name(&self) -> &str {
        self.linkage_name.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone)]
pub struct VariableRef {
    pub cu_id: usize,
    pub name: String,
    pub linkage_name: Option<String>,
    pub external: bool,
}

impl VariableRef {
    pub fn export_name(&self) -> &str {
        self.linkage_name.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone)]
pub enum ResolvedTarget<'a> {
    /// Resolved to a function inside one of our CUs.
    Internal(&'a FunctionRef),
    /// Resolved via the PLT to an imported dynamic symbol.
    ExternalPlt(&'a str),
    /// Address falls outside all known ranges.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DataResolution {
    pub symbol: String,
    pub addend: i64,
    pub source: DataSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSource {
    Function,
    Variable,
    GotSlot,
    SectionRelative,
}

/// Canonical symbol names we emit at the start of each shared data section.
/// Per-CU `.o`s reference these via addends; `__shared_data.o` defines them.
pub const SYM_RODATA_START: &str = "__delink_rodata_start";
pub const SYM_DATA_START: &str = "__delink_data_start";
pub const SYM_DATA_REL_RO_START: &str = "__delink_data_rel_ro_start";
pub const SYM_BSS_START: &str = "__delink_bss_start";

pub struct GlobalSymbols {
    /// Function start address → function descriptor.
    pub functions: BTreeMap<u64, FunctionRef>,
    /// Global variable address → variable descriptor.
    pub variables: BTreeMap<u64, VariableRef>,
    /// PLT stub address → dynamic symbol name.
    pub plt: HashMap<u64, String>,
    /// `.got` slot address → dynamic symbol name.
    pub got: HashMap<u64, String>,
    pub plt_range: Option<Range<u64>>,
    pub got_range: Option<Range<u64>>,
    pub text_range: Range<u64>,
    pub rodata_range: Option<Range<u64>>,
    pub data_range: Option<Range<u64>>,
    pub data_rel_ro_range: Option<Range<u64>>,
    pub bss_range: Option<Range<u64>>,
}

const AARCH64_PLT_HEADER_SIZE: u64 = 32;
const AARCH64_PLT_ENTRY_SIZE: u64 = 16;

impl GlobalSymbols {
    pub fn build(binary: &Binary<'_>, cus: &CuIndex) -> Result<Self> {
        let mut functions = BTreeMap::new();
        let mut variables = BTreeMap::new();
        for cu in &cus.units {
            for f in &cu.functions {
                if f.size == 0 {
                    continue;
                }
                functions.insert(
                    f.addr,
                    FunctionRef {
                        cu_id: cu.id,
                        name: f.name.clone(),
                        linkage_name: f.linkage_name.clone(),
                        size: f.size,
                        external: f.external,
                    },
                );
            }
            for v in &cu.variables {
                if v.addr == 0 {
                    continue;
                }
                variables.insert(
                    v.addr,
                    VariableRef {
                        cu_id: cu.id,
                        name: v.name.clone(),
                        linkage_name: v.linkage_name.clone(),
                        external: v.external,
                    },
                );
            }
        }

        let section_range = |name: &str| {
            binary
                .elf
                .section_by_name(name)
                .map(|s| s.address()..s.address() + s.size())
        };

        let plt_range = section_range(".plt");
        let got_range = section_range(".got");
        let text_range = section_range(".text").unwrap_or(0..0);
        let rodata_range = section_range(".rodata");
        let data_range = section_range(".data");
        let data_rel_ro_range = section_range(".data.rel.ro");
        let bss_range = section_range(".bss");

        let plt = build_plt_map(&binary.elf, plt_range.clone())?;
        let got = build_got_map(&binary.elf, got_range.clone())?;

        Ok(Self {
            functions,
            variables,
            plt,
            got,
            plt_range,
            got_range,
            text_range,
            rodata_range,
            data_range,
            data_rel_ro_range,
            bss_range,
        })
    }

    pub fn resolve(&self, target: u64) -> ResolvedTarget<'_> {
        if let Some(f) = self.functions.get(&target) {
            return ResolvedTarget::Internal(f);
        }
        if let Some(range) = &self.plt_range {
            if range.contains(&target) {
                if let Some(name) = self.plt.get(&target) {
                    return ResolvedTarget::ExternalPlt(name);
                }
            }
        }
        ResolvedTarget::Unknown
    }

    /// If `target` lands inside a known function (not just at its start),
    /// return the owning function and the offset within it.
    pub fn resolve_into(&self, target: u64) -> Option<(&FunctionRef, u64)> {
        let (start, f) = self.functions.range(..=target).next_back()?;
        if target < *start + f.size {
            Some((f, target - *start))
        } else {
            None
        }
    }

    /// Resolve a data/code address that materialized from e.g. `adrp+add`.
    /// Returns the best symbolic reference we can make.
    pub fn resolve_data(&self, addr: u64) -> Option<DataResolution> {
        if let Some(v) = self.variables.get(&addr) {
            return Some(DataResolution {
                symbol: v.export_name().to_string(),
                addend: 0,
                source: DataSource::Variable,
            });
        }
        if let Some(f) = self.functions.get(&addr) {
            return Some(DataResolution {
                symbol: f.export_name().to_string(),
                addend: 0,
                source: DataSource::Function,
            });
        }
        if let Some((start, f)) = self.functions.range(..=addr).next_back() {
            if addr < *start + f.size {
                return Some(DataResolution {
                    symbol: f.export_name().to_string(),
                    addend: (addr - *start) as i64,
                    source: DataSource::Function,
                });
            }
        }
        if let Some(name) = self.got.get(&addr) {
            return Some(DataResolution {
                symbol: name.clone(),
                addend: 0,
                source: DataSource::GotSlot,
            });
        }
        if let Some(r) = self.section_relative(addr) {
            return Some(r);
        }
        None
    }

    fn section_relative(&self, addr: u64) -> Option<DataResolution> {
        let hit = |range: &Option<Range<u64>>, name: &'static str| -> Option<DataResolution> {
            range.as_ref().and_then(|r| {
                if r.contains(&addr) {
                    Some(DataResolution {
                        symbol: name.to_string(),
                        addend: (addr - r.start) as i64,
                        source: DataSource::SectionRelative,
                    })
                } else {
                    None
                }
            })
        };
        hit(&self.rodata_range, SYM_RODATA_START)
            .or_else(|| hit(&self.data_range, SYM_DATA_START))
            .or_else(|| hit(&self.bss_range, SYM_BSS_START))
            .or_else(|| {
                self.elf_section_range(".data.rel.ro")
                    .and_then(|r| {
                        if r.contains(&addr) {
                            Some(DataResolution {
                                symbol: SYM_DATA_REL_RO_START.to_string(),
                                addend: (addr - r.start) as i64,
                                source: DataSource::SectionRelative,
                            })
                        } else {
                            None
                        }
                    })
            })
    }

    /// Separately-cached `.data.rel.ro` range, if present. Stored lazily here
    /// rather than as a field to keep the struct shape stable.
    fn elf_section_range(&self, _name: &str) -> Option<Range<u64>> {
        // Populated up-front during build via data_rel_ro_range (new field below).
        self.data_rel_ro_range.clone()
    }

    pub fn in_got(&self, addr: u64) -> bool {
        self.got_range
            .as_ref()
            .is_some_and(|r| r.contains(&addr))
    }

    pub fn in_plt(&self, addr: u64) -> bool {
        self.plt_range
            .as_ref()
            .is_some_and(|r| r.contains(&addr))
    }

    pub fn classify_section(&self, addr: u64) -> &'static str {
        fn hit(r: &Option<Range<u64>>, a: u64) -> bool {
            r.as_ref().is_some_and(|x| x.contains(&a))
        }
        if self.text_range.contains(&addr) {
            ".text"
        } else if hit(&self.plt_range, addr) {
            ".plt"
        } else if hit(&self.got_range, addr) {
            ".got"
        } else if hit(&self.rodata_range, addr) {
            ".rodata"
        } else if hit(&self.data_range, addr) {
            ".data"
        } else if hit(&self.bss_range, addr) {
            ".bss"
        } else {
            "?"
        }
    }
}

fn build_plt_map(
    elf: &ElfFile64<'_, Endianness>,
    plt_range: Option<Range<u64>>,
) -> Result<HashMap<u64, String>> {
    let mut map = HashMap::new();
    let Some(plt_range) = plt_range else {
        return Ok(map);
    };

    let entries = read_dynamic_relocs(elf, ".rela.plt")?;
    for (i, entry) in entries.iter().enumerate() {
        if entry.sym_name.is_empty() {
            continue;
        }
        let stub_addr = plt_range.start + AARCH64_PLT_HEADER_SIZE + (i as u64) * AARCH64_PLT_ENTRY_SIZE;
        map.insert(stub_addr, entry.sym_name.clone());
    }
    Ok(map)
}

fn build_got_map(
    elf: &ElfFile64<'_, Endianness>,
    _got_range: Option<Range<u64>>,
) -> Result<HashMap<u64, String>> {
    // Walk both .rela.dyn and .rela.plt; every entry whose r_offset lands in
    // .got (or .got.plt) gives us a slot → symbol mapping. We use r_offset
    // directly since it is the GOT slot VA.
    let mut map = HashMap::new();
    for section in [".rela.dyn", ".rela.plt"] {
        for entry in read_dynamic_relocs(elf, section)? {
            if entry.sym_name.is_empty() {
                continue;
            }
            map.insert(entry.r_offset, entry.sym_name);
        }
    }
    Ok(map)
}

/// A single entry from a dynamic relocation section (`.rela.dyn` or
/// `.rela.plt`), with the dynamic symbol's name resolved (empty for
/// relocations that target no specific symbol, e.g. `R_AARCH64_RELATIVE`).
#[derive(Debug, Clone)]
pub struct DynReloc {
    pub r_offset: u64,
    pub r_type: u32,
    pub r_sym: u32,
    pub r_addend: i64,
    pub sym_name: String,
}

/// Read all dynamic relocations from `.rela.dyn` and `.rela.plt` as
/// structured entries.
pub fn read_all_dyn_relocs(binary: &Binary<'_>) -> Result<Vec<DynReloc>> {
    let mut out = Vec::new();
    for section in [".rela.dyn", ".rela.plt"] {
        out.extend(read_dyn_relocs_full(&binary.elf, section)?);
    }
    Ok(out)
}

fn read_dyn_relocs_full(
    elf: &ElfFile64<'_, Endianness>,
    section_name: &str,
) -> Result<Vec<DynReloc>> {
    let Some(section) = elf.section_by_name(section_name) else {
        return Ok(Vec::new());
    };
    let Some(dynsym) = elf.section_by_name(".dynsym") else {
        return Ok(Vec::new());
    };
    let Some(dynstr) = elf.section_by_name(".dynstr") else {
        return Ok(Vec::new());
    };

    let endian = Endianness::Little;
    let rela_data = section.data()?;
    let dynsym_data = dynsym.data()?;
    let dynstr_data = dynstr.data()?;
    let rela_entsize = section.elf_section_header().sh_entsize(endian);
    let sym_entsize = dynsym.elf_section_header().sh_entsize(endian);
    if rela_entsize == 0 || sym_entsize == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let rela_count = rela_data.len() as u64 / rela_entsize;
    for i in 0..rela_count {
        let off = (i * rela_entsize) as usize;
        let r_offset = u64::from_le_bytes(rela_data[off..off + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(rela_data[off + 8..off + 16].try_into().unwrap());
        let r_addend = i64::from_le_bytes(rela_data[off + 16..off + 24].try_into().unwrap());
        let r_sym = (r_info >> 32) as u32;
        let r_type = (r_info & 0xffff_ffff) as u32;
        let sym_name = if r_sym == 0 {
            String::new()
        } else {
            let sym_off = (r_sym as usize) * sym_entsize as usize;
            if sym_off + 24 > dynsym_data.len() {
                String::new()
            } else {
                let st_name =
                    u32::from_le_bytes(dynsym_data[sym_off..sym_off + 4].try_into().unwrap());
                read_cstr(dynstr_data, st_name as usize).unwrap_or_default()
            }
        };
        out.push(DynReloc {
            r_offset,
            r_type,
            r_sym,
            r_addend,
            sym_name,
        });
    }
    Ok(out)
}

struct RelocEntry {
    r_offset: u64,
    sym_name: String,
}

fn read_dynamic_relocs(
    elf: &ElfFile64<'_, Endianness>,
    section_name: &str,
) -> Result<Vec<RelocEntry>> {
    let Some(section) = elf.section_by_name(section_name) else {
        return Ok(Vec::new());
    };
    let Some(dynsym) = elf.section_by_name(".dynsym") else {
        return Ok(Vec::new());
    };
    let Some(dynstr) = elf.section_by_name(".dynstr") else {
        return Ok(Vec::new());
    };

    let endian = Endianness::Little;
    let rela_data = section.data()?;
    let dynsym_data = dynsym.data()?;
    let dynstr_data = dynstr.data()?;

    let rela_entsize = section.elf_section_header().sh_entsize(endian);
    let sym_entsize = dynsym.elf_section_header().sh_entsize(endian);
    if rela_entsize == 0 || sym_entsize == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let rela_count = rela_data.len() as u64 / rela_entsize;
    for i in 0..rela_count {
        let off = (i * rela_entsize) as usize;
        let r_offset = u64::from_le_bytes(rela_data[off..off + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(rela_data[off + 8..off + 16].try_into().unwrap());
        let sym_idx = (r_info >> 32) as usize;
        let sym_name = if sym_idx == 0 {
            String::new()
        } else {
            let sym_off = sym_idx * sym_entsize as usize;
            if sym_off + 24 > dynsym_data.len() {
                String::new()
            } else {
                let st_name =
                    u32::from_le_bytes(dynsym_data[sym_off..sym_off + 4].try_into().unwrap());
                read_cstr(dynstr_data, st_name as usize).unwrap_or_default()
            }
        };
        out.push(RelocEntry { r_offset, sym_name });
    }
    Ok(out)
}

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..].iter().position(|&b| b == 0).unwrap_or(0);
    std::str::from_utf8(&data[offset..offset + end])
        .ok()
        .map(|s| s.to_string())
}
