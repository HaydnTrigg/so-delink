//! ET_REL writer. Emits one relocatable ELF object per compilation unit,
//! plus a single `__shared_data.o` that carries the binary's `.rodata` /
//! `.bss` bytes referenced by every other `.o` through named section-start
//! globals.

pub mod dwarf_relocs;

use anyhow::{anyhow, Context, Result};
use delink_aarch64::{recover, RelocKind};
use delink_core::binary::Binary;
use delink_core::cu::CompilationUnit;
use delink_core::symbols::{
    read_all_dyn_relocs, DynReloc, GlobalSymbols, SYM_BSS_START, SYM_DATA_REL_RO_START,
    SYM_DATA_START, SYM_RODATA_START,
};
use object::write::{Comdat, Object, Relocation, SectionId, Symbol, SymbolId, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, Object as _, ObjectSection as _, RelocationFlags,
    SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use std::collections::HashMap;
use std::path::Path;

pub struct EmitOptions<'a> {
    pub cu: &'a CompilationUnit,
    pub symbols: &'a GlobalSymbols,
    /// Emit linkage-scope functions as `STB_WEAK` inside `GRP_COMDAT`
    /// section groups so the linker dedupes duplicate mangled names
    /// across CUs (inline / template instantiations). Off by default
    /// because some analysis tools (objdiff) hide COMDAT-grouped weak
    /// symbols from their UI.
    pub comdat: bool,
}

#[derive(Debug, Default)]
pub struct EmitStats {
    pub text_bytes: u64,
    pub local_symbols: usize,
    pub undef_symbols: usize,
    pub relocations: usize,
    pub unresolved_calls: usize,
    pub decode_failures: usize,
    pub instructions: usize,
    pub ranges_coalesced: usize,
    pub adrp_seen: usize,
    pub adrp_paired: usize,
    pub adrp_unresolved: usize,
    pub dwarf_bytes: u64,
}

pub fn emit_cu(binary: &Binary<'_>, opts: EmitOptions<'_>, out_path: &Path) -> Result<EmitStats> {
    let cu = opts.cu;
    let globals = opts.symbols;

    if cu.functions.is_empty() {
        return Err(anyhow!(
            "CU '{}' has no functions with concrete addresses",
            cu.name
        ));
    }

    let text_section = binary
        .elf
        .section_by_name(".text")
        .ok_or_else(|| anyhow!("binary has no .text section"))?;
    let text_base = text_section.address();
    let text_data = text_section.data().context("read .text")?;
    let text_end_abs = text_base + text_section.size();

    let live_functions: Vec<_> = cu
        .functions
        .iter()
        .filter(|f| f.size > 0 && f.addr >= text_base && f.addr + f.size <= text_end_abs)
        .collect();

    if live_functions.is_empty() {
        return Err(anyhow!(
            "CU '{}' has no functions with addresses inside .text",
            cu.name
        ));
    }

    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);

    // Pass 1: create a section + symbol for every live function so that
    // intra-CU references resolve to local symbols during reloc emission.
    struct FunctionSlot {
        section_id: SectionId,
        addr: u64,
        size: u64,
    }
    let mut slots: Vec<FunctionSlot> = Vec::with_capacity(live_functions.len());
    let mut local_syms: HashMap<String, SymbolId> = HashMap::new();
    let mut total_text_bytes: u64 = 0;

    for f in &live_functions {
        let raw_name = f
            .linkage_name
            .as_deref()
            .unwrap_or(f.name.as_str());
        // Anonymous functions (no linkage_name, no DW_AT_name) get a
        // synthesized name so every symbol is unique and linkable.
        let name = if raw_name.is_empty() || raw_name == "<anon>" {
            format!("__delink_sub_{:x}", f.addr)
        } else {
            raw_name.to_string()
        };

        let section_name = format!(".text.{}", sanitize_section_suffix(&name));
        let section_id = obj.add_section(
            Vec::new(),
            section_name.into_bytes(),
            SectionKind::Text,
        );

        let start = (f.addr - text_base) as usize;
        let end = start + f.size as usize;
        obj.append_section_data(section_id, &text_data[start..end], 4);
        total_text_bytes += f.size;

        let scope = if f.external {
            SymbolScope::Linkage
        } else {
            SymbolScope::Compilation
        };
        let is_linkage = matches!(scope, SymbolScope::Linkage);
        let weak = opts.comdat && is_linkage;
        let symbol_id = obj.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: f.size,
            kind: SymbolKind::Text,
            scope,
            weak,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });
        local_syms.insert(name.clone(), symbol_id);

        if opts.comdat && is_linkage {
            obj.add_comdat(Comdat {
                kind: object::ComdatKind::Any,
                symbol: symbol_id,
                sections: vec![section_id],
            });
        }

        slots.push(FunctionSlot {
            section_id,
            addr: f.addr,
            size: f.size,
        });
    }

    // Pass 2: run recovery per function and attach relocations to each
    // function's own section (offsets are already function-relative because
    // we hand each function its own `base` address to the recovery pass).
    let mut undef_cache: HashMap<String, SymbolId> = HashMap::new();
    let mut relocations = 0usize;
    let mut agg = delink_aarch64::RecoveryDiagnostics::default();

    for slot in &slots {
        let start = (slot.addr - text_base) as usize;
        let end = start + slot.size as usize;
        let fn_bytes = &text_data[start..end];
        let rec = recover(fn_bytes, slot.addr, globals)
            .with_context(|| format!("recover relocations for function at {:#x}", slot.addr))?;

        for r in &rec.relocs {
            let sym_id = resolve_symbol(&mut obj, &local_syms, &mut undef_cache, &r.target);
            let flags = RelocationFlags::Elf {
                r_type: elf_reloc_type(r.kind),
            };
            obj.add_relocation(
                slot.section_id,
                Relocation {
                    offset: r.offset,
                    symbol: sym_id,
                    addend: r.addend,
                    flags,
                },
            )
            .with_context(|| format!("add reloc at {:#x}", r.offset))?;
            relocations += 1;
        }
        agg.instructions += rec.diag.instructions;
        agg.decode_failures += rec.diag.decode_failures;
        agg.bl_resolved += rec.diag.bl_resolved;
        agg.bl_unresolved += rec.diag.bl_unresolved;
        agg.adrp_seen += rec.diag.adrp_seen;
        agg.adrp_paired += rec.diag.adrp_paired;
        agg.adrp_unresolved += rec.diag.adrp_unresolved;
    }

    // DWARF slices — per-CU .debug_info + .debug_abbrev + .debug_line.
    // Each address-bearing field gets a relocation so the linker rewrites
    // it for the new layout.
    let (debug_info_section, debug_info_slice) = add_dwarf_slice(
        &mut obj,
        binary,
        ".debug_info",
        cu.debug_info_range.clone(),
    );
    add_dwarf_slice(
        &mut obj,
        binary,
        ".debug_abbrev",
        cu.debug_abbrev_range.clone(),
    );
    let (debug_line_section, debug_line_slice) = if let Some(range) = cu.debug_line_range.clone() {
        add_dwarf_slice(&mut obj, binary, ".debug_line", range)
    } else {
        (None, None)
    };

    // Synthesize DWARF relocations.
    if let (Some(info_section), Some(info_slice), Some(abbrev_slice)) = (
        debug_info_section,
        debug_info_slice,
        dwarf_section_slice(binary, ".debug_abbrev", cu.debug_abbrev_range.clone()),
    ) {
        match dwarf_relocs::scan_debug_info(info_slice, abbrev_slice, globals) {
            Ok((recs, _diag)) => {
                for r in recs {
                    attach_dwarf_reloc(
                        &mut obj,
                        info_section,
                        &mut local_syms,
                        &mut undef_cache,
                        &r,
                    )?;
                }
            }
            Err(e) => tracing::warn!(cu = %cu.name, error = %e, "debug_info scan failed"),
        }
    }

    if let (Some(line_section), Some(line_slice)) = (debug_line_section, debug_line_slice) {
        match dwarf_relocs::scan_debug_line(line_slice, globals) {
            Ok((recs, _diag)) => {
                for r in recs {
                    attach_dwarf_reloc(
                        &mut obj,
                        line_section,
                        &mut local_syms,
                        &mut undef_cache,
                        &r,
                    )?;
                }
            }
            Err(e) => tracing::warn!(cu = %cu.name, error = %e, "debug_line scan failed"),
        }
    }

    let bytes = obj.write().context("serialize ET_REL")?;
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(out_path, &bytes)
        .with_context(|| format!("write {}", out_path.display()))?;

    let dwarf_bytes = (cu.debug_info_range.end.saturating_sub(cu.debug_info_range.start)
        + cu.debug_abbrev_range
            .end
            .saturating_sub(cu.debug_abbrev_range.start)
        + cu.debug_line_range
            .as_ref()
            .map(|r| r.end - r.start)
            .unwrap_or(0)) as u64;

    Ok(EmitStats {
        text_bytes: total_text_bytes,
        local_symbols: local_syms.len(),
        undef_symbols: undef_cache.len(),
        relocations,
        unresolved_calls: agg.bl_unresolved,
        decode_failures: agg.decode_failures,
        instructions: agg.instructions,
        ranges_coalesced: cu.ranges.len().max(1),
        adrp_seen: agg.adrp_seen,
        adrp_paired: agg.adrp_paired,
        adrp_unresolved: agg.adrp_unresolved,
        dwarf_bytes,
    })
}

/// Copy a byte slice of a DWARF section into the output object and return
/// the new section id + a borrow of the slice (for follow-up reloc scans).
fn add_dwarf_slice<'a>(
    obj: &mut Object,
    binary: &'a Binary<'_>,
    section_name: &str,
    range: std::ops::Range<usize>,
) -> (Option<SectionId>, Option<&'a [u8]>) {
    let slice = dwarf_section_slice(binary, section_name, range);
    let Some(slice) = slice else {
        return (None, None);
    };
    let kind = if section_name == ".debug_str" || section_name == ".debug_line_str" {
        SectionKind::DebugString
    } else {
        SectionKind::Debug
    };
    let section_id = obj.add_section(Vec::new(), section_name.as_bytes().to_vec(), kind);
    obj.append_section_data(section_id, slice, 1);
    (Some(section_id), Some(slice))
}

fn dwarf_section_slice<'a>(
    binary: &'a Binary<'_>,
    section_name: &str,
    range: std::ops::Range<usize>,
) -> Option<&'a [u8]> {
    let section = binary.elf.section_by_name(section_name)?;
    let data = section.data().ok()?;
    if range.start >= data.len() || range.end > data.len() || range.start >= range.end {
        return None;
    }
    Some(&data[range])
}

fn attach_dwarf_reloc(
    obj: &mut Object,
    section_id: SectionId,
    local_syms: &mut HashMap<String, SymbolId>,
    undef_cache: &mut HashMap<String, SymbolId>,
    reloc: &dwarf_relocs::DwarfReloc,
) -> Result<()> {
    let (offset, symbol, addend, r_type) = match reloc {
        dwarf_relocs::DwarfReloc::Abs64 {
            offset,
            symbol,
            addend,
        } => (*offset, symbol, *addend, object::elf::R_AARCH64_ABS64),
        dwarf_relocs::DwarfReloc::Abs32 {
            offset,
            symbol,
            addend,
        } => (*offset, symbol, *addend, object::elf::R_AARCH64_ABS32),
    };
    let sym_id = resolve_symbol(obj, local_syms, undef_cache, symbol);
    obj.add_relocation(
        section_id,
        Relocation {
            offset,
            symbol: sym_id,
            addend,
            flags: RelocationFlags::Elf { r_type },
        },
    )
    .map_err(Into::into)
}

/// Sanitize a mangled symbol into something safe as a section-name suffix.
/// AArch64 ELF permits most chars, but some tools choke on unusual bytes.
fn sanitize_section_suffix(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            c if c.is_ascii_alphanumeric() => out.push(c),
            '_' | '.' | '$' | '@' => out.push(ch),
            _ => out.push('_'),
        }
    }
    if out.is_empty() {
        out.push('x');
    }
    out
}

fn resolve_symbol(
    obj: &mut Object,
    local: &HashMap<String, SymbolId>,
    undef: &mut HashMap<String, SymbolId>,
    name: &str,
) -> SymbolId {
    if let Some(id) = local.get(name) {
        return *id;
    }
    if let Some(id) = undef.get(name) {
        return *id;
    }
    let id = obj.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    undef.insert(name.to_string(), id);
    id
}

fn elf_reloc_type(kind: RelocKind) -> u32 {
    use object::elf::*;
    match kind {
        RelocKind::Call26 => R_AARCH64_CALL26,
        RelocKind::Jump26 => R_AARCH64_JUMP26,
        RelocKind::AdrPrelPgHi21 => R_AARCH64_ADR_PREL_PG_HI21,
        RelocKind::AddAbsLo12Nc => R_AARCH64_ADD_ABS_LO12_NC,
        RelocKind::Ldst8AbsLo12Nc => R_AARCH64_LDST8_ABS_LO12_NC,
        RelocKind::Ldst16AbsLo12Nc => R_AARCH64_LDST16_ABS_LO12_NC,
        RelocKind::Ldst32AbsLo12Nc => R_AARCH64_LDST32_ABS_LO12_NC,
        RelocKind::Ldst64AbsLo12Nc => R_AARCH64_LDST64_ABS_LO12_NC,
        RelocKind::Ldst128AbsLo12Nc => R_AARCH64_LDST128_ABS_LO12_NC,
        RelocKind::AdrGotPage => R_AARCH64_ADR_GOT_PAGE,
        RelocKind::Ld64GotLo12Nc => R_AARCH64_LD64_GOT_LO12_NC,
    }
}

/// Find a CU by matching the tail of its `name` against `needle`.
pub fn find_cu<'a>(units: &'a [CompilationUnit], needle: &str) -> Option<&'a CompilationUnit> {
    units
        .iter()
        .find(|u| u.name.ends_with(needle) || u.name == needle)
}

/// Emit a single ET_REL carrying the binary's shared data sections with
/// named start symbols. Per-CU `.o`s reference these symbols with addends
/// for anonymous string literals / globals we can't attribute to a CU.
///
/// M4a scope: `.rodata` (bytes, read-only) and `.bss` (size only).
/// `.data` and `.data.rel.ro` carry runtime pointers that need reloc
/// translation from `.rela.dyn`; deferred to M5.
#[derive(Debug, Default)]
pub struct SharedDataStats {
    pub rodata_bytes: u64,
    pub data_bytes: u64,
    pub data_rel_ro_bytes: u64,
    pub init_array_bytes: u64,
    pub fini_array_bytes: u64,
    pub bss_bytes: u64,
    pub eh_frame_bytes: u64,
    pub dwarf_shared_bytes: u64,
    pub debug_ranges_relocs: usize,
    pub debug_loc_relocs: usize,
    pub translated_relatives: usize,
    pub translated_abs64: usize,
    pub translated_glob_dat: usize,
    pub skipped_relocs: usize,
    pub unresolved_relocs: usize,
    pub fde_relocs: usize,
}

struct DataSectionSlot {
    section_id: SectionId,
    vaddr: u64,
    size: u64,
    needs_relocs: bool,
}

pub fn emit_shared_data(
    binary: &Binary<'_>,
    symbols: &GlobalSymbols,
    out_path: &Path,
) -> Result<SharedDataStats> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let mut stats = SharedDataStats::default();
    let mut slots: Vec<DataSectionSlot> = Vec::new();
    let mut undef_cache: HashMap<String, SymbolId> = HashMap::new();

    fn add_data_section(
        obj: &mut Object,
        binary: &Binary<'_>,
        slots: &mut Vec<DataSectionSlot>,
        name: &str,
        kind: SectionKind,
        start_symbol: Option<&str>,
        needs_relocs: bool,
    ) -> Result<u64> {
        let Some(section) = binary.elf.section_by_name(name) else {
            return Ok(0);
        };
        let data = section.data().with_context(|| format!("read {name}"))?;
        let section_id = obj.add_section(Vec::new(), name.as_bytes().to_vec(), kind);
        obj.append_section_data(section_id, data, 16);
        if let Some(sym) = start_symbol {
            add_start_symbol(obj, section_id, sym);
        }
        slots.push(DataSectionSlot {
            section_id,
            vaddr: section.address(),
            size: section.size(),
            needs_relocs,
        });
        Ok(data.len() as u64)
    }

    stats.rodata_bytes = add_data_section(
        &mut obj,
        binary,
        &mut slots,
        ".rodata",
        SectionKind::ReadOnlyData,
        Some(SYM_RODATA_START),
        false,
    )?;
    stats.data_bytes = add_data_section(
        &mut obj,
        binary,
        &mut slots,
        ".data",
        SectionKind::Data,
        Some(SYM_DATA_START),
        true,
    )?;
    stats.data_rel_ro_bytes = add_data_section(
        &mut obj,
        binary,
        &mut slots,
        ".data.rel.ro",
        SectionKind::ReadOnlyDataWithRel,
        Some(SYM_DATA_REL_RO_START),
        true,
    )?;
    stats.init_array_bytes = add_data_section(
        &mut obj,
        binary,
        &mut slots,
        ".init_array",
        SectionKind::Data,
        None,
        true,
    )?;
    stats.fini_array_bytes = add_data_section(
        &mut obj,
        binary,
        &mut slots,
        ".fini_array",
        SectionKind::Data,
        None,
        true,
    )?;

    if let Some(section) = binary.elf.section_by_name(".bss") {
        let size = section.size();
        let section_id =
            obj.add_section(Vec::new(), b".bss".to_vec(), SectionKind::UninitializedData);
        obj.section_mut(section_id).append_bss(size, 16);
        add_start_symbol(&mut obj, section_id, SYM_BSS_START);
        slots.push(DataSectionSlot {
            section_id,
            vaddr: section.address(),
            size,
            needs_relocs: false,
        });
        stats.bss_bytes = size;
    }

    if let Some(section) = binary.elf.section_by_name(".eh_frame") {
        let data = section.data().context("read .eh_frame")?;
        let section_id =
            obj.add_section(Vec::new(), b".eh_frame".to_vec(), SectionKind::ReadOnlyData);
        obj.append_section_data(section_id, data, 8);
        stats.eh_frame_bytes = data.len() as u64;
        stats.fde_relocs =
            translate_eh_frame(&mut obj, section_id, data, section.address(), symbols, &mut undef_cache)?;
    }

    // DWARF sections that are shared across all per-CU `.o`s go here. Per-CU
    // `.debug_info`/`.debug_abbrev`/`.debug_line` live in each CU's own `.o`
    // (see emit_cu), and reference these shared sections by raw offset.
    //
    // For address-bearing shared sections (.debug_ranges / .debug_loc) we
    // walk their content and attach per-pair relocations so the linker
    // rewrites absolute VAs to point at the new function layout.
    let mut debug_ranges_info: Option<(SectionId, &[u8])> = None;
    let mut debug_loc_info: Option<(SectionId, &[u8])> = None;

    for dwarf_shared in [
        ".debug_str",
        ".debug_line_str",
        ".debug_str_offsets",
        ".debug_ranges",
        ".debug_rnglists",
        ".debug_loc",
        ".debug_loclists",
        ".debug_addr",
    ] {
        if let Some(section) = binary.elf.section_by_name(dwarf_shared) {
            let data = section.data().unwrap_or(&[]);
            if data.is_empty() {
                continue;
            }
            let kind = if dwarf_shared == ".debug_str" || dwarf_shared == ".debug_line_str" {
                SectionKind::DebugString
            } else {
                SectionKind::Debug
            };
            let sid =
                obj.add_section(Vec::new(), dwarf_shared.as_bytes().to_vec(), kind);
            obj.append_section_data(sid, data, 1);
            stats.dwarf_shared_bytes += data.len() as u64;

            let start_sym = match dwarf_shared {
                ".debug_str" => Some("__delink_debug_str_start"),
                ".debug_line_str" => Some("__delink_debug_line_str_start"),
                ".debug_ranges" => Some("__delink_debug_ranges_start"),
                ".debug_rnglists" => Some("__delink_debug_rnglists_start"),
                ".debug_loc" => Some("__delink_debug_loc_start"),
                ".debug_loclists" => Some("__delink_debug_loclists_start"),
                _ => None,
            };
            if let Some(sym) = start_sym {
                obj.add_symbol(Symbol {
                    name: sym.as_bytes().to_vec(),
                    value: 0,
                    size: 0,
                    kind: SymbolKind::Data,
                    scope: SymbolScope::Linkage,
                    weak: false,
                    section: SymbolSection::Section(sid),
                    flags: SymbolFlags::None,
                });
            }

            if dwarf_shared == ".debug_ranges" {
                debug_ranges_info = Some((sid, data));
            } else if dwarf_shared == ".debug_loc" {
                debug_loc_info = Some((sid, data));
            }
        }
    }

    if let Some((sid, data)) = debug_ranges_info {
        let (recs, diag) = dwarf_relocs::scan_debug_ranges(data, 8, symbols);
        for r in recs {
            attach_dwarf_reloc(&mut obj, sid, &mut HashMap::new(), &mut undef_cache, &r)?;
        }
        stats.debug_ranges_relocs = diag.range_pairs_resolved;
    }
    if let Some((sid, data)) = debug_loc_info {
        let (recs, diag) = dwarf_relocs::scan_debug_loc(data, 8, symbols);
        for r in recs {
            attach_dwarf_reloc(&mut obj, sid, &mut HashMap::new(), &mut undef_cache, &r)?;
        }
        stats.debug_loc_relocs = diag.loc_pairs_resolved;
    }

    // Emit every DWARF-named global as a defined symbol in the section
    // whose range contains it, so per-CU `.o`s can resolve by name.
    for (addr, var) in &symbols.variables {
        let Some(slot) = slots
            .iter()
            .find(|s| s.vaddr <= *addr && *addr < s.vaddr + s.size)
        else {
            continue;
        };
        let name = var.export_name().to_string();
        if name.is_empty() {
            continue;
        }
        obj.add_symbol(Symbol {
            name: name.into_bytes(),
            value: *addr - slot.vaddr,
            size: 0,
            kind: SymbolKind::Data,
            scope: if var.external {
                SymbolScope::Linkage
            } else {
                SymbolScope::Compilation
            },
            weak: false,
            section: SymbolSection::Section(slot.section_id),
            flags: SymbolFlags::None,
        });
    }

    // Translate .rela.dyn / .rela.plt entries that land in the sections
    // above into per-object R_AARCH64_ABS64 relocations.
    let all_relocs = read_all_dyn_relocs(binary)?;
    for rel in &all_relocs {
        let Some(slot) = slots
            .iter()
            .find(|s| s.needs_relocs && s.vaddr <= rel.r_offset && rel.r_offset < s.vaddr + s.size)
        else {
            stats.skipped_relocs += 1;
            continue;
        };
        let section_offset = rel.r_offset - slot.vaddr;

        let translated = match classify_dyn_reloc(rel) {
            DynClass::Relative => {
                let target_addr = rel.r_addend as u64;
                resolve_target_name(symbols, target_addr)
                    .map(|(name, addend)| (name, addend))
            }
            DynClass::Abs64 => Some((rel.sym_name.clone(), rel.r_addend)),
            DynClass::GlobDat => Some((rel.sym_name.clone(), rel.r_addend)),
            DynClass::JumpSlot => {
                stats.skipped_relocs += 1;
                continue;
            }
            DynClass::Other => {
                stats.skipped_relocs += 1;
                continue;
            }
        };

        let Some((name, addend)) = translated else {
            stats.unresolved_relocs += 1;
            continue;
        };
        if name.is_empty() {
            stats.unresolved_relocs += 1;
            continue;
        }

        let sym_id = resolve_or_add_undef(&mut obj, &mut undef_cache, &name);
        obj.add_relocation(
            slot.section_id,
            Relocation {
                offset: section_offset,
                symbol: sym_id,
                addend,
                flags: RelocationFlags::Elf {
                    r_type: object::elf::R_AARCH64_ABS64,
                },
            },
        )
        .with_context(|| format!("add dyn reloc at {:#x}", rel.r_offset))?;

        match classify_dyn_reloc(rel) {
            DynClass::Relative => stats.translated_relatives += 1,
            DynClass::Abs64 => stats.translated_abs64 += 1,
            DynClass::GlobDat => stats.translated_glob_dat += 1,
            _ => {}
        }
    }

    let bytes = obj.write().context("serialize shared-data ET_REL")?;
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(out_path, &bytes)
        .with_context(|| format!("write {}", out_path.display()))?;

    Ok(stats)
}

/// Walk `.eh_frame`, find each FDE's `pc_begin` field (assumed `DW_EH_PE_pcrel
/// | DW_EH_PE_sdata4` — standard on AArch64 ELF), resolve the target function
/// address to a symbol, and emit an `R_AARCH64_PREL32` relocation at that
/// field so the linker rewrites the offset when the function moves.
///
/// Returns the number of relocations emitted.
fn translate_eh_frame(
    obj: &mut Object,
    section_id: SectionId,
    data: &[u8],
    section_vaddr: u64,
    symbols: &GlobalSymbols,
    undef_cache: &mut HashMap<String, SymbolId>,
) -> Result<usize> {
    let mut cursor = 0usize;
    let mut emitted = 0usize;

    while cursor + 4 <= data.len() {
        let length = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
        if length == 0 {
            // Terminator.
            break;
        }
        if length == 0xffff_ffff {
            // 64-bit extended length — uncommon on AArch64 ELF, skip.
            tracing::warn!(".eh_frame has 64-bit record at offset {cursor}; skipping");
            break;
        }

        let record_start = cursor;
        let record_header_end = cursor + 4;
        let record_end = record_header_end + length;
        if record_end > data.len() {
            tracing::warn!(
                ".eh_frame truncated at offset {cursor}: record claims {length} bytes, only {} left",
                data.len() - record_header_end
            );
            break;
        }

        // The second u32 is CIE_id (for CIEs) or CIE_pointer (for FDEs).
        // CIE_id == 0 → this is a CIE; anything else → FDE.
        let cie_id = u32::from_le_bytes(data[record_header_end..record_header_end + 4].try_into().unwrap());
        if cie_id != 0 {
            // FDE: pc_begin follows at record_start + 8.
            let pc_begin_field_off = record_start + 8;
            let pc_begin_rel = i32::from_le_bytes(
                data[pc_begin_field_off..pc_begin_field_off + 4]
                    .try_into()
                    .unwrap(),
            ) as i64;
            let field_vaddr = section_vaddr + pc_begin_field_off as u64;
            let target_vaddr = field_vaddr.wrapping_add(pc_begin_rel as u64);

            if let Some((name, addend)) = fde_resolve_target(symbols, target_vaddr) {
                let sym_id = resolve_or_add_undef(obj, undef_cache, &name);
                obj.add_relocation(
                    section_id,
                    Relocation {
                        offset: pc_begin_field_off as u64,
                        symbol: sym_id,
                        addend,
                        flags: RelocationFlags::Elf {
                            r_type: object::elf::R_AARCH64_PREL32,
                        },
                    },
                )
                .with_context(|| format!("add FDE pc_begin reloc at {:#x}", pc_begin_field_off))?;
                emitted += 1;
            } else {
                tracing::trace!(
                    "FDE at {:#x}: pc_begin {:#x} resolves to no known function",
                    record_start,
                    target_vaddr
                );
            }
        }

        cursor = record_end;
    }

    Ok(emitted)
}

fn fde_resolve_target(symbols: &GlobalSymbols, addr: u64) -> Option<(String, i64)> {
    if let Some(f) = symbols.functions.get(&addr) {
        return Some((f.export_name().to_string(), 0));
    }
    // FDE pc_begin usually points at the first byte of the function. If it
    // didn't (cold-split function segments etc.), fall through to interior
    // lookup.
    if let Some((start, f)) = symbols.functions.range(..=addr).next_back() {
        if addr < *start + f.size {
            return Some((f.export_name().to_string(), (addr - *start) as i64));
        }
    }
    None
}

enum DynClass {
    Relative,
    Abs64,
    GlobDat,
    JumpSlot,
    Other,
}

fn classify_dyn_reloc(rel: &DynReloc) -> DynClass {
    use object::elf::*;
    match rel.r_type {
        R_AARCH64_RELATIVE => DynClass::Relative,
        R_AARCH64_ABS64 => DynClass::Abs64,
        R_AARCH64_GLOB_DAT => DynClass::GlobDat,
        R_AARCH64_JUMP_SLOT => DynClass::JumpSlot,
        _ => DynClass::Other,
    }
}

fn resolve_target_name(symbols: &GlobalSymbols, addr: u64) -> Option<(String, i64)> {
    // Prefer function at exact start; then variable; then fall back to section-relative.
    if let Some(f) = symbols.functions.get(&addr) {
        return Some((f.export_name().to_string(), 0));
    }
    if let Some(v) = symbols.variables.get(&addr) {
        return Some((v.export_name().to_string(), 0));
    }
    if let Some((start, f)) = symbols.functions.range(..=addr).next_back() {
        if addr < *start + f.size {
            return Some((f.export_name().to_string(), (addr - *start) as i64));
        }
    }
    // Section-relative fallback via resolve_data.
    let r = symbols.resolve_data(addr)?;
    Some((r.symbol, r.addend))
}

fn resolve_or_add_undef(
    obj: &mut Object,
    undef: &mut HashMap<String, SymbolId>,
    name: &str,
) -> SymbolId {
    if let Some(id) = undef.get(name) {
        return *id;
    }
    let id = obj.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Unknown,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    undef.insert(name.to_string(), id);
    id
}

fn add_start_symbol(obj: &mut Object, section_id: SectionId, name: &str) {
    obj.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section_id),
        flags: SymbolFlags::None,
    });
}

/// Sanitize a DWARF CU name (which often contains backslashes and colons
/// on Windows-compiled inputs) into a filesystem-safe stem.
pub fn sanitize_cu_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            '/' | '\\' | ':' => out.push('_'),
            c if c.is_ascii_whitespace() => out.push('_'),
            c => out.push(c),
        }
    }
    out
}

/// Split every CU in `idx` into its own `.o` under `out_dir`, in parallel.
/// Skips CUs with no sized functions; returns per-CU outcomes.
#[derive(Debug)]
pub struct CuOutcome {
    pub cu_name: String,
    pub file: std::path::PathBuf,
    pub result: std::result::Result<EmitStats, String>,
}

pub fn split_all(
    binary: &Binary<'_>,
    idx: &delink_core::cu::CuIndex,
    symbols: &GlobalSymbols,
    out_dir: &Path,
    comdat: bool,
) -> Result<Vec<CuOutcome>> {
    use rayon::prelude::*;
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("create {}", out_dir.display()))?;

    let outcomes: Vec<CuOutcome> = idx
        .units
        .par_iter()
        .filter(|cu| cu.functions.iter().any(|f| f.size > 0))
        .map(|cu| {
            let stem = sanitize_cu_name(&cu.name);
            let file = out_dir.join(format!("{:04}_{stem}.o", cu.id));
            let result = emit_cu(
                binary,
                EmitOptions {
                    cu,
                    symbols,
                    comdat,
                },
                &file,
            )
            .map_err(|e| format!("{e:#}"));
            CuOutcome {
                cu_name: cu.name.clone(),
                file,
                result,
            }
        })
        .collect();

    Ok(outcomes)
}
