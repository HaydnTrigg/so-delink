use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "so-delink", version, about = "Split a debug .so into .o files")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report sections, dynamic relocations, and DWARF compilation units.
    Inspect { input: PathBuf },

    /// Emit a single CU as an ET_REL `.o` file (no relocations yet; M2 validation).
    Emit {
        input: PathBuf,
        /// Match against the suffix of the CU name (e.g. `bacolor.cpp`).
        #[arg(long)]
        cu: String,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// List CUs matching a substring, sorted by .text size ascending.
    ListCus {
        input: PathBuf,
        #[arg(long, default_value = "")]
        contains: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Dump a relocatable `.o` file's sections and symbols (for validation).
    Readobj { input: PathBuf },

    /// Emit `__shared_data.o` carrying .rodata / .bss (and eventually .data).
    EmitShared {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Split the whole `.so` into one `.o` per CU plus `__shared_data.o`.
    Split {
        input: PathBuf,
        #[arg(short, long)]
        outdir: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Inspect { input } => cmd_inspect(&input),
        Cmd::Emit { input, cu, output } => cmd_emit(&input, &cu, &output),
        Cmd::ListCus { input, contains, limit } => cmd_list_cus(&input, &contains, limit),
        Cmd::Readobj { input } => cmd_readobj(&input),
        Cmd::EmitShared { input, output } => cmd_emit_shared(&input, &output),
        Cmd::Split { input, outdir } => cmd_split(&input, &outdir),
    }
}

fn cmd_split(path: &Path, outdir: &Path) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    tracing::info!("indexing DWARF…");
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    tracing::info!("building symbol resolver…");
    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    tracing::info!(
        "emitting {} CUs in parallel",
        idx.units.iter().filter(|u| u.functions.iter().any(|f| f.size > 0)).count()
    );
    let outcomes = delink_emit::split_all(&binary, &idx, &symbols, outdir)?;
    let shared = outdir.join("__shared_data.o");
    let shared_stats = delink_emit::emit_shared_data(&binary, &symbols, &shared)?;

    let mut total = delink_emit::EmitStats::default();
    let mut failures = 0usize;
    for o in &outcomes {
        match &o.result {
            Ok(s) => {
                total.text_bytes += s.text_bytes;
                total.local_symbols += s.local_symbols;
                total.undef_symbols += s.undef_symbols;
                total.relocations += s.relocations;
                total.unresolved_calls += s.unresolved_calls;
                total.instructions += s.instructions;
                total.adrp_seen += s.adrp_seen;
                total.adrp_paired += s.adrp_paired;
                total.adrp_unresolved += s.adrp_unresolved;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(cu = %o.cu_name, error = %e, "emit failed");
            }
        }
    }
    println!(
        "split complete: {} CUs ({} failed)\n  {} bytes .text, {} instructions\n  {} local + {} undef symbols\n  {} relocs ({} unresolved calls, {} unresolved adrps of {})\n  shared data: rodata={} data={} data.rel.ro={} bss={}",
        outcomes.len() - failures,
        failures,
        total.text_bytes,
        total.instructions,
        total.local_symbols,
        total.undef_symbols,
        total.relocations,
        total.unresolved_calls,
        total.adrp_unresolved,
        total.adrp_seen,
        shared_stats.rodata_bytes,
        shared_stats.data_bytes,
        shared_stats.data_rel_ro_bytes,
        shared_stats.bss_bytes,
    );
    Ok(())
}

fn cmd_emit_shared(path: &Path, output: &Path) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    let stats = delink_emit::emit_shared_data(&binary, &symbols, output)?;
    println!(
        "wrote {}\n  .rodata: {} bytes\n  .data: {} bytes\n  .data.rel.ro: {} bytes\n  .init_array: {} bytes\n  .fini_array: {} bytes\n  .bss: {} bytes\n  .eh_frame: {} bytes ({} FDE relocs)\n  data relocs: {} RELATIVE + {} ABS64 + {} GLOB_DAT translated; {} skipped, {} unresolved",
        output.display(),
        stats.rodata_bytes,
        stats.data_bytes,
        stats.data_rel_ro_bytes,
        stats.init_array_bytes,
        stats.fini_array_bytes,
        stats.bss_bytes,
        stats.eh_frame_bytes,
        stats.fde_relocs,
        stats.translated_relatives,
        stats.translated_abs64,
        stats.translated_glob_dat,
        stats.skipped_relocs,
        stats.unresolved_relocs,
    );
    Ok(())
}

fn cmd_readobj(path: &Path) -> Result<()> {
    use object::read::elf::{ElfFile64, FileHeader};
    use object::{Endianness, Object, ObjectSection, ObjectSymbol};

    let mmap = mmap_file(path)?;
    let elf = ElfFile64::<Endianness>::parse(&mmap[..])
        .with_context(|| format!("parse {}", path.display()))?;
    let endian = elf.elf_header().endian()?;
    let e_type = elf.elf_header().e_type(endian);
    let e_machine = elf.elf_header().e_machine(endian);

    println!("ELF  e_type=0x{:x} e_machine=0x{:x}", e_type, e_machine);
    println!("\nSECTIONS");
    for s in elf.sections() {
        let name = s.name().unwrap_or("<?>");
        println!(
            "  {:<24} addr={:#010x} size={:>8} kind={:?}",
            name,
            s.address(),
            s.size(),
            s.kind()
        );
    }

    println!("\nSYMBOLS");
    for sym in elf.symbols() {
        let name = sym.name().unwrap_or("<?>");
        if name.is_empty() {
            continue;
        }
        println!(
            "  {:<40} value={:#010x} size={:>6} kind={:?} scope={:?} section={:?}",
            name,
            sym.address(),
            sym.size(),
            sym.kind(),
            sym.scope(),
            sym.section(),
        );
    }

    println!("\nRELOCATIONS");
    let symbols: Vec<_> = elf.symbols().collect();
    for section in elf.sections() {
        let relocs: Vec<_> = section.relocations().collect();
        if relocs.is_empty() {
            continue;
        }
        println!("  in {}:", section.name().unwrap_or("<?>"));
        for (offset, rel) in relocs {
            let target_name = match rel.target() {
                object::RelocationTarget::Symbol(idx) => symbols
                    .iter()
                    .find(|s| s.index() == idx)
                    .and_then(|s| s.name().ok())
                    .unwrap_or("<?>")
                    .to_string(),
                other => format!("{:?}", other),
            };
            let flags = match rel.flags() {
                object::RelocationFlags::Elf { r_type } => {
                    format!("elf_type={}", aarch64_reloc_name(r_type))
                }
                other => format!("{:?}", other),
            };
            println!(
                "    {:#010x} -> {:<40} addend={:+#x} {}",
                offset, target_name, rel.addend(), flags
            );
        }
    }
    Ok(())
}

fn aarch64_reloc_name(t: u32) -> String {
    use object::elf::*;
    let name = match t {
        R_AARCH64_NONE => "R_AARCH64_NONE",
        R_AARCH64_ABS64 => "R_AARCH64_ABS64",
        R_AARCH64_CALL26 => "R_AARCH64_CALL26",
        R_AARCH64_JUMP26 => "R_AARCH64_JUMP26",
        R_AARCH64_ADR_PREL_PG_HI21 => "R_AARCH64_ADR_PREL_PG_HI21",
        R_AARCH64_ADD_ABS_LO12_NC => "R_AARCH64_ADD_ABS_LO12_NC",
        R_AARCH64_ADR_GOT_PAGE => "R_AARCH64_ADR_GOT_PAGE",
        R_AARCH64_LD64_GOT_LO12_NC => "R_AARCH64_LD64_GOT_LO12_NC",
        _ => return format!("R_AARCH64_{t}"),
    };
    name.to_string()
}

fn open_binary<'a>(mmap: &'a memmap2::Mmap, path: &Path) -> Result<delink_core::Binary<'a>> {
    delink_core::Binary::load(&mmap[..])
        .with_context(|| format!("failed to load {}", path.display()))
        .map_err(Into::into)
}

fn mmap_file(path: &Path) -> Result<memmap2::Mmap> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    Ok(unsafe { memmap2::Mmap::map(&file)? })
}

fn cmd_inspect(path: &Path) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let report = delink_core::inspect::inspect(&binary)?;
    print!("{}", delink_core::inspect::format_text(&report));
    Ok(())
}

fn cmd_emit(path: &Path, cu_needle: &str, output: &Path) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let cu = delink_emit::find_cu(&idx.units, cu_needle)
        .ok_or_else(|| anyhow!("no CU matches suffix '{}'", cu_needle))?;

    tracing::info!(
        "emitting CU '{}' ({} functions, {} ranges)",
        cu.name,
        cu.functions.len(),
        cu.ranges.len()
    );

    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    tracing::info!(
        "resolved {} functions across all CUs, {} PLT stubs",
        symbols.functions.len(),
        symbols.plt.len()
    );

    let stats = delink_emit::emit_cu(
        &binary,
        delink_emit::EmitOptions { cu, symbols: &symbols },
        output,
    )?;
    println!(
        "wrote {}\n  .text: {} bytes ({} insns)\n  symbols: {} local, {} undef\n  relocs: {} emitted\n  calls: {} unresolved\n  adrp: {} seen, {} paired, {} unresolved\n  ranges coalesced: {}",
        output.display(),
        stats.text_bytes,
        stats.instructions,
        stats.local_symbols,
        stats.undef_symbols,
        stats.relocations,
        stats.unresolved_calls,
        stats.adrp_seen,
        stats.adrp_paired,
        stats.adrp_unresolved,
        stats.ranges_coalesced,
    );
    Ok(())
}

fn cmd_list_cus(path: &Path, contains: &str, limit: usize) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let mut rows: Vec<_> = idx
        .units
        .iter()
        .filter(|u| u.name.contains(contains))
        .map(|u| {
            let bytes: u64 = u.ranges.iter().map(|r| r.end - r.start).sum();
            (bytes, u.functions.len(), u.name.clone())
        })
        .collect();
    rows.sort_by_key(|(b, _, _)| *b);
    println!("{:>10} {:>6}  {}", "bytes", "funcs", "name");
    for (bytes, funcs, name) in rows.iter().take(limit) {
        println!("{:>10} {:>6}  {}", bytes, funcs, name);
    }
    Ok(())
}
