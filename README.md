# so-delink

Split an Android debug `.so` into per-compilation-unit `.o` files suitable for relinking.

## What it does

Given an unstripped AArch64 Android shared library with DWARF, `so-delink`
produces one relocatable ELF object per DWARF compilation unit plus a single
`__shared_data.o` carrying the binary's data sections. Together they are a
structural round-trip of the original `.so`: every function lives in its own
`.text.<mangled_name>` section, every static reference is a named symbol, and
every vtable / function-pointer slot / exception-unwind entry carries a
relocation that lets a linker rewrite it for a new address layout.

The goal is relinking: modifying one TU, recompiling it, and linking the
result back against the other `.o` files to get an equivalent `.so`. Not
byte-identical — functionally equivalent.

Covers:

- **Code recovery** — `bl` / `b` / `adrp+add` / `adrp+ldst` / `adrp+ldr-got`
  patterns via a Capstone-driven stateful register tracker.
- **Data recovery** — `.rela.dyn` translation into per-object
  `R_AARCH64_ABS64`s against reconstructed symbols. Covers vtables,
  `.init_array`, `.fini_array`, typeinfo, function-pointer tables.
- **Unwind recovery** — `.eh_frame` FDE `pc_begin` fields rewritten as
  `R_AARCH64_PREL32` against the corresponding function symbol.
- **Per-function section layout** — one `.text.<sym>` section per function,
  standard `-ffunction-sections` idiom consumed natively by `lld` /
  `ld.bfd`.
- **Per-CU DWARF** — each CU's `.debug_info` / `.debug_abbrev` /
  `.debug_line` slice travels with its `.o`. Every `DW_FORM_addr`
  attribute (DIE `DW_AT_low_pc` / `high_pc` / `entry_pc`) gets an
  `R_AARCH64_ABS64` relocation against its function symbol; every
  `DW_FORM_strp` gets an `R_AARCH64_ABS32` against
  `__delink_debug_str_start` + addend. Line programs relocate
  `DW_LNE_set_address`. `.debug_str` / `.debug_line_str` live once
  in `__shared_data.o`; `.debug_ranges` and `.debug_loc` also live
  there but carry their own per-address-pair `R_AARCH64_ABS64`
  relocations so the linker rewrites every range/location entry.
- **COMDAT dedup (opt-in)** — with `--comdat`, every linkage-scope
  function is a weak symbol inside an `SHT_GROUP` (`GRP_COMDAT`)
  keyed on the mangled name. The linker picks one copy when inline
  functions and template instantiations duplicate across CUs. Off by
  default because objdiff and similar tools hide such symbols.

Does not yet cover:

- Real relink verification against a cross-linker (need `ld.lld`
  aarch64-linux for this; no relink attempt has happened).
- Version-script reconstruction (`.gnu.version_d`).
- `DT_NEEDED` / `DT_SONAME` recovery for `link.txt` generation.
- Duplicate-symbol dedup across CUs (COMDAT-like inline/template collisions
  may need merging).
- TLS relocations (the test binary has none).
- ARM32 / Thumb (AArch64 only).
- `.debug_ranges` / `.debug_rnglists` / `.debug_loc` / `.debug_loclists`
  address entries (content carried but absolute VAs unpatched — fix in M8).
- Per-function splitting of line programs (linker-merged line programs
  use `advance_pc` deltas between functions; M8 item).
- DWARF 5 specific forms (`addrx`, `strx`, `line_strp`).

## Install

```
cargo build --release
```

Produces `target/release/so-delink`.

## Usage

```
so-delink inspect <input.so>
    Print sections, dynamic reloc histogram, and CU table.

so-delink list-cus <input.so> [--contains SUBSTR] [--limit N]
    List CUs sorted by .text size ascending.

so-delink emit <input.so> --cu <suffix> -o <output.o>
    Emit one CU as an ET_REL (debugging aid).

so-delink emit-shared <input.so> -o __shared_data.o
    Emit the shared-data object carrying .rodata, .data, .data.rel.ro,
    .init_array, .fini_array, .bss, and .eh_frame with their translated
    relocations.

so-delink split <input.so> -o <outdir> [--comdat]
    Full split: one .o per CU + __shared_data.o. The product surface.
    --comdat enables link-time dedup (weak + SHT_GROUP); off by default
    because it hides symbols from objdiff.

so-delink readobj <input.o>
    Dump sections, symbols, and relocations of an emitted .o (validation).
```

### Example

```
$ so-delink split libExample.so -o out/example-split
split complete: 1000 CUs (0 failed)
  5000000 bytes .text, 1000000 instructions
  15000 local + 30000 undef symbols
  200000 relocs (0 unresolved calls, 0 unresolved adrps of 50000)
  shared data: rodata=370000 data=250000 data.rel.ro=110000 bss=5000000
```

## Architecture

```
crates/
├── delink-core/       ELF + DWARF load, CU partitioning, global symbols,
│                      PLT/GOT maps, .rela.dyn access
├── delink-arch/       Architecture enum (Aarch64 only for now)
├── delink-aarch64/    Capstone-driven relocation recovery pass
├── delink-emit/       ET_REL writer (per-CU .o + __shared_data.o)
└── delink-cli/        so-delink binary
```

Main dependencies: `object` 0.36 (ELF read/write), `gimli` 0.31 (DWARF),
`capstone` 0.13 (AArch64 disassembly), `rayon` (parallel per-CU emission).

### Pipeline

1. **Load** — mmap the `.so`, parse ELF, load DWARF sections.
2. **Index CUs** — walk every DWARF compilation unit, collect functions
   (`DW_TAG_subprogram` with `DW_AT_low_pc`/`DW_AT_high_pc` or `DW_AT_ranges`)
   and variables (`DW_TAG_variable` with `DW_OP_addr`).
3. **Build symbol resolver** — map address → function/variable, plus
   `.plt` stub address → dynsym name (parsed from `.rela.plt`) and
   `.got` slot address → dynsym name (parsed from `.rela.dyn` and
   `.rela.plt`).
4. **Per-CU emit** (parallel over CUs):
   - Filter functions with `addr > 0` and `[addr, addr+size) ⊂ .text`.
   - For each function, create a `.text.<mangled>` section, copy its bytes.
   - Run the AArch64 recovery pass per function. For every recognized
     pattern (`bl`, `adrp+add/ldst`, `adrp+ldr-got`), resolve target
     against the symbol tables and emit an ELF relocation against either
     a local symbol (intra-`.o`), an UNDEF pulled in from the symbol
     cache, or a section-relative fallback (`__delink_<section>_start` +
     offset) for anonymous data references.
5. **Shared-data emit** — single `__shared_data.o`:
   - `.rodata`, `.data`, `.data.rel.ro`, `.init_array`, `.fini_array`,
     `.bss`, `.eh_frame` copied verbatim.
   - Named start symbols (`__delink_rodata_start` etc.) for anonymous
     references.
   - Every DWARF-named global emitted as a defined symbol at its
     section-relative offset.
   - Every `.rela.dyn` entry landing in one of these sections translated
     into a per-object `R_AARCH64_ABS64` against the reconstructed
     symbol (RELATIVE via address resolution, ABS64/GLOB_DAT via
     dynsym name). JUMP_SLOT and GOT-resident GLOB_DAT skipped (linker
     regenerates).
   - `.eh_frame` FDE `pc_begin` fields translated into
     `R_AARCH64_PREL32` relocs against their target function symbols.

### AArch64 relocation recovery detail

Per-function forward walker over Capstone-decoded instructions with a
`HashMap<Reg, AdrpSite>` tracker that invalidates on branches, calls, and
writes to the tracked register:

| source pattern | emitted relocations |
|---|---|
| `bl <imm>` → known func / PLT stub | `R_AARCH64_CALL26` |
| `b <imm>` out of function | `R_AARCH64_JUMP26` |
| `adrp Rd, page; add Rd2, Rd, #lo12` → data | `ADR_PREL_PG_HI21` + `ADD_ABS_LO12_NC` |
| `adrp Rd, page; ldst Rt, [Rd, #lo12]` → data | `ADR_PREL_PG_HI21` + `LDST{8/16/32/64}_ABS_LO12_NC` |
| `adrp Rd, page; ldr Rt, [Rd, #lo12]` → target in `.got` | `ADR_GOT_PAGE` + `LD64_GOT_LO12_NC` |
| in-function `b.cond` / `cbz` / etc. | no reloc (intra-function) |

## Output layout

`split` produces:

```
<outdir>/
├── 0000_<sanitized_cu_path>.o    (one per CU, prefixed by CU id)
├── 0001_<sanitized_cu_path>.o
├── ...
└── __shared_data.o
```

Each per-CU `.o`:

- `.text.<mangled_sym>` — one section per function, aligned to 4 bytes
- `.rela.text.<mangled_sym>` — relocations for that function's text
- Symbols: local per-function (DWARF `STB_LOCAL`) or global (`STB_GLOBAL`
  when `DW_AT_external`). UNDEFs pulled in for cross-CU / external refs.

`__shared_data.o`:

- `.rodata`, `.data`, `.data.rel.ro`, `.init_array`, `.fini_array`,
  `.bss`, `.eh_frame` + their `.rela.*` pairs
- `__delink_{rodata,data,data_rel_ro,bss}_start` globals defining each
  section's base
- Every DWARF-named global (at its section-relative offset)

## Limitations / known sharp edges

- **No relink verification yet.** Structural correctness has been audited
  (all `bl` targets resolved, all `adrp` pairs paired, all `.rela.dyn`
  entries translated, all FDE `pc_begin`s relocated) but the output has
  not been fed through `ld.lld -shared` end-to-end.
- **Anonymous `.rodata` strings** resolve via section-relative fallback,
  not per-CU attribution. Means `.rodata` duplicates exist across the
  shared data and per-CU references travel through `__delink_rodata_start`.
- **Duplicate mangled symbols across CUs** (common for inline functions
  and template instantiations) are not deduplicated. Expect some
  `multiple definition of ...` from the linker until a dedup pass exists.
- **Truly nameless functions** (compiler-emitted thunks without any
  DWARF name even via `DW_AT_specification` / `DW_AT_abstract_origin`)
  get a synthesized `__delink_sub_<addr>` fallback.
- **Register-width inference for `ldr w*` vs `ldr x*`** uses a mnemonic
  heuristic that defaults to 64-bit. Real output would use
  `LDST32_ABS_LO12_NC` for 32-bit loads. The `NC` (no-check) suffix means
  lo12 bits aren't bounds-checked, so this usually doesn't break linking,
  just produces slightly-less-strict relocations.
- **DW_FORM_addrx (DWARF 5)** path is partially exercised through gimli;
  some DWARF 5 shapes may need manual `DebugAddr` lookup.
- **ARM32 / Thumb** is not implemented. The architecture backend trait
  exists but only AArch64 is wired up.

## Roadmap

- [x] M1 — ELF+DWARF load, CU index, `inspect` subcommand
- [x] M2 — ET_REL emission (text + symbols, no relocs)
- [x] M3a — `bl` / `b` recovery
- [x] M3b — `adrp+add` / `adrp+ldst` / GOT pair recovery
- [x] M4a — section-relative fallback, shared data bytes
- [x] M4c — per-function `.text.<sym>` sections
- [x] M5 — `.rela.dyn` translation for `.data` / `.data.rel.ro` /
             `.init_array` / `.fini_array`
- [x] M6 — `.eh_frame` FDE translation
- [x] M7a — DWARF abbrev parser + DIE walker
- [x] M7b — `.debug_info` `DW_FORM_addr` → `R_AARCH64_ABS64` against
           function symbols
- [x] M7c — `.debug_info` `DW_FORM_strp` → `R_AARCH64_ABS32` against
           `__delink_debug_str_start` + addend
- [x] M7d — `.debug_line` `DW_LNE_set_address` → `R_AARCH64_ABS64`
           (partial — linked-binary line programs use `advance_pc`
           deltas between functions rather than per-function
           `set_address`, so fine line info drifts across function
           boundaries post-relink. Per-function line program splitting
           deferred as a future refinement.)
- [x] M8 — `.debug_ranges` / `.debug_loc` address-pair relocs.
           ~140K ABS64 relocs on range pairs, ~111K on location
           pairs. `.debug_rnglists` / `.debug_loclists` (DWARF 5)
           not present in the test binary; not implemented.
- [x] M9 — DWARF 5 forms. Verified the test binary uses DWARF 4;
           no `addrx` / `strx` / `line_strp` / cross-unit `ref_addr`
           in the input. Implementation deferred until a DWARF 5
           binary is on hand.
- [ ] M10 — real relink attempt against `ld.lld` (next big
            unblocker)
- [x] M11 — COMDAT groups, opt-in via `--comdat`. When enabled,
           every linkage-scope function becomes a weak symbol inside
           an `SHT_GROUP` (`GRP_COMDAT`) keyed on its mangled name.
           Off by default because some analysis tools (objdiff)
           hide COMDAT-grouped weak symbols from their UI. Turn on
           when preparing input for a real relink.
- [ ] M12 — version script + `DT_NEEDED` / `DT_SONAME`
- [ ] M13 — ARM32 / Thumb backend
- [ ] M14 — TLS relocations

## License

MIT
