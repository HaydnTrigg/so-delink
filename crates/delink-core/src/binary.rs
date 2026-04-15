//! Load and index an Android debug `.so`.
//!
//! `Binary` borrows from a byte slice (typically an mmap owned by the caller)
//! so parsing is zero-copy. Holds parsed ELF plus a `gimli::Dwarf` handle.

use crate::error::{Error, Result};
use gimli::{EndianSlice, LittleEndian};
use object::read::elf::{ElfFile64, FileHeader};
use object::{Endianness, Object as _, ObjectSection as _};

pub type Endian = LittleEndian;
pub type DwarfSlice<'a> = EndianSlice<'a, Endian>;
pub type Dwarf<'a> = gimli::Dwarf<DwarfSlice<'a>>;

pub struct Binary<'a> {
    pub data: &'a [u8],
    pub elf: ElfFile64<'a, Endianness>,
    pub dwarf: Dwarf<'a>,
}

impl<'a> Binary<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self> {
        let elf = ElfFile64::<'a, Endianness>::parse(data)?;

        let header = elf.elf_header();
        let endian = header.endian()?;
        if !matches!(endian, Endianness::Little) {
            return Err(Error::Unsupported("big-endian ELF".into()));
        }
        let e_type = header.e_type(endian);
        if e_type != object::elf::ET_DYN {
            return Err(Error::Unsupported(format!(
                "expected ET_DYN shared object, got e_type=0x{e_type:x}"
            )));
        }
        let machine = header.e_machine(endian);
        if machine != object::elf::EM_AARCH64 {
            return Err(Error::Unsupported(format!(
                "only AArch64 supported in v1 (got e_machine=0x{machine:x})"
            )));
        }

        let dwarf = load_dwarf(&elf)?;

        Ok(Self { data, elf, dwarf })
    }

    pub fn has_dwarf(&self) -> bool {
        self.elf.section_by_name(".debug_info").is_some()
    }
}

fn load_dwarf<'a>(elf: &ElfFile64<'a, Endianness>) -> Result<Dwarf<'a>> {
    let load_section = |id: gimli::SectionId| -> std::result::Result<DwarfSlice<'a>, gimli::Error> {
        let name = id.name();
        let data = match elf.section_by_name(name) {
            Some(section) => section.data().unwrap_or(&[]),
            None => &[],
        };
        Ok(EndianSlice::new(data, LittleEndian))
    };
    let dwarf = gimli::Dwarf::load(load_section)?;
    Ok(dwarf)
}
