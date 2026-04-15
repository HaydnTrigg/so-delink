use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ELF parse error: {0}")]
    Elf(#[from] object::Error),

    #[error("DWARF parse error: {0}")]
    Dwarf(#[from] gimli::Error),

    #[error("unsupported binary: {0}")]
    Unsupported(String),

    #[error("missing required section: {0}")]
    MissingSection(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
