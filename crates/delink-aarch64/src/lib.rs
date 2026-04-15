//! AArch64 relocation recovery.

pub mod recover;

pub use recover::{recover, RecoveredReloc, RecoveryDiagnostics, RelocKind};
