//! Cible cargo-fuzz : parser de scope TOML (core::scope #3).
//!
//! Invariant : charger un fichier de scope malformé renvoie une erreur typée,
//! jamais une panique (fail-safe §1/§12). Pendant nightly uniquement.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nickmare_core::scope::Scope;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Scope::from_toml(text);
        // `load` avec une clé malformée : si [integrity] est présent, le refus
        // doit être propre (Err), jamais une panique.
        let _ = Scope::load(text, Some("00"));
    }
});
