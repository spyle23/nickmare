//! Crate `core` de Nickmare — logique métier pure et testable, sans I/O réseau.
//!
//! Elle regroupe les types partagés par tous les niveaux (`model`), le
//! chargement/validation du périmètre (`scope`), le journal d'audit chaîné
//! (`audit`), les garde-fous obligatoires (`gate`, le « mur », cf.
//! `docs/ARCHITECTURE.md` §3.2), la limitation de débit partagée (`rate`) et les
//! traits d'abstraction (`traits`).

pub mod audit;
pub mod gate;
pub mod model;
pub mod rate;
pub mod scope;
pub mod traits;

/// Nom de la crate — jalon trivial « hello workspace » (issue #1).
pub fn nom_crate() -> &'static str {
    "core"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_workspace() {
        assert_eq!(nom_crate(), "core");
    }
}
