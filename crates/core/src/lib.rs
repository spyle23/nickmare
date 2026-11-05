//! Crate `core` de Nickmare — logique métier pure et testable, sans I/O réseau.
//!
//! Elle regroupe les types partagés par tous les niveaux (`model`), le
//! chargement/validation du périmètre (`scope`), le journal d'audit chaîné
//! (`audit`) et les traits d'abstraction (`traits`) ; elle accueillera dans les
//! tickets suivants les garde-fous (le « mur », cf. `docs/ARCHITECTURE.md` §6).

pub mod audit;
pub mod model;
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
