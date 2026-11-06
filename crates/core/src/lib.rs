//! Crate `core` de Nickmare — logique métier pure et testable, sans I/O réseau.
//!
//! Elle regroupe les types partagés par tous les niveaux (`model`), le
//! chargement/validation du périmètre (`scope`), la sélection interactive voie A
//! (`target`), le mode laboratoire voie C (`lab`), le journal d'audit chaîné
//! (`audit`), les garde-fous obligatoires (`gate`, le « mur », cf.
//! `docs/ARCHITECTURE.md` §3.2), la limitation de débit partagée (`rate`), les
//! traits d'abstraction (`traits`), la sûreté opérationnelle transverse
//! (`safety`, §11.1) et la fiabilité/reprise d'engagement (`engagement`, §11.2).

pub mod audit;
pub mod engagement;
pub mod gate;
pub mod lab;
pub mod model;
pub mod rate;
pub mod safety;
pub mod scope;
pub mod target;
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
