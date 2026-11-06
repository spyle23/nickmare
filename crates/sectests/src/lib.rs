//! Crate `sectests` de Nickmare — **tests de non-régression de sécurité**
//! transverses (issue #28, cf. `docs/ARCHITECTURE.md` §10.4, `docs/TESTING.md`
//! §2 & §3).
//!
//! # Rôle : le filet de sécurité **secondaire**
//!
//! L'objectif du produit est de **réussir l'infiltration** dans la zone
//! autorisée (`docs/TESTING.md` §1). Ce crate n'y touche pas : il héberge le
//! **filet de sécurité secondaire** qui garantit que l'outil **reste** dans la
//! zone autorisée. Règle d'or (§10.4) : il ne doit **jamais** empêcher
//! l'infiltration *dans* le périmètre — seulement **bloquer et journaliser** ce
//! qui en sort.
//!
//! La bibliothèque elle-même est volontairement vide : tout vit dans `tests/`,
//! exécuté par `cargo test` (contrat de CI **bloquant**, job `negatif`) :
//!
//! - [`tests/confinement_negatif.rs`] — suite **négative** transverse sur les
//!   capacités existantes : dépassement de plafond, hors-scope, hôte hors
//!   `allowed_hosts`, capacité désactivée rendue inatteignable, mode `manual`
//!   sans confirmation, module destructeur refusé — chaque refus **journalisé**
//!   (audit chaîné `blocked_*`).
//! - [`tests/scenario_mock.rs`] — scénario d'intégration **contre mocks** sur la
//!   chaîne qui existe (recon → scan → service_id → corrélation CVE → constats),
//!   sans réseau réel ni exploitation réelle.
//! - [`tests/fuzz_parsers.rs`] — robustesse « type fuzz » **déterministe** des
//!   parsers existants (bannières, TOML de scope, pcap WiFi) : aucune entrée
//!   hostile ne fait paniquer l'outil (§12). Pendant nightly : `fuzz/`.
//!
//! # Extensibilité (Phases 6/7/8)
//!
//! Les capacités N2–N4 (exploit #19, pivot #20, crack #21, émulation #22)
//! **n'existent pas encore** (jalon de revue #17 non franchi). Leurs cas
//! négatifs — exploiter hors `allowed_hosts` via un vrai moteur, craquer sans
//! capacité, technique ATT&CK non listée, scénario complet
//! recon→exploit→crack→émulation→report — se **branchent ici** en ajoutant les
//! dev-dependencies et les fichiers de test correspondants, sans refondre la
//! structure. Les décisions du gate pour ces actions existent déjà et sont
//! couvertes au niveau unitaire ; ce crate les re-éprouve transversalement à
//! mesure que les moteurs arrivent.

/// Nom de la crate — jalon trivial « hello workspace » (issue #1) : prouve que
/// la matrice CI compile et exécute bien ce crate transverse.
#[must_use]
pub fn nom_crate() -> &'static str {
    "sectests"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_workspace() {
        assert_eq!(nom_crate(), "sectests");
    }
}
