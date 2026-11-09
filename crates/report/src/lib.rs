//! Crate `report` de Nickmare — **socle de restitution Niveau 1** (issue #16, cf.
//! `docs/ARCHITECTURE.md` §9 Phase 5, US-H1/US-H2).
//!
//! Elle agrège les résultats de recon N1 (carte réseau, constats, état
//! d'engagement) en un [`ReportModel`] pur et sérialisable, puis le restitue de
//! deux façons :
//!
//! - **HTML** lisible ([`ReportModel::to_html`]) via des templates `askama`
//!   compilés et typés (`templates/report.html`), avec échappement automatique
//!   des entrées (garde-fou anti-injection, §12) — US-H1 ;
//! - **JSON** complet et interopérable ([`ReportModel::to_json`]) par
//!   `serde_json` — US-H2.
//!
//! La lecture depuis l'état d'engagement ([`load_from_store`]) passe par le trait
//! [`EngagementStore`](nickmare_core::engagement::EngagementStore) — le même
//! qu'implémente `SqliteStore` (#26) — ce qui garde le crate pur et testable par
//! mock, sans dépendance SQLite. Un même engagement produit toujours le même
//! rapport (reproductibilité).
//!
//! # Deux restitutions : socle N1 et rapport consolidé N1→N4
//!
//! Le socle [`ReportModel`] ne porte **que** du N1 (recon : hôtes, services,
//! constats, carte). La Phase 9 (issue #23) l'étend par un
//! [`ConsolidatedReport`](consolidated::ConsolidatedReport) couvrant tous les
//! niveaux : exploits confirmés (N2), taux de craquage et verdict de politique
//! (N3), matrice de couverture ATT&CK + MTTD (N4), carte annotée, timeline
//! horodatée et comparaison des taux de détection entre profils. C'est un
//! **livrable défensif** de restitution : aucune capacité offensive n'est
//! implémentée ici, et les secrets craqués restent masqués (`CrackResult` ne
//! porte que des statistiques, §7).

pub mod consolidated;
mod consolidated_html;
mod display;
mod error;
mod html;
pub mod model;
pub mod store;

pub use consolidated::{
    load_consolidated_from_store, ConsolidatedInputs, ConsolidatedReport, ExecutiveSummary,
    TimelineEvent,
};
pub use consolidated::{CRACKING_KEY, EXECUTIONS_KEY, EXPLOITS_KEY};
pub use error::ReportError;
pub use model::{OperationView, ReportMeta, ReportModel, SeverityCount, Summary, UsageView};
pub use store::{load_from_store, FINDINGS_KEY, NETWORK_MAP_KEY};

/// Nom de la crate — jalon trivial « hello workspace » (issue #1) : prouve que
/// la matrice CI exécute bien les tests de chaque crate sur Windows et Linux.
#[must_use]
pub fn nom_crate() -> &'static str {
    "report"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_workspace() {
        assert_eq!(nom_crate(), "report");
    }
}
