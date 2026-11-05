//! Crate `cve` de Nickmare — **corrélation CVE** (issue #14, cf.
//! `docs/ARCHITECTURE.md` §2, §5, §9 Phase 3, US-C2 ; décision 2 : API NVD **+**
//! cache/miroir local).
//!
//! # Rôle
//!
//! Là où #13 ([`net::service_id`]) identifie un service (nom/produit/version) et
//! promet « corrélation CVE à suivre », cette crate **tient** la promesse : elle
//! consomme le [`Service`](nickmare_core::model::Service) identifié et une base
//! NVD **locale**, et en déduit des [`Finding`](nickmare_core::model::Finding) de
//! vulnérabilité, chacun porteur de son identifiant CVE et d'une gravité tirée du
//! score CVSS.
//!
//! # Architecture : un cœur pur + une seule porte réseau
//!
//! - [`version`] — comparaison de versions **défensive** (jamais de panique sur
//!   une version malformée ; prudence anti-faux-positif sur les plages).
//! - [`model`] — schéma de la **base/cache locale** ([`CveDatabase`]), dérivé du
//!   NVD mais stable, sérialisable, avec le mapping CVSS → gravité.
//! - [`nvd`] — lecture **défensive** du flux NVD (format API 2.0) vers la base.
//! - [`correlate`] — la corrélation **pure** service+version → CVE → findings.
//! - [`cache`] — persistance locale + **rafraîchissement** réseau explicite.
//! - [`client`] — abstraction **injectable** du client NVD en ligne ([`NvdClient`]),
//!   bouchonnée dans les tests ; clé API lue de l'environnement, jamais en clair.
//! - [`error`] — erreurs de la crate, **sans secret**.
//!
//! # Garanties (CI sans réseau, §10 ; sûreté §12)
//!
//! La corrélation ne touche **jamais** le réseau : elle lit uniquement le cache
//! local, et se teste intégralement sur des fixtures synthétiques
//! (`testdata/cve/`). La seule opération réseau ([`cache::refresh`]) passe par le
//! trait [`NvdClient`] et est, en CI comme en test, **bouchonnée** — aucune socket
//! n'est jamais ouverte. Enfin, la corrélation reste **informative** : elle ne
//! lance aucun exploit (politique d'usage autorisé, §1).
//!
//! [`net::service_id`]: ../nickmare_net/service_id/index.html

pub mod cache;
pub mod client;
pub mod correlate;
pub mod error;
pub mod model;
pub mod nvd;
pub mod version;

// Ré-exports des entrées les plus utilisées (ergonomie de l'appelant).
pub use cache::{load_from_path, load_from_str, load_or_empty, refresh, save_to_path};
pub use client::{ApiKey, FeedQuery, NvdClient, OfflineNvdClient, StubNvdClient};
pub use correlate::{correlate_host, correlate_service};
pub use error::{CveError, CveResult};
pub use model::{AffectedProduct, Cvss, CveDatabase, CveRecord};
pub use nvd::parse_feed;
pub use version::{matches_range, Version, VersionRange};

/// Nom de la crate — jalon trivial « hello workspace » (issue #1) : prouve que
/// la matrice CI exécute bien les tests de chaque crate sur Windows et Linux.
#[must_use]
pub fn nom_crate() -> &'static str {
    "cve"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_workspace() {
        assert_eq!(nom_crate(), "cve");
    }
}
