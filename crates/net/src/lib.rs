//! Crate `net` de Nickmare — implémentations réseau de niveau 1 (recon).
//!
//! Cf. `docs/ARCHITECTURE.md` §6. La **découverte** (recon passive : listing des
//! réseaux à portée, ARP sweep + ping ICMP, débit plafonné) arrive en Phase 1
//! (issue #7) dans [`discovery`]. La **carte réseau** — mise à jour incrémentale
//! et vue textuelle de la [`NetworkMap`](nickmare_core::model::NetworkMap) —
//! arrive en Phase 1 (issue #9) dans [`map`]. Scan de ports, identification de
//! services et WiFi passif suivent dans les phases suivantes.

pub mod discovery;
pub mod map;

/// Nom de la crate — jalon trivial « hello workspace » (issue #1) : prouve que
/// la matrice CI exécute bien les tests de chaque crate sur Windows et Linux.
pub fn nom_crate() -> &'static str {
    "net"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_workspace() {
        assert_eq!(nom_crate(), "net");
    }
}
