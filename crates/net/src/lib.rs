//! Crate `net` de Nickmare — implémentations réseau de niveau 1 (recon).
//!
//! Cf. `docs/ARCHITECTURE.md` §4, §5, §6, §9 Phase 1. La **logique pure** de
//! découverte (listing des réseaux à portée, énumération CIDR, plafonnement de
//! débit) vient de #7 dans [`discovery`] ; la **carte réseau** (mise à jour
//! incrémentale et vue textuelle de la
//! [`NetworkMap`](nickmare_core::model::NetworkMap)) de #9 dans [`map`].
//! L'**implémentation réseau réelle** du trait
//! [`NetworkProvider`](nickmare_core::traits::NetworkProvider) (#8) les branche
//! derrière des sockets réelles :
//!
//! - [`provider`] : [`RealNetworkProvider`](provider::RealNetworkProvider), le
//!   pendant réel du mock, interchangeable avec lui (même trait).
//! - [`probe`] : abstraction d'émission de sondes de présence
//!   ([`ProbeEmitter`](probe::ProbeEmitter)), avec le repli `tcp_connect_only`.
//! - [`privilege`] : détection `CAP_NET_RAW` / root et choix de stratégie.
//! - [`interfaces`] : énumération réelle des interfaces (Linux), branchée sur le
//!   listing pur de #7.
//! - [`icmp`] / [`arp`] : construction/analyse pures des paquets (+ émission ICMP
//!   brute Linux derrière l'abstraction).
//!
//! Le **scan de ports** (#8+, Phase 2) prolonge ce socle dans [`portscan`] :
//! recon **active** (confinée au gate), TCP connect réutilisant le provider, UDP
//! basique portable, et SYN demi-ouvert pur + brut Linux (labo).
//!
//! Tout ce qui touche une socket réelle ou un privilège est soit **portable et
//! testé en loopback** (repli TCP, UDP), soit **isolé derrière une abstraction**
//! et réservé au labo (émission brute ARP/ICMP/SYN), de sorte que la CI reste
//! verte sans réseau ni root (Windows + Linux). Identification de services et
//! WiFi passif suivent dans les phases suivantes.

pub mod arp;
pub mod discovery;
pub mod icmp;
pub mod interfaces;
pub mod map;
pub mod portscan;
pub mod privilege;
pub mod probe;
pub mod provider;
pub mod tcp;

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
