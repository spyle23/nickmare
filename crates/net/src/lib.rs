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
//! L'**identification de services** (#13, Phase 3) prolonge à son tour le scan
//! dans [`service_id`] : elle **consomme** les ports ouverts et les bannières
//! déjà capturées par le provider (sans rouvrir de socket), en extrait
//! nom/produit/version par empreinte **pure et défensive**, et alimente carte et
//! findings — le tout confiné au gate ([`service_id::identify_gated`]).
//!
//! L'**inventaire WiFi passif** (#15, Phase 4) complète la recon N1 dans
//! [`wifi`] : écoute **strictement passive** (aucune trame émise) des beacons et
//! probe-responses 802.11, par **rejeu de captures pcap** (radiotap ou 802.11
//! brut) pour en extraire SSID, BSSID, canal, chiffrement (ouvert/WEP/WPA/WPA2/
//! WPA3) et puissance. La capture en direct (mode monitor Linux / Npcap Windows)
//! se branche derrière la même source en réception seule, avec un repli clair
//! tant que le pilote n'est pas disponible.
//!
//! Tout ce qui touche une socket réelle ou un privilège est soit **portable et
//! testé en loopback** (repli TCP, UDP), soit **isolé derrière une abstraction**
//! et réservé au labo (émission brute ARP/ICMP/SYN), soit **purement passif et
//! rejoué sur fixtures** (WiFi), de sorte que la CI reste verte sans réseau, ni
//! root, ni matériel WiFi (Windows + Linux).

pub mod arp;
pub mod discovery;
pub mod icmp;
pub mod interfaces;
pub mod map;
pub mod portscan;
pub mod privilege;
pub mod probe;
pub mod provider;
pub mod service_id;
pub mod tcp;
pub mod wifi;

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
