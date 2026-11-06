//! Test d'intégration (mock) — recon réseau **complète sans socket réelle**
//! (issue #7 ; cf. `docs/ARCHITECTURE.md` §10.2, `docs/TESTING.md` §3 ligne
//! « Intégration (mocks) »).
//!
//! On rejoue une fixture déterministe (`testdata/mock/recon_simple.json`) via
//! `MockNetworkProvider` : aucune I/O réseau, aucun privilège, aucun scope — la
//! recon passive ne demande rien (US-A0). On prouve la chaîne
//! « planifier le sweep → découvrir les hôtes → bâtir la carte ».

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'appliquent pas ici — un `unwrap` qui échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::time::Duration;

use nickmare_core::model::{HostRole, MacAddr};
use nickmare_core::traits::{MockNetworkProvider, NetworkProvider};
use nickmare_net::discovery::{self, Discovery};

const FIXTURE: &str = include_str!("../../../testdata/mock/recon_simple.json");

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

#[tokio::test]
async fn recon_reseau_complete_contre_le_mock() {
    let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();

    // Planification du sweep ARP au débit par défaut (200 pps, cf. §3.1) :
    // 254 cibles sur un /24, émises bien en-deçà des 10 s (US-B1).
    let d = Discovery::new(200);
    assert_eq!(d.sweep_targets("192.168.1.0/24").unwrap().len(), 254);
    let duree = d.sweep_duration("192.168.1.0/24").unwrap();
    assert!(duree < Duration::from_secs(10), "sweep /24 = {duree:?}");

    // Découverte des hôtes (ARP/ICMP sous le capot ; ici le mock) → carte réseau.
    let map = discovery::discover_map(&provider, "192.168.1.0/24")
        .await
        .unwrap();
    assert_eq!(map.scope_network, "192.168.1.0/24");
    assert_eq!(map.hosts.len(), 2);
    assert!(map.pivots.is_empty(), "la recon ne crée aucun pivot (N2)");

    // Hôtes triés par IP, portant IP + MAC qui alimentent la carte (US-B1).
    assert_eq!(map.hosts[0].ip, ip("192.168.1.1"));
    assert_eq!(map.hosts[0].mac, Some(MacAddr([0, 26, 43, 60, 77, 94])));
    assert_eq!(map.hosts[0].role, HostRole::Gateway);
    assert_eq!(map.hosts[1].ip, ip("192.168.1.10"));
    assert_eq!(map.hosts[1].mac, None);
}

#[tokio::test]
async fn reseau_inconnu_donne_une_carte_vide() {
    // Un réseau sans hôte connu du mock produit une carte vide, sans erreur.
    let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();
    let map = discovery::discover_map(&provider, "10.0.0.0/24")
        .await
        .unwrap();
    assert!(map.hosts.is_empty());
    assert_eq!(map.scope_network, "10.0.0.0/24");
}

#[tokio::test]
async fn decouverte_injectable_en_objet_de_trait() {
    // La découverte accepte aussi un `dyn NetworkProvider` (object-safe) : même
    // garantie que l'implémentation réelle (#8) une fois branchée.
    let provider: Box<dyn NetworkProvider> =
        Box::new(MockNetworkProvider::from_json(FIXTURE).unwrap());
    let hosts = discovery::discover(&*provider, "192.168.1.0/24")
        .await
        .unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].ip, ip("192.168.1.1"));
}
