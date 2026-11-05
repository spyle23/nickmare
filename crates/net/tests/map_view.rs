//! Test d'intégration (mock) — chaîne **découverte → carte → vue textuelle**
//! sans socket réelle (issue #9 ; cf. `docs/ARCHITECTURE.md` §4, §7, US-B3,
//! `docs/TESTING.md` §3 ligne « Intégration (mocks) »).
//!
//! On rejoue la même fixture déterministe que la recon (`recon_simple.json`) via
//! `MockNetworkProvider`, on en bâtit la `NetworkMap` avec `discover_map` (issue
//! #7, non réimplémentée ici) puis on en **rend la vue carte textuelle** — la
//! brique apportée par ce ticket.

use nickmare_core::traits::MockNetworkProvider;
use nickmare_net::discovery;
use nickmare_net::map::render_map;

const FIXTURE: &str = include_str!("../../../testdata/mock/recon_simple.json");

#[tokio::test]
async fn la_carte_decouverte_se_rend_en_texte_lisible() {
    let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();
    let map = discovery::discover_map(&provider, "192.168.1.0/24")
        .await
        .unwrap();

    let view = render_map(&map);

    // Le périmètre et les hôtes découverts apparaissent dans la vue.
    assert!(view.contains("Carte réseau — périmètre 192.168.1.0/24"), "{view}");
    assert!(view.contains("Bilan : 2 hôte(s)"), "{view}");
    assert!(view.contains("192.168.1.1 — passerelle"), "{view}");
    assert!(view.contains("192.168.1.10 — serveur"), "{view}");
    // La recon ne crée aucun pivot (N2) : la section le dit explicitement.
    assert!(view.contains("(aucun chemin de pivot établi)"), "{view}");
}

#[tokio::test]
async fn un_reseau_sans_hote_se_rend_sans_paniquer() {
    let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();
    let map = discovery::discover_map(&provider, "10.0.0.0/24")
        .await
        .unwrap();
    let view = render_map(&map);
    assert!(view.contains("(aucun hôte découvert)"), "{view}");
}
