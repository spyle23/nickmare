//! Test d'intégration de l'implémentation réseau **réelle** (#8), restreint à la
//! loopback et **sans privilège** : vérifiable sur Windows comme sur Linux en CI
//! (cf. `docs/TESTING.md` §3 « Local / CI », §10.2 ; `docs/ARCHITECTURE.md` §11.4).
//!
//! On prouve sur de vraies sockets, sans root ni cible externe :
//! - scan TCP-connect : port ouvert → `Open`, port fermé → `Closed` ;
//! - lecture de bannière réelle ;
//! - **robustesse** (§11.4) : une cible silencieuse (lente/coupée) voit son délai
//!   de lecture **respecté** — l'opération rend la main vite, jamais de blocage ;
//! - **interchangeabilité** : le provider réel se glisse derrière `dyn NetworkProvider`
//!   et la découverte pure de #7, exactement comme le mock.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'appliquent pas ici — un `unwrap` qui échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nickmare_core::model::PortState;
use nickmare_core::traits::NetworkProvider;
use nickmare_net::discovery;
use nickmare_net::probe::TcpConnectEmitter;
use nickmare_net::provider::{RealNetworkProvider, Timeouts};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Réserve un port lié (gardé ouvert tant que le `TcpListener` vit).
fn bound_listener() -> (u16, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    (port, listener)
}

/// Un port sûrement fermé : lié puis relâché immédiatement.
fn closed_port() -> u16 {
    let (port, listener) = bound_listener();
    drop(listener);
    port
}

#[tokio::test]
async fn scan_tcp_distingue_ouvert_et_ferme() {
    let (open, _listener) = bound_listener(); // gardé ouvert
    let closed = closed_port();

    let timeouts = Timeouts::new(Duration::from_millis(500), Duration::from_millis(500));
    let provider = RealNetworkProvider::new().with_timeouts(timeouts);
    let scanned = provider.scan_ports(LOOPBACK, &[open, closed]).await;
    let ports = scanned.unwrap();

    let open_state = ports.iter().find(|p| p.number == open).unwrap();
    let closed_state = ports.iter().find(|p| p.number == closed).unwrap();
    assert_eq!(open_state.state, PortState::Open);
    // Port fermé : refusé (`Closed`) sous Unix, mais silencieusement rejeté
    // (`Filtered`, timeout) sous Windows. Ce qui compte et reste portable : il
    // n'est jamais vu `Open`, donc bien distingué du port ouvert.
    assert_ne!(closed_state.state, PortState::Open);
}

#[tokio::test]
async fn lecture_de_banniere_reelle() {
    let (port, listener) = bound_listener();
    // Serveur minimal : accepte puis émet une bannière, et relâche la connexion.
    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_test\r\n");
        }
    });

    let timeouts = Timeouts::new(Duration::from_millis(500), Duration::from_secs(1));
    let provider = RealNetworkProvider::new().with_timeouts(timeouts);
    let found = provider.read_banner(LOOPBACK, port).await.unwrap();
    let service = found.expect("service présent");
    let banner = service.banner.expect("bannière lue");
    assert!(banner.contains("SSH-2.0"), "bannière inattendue : {banner}");

    server.join().unwrap();
}

#[tokio::test]
async fn port_ferme_na_pas_de_service() {
    let provider = RealNetworkProvider::new();
    let port = closed_port();
    let banner = provider.read_banner(LOOPBACK, port).await;
    // Port fermé → aucun service : connexion refusée (`Ok(None)`) sous Unix,
    // timeout de connexion (`Err`) sous Windows. Jamais un service.
    match banner {
        Ok(None) | Err(_) => {}
        Ok(Some(_)) => panic!("port fermé ne doit exposer aucun service"),
    }
}

#[tokio::test]
async fn cible_silencieuse_respecte_le_timeout_de_lecture() {
    // Cible lente/coupée : liée mais n'émet jamais rien côté serveur (§11.4).
    let (port, _listener) = bound_listener();
    // Connexion permise, lecture bornée très court (cible muette).
    let timeouts = Timeouts::new(Duration::from_millis(500), Duration::from_millis(200));
    let provider = RealNetworkProvider::new().with_timeouts(timeouts);

    let start = Instant::now();
    let found = provider.read_banner(LOOPBACK, port).await.unwrap();
    let elapsed = start.elapsed();

    // Port ouvert mais muet : service nommé, sans bannière — et surtout rendu
    // bien avant tout blocage (le délai de lecture est respecté).
    let service = found.expect("port ouvert → service présent");
    assert!(
        service.banner.is_none(),
        "aucune bannière d'une cible muette"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "le timeout de lecture doit borner l'attente, écoulé = {elapsed:?}"
    );
}

#[tokio::test]
async fn provider_reel_interchangeable_avec_le_mock() {
    // Émetteur TCP visant le port ouvert : l'unique hôte 127.0.0.1/32 est « vivant ».
    let (open, _listener) = bound_listener();
    let emitter = Arc::new(TcpConnectEmitter::new(
        vec![open],
        Duration::from_millis(500),
    ));
    let provider = RealNetworkProvider::new().with_emitter(emitter);

    // Utilisable derrière un objet de trait, et via la découverte pure de #7.
    let dynamique: Box<dyn NetworkProvider> = Box::new(provider);
    let hosts = discovery::discover(&*dynamique, "127.0.0.1/32")
        .await
        .unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip, LOOPBACK);
}
