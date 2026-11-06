//! Test d'intégration du scan de ports (#12) — **sur de vraies sockets, en
//! loopback et sans privilège**, donc vérifiable sur Windows comme sur Linux en
//! CI (cf. `docs/TESTING.md` §3 « Local / CI », §10.2/§10.4 ;
//! `docs/ARCHITECTURE.md` §9 Phase 2).
//!
//! On prouve, de bout en bout et sans cible externe :
//! - le scan **passe par le gate** : un port d'un hôte **in-scope** est scanné et
//!   classifié (TCP connect réutilisant le provider réel ; UDP basique) ;
//! - **filet de sécurité** (§10.4) : un hôte **hors scope** est refusé + audité,
//!   **sans émettre une seule sonde**.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'appliquent pas ici — un `unwrap` qui échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use nickmare_core::audit::AuditMode;
use nickmare_core::gate::{Attestation, Gate, Request};
use nickmare_core::model::{PortState, Proto};
use nickmare_core::scope::Scope;
use nickmare_net::portscan::{scan_gated, ProviderProbe, ScanReport, UdpProbe};
use nickmare_net::provider::{RealNetworkProvider, Timeouts};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OP: &str = "operateur@example.test";

/// Scope de session attesté sur la loopback (`127.0.0.1/32`) : seule la recon,
/// fenêtre large englobant l'instant courant.
fn loopback_scope() -> Scope {
    let toml = "\
[engagement]
client = \"Lab loopback\"
reference = \"PORTSCAN-12\"
authorized_by = \"self\"
operator = \"operateur@example.test\"
valid_from = \"2000-01-01T00:00:00Z\"
valid_until = \"2100-01-01T00:00:00Z\"

[targets]
networks = [\"127.0.0.1/32\"]

[capabilities]
recon = true
";
    Scope::from_toml(toml).unwrap()
}

fn gated_setup() -> (Gate, Attestation) {
    let scope = loopback_scope();
    let attestation = Attestation::for_scope(&scope, OP, "127.0.0.1/32");
    let gate = Gate::with_scope(scope, AuditMode::Standard);
    (gate, attestation)
}

#[tokio::test]
async fn scan_connect_in_scope_classe_un_port_ouvert_en_loopback() {
    // Un listener local gardé ouvert → le port doit ressortir `Open`.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let open = listener.local_addr().unwrap().port();

    let timeouts = Timeouts::new(Duration::from_millis(500), Duration::from_millis(500));
    let provider = RealNetworkProvider::new().with_timeouts(timeouts);
    let probe = ProviderProbe::new(&provider);
    let (mut gate, att) = gated_setup();
    let req = Request::new(Utc::now(), OP).with_attestation(&att);

    let report = scan_gated(&mut gate, &req, OP, &probe, LOOPBACK, &[open], 0).await;
    let ports = report.ports().expect("scan autorisé in-scope");
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].number, open);
    assert_eq!(ports[0].proto, Proto::Tcp);
    assert_eq!(ports[0].state, PortState::Open, "un listener ouvert → Open");
    assert_eq!(report.record().action, "recon.active");
}

#[tokio::test]
async fn negatif_scan_hors_scope_refuse_sans_sonder() {
    // §10.4 : hôte hors du périmètre attesté → refus + audit `blocked_target`.
    // La cible étant hors loopback, aucune socket n'est touchée.
    let provider = RealNetworkProvider::new();
    let probe = ProviderProbe::new(&provider);
    let (mut gate, att) = gated_setup();
    let req = Request::new(Utc::now(), OP).with_attestation(&att);

    let report = scan_gated(
        &mut gate,
        &req,
        OP,
        &probe,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        &[22, 80],
        0,
    )
    .await;

    match report {
        ScanReport::Refused { record, .. } => {
            assert_eq!(record.action, "blocked_target");
            assert_eq!(record.result, "blocked");
        }
        ScanReport::Allowed { .. } => panic!("un hôte hors scope ne doit jamais être scanné"),
    }
}

#[tokio::test]
async fn scan_udp_in_scope_detecte_un_service_qui_repond() {
    // Un « service » UDP loopback qui renvoie tout datagramme reçu → `Open`.
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind UDP loopback");
    let port = server.local_addr().unwrap().port();
    let responder = thread::spawn(move || {
        let mut buf = [0u8; 64];
        if let Ok((received, from)) = server.recv_from(&mut buf) {
            let _ = server.send_to(&buf[..received], from);
        }
    });

    let probe = UdpProbe::new(Duration::from_millis(500));
    let (mut gate, att) = gated_setup();
    let req = Request::new(Utc::now(), OP).with_attestation(&att);

    let report = scan_gated(&mut gate, &req, OP, &probe, LOOPBACK, &[port], 0).await;
    let ports = report.ports().expect("scan UDP autorisé");
    assert_eq!(ports[0].proto, Proto::Udp);
    assert_eq!(
        ports[0].state,
        PortState::Open,
        "un service UDP qui répond → Open"
    );

    responder.join().unwrap();
}

/// La sonde UDP d'un port fermé reste portable : jamais vue « ouverte ».
#[tokio::test]
async fn scan_udp_port_ferme_nest_jamais_ouvert() {
    // Port lié puis relâché : plus personne n'écoute en loopback.
    let port = {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    };

    let probe = UdpProbe::new(Duration::from_millis(200));
    let (mut gate, att) = gated_setup();
    let req = Request::new(Utc::now(), OP).with_attestation(&att);

    let report = scan_gated(&mut gate, &req, OP, &probe, LOOPBACK, &[port], 0).await;
    let ports = report.ports().expect("scan UDP autorisé");
    assert_ne!(ports[0].state, PortState::Open);
}
