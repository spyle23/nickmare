//! Test d'intégration de l'identification de services (#13) — **de bout en bout,
//! sans socket réelle** : les bannières proviennent d'une fixture rejouée par
//! `MockNetworkProvider`, donc vérifiable sur Windows comme sur Linux en CI (cf.
//! `docs/TESTING.md` §3, §10.2/§10.4 ; `docs/ARCHITECTURE.md` §9 Phase 3, US-C1).
//!
//! On prouve :
//! - l'identification **passe par le gate** : sur un hôte in-scope, les ports
//!   ouverts voient leur service identifié (nom + produit + version) ;
//! - les résultats **alimentent la carte** (`merge_host` + `render_map`) et les
//!   **findings** (`service_findings`) ;
//! - **filet de sécurité** (§10.4) : un hôte hors scope est refusé + audité,
//!   **sans lire une seule bannière**.

use chrono::Utc;

use nickmare_core::audit::AuditMode;
use nickmare_core::gate::{Attestation, Gate, Request};
use nickmare_core::model::{Host, HostRole, NetworkMap, Port, Severity};
use nickmare_core::scope::Scope;
use nickmare_core::traits::{MockNetworkProvider, NetworkProvider};

use nickmare_net::map::{merge_host, render_map};
use nickmare_net::service_id::{identify_gated, IdentifyReport};

const FIXTURE: &str = include_str!("../../../testdata/mock/service_banners.json");
const NETWORK: &str = "192.168.56.0/24";
const OP: &str = "operateur@example.test";

fn scope() -> Scope {
    let toml = "\
[engagement]
client = \"Lab\"
reference = \"SERVICEID-13\"
authorized_by = \"self\"
operator = \"operateur@example.test\"
valid_from = \"2000-01-01T00:00:00Z\"
valid_until = \"2100-01-01T00:00:00Z\"

[targets]
networks = [\"192.168.56.0/24\"]

[capabilities]
recon = true
";
    Scope::from_toml(toml).unwrap()
}

fn gated_setup() -> (Gate, Attestation) {
    let scope = scope();
    let attestation = Attestation::for_scope(&scope, OP, NETWORK);
    let gate = Gate::with_scope(scope, AuditMode::Standard);
    (gate, attestation)
}

#[tokio::test]
async fn identification_in_scope_nomme_versionne_et_alimente_carte_et_findings() {
    let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();
    let target = "192.168.56.10".parse().unwrap();

    // On consomme les résultats de scan existants (les ports connus du mock).
    let ports = provider.scan_ports(target, &[]).await.unwrap();

    let (mut gate, att) = gated_setup();
    let req = Request::new(Utc::now(), OP).with_attestation(&att);

    let report = identify_gated(&mut gate, &req, OP, &provider, target, &ports, 0).await;
    let IdentifyReport::Allowed {
        ports: enriched,
        findings,
        ..
    } = &report
    else {
        panic!("identification in-scope refusée");
    };
    assert_eq!(report.record().action, "recon.active");

    let service = |number: u16| {
        enriched
            .iter()
            .find(|p| p.number == number)
            .and_then(|p| p.service.clone())
    };

    // SSH versionné (US-C1 : nom + version quand disponible).
    let ssh = service(22).expect("ssh identifié");
    assert_eq!(ssh.name, "ssh");
    assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
    assert_eq!(ssh.version.as_deref(), Some("9.6p1"));

    // HTTP via l'en-tête Server.
    let http = service(80).expect("http identifié");
    assert_eq!(http.name, "http");
    assert_eq!(http.product.as_deref(), Some("nginx"));
    assert_eq!(http.version.as_deref(), Some("1.24.0"));

    // FTP via la bannière de salutation.
    let ftp = service(21).expect("ftp identifié");
    assert_eq!(ftp.name, "ftp");
    assert_eq!(ftp.product.as_deref(), Some("vsFTPd"));
    assert_eq!(ftp.version.as_deref(), Some("3.0.5"));

    // Port ouvert muet (23, pas de bannière dans la fixture) : nom par le port.
    let telnet = service(23).expect("telnet nommé");
    assert_eq!(telnet.name, "telnet");
    assert!(telnet.version.is_none());

    // Le port fermé (3389) n'est jamais identifié.
    assert!(service(3389).is_none());

    // Findings : au moins un constat d'info par service, plus les « en clair ».
    assert!(findings
        .iter()
        .any(|f| f.severity == Severity::Info && f.title.contains("ssh")));
    assert!(findings
        .iter()
        .any(|f| f.severity == Severity::Medium && f.title.contains("telnet")));
    assert!(findings
        .iter()
        .any(|f| f.severity == Severity::Low && f.title.contains("ftp")));

    // Alimentation de la carte : les ports enrichis s'agrègent tels quels et la
    // vue textuelle montre produit + version (US-B3 + US-C1).
    let mut map = NetworkMap {
        scope_network: NETWORK.to_string(),
        hosts: Vec::new(),
        pivots: Vec::new(),
    };
    merge_host(&mut map, host_with(target, enriched.clone()));
    let view = render_map(&map);
    assert!(view.contains("22/tcp ssh (OpenSSH 9.6p1)"), "{view}");
    assert!(view.contains("80/tcp http (nginx 1.24.0)"), "{view}");
    assert!(view.contains("21/tcp ftp (vsFTPd 3.0.5)"), "{view}");
}

#[tokio::test]
async fn negatif_identification_hors_scope_refuse_sans_lire_de_banniere() {
    let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();
    // Hôte hors du réseau attesté : le gate refuse à l'étape 2.
    let target = "10.0.0.5".parse().unwrap();
    let ports = vec![Port {
        number: 22,
        proto: nickmare_core::model::Proto::Tcp,
        state: nickmare_core::model::PortState::Open,
        service: None,
    }];

    let (mut gate, att) = gated_setup();
    let req = Request::new(Utc::now(), OP).with_attestation(&att);

    let report = identify_gated(&mut gate, &req, OP, &provider, target, &ports, 0).await;
    match report {
        IdentifyReport::Refused { record, .. } => {
            assert_eq!(record.action, "blocked_target");
            assert_eq!(record.result, "blocked");
        }
        IdentifyReport::Allowed { .. } => panic!("un hôte hors scope ne doit pas être sondé"),
    }
}

fn host_with(ip: std::net::IpAddr, ports: Vec<Port>) -> Host {
    Host {
        ip,
        mac: None,
        hostname: Some("srv.lab".to_string()),
        os_guess: None,
        ports,
        role: HostRole::Server,
        compromised: false,
        first_seen: Utc::now(),
    }
}
