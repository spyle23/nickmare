//! Tests d'intégration du socle de rapport N1 (issue #16, US-H1/US-H2).
//!
//! On exerce l'API publique **de l'extérieur du crate**, comme le fait le binaire
//! `nickmare` : on peuple un store (mock `InMemoryStore`, même trait que
//! `SqliteStore`) via la convention de clés réservées, on charge un
//! [`ReportModel`], puis on vérifie le rendu HTML, l'export JSON (validité +
//! round-trip) et la reproductibilité — sans réseau ni privilège.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'y appliquent pas — un `unwrap` qui échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use nickmare_core::engagement::{EngagementStore, InMemoryStore};
use nickmare_core::model::{
    Finding, Host, HostRole, NetworkMap, OsGuess, Port, PortState, Proto, Service, Severity,
};
use nickmare_report::{FINDINGS_KEY, NETWORK_MAP_KEY, ReportModel, load_from_store};

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
}

fn network() -> NetworkMap {
    NetworkMap {
        scope_network: "10.0.0.0/24".to_string(),
        hosts: vec![Host {
            ip: ip("10.0.0.5"),
            mac: None,
            hostname: Some("web.lab".to_string()),
            os_guess: Some(OsGuess::Linux),
            ports: vec![Port {
                number: 80,
                proto: Proto::Tcp,
                state: PortState::Open,
                service: Some(Service {
                    name: "http".to_string(),
                    product: Some("nginx".to_string()),
                    version: Some("1.24".to_string()),
                    banner: None,
                }),
            }],
            role: HostRole::Server,
            compromised: false,
            first_seen: ts(0),
        }],
        pivots: Vec::new(),
    }
}

fn findings() -> Vec<Finding> {
    vec![Finding {
        host: ip("10.0.0.5"),
        port: Some(80),
        severity: Severity::Low,
        cve: None,
        title: "HTTP en clair".to_string(),
        description: "Service HTTP sans TLS.".to_string(),
        recommendation: "Activer HTTPS.".to_string(),
    }]
}

fn seeded() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    let map = serde_json::to_string(&network()).unwrap();
    let find = serde_json::to_string(&findings()).unwrap();
    store.put_result(NETWORK_MAP_KEY, &map).unwrap();
    store.put_result(FINDINGS_KEY, &find).unwrap();
    store.begin("scan:h", "scan", "h", ts(1)).unwrap();
    store.complete("scan:h", ts(2)).unwrap();
    store
}

fn load(store: &InMemoryStore) -> ReportModel {
    load_from_store(store, "lab", "nm", ts(50)).unwrap()
}

#[test]
fn chaine_store_vers_html_lisible() {
    let html = load(&seeded()).to_html().unwrap();
    // Rapport lisible N1 (US-H1) : résumé, carte, hôte, service, constat.
    assert!(html.contains("Résumé exécutif"), "{html}");
    assert!(html.contains("Carte réseau"), "{html}");
    assert!(html.contains("10.0.0.0/24"), "{html}");
    assert!(html.contains("web.lab"), "{html}");
    assert!(html.contains("http"), "{html}");
    assert!(html.contains("HTTP en clair"), "{html}");
    assert!(html.contains("Niveau N1"), "{html}");
}

#[test]
fn chaine_store_vers_json_complet_et_round_trip() {
    let model = load(&seeded());
    let json = model.to_json().unwrap();

    // Export valide et complet (US-H2).
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(value.get("network").is_some());
    assert!(value.get("findings").is_some());
    assert!(json.contains("10.0.0.0/24"));

    // Round-trip : réimporter redonne le même modèle.
    let back = ReportModel::from_json(&json).unwrap();
    assert_eq!(model, back);
}

#[test]
fn rapport_reproductible_depuis_un_meme_engagement() {
    let store = seeded();
    let a = load(&store);
    let b = load(&store);
    assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
    assert_eq!(a.to_html().unwrap(), b.to_html().unwrap());
}
