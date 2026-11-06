//! Scénario d'intégration **contre mocks** (issue #28, §10.2/§10.4 ;
//! `docs/TESTING.md` §3 « Intégration (mocks) »).
//!
//! On rejoue, **sans réseau réel ni exploitation réelle**, la portion de la
//! chaîne d'intrusion qui **existe aujourd'hui** :
//!
//! ```text
//! recon (passif) → scan/identify (recon active, confinée au gate)
//!                → corrélation CVE (pure, hors ligne) → constats
//! ```
//!
//! C'est l'ossature extensible du scénario complet de §10.4. Les legs suivants —
//! **exploit → crack → émulation → report consolidé** — dépendent des capacités
//! N2–N4 (moteurs #19/#21/#22, derrière le jalon de revue #17, **non franchi**).
//! Ils sont donc **DIFFÉRÉS** : ils s'ajouteront ici, dans le même fichier,
//! lorsque leurs crates existeront (Phases 6/7/8). On n'invente aucun moteur
//! offensif pour les simuler prématurément.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'appliquent pas ici — un `unwrap` qui échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;

use chrono::{DateTime, TimeZone, Utc};

use nickmare_core::audit::AuditMode;
use nickmare_core::gate::{Attestation, Gate, Request};
use nickmare_core::model::{Finding, Severity};
use nickmare_core::traits::{MockNetworkProvider, NetworkProvider};
use nickmare_cve::{correlate_service, load_from_str, CveDatabase};
use nickmare_net::discovery;
use nickmare_net::map::render_map;
use nickmare_net::service_id::identify_gated;

const OP: &str = "operateur@example.test";
const NET: &str = "192.168.56.0/24";

/// Base CVE locale (fixture synthétique) : connaît OpenSSH < 9.3p2
/// (CVE-2023-38408, critique) et nginx < 1.20.1 (CVE-2021-23017).
const CACHE: &str = include_str!("../../../testdata/cve/cache_sample.json");

/// Scénario mock : un serveur en scope exposant un SSH **vulnérable**
/// (OpenSSH_9.1) et un nginx **vulnérable** (1.18.0). JSON littéral (raw string)
/// → les `\r\n` sont interprétés par le parseur JSON en vrais CR/LF.
const SCENARIO: &str = r#"{
  "hosts_by_network": {
    "192.168.56.0/24": [
      {
        "ip": "192.168.56.10",
        "mac": null,
        "hostname": "srv.lab",
        "os_guess": "Linux",
        "ports": [],
        "role": "Server",
        "compromised": false,
        "first_seen": "2026-06-01T12:00:00Z"
      }
    ]
  },
  "ports_by_host": {
    "192.168.56.10": [
      { "number": 22, "proto": "Tcp", "state": "Open", "service": null },
      { "number": 80, "proto": "Tcp", "state": "Open", "service": null },
      { "number": 443, "proto": "Tcp", "state": "Closed", "service": null }
    ]
  },
  "banners": [
    {
      "host": "192.168.56.10",
      "port": 22,
      "service": { "name": "raw", "product": null, "version": null, "banner": "SSH-2.0-OpenSSH_9.1\r\n" }
    },
    {
      "host": "192.168.56.10",
      "port": 80,
      "service": { "name": "raw", "product": null, "version": null, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n" }
    }
  ]
}"#;

/// Scope attesté couvrant le réseau du scénario (recon activée).
const SCOPE_TOML: &str = "\
[engagement]
client = \"Lab\"
reference = \"SECTESTS-28\"
authorized_by = \"self\"
operator = \"operateur@example.test\"
valid_from = \"2026-01-01T00:00:00Z\"
valid_until = \"2027-12-31T23:59:59Z\"

[targets]
networks = [\"192.168.56.0/24\"]

[capabilities]
recon = true
";

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap()
}

fn db() -> CveDatabase {
    load_from_str(CACHE).expect("cache CVE local valide")
}

/// Scope attesté du scénario (recon activée sur `NET`).
fn scope() -> nickmare_core::scope::Scope {
    nickmare_core::scope::Scope::from_toml(SCOPE_TOML).unwrap()
}

#[tokio::test]
async fn chaine_recon_scan_serviceid_cve_contre_mocks() {
    let provider = MockNetworkProvider::from_json(SCENARIO).unwrap();

    // 1) Recon (passive) → carte réseau : un serveur découvert, aucun pivot (N2).
    let discovered = discovery::discover_map(&provider, NET).await;
    let mut map = discovered.unwrap();
    assert_eq!(map.scope_network, NET);
    assert_eq!(map.hosts.len(), 1);
    assert!(map.pivots.is_empty(), "la recon ne crée aucun pivot (N2)");
    let host = map.hosts[0].ip;
    assert_eq!(host, ip("192.168.56.10"));

    // 2) Scan + identification, CONFINÉS AU GATE (recon active N1). L'attestation
    // est requise (étape 8) ; la cible est dans le périmètre.
    let sc = scope();
    let att = Attestation::for_scope(&sc, OP, NET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP).with_attestation(&att);

    let scanned = provider.scan_ports(host, &[]).await;
    let ports = scanned.unwrap();
    let report = identify_gated(&mut gate, &req, OP, &provider, host, &ports, 0).await;
    assert!(
        report.is_allowed(),
        "scan in-scope doit aboutir (§10.4 règle d'or)"
    );
    assert_eq!(report.record().action, "recon.active");
    assert_eq!(report.record().result, "ok");
    let enriched = report.ports().unwrap().to_vec();

    // Les services sont identifiés à partir des bannières rejouées.
    let ssh = enriched.iter().find(|p| p.number == 22).unwrap();
    let ssh_svc = ssh.service.as_ref().expect("service ssh identifié");
    assert_eq!(ssh_svc.name, "ssh");
    assert_eq!(ssh_svc.version.as_deref(), Some("9.1"));

    // 3) Corrélation CVE (pure, hors ligne) sur chaque service identifié.
    let db = db();
    let mut cve_findings: Vec<Finding> = Vec::new();
    for port in &enriched {
        if let Some(service) = port.service.as_ref() {
            cve_findings.extend(correlate_service(host, Some(port.number), service, &db));
        }
    }
    let a_cve_openssh = cve_findings
        .iter()
        .any(|f| f.cve.as_deref() == Some("CVE-2023-38408"));
    let a_cve_nginx = cve_findings
        .iter()
        .any(|f| f.cve.as_deref() == Some("CVE-2021-23017"));
    let a_critique = cve_findings
        .iter()
        .any(|f| f.severity == Severity::Critical);
    assert!(a_cve_openssh, "OpenSSH 9.1 doit corréler la CVE critique");
    assert!(a_cve_nginx, "nginx 1.18.0 doit corréler sa CVE");
    assert!(a_critique, "au moins un constat critique attendu");

    // 4) Report (leg existant) : la carte enrichie se rend en vue textuelle.
    map.hosts[0].ports = enriched;
    let rendu = render_map(&map);
    assert!(rendu.contains("192.168.56.10"), "l'hôte figure au rapport");

    // --- DIFFÉRÉ (jalon #17) : exploit → crack → émulation → report consolidé.
    // Ces legs se brancheront ici une fois leurs moteurs disponibles ; pas de
    // simulation prématurée d'une capacité offensive inexistante.
}

#[tokio::test]
async fn reseau_hors_scenario_donne_une_carte_vide() {
    // Un réseau inconnu du mock produit une carte vide, sans erreur : la recon
    // n'invente rien.
    let provider = MockNetworkProvider::from_json(SCENARIO).unwrap();
    let discovered = discovery::discover_map(&provider, "10.0.0.0/24").await;
    let map = discovered.unwrap();
    assert!(map.hosts.is_empty());
    assert_eq!(map.scope_network, "10.0.0.0/24");
}
