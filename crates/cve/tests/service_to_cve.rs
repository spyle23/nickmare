//! Test d'intégration de la chaîne **identification (#13) → corrélation CVE (#14)**
//! (cf. `docs/ARCHITECTURE.md` §9 Phase 3, US-C1/US-C2, §10.2).
//!
//! On part d'une **bannière brute** (donnée réseau, §12), on l'identifie via
//! `net::service_id` (pur), puis on **consomme** le `Service` obtenu dans la
//! corrélation `cve` contre une base locale (fixture). Aucune socket, aucun
//! réseau : tout le chemin tient hors ligne, comme en CI.

use std::net::IpAddr;

use nickmare_core::model::Severity;
use nickmare_cve::{correlate_service, load_from_str, CveDatabase};
use nickmare_net::service_id::identify_service;

const CACHE: &str = include_str!("../../../testdata/cve/cache_sample.json");

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn db() -> CveDatabase {
    load_from_str(CACHE).expect("cache local valide")
}

#[test]
fn banniere_vulnerable_est_identifiee_puis_correlee() {
    // Bannière SSH d'une version affectée (< 9.3p2) : #13 extrait produit+version,
    // #14 corrèle la CVE critique.
    let service = identify_service(22, Some(b"SSH-2.0-OpenSSH_9.1\r\n"));
    assert_eq!(service.name, "ssh");
    assert_eq!(service.product.as_deref(), Some("OpenSSH"));
    assert_eq!(service.version.as_deref(), Some("9.1"));

    let findings = correlate_service(ip("192.168.56.10"), Some(22), &service, &db());
    assert!(!findings.is_empty(), "OpenSSH 9.1 doit corréler une CVE");
    let crit = findings
        .iter()
        .find(|f| f.cve.as_deref() == Some("CVE-2023-38408"))
        .expect("la CVE OpenSSH corrélée");
    assert_eq!(crit.severity, Severity::Critical);
    assert_eq!(crit.port, Some(22));
}

#[test]
fn banniere_a_jour_ne_produit_aucun_faux_positif() {
    // La même bannière que la fixture de services (#13) : OpenSSH 9.6p1, à jour.
    let service = identify_service(22, Some(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1\r\n"));
    assert_eq!(service.version.as_deref(), Some("9.6p1"));
    let findings = correlate_service(ip("192.168.56.10"), Some(22), &service, &db());
    assert!(
        findings.is_empty(),
        "une version corrigee ne doit produire aucun constat"
    );
}

#[test]
fn banniere_nginx_identifiee_puis_correlee() {
    // nginx vulnérable (< 1.20.1) : identification HTTP puis corrélation.
    let service = identify_service(
        80,
        Some(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n"),
    );
    assert_eq!(service.product.as_deref(), Some("nginx"));
    assert_eq!(service.version.as_deref(), Some("1.18.0"));
    let findings = correlate_service(ip("192.168.56.10"), Some(80), &service, &db());
    assert!(findings.iter().any(|f| f.cve.as_deref() == Some("CVE-2021-23017")));
}
