//! Corrélation **pure** service+version → CVE → [`Finding`] (issue #14, US-C2,
//! cf. `docs/ARCHITECTURE.md` §5, §9 Phase 3).
//!
//! C'est le cœur de la crate et le pendant direct de #13 : là où
//! [`net::service_id`](../../nickmare_net/service_id/index.html) produit un
//! [`Service`] (nom/produit/version) et un constat d'information en promettant la
//! « corrélation CVE à suivre », ce module **tient** cette promesse. Il consomme
//! le [`Service`] déjà identifié et la [`CveDatabase`] locale, et en déduit les
//! [`Finding`] de vulnérabilité, chacun porteur de son identifiant CVE et d'une
//! gravité tirée du score CVSS.
//!
//! # Fonction pure, testée sur fixtures
//!
//! [`correlate_service`] et [`correlate_host`] sont **pures** : aucune I/O, aucun
//! appel réseau, aucune horloge. Elles se testent intégralement sur une base
//! chargée depuis une fixture locale ([`crate::nvd`] / [`crate::cache`]), ce qui
//! garantit le **chemin hors ligne** (US-C2) et une CI **sans réseau**.
//!
//! # Prudence (anti-faux-positif, §12)
//!
//! La corrélation n'émet un constat que lorsque **le produit identifié correspond
//! et la version détectée tombe dans la plage affectée** (cf.
//! [`crate::version::matches_range`], qui refuse les versions vides et les plages
//! sans contrainte). Un service sans version n'est jamais corrélé. Et conformément
//! à la politique d'usage (§1), un [`Finding`] CVE reste **informatif** : il ne
//! déclenche aucun exploit ; la vérification d'exploitabilité est une étape N2
//! distincte, explicitement confirmée.

use std::net::IpAddr;

use nickmare_core::model::{Finding, Host, Service};

use crate::model::{CveDatabase, CveRecord};
use crate::version::matches_range;

/// Recommandation d'un constat CVE. Volontairement **générique** et informative :
/// la corrélation ne prouve pas l'exploitabilité et ne lance aucun exploit
/// (politique d'usage autorisé, §1). Le produit/version concerné figure dans le
/// titre et la description du constat.
const CVE_RECOMMENDATION: &str =
    "Mettre à jour le produit vers une version non affectée. Constat informatif (corrélation de version, aucun exploit lancé) : confirmer l'exploitabilité en mode validation avant de conclure.";

/// Corrèle un [`Service`] identifié sur `host:port` contre la base locale et
/// renvoie un [`Finding`] par CVE correspondante, **trié par gravité décroissante**
/// (score CVSS, puis identifiant CVE pour un ordre stable).
///
/// Renvoie un vecteur vide si le service n'a pas de version exploitable, si aucun
/// nom de produit n'est disponible, ou si rien ne corrèle (cas nominal d'un
/// service à jour).
#[must_use]
pub fn correlate_service(
    host: IpAddr,
    port: Option<u16>,
    service: &Service,
    db: &CveDatabase,
) -> Vec<Finding> {
    let Some(version) = service.version.as_deref().filter(|v| !v.trim().is_empty()) else {
        // Sans version, aucune corrélation fiable (anti-faux-positif).
        return Vec::new();
    };
    let candidates = product_candidates(service);
    if candidates.is_empty() {
        return Vec::new();
    }

    // On garde le score à côté du constat pour un tri déterministe ensuite.
    let mut scored: Vec<(f32, String, Finding)> = Vec::new();
    for record in &db.records {
        if record_matches(record, &candidates, version) {
            let finding = finding_from(host, port, service, version, record);
            scored.push((record.cvss.base_score, record.id.clone(), finding));
        }
    }

    // Gravité décroissante, puis identifiant CVE croissant (ordre déterministe).
    scored.sort_by(|a, b| {
        let by_score = b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal);
        by_score.then_with(|| a.1.cmp(&b.1))
    });

    scored.into_iter().map(|(_, _, finding)| finding).collect()
}

/// Corrèle **tous** les services d'un [`Host`] (ses ports portant un [`Service`])
/// contre la base locale. Pratique pour brancher directement la sortie de
/// l'identification de services (#13) sur la corrélation. Pur.
#[must_use]
pub fn correlate_host(host: &Host, db: &CveDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    for port in &host.ports {
        if let Some(service) = &port.service {
            findings.extend(correlate_service(host.ip, Some(port.number), service, db));
        }
    }
    findings
}

/// Noms de produit candidats pour la corrélation : le produit identifié et le nom
/// de service, dédupliqués, en minuscules et non vides. Le nom (`"mysql"`) sert de
/// repli quand il coïncide avec un produit NVD, mais la correspondance reste
/// exacte (pas de sous-chaîne) et toujours conditionnée à la version.
fn product_candidates(service: &Service) -> Vec<String> {
    let mut names = Vec::new();
    let mut push = |raw: &str| {
        let norm = raw.trim().to_ascii_lowercase();
        if !norm.is_empty() && !names.contains(&norm) {
            names.push(norm);
        }
    };
    if let Some(product) = &service.product {
        push(product.as_str());
    }
    push(service.name.as_str());
    names
}

/// Vrai si l'un des produits affectés de `record` correspond à un candidat **et**
/// que `version` tombe dans sa plage.
fn record_matches(record: &CveRecord, candidates: &[String], version: &str) -> bool {
    record.affected.iter().any(|affected| {
        candidates.iter().any(|name| affected.matches_product(name))
            && matches_range(version, &affected.range)
    })
}

/// Construit le [`Finding`] informatif d'une CVE corrélée.
fn finding_from(
    host: IpAddr,
    port: Option<u16>,
    service: &Service,
    version: &str,
    record: &CveRecord,
) -> Finding {
    let label = product_label(service, version);
    let severity = record.cvss.severity();
    let score = record.cvss.base_score;

    let mut description = format!("{} corrélée à {label} (CVSS {score:.1}).", record.id);
    if !record.description.trim().is_empty() {
        description.push(' ');
        description.push_str(record.description.trim());
    }
    if let Some(vector) = &record.cvss.vector {
        description.push_str(&format!(" Vecteur : {vector}."));
    }

    Finding {
        host,
        port,
        severity,
        cve: Some(record.id.clone()),
        title: format!("{} — {label} (CVSS {score:.1})", record.id),
        description,
        recommendation: CVE_RECOMMENDATION.to_string(),
    }
}

/// Libellé « produit version » (ou « service version » à défaut de produit).
fn product_label(service: &Service, version: &str) -> String {
    let product = match service.product.as_deref() {
        Some(p) if !p.trim().is_empty() => p,
        _ => service.name.as_str(),
    };
    format!("{product} {version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    use nickmare_core::model::{HostRole, Port, PortState, Proto, Severity};

    use crate::model::{AffectedProduct, Cvss};
    use crate::version::VersionRange;

    const FEED: &str = include_str!("../../../testdata/cve/nvd_feed_sample.json");

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn service(name: &str, product: Option<&str>, version: Option<&str>) -> Service {
        Service {
            name: name.to_string(),
            product: product.map(str::to_string),
            version: version.map(str::to_string),
            banner: None,
        }
    }

    fn db() -> CveDatabase {
        crate::nvd::parse_feed(FEED)
    }

    #[test]
    fn service_versionne_donne_des_cve_avec_cvss() {
        // US-C2 : OpenSSH 9.1 → au moins une CVE corrélée, avec gravité CVSS.
        let svc = service("ssh", Some("OpenSSH"), Some("9.1"));
        let findings = correlate_service(ip("192.168.56.10"), Some(22), &svc, &db());
        assert!(!findings.is_empty(), "OpenSSH 9.1 doit corréler des CVE");
        let top = &findings[0];
        assert_eq!(top.cve.as_deref(), Some("CVE-2023-38408"));
        assert_eq!(top.severity, Severity::Critical);
        assert_eq!(top.host, ip("192.168.56.10"));
        assert_eq!(top.port, Some(22));
        assert!(top.title.contains("CVSS"));
        // Constat informatif : aucune incitation à exploiter.
        assert!(top.recommendation.contains("aucun exploit"));
    }

    #[test]
    fn version_corrigee_ne_corrige_aucun_faux_positif() {
        // OpenSSH 9.6p1 est au-delà de la plage affectée (< 9.3p2) → rien.
        let svc = service("ssh", Some("OpenSSH"), Some("9.6p1"));
        let findings = correlate_service(ip("192.168.56.10"), Some(22), &svc, &db());
        assert!(
            findings.iter().all(|f| f.cve.as_deref() != Some("CVE-2023-38408")),
            "une version corrigée ne doit pas être signalée"
        );
    }

    #[test]
    fn nginx_a_jour_nest_pas_signale() {
        // La fixture n'affecte nginx que < 1.20 ; 1.24.0 est à jour → aucune CVE.
        let svc = service("http", Some("nginx"), Some("1.24.0"));
        let findings = correlate_service(ip("192.168.56.10"), Some(80), &svc, &db());
        assert!(findings.is_empty(), "nginx 1.24.0 ne doit rien corréler");
    }

    #[test]
    fn nginx_vulnerable_est_signale() {
        let svc = service("http", Some("nginx"), Some("1.18.0"));
        let findings = correlate_service(ip("192.168.56.10"), Some(80), &svc, &db());
        assert!(
            findings.iter().any(|f| f.cve.is_some()),
            "nginx 1.18.0 (< 1.20) doit corréler"
        );
    }

    #[test]
    fn service_sans_version_nest_jamais_correle() {
        let svc = service("ssh", Some("OpenSSH"), None);
        let findings = correlate_service(ip("10.0.0.1"), Some(22), &svc, &db());
        assert!(findings.is_empty());
        // Version vide/espaces : idem.
        let svc = service("ssh", Some("OpenSSH"), Some("   "));
        assert!(correlate_service(ip("10.0.0.1"), Some(22), &svc, &db()).is_empty());
    }

    #[test]
    fn produit_inconnu_ne_correle_rien() {
        let svc = service("ssh", Some("Produit-Inexistant"), Some("1.0"));
        assert!(correlate_service(ip("10.0.0.1"), Some(22), &svc, &db()).is_empty());
    }

    #[test]
    fn exact_vsftpd_correle_sur_la_version_exacte() {
        let db = db();
        let vuln = service("ftp", Some("vsFTPd"), Some("2.3.4"));
        assert!(!correlate_service(ip("10.0.0.1"), Some(21), &vuln, &db).is_empty());
        // Une autre version du même produit ne matche pas la CVE exacte.
        let safe = service("ftp", Some("vsFTPd"), Some("3.0.5"));
        let findings = correlate_service(ip("10.0.0.1"), Some(21), &safe, &db);
        assert!(findings.iter().all(|f| f.cve.as_deref() != Some("CVE-2011-2523")));
    }

    #[test]
    fn findings_tries_par_gravite_decroissante() {
        // Base synthétique : deux CVE sur le même produit, gravités différentes.
        let db = CveDatabase {
            refreshed_at: None,
            records: vec![
                CveRecord {
                    id: "CVE-0000-LOW".to_string(),
                    description: "basse".to_string(),
                    cvss: Cvss::new(3.1),
                    affected: vec![AffectedProduct {
                        product: "demo".to_string(),
                        vendor: None,
                        aliases: vec![],
                        range: VersionRange::end_excluding("2.0"),
                    }],
                    published: None,
                    last_modified: None,
                },
                CveRecord {
                    id: "CVE-0000-CRIT".to_string(),
                    description: "critique".to_string(),
                    cvss: Cvss::new(9.9),
                    affected: vec![AffectedProduct {
                        product: "demo".to_string(),
                        vendor: None,
                        aliases: vec![],
                        range: VersionRange::end_excluding("2.0"),
                    }],
                    published: None,
                    last_modified: None,
                },
            ],
        };
        let svc = service("demo", Some("demo"), Some("1.0"));
        let findings = correlate_service(ip("10.0.0.1"), None, &svc, &db);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].cve.as_deref(), Some("CVE-0000-CRIT"));
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].cve.as_deref(), Some("CVE-0000-LOW"));
    }

    #[test]
    fn correlate_host_parcourt_les_ports_services() {
        let host = Host {
            ip: ip("192.168.56.10"),
            mac: None,
            hostname: Some("srv.lab".to_string()),
            os_guess: None,
            ports: vec![
                Port {
                    number: 22,
                    proto: Proto::Tcp,
                    state: PortState::Open,
                    service: Some(service("ssh", Some("OpenSSH"), Some("9.1"))),
                },
                Port {
                    number: 80,
                    proto: Proto::Tcp,
                    state: PortState::Open,
                    service: Some(service("http", Some("nginx"), Some("1.24.0"))),
                },
                Port {
                    number: 443,
                    proto: Proto::Tcp,
                    state: PortState::Closed,
                    service: None,
                },
            ],
            role: HostRole::Server,
            compromised: false,
            first_seen: chrono_now(),
        };
        let findings = correlate_host(&host, &db());
        // OpenSSH 9.1 corrèle (port 22), nginx 1.24 non, port 443 sans service non.
        assert!(findings.iter().all(|f| f.port == Some(22)));
        assert!(findings.iter().any(|f| f.cve.is_some()));
    }

    /// Horodatage figé pour construire un `Host` sans dépendre de l'horloge réelle.
    fn chrono_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }
}
