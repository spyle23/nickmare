//! Lecture d'un rapport depuis l'**état d'engagement** (§11.2).
//!
//! Le rapport consomme le store via le trait
//! [`EngagementStore`](nickmare_core::engagement::EngagementStore) — le même
//! qu'implémente `SqliteStore` (crate `nickmare-store`) et le mock
//! [`InMemoryStore`](nickmare_core::engagement::InMemoryStore). Le crate reste
//! ainsi **pur et testable** sans SQLite ; le binaire `nickmare` branche le store
//! réel.
//!
//! # Convention de persistance (N1)
//!
//! Le store de #26 persiste des **opérations** idempotentes, leur **résultat**
//! (charge utile opaque indexée par clé) et la **consommation**. Pour le rapport,
//! deux **clés de résultat réservées** portent les agrégats sérialisés en JSON :
//!
//! - [`NETWORK_MAP_KEY`] → une [`NetworkMap`] ;
//! - [`FINDINGS_KEY`] → un `Vec<Finding>`.
//!
//! Elles sont lues si présentes, sinon le rapport reste **valide mais sobre**
//! (carte/constats vides) : il reflète toujours au moins les opérations et la
//! consommation de l'engagement. L'alimentation de ces clés par les commandes de
//! recon (scan/service id → store) est un **branchement distinct** (cf. la PR) ;
//! ce module en définit le contrat de lecture, stable et testé.

use chrono::{DateTime, Utc};
use nickmare_core::engagement::EngagementStore;
use nickmare_core::model::{Finding, NetworkMap};

use crate::error::ReportError;
use crate::model::{OperationView, ReportMeta, ReportModel, UsageView};

/// Clé de résultat réservée portant la [`NetworkMap`] sérialisée (JSON).
pub const NETWORK_MAP_KEY: &str = "report:network-map";

/// Clé de résultat réservée portant les `Vec<Finding>` sérialisés (JSON).
pub const FINDINGS_KEY: &str = "report:findings";

/// Niveau de restitution couvert par ce socle.
const LEVEL_N1: &str = "N1";

/// Construit un [`ReportModel`] N1 reproductible à partir de l'état d'un
/// engagement. `generated_at` est injecté (horloge testable), `tool` et
/// `engagement` étiquettent le rapport.
pub fn load_from_store(
    store: &dyn EngagementStore,
    engagement: &str,
    tool: &str,
    generated_at: DateTime<Utc>,
) -> Result<ReportModel, ReportError> {
    let network = match store.get_result(NETWORK_MAP_KEY)? {
        Some(payload) => serde_json::from_str(&payload)?,
        None => empty_map(),
    };
    let findings: Vec<Finding> = match store.get_result(FINDINGS_KEY)? {
        Some(payload) => serde_json::from_str(&payload)?,
        None => Vec::new(),
    };

    let mut operations = Vec::new();
    for op in store.operations()? {
        operations.push(OperationView::from(op));
    }
    let usage = UsageView::from(store.usage()?);

    let meta = ReportMeta {
        tool: tool.to_string(),
        engagement: engagement.to_string(),
        level: LEVEL_N1.to_string(),
        generated_at,
    };
    Ok(ReportModel::new(meta, network, findings, operations, usage))
}

/// Carte vide (aucune donnée de recon persistée).
fn empty_map() -> NetworkMap {
    NetworkMap {
        scope_network: String::new(),
        hosts: Vec::new(),
        pivots: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use nickmare_core::engagement::InMemoryStore;
    use nickmare_core::model::{Host, HostRole, OsGuess, Port, PortState, Proto, Service, Severity};

    fn ip(addr: &str) -> IpAddr {
        addr.parse().expect("ip de test")
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("horodatage de test")
    }

    fn sample_map() -> NetworkMap {
        NetworkMap {
            scope_network: "192.168.1.0/24".to_string(),
            hosts: vec![Host {
                ip: ip("192.168.1.10"),
                mac: None,
                hostname: Some("srv.local".to_string()),
                os_guess: Some(OsGuess::Linux),
                ports: vec![Port {
                    number: 22,
                    proto: Proto::Tcp,
                    state: PortState::Open,
                    service: Some(Service {
                        name: "ssh".to_string(),
                        product: Some("OpenSSH".to_string()),
                        version: Some("9.6".to_string()),
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

    fn sample_findings() -> Vec<Finding> {
        vec![Finding {
            host: ip("192.168.1.10"),
            port: Some(22),
            severity: Severity::Medium,
            cve: None,
            title: "SSH exposé".to_string(),
            description: "Service SSH accessible.".to_string(),
            recommendation: "Restreindre l'accès.".to_string(),
        }]
    }

    /// Store peuplé selon la convention : clés réservées + une opération terminée.
    fn seeded_store() -> InMemoryStore {
        let mut store = InMemoryStore::new();
        let map = serde_json::to_string(&sample_map()).expect("carte");
        let findings = serde_json::to_string(&sample_findings()).expect("findings");
        store.put_result(NETWORK_MAP_KEY, &map).expect("put map");
        store.put_result(FINDINGS_KEY, &findings).expect("put find");
        store.begin("scan:h", "scan", "h", ts(1)).expect("begin");
        store.complete("scan:h", ts(2)).expect("complete");
        store.add_usage(1, 128).expect("usage");
        store
    }

    /// Chargement court, pour garder les lignes de test sous la limite rustfmt.
    fn load(store: &InMemoryStore, now_s: i64) -> ReportModel {
        load_from_store(store, "acme", "nm", ts(now_s)).expect("chargement")
    }

    #[test]
    fn lit_la_carte_les_findings_et_l_etat() {
        let model = load(&seeded_store(), 100);

        assert_eq!(model.network.scope_network, "192.168.1.0/24");
        assert_eq!(model.network.hosts.len(), 1);
        assert_eq!(model.findings.len(), 1);
        assert_eq!(model.summary.host_count, 1);
        assert_eq!(model.summary.open_service_count, 1);
        assert_eq!(model.operations.len(), 1);
        assert_eq!(model.operations[0].status, "done");
        assert_eq!(model.usage.actions, 1);
        assert_eq!(model.usage.bytes, 128);
        assert_eq!(model.meta.engagement, "acme");
        assert_eq!(model.meta.level, "N1");
    }

    #[test]
    fn store_vide_donne_un_rapport_valide_mais_sobre() {
        let model = load(&InMemoryStore::new(), 0);
        assert!(model.network.hosts.is_empty());
        assert!(model.findings.is_empty());
        assert!(model.operations.is_empty());
        // Reste exportable et rendu sans paniquer.
        assert!(model.to_json().is_ok());
        assert!(model.to_html().is_ok());
    }

    #[test]
    fn charge_puis_exporte_est_reproductible() {
        let store = seeded_store();
        let a = load(&store, 100);
        let b = load(&store, 100);
        assert_eq!(a, b);
        assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
    }

    #[test]
    fn charge_utile_corrompue_remonte_une_erreur() {
        let mut store = InMemoryStore::new();
        let bad = "{ ceci n'est pas du json";
        store.put_result(NETWORK_MAP_KEY, bad).expect("put");
        let err = load_from_store(&store, "acme", "nm", ts(0));
        assert!(matches!(err, Err(ReportError::Json(_))));
    }
}
