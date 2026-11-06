//! Modèle de rapport **Niveau 1** (issue #16, cf. `docs/ARCHITECTURE.md` §9
//! Phase 5, US-H1/US-H2).
//!
//! Le [`ReportModel`] est une **agrégation pure** (aucune I/O) des résultats de
//! recon N1 : la [`NetworkMap`] (hôtes, rôles, services, pivots), les
//! [`Finding`]s, l'état des opérations de l'engagement et la consommation. Il est
//! entièrement **sérialisable** (US-H2 : export JSON complet et interopérable) et
//! sert de source unique aux deux restitutions — JSON ([`ReportModel::to_json`])
//! et HTML (module [`crate::html`]).
//!
//! Invariant de niveau (§9) : ce socle ne porte **que** du N1. Les sections N2–N4
//! (exploits, craquage, émulation) s'ajouteront en Phase 9, derrière le jalon de
//! revue #17 — elles n'existent pas ici.

use chrono::{DateTime, Utc};
use nickmare_core::engagement::{Operation, Usage};
use nickmare_core::model::{Finding, NetworkMap, PortState, Severity};
use serde::{Deserialize, Serialize};

use crate::error::ReportError;

/// Gravités dans l'ordre d'affichage du résumé exécutif (de la plus forte à la
/// plus faible).
const SEVERITIES: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// Clé stable (anglais, minuscule) d'une gravité pour le JSON interopérable.
#[must_use]
pub fn severity_key(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Métadonnées d'un rapport : outil générateur, engagement, niveau couvert et
/// horodatage de génération (injecté, pour un rendu reproductible en test).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportMeta {
    /// Outil et version (`nickmare x.y.z`).
    pub tool: String,
    /// Identifiant/nom de l'engagement rapporté.
    pub engagement: String,
    /// Niveau de restitution couvert par ce socle (`N1`).
    pub level: String,
    /// Horodatage de génération du rapport.
    pub generated_at: DateTime<Utc>,
}

/// Décompte de constats pour une gravité donnée (résumé exécutif, US-H1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCount {
    /// Clé stable de la gravité (`critical`, `high`, …).
    pub severity: String,
    /// Nombre de constats de cette gravité.
    pub count: usize,
}

/// Résumé exécutif : chiffres clés agrégés de la carte et des constats (US-H1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Nombre d'hôtes découverts.
    pub host_count: usize,
    /// Nombre de services sur un port **ouvert**.
    pub open_service_count: usize,
    /// Nombre total de constats.
    pub finding_count: usize,
    /// Décompte des constats par gravité (ordre décroissant).
    pub findings_by_severity: Vec<SeverityCount>,
    /// Nombre d'hôtes marqués compromis (toujours 0 en N1).
    pub compromised_count: usize,
    /// Nombre de chemins de pivot tracés (toujours 0 en N1).
    pub pivot_count: usize,
}

impl Summary {
    /// Calcule le résumé exécutif à partir de la carte et des constats.
    #[must_use]
    pub fn compute(network: &NetworkMap, findings: &[Finding]) -> Self {
        let mut open_service_count = 0usize;
        let mut compromised_count = 0usize;
        for host in &network.hosts {
            if host.compromised {
                compromised_count += 1;
            }
            for port in &host.ports {
                if port.state == PortState::Open && port.service.is_some() {
                    open_service_count += 1;
                }
            }
        }
        let mut findings_by_severity = Vec::with_capacity(SEVERITIES.len());
        for severity in SEVERITIES {
            let count = findings.iter().filter(|f| f.severity == severity).count();
            findings_by_severity.push(SeverityCount {
                severity: severity_key(severity).to_string(),
                count,
            });
        }
        Self {
            host_count: network.hosts.len(),
            open_service_count,
            finding_count: findings.len(),
            findings_by_severity,
            compromised_count,
            pivot_count: network.pivots.len(),
        }
    }
}

/// Vue sérialisable d'une opération d'engagement (le type `core` ne dérive pas
/// `serde`). Reflète l'état consigné dans le store (§11.2) pour un rapport
/// reproductible depuis un même engagement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationView {
    pub key: String,
    pub kind: String,
    pub target: String,
    /// Statut persisté (`pending`, `incomplete`, `done`).
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl From<Operation> for OperationView {
    fn from(op: Operation) -> Self {
        Self {
            key: op.key,
            kind: op.kind,
            target: op.target,
            status: op.status.as_str().to_string(),
            started_at: op.started_at,
            finished_at: op.finished_at,
        }
    }
}

/// Consommation cumulée de l'engagement (actions, octets), sérialisable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UsageView {
    pub actions: u64,
    pub bytes: u64,
}

impl From<Usage> for UsageView {
    fn from(usage: Usage) -> Self {
        Self {
            actions: usage.actions,
            bytes: usage.bytes,
        }
    }
}

/// Rapport complet de Niveau 1 : agrégation prête à restituer en JSON ou HTML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportModel {
    pub meta: ReportMeta,
    pub summary: Summary,
    pub network: NetworkMap,
    pub findings: Vec<Finding>,
    pub operations: Vec<OperationView>,
    pub usage: UsageView,
}

impl ReportModel {
    /// Assemble un rapport et calcule son résumé exécutif à partir des éléments
    /// agrégés. Le résumé est donc toujours cohérent avec la carte et les
    /// constats portés.
    #[must_use]
    pub fn new(
        meta: ReportMeta,
        network: NetworkMap,
        findings: Vec<Finding>,
        operations: Vec<OperationView>,
        usage: UsageView,
    ) -> Self {
        let summary = Summary::compute(&network, &findings);
        Self {
            meta,
            summary,
            network,
            findings,
            operations,
            usage,
        }
    }

    /// Export JSON complet et indenté (US-H2). Déterministe : l'ordre des champs
    /// et des collections est stable, donc reproductible depuis un même rapport.
    pub fn to_json(&self) -> Result<String, ReportError> {
        let json = serde_json::to_string_pretty(self)?;
        Ok(json)
    }

    /// (Re)construit un rapport depuis son export JSON (round-trip, US-H2).
    pub fn from_json(json: &str) -> Result<Self, ReportError> {
        let model = serde_json::from_str(json)?;
        Ok(model)
    }

    /// Rendu HTML lisible (US-H1), via les templates `askama` compilés.
    pub fn to_html(&self) -> Result<String, ReportError> {
        crate::html::render(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use nickmare_core::model::{Host, HostRole, OsGuess, PivotLink, Port, Proto, Service};

    fn ip(addr: &str) -> IpAddr {
        addr.parse().expect("ip de test")
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("horodatage de test")
    }

    fn server() -> Host {
        Host {
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
        }
    }

    fn map() -> NetworkMap {
        NetworkMap {
            scope_network: "192.168.1.0/24".to_string(),
            hosts: vec![server()],
            pivots: Vec::new(),
        }
    }

    fn findings() -> Vec<Finding> {
        vec![
            Finding {
                host: ip("192.168.1.10"),
                port: Some(22),
                severity: Severity::Medium,
                cve: None,
                title: "SSH exposé".to_string(),
                description: "Service SSH accessible.".to_string(),
                recommendation: "Restreindre l'accès.".to_string(),
            },
            Finding {
                host: ip("192.168.1.10"),
                port: Some(445),
                severity: Severity::High,
                cve: Some("CVE-2017-0144".to_string()),
                title: "SMBv1 exposé".to_string(),
                description: "Service SMBv1 actif.".to_string(),
                recommendation: "Désactiver SMBv1.".to_string(),
            },
        ]
    }

    fn meta() -> ReportMeta {
        ReportMeta {
            tool: "nickmare 0.2.0".to_string(),
            engagement: "acme".to_string(),
            level: "N1".to_string(),
            generated_at: ts(42),
        }
    }

    fn model() -> ReportModel {
        ReportModel::new(meta(), map(), findings(), Vec::new(), UsageView::default())
    }

    #[test]
    fn resume_compte_hotes_services_et_gravites() {
        let summary = Summary::compute(&map(), &findings());
        assert_eq!(summary.host_count, 1);
        assert_eq!(summary.open_service_count, 1);
        assert_eq!(summary.finding_count, 2);
        assert_eq!(summary.compromised_count, 0);
        assert_eq!(summary.pivot_count, 0);

        // Décompte par gravité, dans l'ordre décroissant imposé.
        let by_sev = &summary.findings_by_severity;
        let keys: Vec<&str> = by_sev.iter().map(|s| s.severity.as_str()).collect();
        assert_eq!(keys, vec!["critical", "high", "medium", "low", "info"]);
        let high = by_sev.iter().find(|s| s.severity == "high").expect("high");
        assert_eq!(high.count, 1);
        let medium = by_sev.iter().find(|s| s.severity == "medium").expect("med");
        assert_eq!(medium.count, 1);
    }

    #[test]
    fn resume_ignore_les_ports_fermes_et_sans_service() {
        let mut host = server();
        host.ports.push(Port {
            number: 80,
            proto: Proto::Tcp,
            state: PortState::Closed,
            service: None,
        });
        host.ports.push(Port {
            number: 443,
            proto: Proto::Tcp,
            state: PortState::Open,
            service: None,
        });
        let network = NetworkMap {
            scope_network: "192.168.1.0/24".to_string(),
            hosts: vec![host],
            pivots: Vec::new(),
        };
        // Seul le port 22 (ouvert + service) compte comme service identifié.
        assert_eq!(Summary::compute(&network, &[]).open_service_count, 1);
    }

    #[test]
    fn json_round_trip_identite() {
        let model = model();
        let json = model.to_json().expect("export JSON");
        let back = ReportModel::from_json(&json).expect("relecture JSON");
        assert_eq!(model, back);
    }

    #[test]
    fn json_est_complet_et_valide() {
        let json = model().to_json().expect("export JSON");
        // Valide (reparse générique) et complet (sections clés présentes).
        let value: serde_json::Value = serde_json::from_str(&json).expect("JSON valide");
        assert!(value.get("meta").is_some());
        assert!(value.get("summary").is_some());
        assert!(value.get("network").is_some());
        assert!(value.get("findings").is_some());
        assert!(value.get("operations").is_some());
        assert!(value.get("usage").is_some());
        // Carte réseau présente et peuplée (DoD : carte dans le rapport).
        assert!(json.contains("192.168.1.0/24"));
        assert!(json.contains("CVE-2017-0144"));
    }

    #[test]
    fn export_json_est_reproductible() {
        // Deux exports du même rapport sont strictement identiques (reproductible).
        let model = model();
        assert_eq!(model.to_json().unwrap(), model.to_json().unwrap());
    }

    #[test]
    fn operation_view_reflete_le_statut_persiste() {
        use nickmare_core::engagement::OpStatus;
        let op = Operation {
            key: "scan:192.168.1.10:22".to_string(),
            kind: "scan".to_string(),
            target: "192.168.1.10".to_string(),
            status: OpStatus::Done,
            started_at: ts(1),
            finished_at: Some(ts(2)),
        };
        let view = OperationView::from(op);
        assert_eq!(view.status, "done");
        assert_eq!(view.finished_at, Some(ts(2)));
    }

    #[test]
    fn pivot_et_compromission_comptes_quand_presents() {
        // Même si N1 ne les produit pas, le résumé reste correct si la carte en
        // porte (robustesse du calcul, pas une capacité offensive).
        let mut host = server();
        host.compromised = true;
        let network = NetworkMap {
            scope_network: "10.0.0.0/24".to_string(),
            hosts: vec![host],
            pivots: vec![PivotLink {
                from: ip("10.0.0.1"),
                to: ip("10.0.0.2"),
                via: "ssh".to_string(),
                at: ts(5),
            }],
        };
        let summary = Summary::compute(&network, &[]);
        assert_eq!(summary.compromised_count, 1);
        assert_eq!(summary.pivot_count, 1);
    }
}
