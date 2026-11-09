//! Modèle de **rapport consolidé** couvrant tous les niveaux N1→N4 (issue #23,
//! cf. `docs/ARCHITECTURE.md` §9 Phase 9, §11.3, US-H1).
//!
//! Le socle [`ReportModel`](crate::ReportModel) (issue #16) ne porte que le N1
//! (recon). Ce module l'étend en un [`ConsolidatedReport`] qui agrège, en plus de
//! la carte et des constats :
//!
//! - **N2** — les [`ExploitAttempt`] confirmés (exploits prouvés) ;
//! - **N3** — les [`CrackResult`] (taux de craquage, verdict de politique,
//!   patterns faibles) — **jamais** un secret en clair : `CrackResult` est, par
//!   construction (§7, masquage `MaskedSecret` de `crates/crack`), un agrégat
//!   statistique sans credential ;
//! - **N4** — la **matrice de couverture ATT&CK** et le **MTTD** par technique,
//!   réutilisés tels quels de `nickmare-emulation`
//!   ([`CoverageMatrix`](nickmare_emulation::verdict::CoverageMatrix)), plus la
//!   **comparaison des taux de détection entre profils**
//!   ([`CoverageMatrix::compare_profiles`]).
//!
//! S'y ajoute une **timeline horodatée** ([`TimelineEvent`]) qui corrèle l'action
//! opérateur et l'évènement de détection côté défense (§11.3).
//!
//! # Restitution, pas offensive
//!
//! Ce module **ne pilote aucun moteur** : il consomme des types **purs** déjà
//! tracés (opérations, exploits confirmés, résultats de craquage, exécutions
//! ATT&CK) et les restitue. Il n'introduit aucune capacité d'exécution de
//! technique, d'exploit ou de craquage. Comme le socle, il est **reproductible**
//! (un même état d'engagement produit toujours le même rapport) et lisible via un
//! mock de store, sans SQLite.

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use nickmare_core::engagement::EngagementStore;
use nickmare_core::model::{
    AttackExecution, CrackResult, DetectionVerdict, ExploitAttempt, ExploitOutcome, Finding,
    NetworkMap, PolicyVerdict,
};
use nickmare_emulation::profile::profile_label;
use nickmare_emulation::techniques::TechniqueCatalog;
use nickmare_emulation::verdict::{CoverageMatrix, DetectionStats};

use crate::error::ReportError;
use crate::model::{OperationView, ReportMeta, SeverityCount, Summary, UsageView};
use crate::store::{FINDINGS_KEY, NETWORK_MAP_KEY};

/// Clé de résultat réservée portant les `Vec<ExploitAttempt>` sérialisés (N2).
pub const EXPLOITS_KEY: &str = "report:exploits";

/// Clé de résultat réservée portant les `Vec<CrackResult>` sérialisés (N3).
pub const CRACKING_KEY: &str = "report:cracking";

/// Clé de résultat réservée portant les `Vec<AttackExecution>` sérialisés (N4).
pub const EXECUTIONS_KEY: &str = "report:executions";

/// Niveau de restitution couvert par le rapport consolidé.
const LEVEL_CONSOLIDATED: &str = "N1-N4";

/// Origine « opérateur » d'un évènement de timeline (action menée, en clair).
const ORIGIN_OPERATOR: &str = "operateur";

/// Origine « SIEM / blue team » d'un évènement de timeline (alerte de détection).
const ORIGIN_SIEM: &str = "siem";

/// Clé stable (anglais, minuscule) d'un verdict de politique, pour le JSON.
#[must_use]
pub fn policy_verdict_key(verdict: PolicyVerdict) -> &'static str {
    match verdict {
        PolicyVerdict::Compliant => "compliant",
        PolicyVerdict::Weak => "weak",
        PolicyVerdict::NonCompliant => "non-compliant",
        PolicyVerdict::Unknown => "unknown",
    }
}

/// Vrai si une tentative d'exploitation est **confirmée** : exploitabilité
/// prouvée (`Vulnerable`, mode validation) ou intrusion réussie (`Success`, mode
/// exploit). `NotVulnerable`/`Failed` ne comptent pas.
#[must_use]
pub fn is_confirmed_exploit(outcome: ExploitOutcome) -> bool {
    matches!(
        outcome,
        ExploitOutcome::Vulnerable | ExploitOutcome::Success
    )
}

/// Taux `part / total` borné (0.0 si `total == 0`, fail-safe anti-division).
fn ratio(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64
    }
}

/// Rang de sévérité d'un verdict de politique (pour retenir le **pire**).
fn verdict_rank(verdict: PolicyVerdict) -> u8 {
    match verdict {
        PolicyVerdict::Unknown => 0,
        PolicyVerdict::Compliant => 1,
        PolicyVerdict::Weak => 2,
        PolicyVerdict::NonCompliant => 3,
    }
}

/// MTTD moyen (secondes) sur l'ensemble des cellules détectées de la matrice, ou
/// `None` si aucune technique n'a de MTTD calculable.
fn mean_mttd_seconds(coverage: &CoverageMatrix) -> Option<i64> {
    let mut sum = 0i64;
    let mut count = 0i64;
    for cell in &coverage.cells {
        if let Some(seconds) = cell.mttd_seconds {
            sum += seconds;
            count += 1;
        }
    }
    if count == 0 {
        None
    } else {
        Some(sum / count)
    }
}

/// **Résumé exécutif** consolidé : chiffres clés agrégés de tous les niveaux
/// (US-H1). Reste cohérent avec le détail porté (calculé, jamais fabriqué).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    // --- N1 (recon) ---
    /// Nombre d'hôtes découverts.
    pub host_count: usize,
    /// Nombre de services sur un port ouvert.
    pub open_service_count: usize,
    /// Nombre total de constats.
    pub finding_count: usize,
    /// Décompte des constats par gravité (ordre décroissant).
    pub findings_by_severity: Vec<SeverityCount>,
    /// Nombre d'hôtes marqués compromis.
    pub compromised_count: usize,
    /// Nombre de chemins de pivot tracés.
    pub pivot_count: usize,
    // --- N2 (exploitation) ---
    /// Nombre de tentatives d'exploitation tracées.
    pub exploit_attempts: usize,
    /// Nombre d'exploits confirmés (exploitabilité prouvée ou intrusion réussie).
    pub exploits_confirmed: usize,
    // --- N3 (craquage) ---
    /// Total de hashes soumis au craquage.
    pub hashes_attempted: u64,
    /// Total de hashes effectivement craqués.
    pub hashes_cracked: u64,
    /// Taux de craquage global (0.0..=1.0).
    pub crack_rate: f64,
    /// Pire verdict de politique observé (clé stable).
    pub policy_verdict: String,
    // --- N4 (émulation) ---
    /// Nombre de techniques ATT&CK émises.
    pub techniques_emitted: usize,
    /// Taux de détection global (détecté + partiel, 0.0..=1.0).
    pub detection_rate: f64,
    /// MTTD moyen (secondes) sur les techniques détectées, si calculable.
    pub mean_mttd_seconds: Option<i64>,
}

impl ExecutiveSummary {
    /// Calcule le résumé exécutif à partir des agrégats de chaque niveau. Le
    /// résumé est donc toujours cohérent avec le détail porté par le rapport.
    #[must_use]
    pub fn compute(
        network: &NetworkMap,
        findings: &[Finding],
        exploits: &[ExploitAttempt],
        cracking: &[CrackResult],
        coverage: &CoverageMatrix,
    ) -> Self {
        let base = Summary::compute(network, findings);

        let exploits_confirmed = exploits
            .iter()
            .filter(|attempt| is_confirmed_exploit(attempt.outcome))
            .count();

        let mut hashes_attempted = 0u64;
        let mut hashes_cracked = 0u64;
        let mut worst = PolicyVerdict::Unknown;
        for result in cracking {
            hashes_attempted += result.attempted;
            hashes_cracked += result.cracked;
            if verdict_rank(result.policy_verdict) > verdict_rank(worst) {
                worst = result.policy_verdict;
            }
        }

        Self {
            host_count: base.host_count,
            open_service_count: base.open_service_count,
            finding_count: base.finding_count,
            findings_by_severity: base.findings_by_severity,
            compromised_count: base.compromised_count,
            pivot_count: base.pivot_count,
            exploit_attempts: exploits.len(),
            exploits_confirmed,
            hashes_attempted,
            hashes_cracked,
            crack_rate: ratio(hashes_cracked, hashes_attempted),
            policy_verdict: policy_verdict_key(worst).to_string(),
            techniques_emitted: coverage.len(),
            detection_rate: coverage.detection_rate(),
            mean_mttd_seconds: mean_mttd_seconds(coverage),
        }
    }
}

/// Un évènement **horodaté** de la timeline consolidée (§11.3) : une action de
/// l'opérateur (recon, pivot, technique émise) ou un évènement de détection côté
/// défense (alerte SIEM). Les évènements partageant un `correlation` identique
/// relient une action à sa détection (corrélation action ↔ SIEM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Horodatage de l'évènement.
    pub at: DateTime<Utc>,
    /// Phase : `recon` | `pivot` | `emulation` | `detection`.
    pub phase: String,
    /// Origine : `operateur` (action) ou `siem` (détection défense).
    pub origin: String,
    /// Étiquette courte (clé d'opération, route de pivot, identifiant ATT&CK).
    pub label: String,
    /// Description lisible de l'évènement.
    pub detail: String,
    /// Clé de corrélation action ↔ détection (identifiant ATT&CK), si applicable.
    pub correlation: Option<String>,
}

/// Construit la timeline en fusionnant les actions tracées (opérations N1, pivots
/// N2, techniques N4) et les évènements de détection (N4), triés par horodatage.
/// Tri **stable** et ordre d'insertion déterministe → timeline reproductible.
fn build_timeline(
    operations: &[OperationView],
    network: &NetworkMap,
    executions: &[AttackExecution],
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for op in operations {
        events.push(TimelineEvent {
            at: op.started_at,
            phase: "recon".to_string(),
            origin: ORIGIN_OPERATOR.to_string(),
            label: op.key.clone(),
            detail: format!("{} sur {}", op.kind, op.target),
            correlation: None,
        });
    }

    for pivot in &network.pivots {
        events.push(TimelineEvent {
            at: pivot.at,
            phase: "pivot".to_string(),
            origin: ORIGIN_OPERATOR.to_string(),
            label: format!("{} → {}", pivot.from, pivot.to),
            detail: format!("pivot via {}", pivot.via),
            correlation: None,
        });
    }

    for exec in executions {
        events.push(TimelineEvent {
            at: exec.performed_at,
            phase: "emulation".to_string(),
            origin: ORIGIN_OPERATOR.to_string(),
            label: exec.technique_id.clone(),
            detail: format!("technique émise (profil {})", profile_label(exec.profile)),
            correlation: Some(exec.technique_id.clone()),
        });
        let is_detected = matches!(
            exec.detection,
            DetectionVerdict::Detected | DetectionVerdict::Partial
        );
        if let Some(detected_at) = exec.detected_at.filter(|_| is_detected) {
            let by = exec.detected_by.as_deref().unwrap_or("contrôle inconnu");
            events.push(TimelineEvent {
                at: detected_at,
                phase: "detection".to_string(),
                origin: ORIGIN_SIEM.to_string(),
                label: exec.technique_id.clone(),
                detail: format!("alerte blue team ({by})"),
                correlation: Some(exec.technique_id.clone()),
            });
        }
    }

    events.sort_by_key(|event| event.at);
    events
}

/// Données agrégées (déjà tracées) alimentant un rapport consolidé. Regroupées en
/// un seul paramètre pour garder [`ConsolidatedReport::new`] lisible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsolidatedInputs {
    /// Carte réseau annotée (hôtes compromis + pivots).
    pub network: NetworkMap,
    /// Constats N1 (avec recommandations).
    pub findings: Vec<Finding>,
    /// Opérations consignées de l'engagement.
    pub operations: Vec<OperationView>,
    /// Consommation cumulée.
    pub usage: UsageView,
    /// Tentatives d'exploitation tracées (N2).
    pub exploits: Vec<ExploitAttempt>,
    /// Résultats de craquage (N3) — statistiques, **sans** secret en clair.
    pub cracking: Vec<CrackResult>,
    /// Exécutions ATT&CK tracées (N4), source de la matrice et de la timeline.
    pub executions: Vec<AttackExecution>,
}

/// Rapport **consolidé** N1→N4 : agrégation pure prête à restituer en JSON ou
/// HTML. Le résumé exécutif, la matrice de couverture et la timeline sont
/// **dérivés** des agrégats à la construction — toujours cohérents avec eux.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsolidatedReport {
    pub meta: ReportMeta,
    pub summary: ExecutiveSummary,
    pub network: NetworkMap,
    pub findings: Vec<Finding>,
    pub operations: Vec<OperationView>,
    pub usage: UsageView,
    pub exploits: Vec<ExploitAttempt>,
    pub cracking: Vec<CrackResult>,
    pub executions: Vec<AttackExecution>,
    pub coverage: CoverageMatrix,
    pub profile_comparison: Vec<DetectionStats>,
    pub timeline: Vec<TimelineEvent>,
}

impl ConsolidatedReport {
    /// Assemble un rapport consolidé à partir des agrégats. La matrice ATT&CK est
    /// **construite** en réutilisant [`CoverageMatrix::build`] sur les exécutions
    /// et le catalogue fourni ; le résumé, la comparaison des profils et la
    /// timeline en sont dérivés.
    #[must_use]
    pub fn new(meta: ReportMeta, inputs: ConsolidatedInputs, catalog: &TechniqueCatalog) -> Self {
        let ConsolidatedInputs {
            network,
            findings,
            operations,
            usage,
            exploits,
            cracking,
            executions,
        } = inputs;

        let coverage = CoverageMatrix::build(&executions, catalog);
        let profile_comparison = coverage.compare_profiles();
        let summary =
            ExecutiveSummary::compute(&network, &findings, &exploits, &cracking, &coverage);
        let timeline = build_timeline(&operations, &network, &executions);

        Self {
            meta,
            summary,
            network,
            findings,
            operations,
            usage,
            exploits,
            cracking,
            executions,
            coverage,
            profile_comparison,
            timeline,
        }
    }

    /// Export JSON complet, indenté et déterministe (reproductible).
    pub fn to_json(&self) -> Result<String, ReportError> {
        let json = serde_json::to_string_pretty(self)?;
        Ok(json)
    }

    /// (Re)construit un rapport consolidé depuis son export JSON (round-trip).
    pub fn from_json(json: &str) -> Result<Self, ReportError> {
        let model = serde_json::from_str(json)?;
        Ok(model)
    }

    /// Rendu HTML lisible (US-H1), via le template `askama` consolidé.
    pub fn to_html(&self) -> Result<String, ReportError> {
        crate::consolidated_html::render(self)
    }
}

/// Lit un `Vec<T>` JSON sous une clé réservée du store, ou un vecteur vide si la
/// clé est absente (rapport **valide mais sobre**, comme le socle N1).
fn read_vec<T: DeserializeOwned>(
    store: &dyn EngagementStore,
    key: &str,
) -> Result<Vec<T>, ReportError> {
    match store.get_result(key)? {
        Some(payload) => Ok(serde_json::from_str(&payload)?),
        None => Ok(Vec::new()),
    }
}

/// Carte vide (aucune donnée de recon persistée).
fn empty_map() -> NetworkMap {
    NetworkMap {
        scope_network: String::new(),
        hosts: Vec::new(),
        pivots: Vec::new(),
    }
}

/// Construit un [`ConsolidatedReport`] reproductible à partir de l'état d'un
/// engagement, via les **clés de résultat réservées** : N1 ([`NETWORK_MAP_KEY`],
/// [`FINDINGS_KEY`]), N2 ([`EXPLOITS_KEY`]), N3 ([`CRACKING_KEY`]) et N4
/// ([`EXECUTIONS_KEY`]). Chaque clé absente donne une section vide. `catalog`
/// annote la matrice ATT&CK (p. ex. [`TechniqueCatalog::embedded`]).
pub fn load_consolidated_from_store(
    store: &dyn EngagementStore,
    engagement: &str,
    tool: &str,
    generated_at: DateTime<Utc>,
    catalog: &TechniqueCatalog,
) -> Result<ConsolidatedReport, ReportError> {
    let network = match store.get_result(NETWORK_MAP_KEY)? {
        Some(payload) => serde_json::from_str(&payload)?,
        None => empty_map(),
    };
    let findings: Vec<Finding> = read_vec(store, FINDINGS_KEY)?;
    let exploits: Vec<ExploitAttempt> = read_vec(store, EXPLOITS_KEY)?;
    let cracking: Vec<CrackResult> = read_vec(store, CRACKING_KEY)?;
    let executions: Vec<AttackExecution> = read_vec(store, EXECUTIONS_KEY)?;

    let mut operations = Vec::new();
    for op in store.operations()? {
        operations.push(OperationView::from(op));
    }
    let usage = UsageView::from(store.usage()?);

    let meta = ReportMeta {
        tool: tool.to_string(),
        engagement: engagement.to_string(),
        level: LEVEL_CONSOLIDATED.to_string(),
        generated_at,
    };
    let inputs = ConsolidatedInputs {
        network,
        findings,
        operations,
        usage,
        exploits,
        cracking,
        executions,
    };
    Ok(ConsolidatedReport::new(meta, inputs, catalog))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use chrono::TimeZone;
    use nickmare_core::model::{
        AdversaryProfile, ExploitMode, Host, HostRole, OsGuess, PivotLink, Port, PortState, Proto,
        Service, Severity,
    };

    fn ip(addr: &str) -> IpAddr {
        addr.parse().expect("ip de test")
    }

    fn at(minute: u32, second: u32) -> DateTime<Utc> {
        let dt = Utc.with_ymd_and_hms(2026, 6, 1, 12, minute, second);
        dt.single().expect("horodatage de test")
    }

    fn catalog() -> TechniqueCatalog {
        TechniqueCatalog::embedded().expect("catalogue embarqué")
    }

    fn server() -> Host {
        Host {
            ip: ip("192.168.1.10"),
            mac: None,
            hostname: Some("srv.local".to_string()),
            os_guess: Some(OsGuess::Linux),
            ports: vec![Port {
                number: 445,
                proto: Proto::Tcp,
                state: PortState::Open,
                service: Some(Service {
                    name: "smb".to_string(),
                    product: Some("Samba".to_string()),
                    version: None,
                    banner: None,
                }),
            }],
            role: HostRole::Server,
            compromised: true,
            first_seen: at(0, 0),
        }
    }

    fn network() -> NetworkMap {
        NetworkMap {
            scope_network: "192.168.1.0/24".to_string(),
            hosts: vec![server()],
            pivots: vec![PivotLink {
                from: ip("192.168.1.10"),
                to: ip("192.168.1.20"),
                via: "smb".to_string(),
                at: at(5, 0),
            }],
        }
    }

    fn findings() -> Vec<Finding> {
        vec![Finding {
            host: ip("192.168.1.10"),
            port: Some(445),
            severity: Severity::High,
            cve: Some("CVE-2017-0144".to_string()),
            title: "SMBv1 exposé".to_string(),
            description: "Service SMBv1 actif.".to_string(),
            recommendation: "Désactiver SMBv1.".to_string(),
        }]
    }

    fn exploits() -> Vec<ExploitAttempt> {
        vec![
            ExploitAttempt {
                host: ip("192.168.1.10"),
                cve: Some("CVE-2017-0144".to_string()),
                module: "exploit/windows/smb/ms17_010".to_string(),
                mode: ExploitMode::Exploit,
                confirmed_by: "operateur".to_string(),
                outcome: ExploitOutcome::Success,
                evidence: Some("session obtenue".to_string()),
            },
            ExploitAttempt {
                host: ip("192.168.1.11"),
                cve: None,
                module: "exploit/linux/http/sample".to_string(),
                mode: ExploitMode::Validate,
                confirmed_by: "operateur".to_string(),
                outcome: ExploitOutcome::NotVulnerable,
                evidence: None,
            },
        ]
    }

    fn cracking() -> Vec<CrackResult> {
        vec![CrackResult {
            source: "dump NTDS".to_string(),
            hash_type: "NTLM".to_string(),
            attempted: 100,
            cracked: 60,
            weak_patterns: vec!["mot du dico + année".to_string()],
            policy_verdict: PolicyVerdict::NonCompliant,
        }]
    }

    fn executions() -> Vec<AttackExecution> {
        vec![
            AttackExecution {
                technique_id: "T1021".to_string(),
                host: ip("192.168.1.10"),
                profile: AdversaryProfile::Stealth,
                performed_at: at(10, 0),
                detection: DetectionVerdict::Detected,
                detected_at: Some(at(10, 30)),
                detected_by: Some("EDR".to_string()),
                notes: None,
            },
            AttackExecution {
                technique_id: "T1046".to_string(),
                host: ip("192.168.1.10"),
                profile: AdversaryProfile::Noisy,
                performed_at: at(11, 0),
                detection: DetectionVerdict::NotDetected,
                detected_at: None,
                detected_by: None,
                notes: None,
            },
        ]
    }

    fn inputs() -> ConsolidatedInputs {
        ConsolidatedInputs {
            network: network(),
            findings: findings(),
            operations: Vec::new(),
            usage: UsageView::default(),
            exploits: exploits(),
            cracking: cracking(),
            executions: executions(),
        }
    }

    fn meta() -> ReportMeta {
        ReportMeta {
            tool: "nickmare 0.2.0".to_string(),
            engagement: "acme".to_string(),
            level: LEVEL_CONSOLIDATED.to_string(),
            generated_at: at(0, 0),
        }
    }

    fn report() -> ConsolidatedReport {
        ConsolidatedReport::new(meta(), inputs(), &catalog())
    }

    #[test]
    fn resume_agrege_tous_les_niveaux() {
        let summary = report().summary;
        // N1.
        assert_eq!(summary.host_count, 1);
        assert_eq!(summary.compromised_count, 1);
        assert_eq!(summary.pivot_count, 1);
        assert_eq!(summary.finding_count, 1);
        // N2 : 2 tentatives, 1 confirmée (Success).
        assert_eq!(summary.exploit_attempts, 2);
        assert_eq!(summary.exploits_confirmed, 1);
        // N3 : 60/100 craqués, verdict le pire = non-compliant.
        assert_eq!(summary.hashes_attempted, 100);
        assert_eq!(summary.hashes_cracked, 60);
        assert!((summary.crack_rate - 0.6).abs() < 1e-9);
        assert_eq!(summary.policy_verdict, "non-compliant");
        // N4 : 2 techniques, 1 détectée sur 2 → 0.5.
        assert_eq!(summary.techniques_emitted, 2);
        assert!((summary.detection_rate - 0.5).abs() < 1e-9);
        assert_eq!(summary.mean_mttd_seconds, Some(30));
    }

    #[test]
    fn matrice_couverture_construite_depuis_les_executions() {
        let report = report();
        assert_eq!(report.coverage.len(), 2);

        // T1021 est au catalogue embarqué → nom résolu (pas « inconnue »).
        let cells = &report.coverage.cells;
        let found = cells.iter().find(|c| c.technique_id == "T1021");
        let cell = found.expect("cellule T1021");
        assert_ne!(cell.technique_name, "(inconnue du catalogue)");
        assert_eq!(cell.mttd_seconds, Some(30));

        // Comparaison de profils : noisy et stealth présents, balanced absent.
        let mut profils = Vec::new();
        for stats in &report.profile_comparison {
            profils.push(stats.profile);
        }
        assert!(profils.contains(&AdversaryProfile::Noisy));
        assert!(profils.contains(&AdversaryProfile::Stealth));
        assert!(!profils.contains(&AdversaryProfile::Balanced));
    }

    #[test]
    fn timeline_ordonnee_et_correle_action_detection() {
        let report = report();
        let events = &report.timeline;
        // Pivot (05:00), T1021 émise (10:00), détection (10:30), T1046 émise (11:00).
        assert_eq!(events.len(), 4);
        let ordered = events.windows(2).all(|w| w[0].at <= w[1].at);
        assert!(ordered, "timeline triée par horodatage");

        // Ordre chronologique et corrélation action ↔ détection (même technique).
        assert_eq!(events[0].phase, "pivot");
        assert_eq!(events[1].phase, "emulation");
        assert_eq!(events[1].label, "T1021");
        assert_eq!(events[2].phase, "detection");
        assert_eq!(events[2].origin, "siem");
        assert_eq!(events[1].correlation, events[2].correlation);
        assert_eq!(events[3].label, "T1046");

        // T1046 (non détectée) ne produit aucun évènement de détection.
        let detections = events.iter().filter(|e| e.phase == "detection").count();
        assert_eq!(detections, 1);
    }

    #[test]
    fn json_round_trip_identite() {
        let report = report();
        let json = report.to_json().expect("export JSON");
        let back = ConsolidatedReport::from_json(&json).expect("relecture JSON");
        assert_eq!(report, back);
    }

    #[test]
    fn export_reproductible() {
        let a = report();
        let b = report();
        assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
        assert_eq!(a.to_html().unwrap(), b.to_html().unwrap());
    }

    #[test]
    fn section_vides_restent_valides() {
        let inputs = ConsolidatedInputs {
            network: empty_map(),
            findings: Vec::new(),
            operations: Vec::new(),
            usage: UsageView::default(),
            exploits: Vec::new(),
            cracking: Vec::new(),
            executions: Vec::new(),
        };
        let report = ConsolidatedReport::new(meta(), inputs, &catalog());
        assert_eq!(report.summary.policy_verdict, "unknown");
        assert_eq!(report.summary.mean_mttd_seconds, None);
        assert!(report.timeline.is_empty());
        assert!(report.to_json().is_ok());
        assert!(report.to_html().is_ok());
    }
}
