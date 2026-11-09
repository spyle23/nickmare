//! Rendu **HTML** du rapport consolidé N1→N4 (issue #23, US-H1), via le template
//! `askama` compilé et typé (`templates/consolidated.html`).
//!
//! Comme pour le socle ([`crate::html`]), on interpose une **vue de présentation**
//! ([`ConsolidatedPage`]) entre le [`ConsolidatedReport`] et le template : toutes
//! les valeurs y sont déjà aplaties en chaînes/nombres lisibles. Le template reste
//! purement déclaratif et l'échappement HTML automatique d'`askama` (extension
//! `.html`) neutralise toute injection depuis une bannière, un nom d'hôte, une
//! description de constat ou une note d'émulation (garde-fou §12).
//!
//! # Masquage des secrets
//!
//! La section N3 n'affiche **que** des statistiques tirées de [`CrackResult`] —
//! source, type de hash, nombre tenté/craqué, taux, verdict de politique et
//! patterns faibles (libellés génériques). `CrackResult` ne porte, par
//! construction (§7, `MaskedSecret` de `crates/crack`), **aucun** mot de passe en
//! clair : aucun credential craqué ne peut donc transiter par ce rendu.

use askama::Template;
use nickmare_core::model::{DetectionVerdict, ExploitMode, ExploitOutcome, PolicyVerdict};
use nickmare_emulation::profile::profile_label;

use crate::consolidated::{policy_verdict_key, ConsolidatedReport};
use crate::display::{
    dash, format_service, os_label, port_state_css, port_state_label, proto_label, role_label,
    severity_css, severity_display, severity_label, status_css,
};
use crate::error::ReportError;

/// Page HTML consolidée — structure typée adossée à `templates/consolidated.html`.
#[derive(Template)]
#[template(path = "consolidated.html")]
struct ConsolidatedPage {
    tool: String,
    engagement: String,
    level: String,
    generated_at: String,
    scope_network: String,
    host_total: usize,
    open_services: usize,
    finding_total: usize,
    compromised: usize,
    pivot_total: usize,
    exploit_attempts: usize,
    exploits_confirmed: usize,
    hashes_attempted: u64,
    hashes_cracked: u64,
    crack_rate: String,
    policy_verdict: String,
    policy_verdict_css: String,
    techniques_emitted: usize,
    detection_rate: String,
    mean_mttd: String,
    summary_rows: Vec<SummaryRow>,
    hosts: Vec<HostRow>,
    pivots: Vec<PivotRow>,
    findings: Vec<FindingRow>,
    exploits: Vec<ExploitRow>,
    cracking: Vec<CrackRow>,
    coverage: Vec<CoverageRow>,
    profiles: Vec<ProfileRow>,
    timeline: Vec<TimelineRow>,
    operations: Vec<OperationRow>,
    operation_total: usize,
    usage_actions: u64,
    usage_bytes: u64,
}

/// Ligne du résumé exécutif par gravité.
struct SummaryRow {
    label: String,
    css: String,
    count: usize,
}

/// Ligne d'un hôte de la carte réseau annotée (+ détail de ses ports).
struct HostRow {
    ip: String,
    role: String,
    os: String,
    mac: String,
    hostname: String,
    compromised: bool,
    ports: Vec<PortRow>,
}

/// Ligne d'un port d'un hôte.
struct PortRow {
    number: u16,
    proto: String,
    state: String,
    state_css: String,
    service: String,
}

/// Ligne d'un chemin de pivot (carte annotée : hôtes compromis + pivots).
struct PivotRow {
    from: String,
    to: String,
    via: String,
    at: String,
}

/// Ligne d'un constat (détail par finding + recommandation).
struct FindingRow {
    host: String,
    port: String,
    severity: String,
    severity_css: String,
    cve: String,
    title: String,
    description: String,
    recommendation: String,
}

/// Ligne d'un exploit confirmé (N2).
struct ExploitRow {
    host: String,
    cve: String,
    module: String,
    mode: String,
    outcome: String,
    outcome_css: String,
    confirmed_by: String,
    evidence: String,
}

/// Ligne d'un résultat de craquage (N3) — **statistiques uniquement**.
struct CrackRow {
    source: String,
    hash_type: String,
    attempted: u64,
    cracked: u64,
    rate: String,
    verdict: String,
    verdict_css: String,
    weak_patterns: String,
}

/// Ligne de la matrice de couverture ATT&CK + MTTD (N4).
struct CoverageRow {
    technique_id: String,
    technique_name: String,
    tactic: String,
    profile: String,
    detection: String,
    detection_css: String,
    mttd: String,
    detected_by: String,
}

/// Ligne de la comparaison des taux de détection entre profils (N4).
struct ProfileRow {
    profile: String,
    total: usize,
    detected: usize,
    partial: usize,
    not_detected: usize,
    detection_rate: String,
    mean_mttd: String,
}

/// Ligne de la timeline horodatée (corrélation action ↔ détection SIEM).
struct TimelineRow {
    at: String,
    phase: String,
    origin: String,
    label: String,
    detail: String,
    correlation: String,
}

/// Ligne d'une opération d'engagement.
struct OperationRow {
    key: String,
    kind: String,
    target: String,
    status: String,
    status_css: String,
    started_at: String,
    finished_at: String,
}

/// Rend le rapport consolidé en HTML autonome (feuille de style embarquée, aucun
/// accès réseau au rendu). Toute défaillance de template remonte en [`ReportError`].
pub(crate) fn render(report: &ConsolidatedReport) -> Result<String, ReportError> {
    let page = page_from(report);
    let html = page.render()?;
    Ok(html)
}

/// Construit la vue de présentation à partir du rapport consolidé.
fn page_from(report: &ConsolidatedReport) -> ConsolidatedPage {
    let scope_network = if report.network.scope_network.is_empty() {
        dash()
    } else {
        report.network.scope_network.clone()
    };
    let (policy_verdict, policy_verdict_css) = policy_display(&report.summary.policy_verdict);

    ConsolidatedPage {
        tool: report.meta.tool.clone(),
        engagement: report.meta.engagement.clone(),
        level: report.meta.level.clone(),
        generated_at: report.meta.generated_at.to_rfc3339(),
        scope_network,
        host_total: report.summary.host_count,
        open_services: report.summary.open_service_count,
        finding_total: report.summary.finding_count,
        compromised: report.summary.compromised_count,
        pivot_total: report.summary.pivot_count,
        exploit_attempts: report.summary.exploit_attempts,
        exploits_confirmed: report.summary.exploits_confirmed,
        hashes_attempted: report.summary.hashes_attempted,
        hashes_cracked: report.summary.hashes_cracked,
        crack_rate: percent(report.summary.crack_rate),
        policy_verdict: policy_verdict.to_string(),
        policy_verdict_css: policy_verdict_css.to_string(),
        techniques_emitted: report.summary.techniques_emitted,
        detection_rate: percent(report.summary.detection_rate),
        mean_mttd: mttd_label(report.summary.mean_mttd_seconds),
        summary_rows: summary_rows(report),
        hosts: host_rows(report),
        pivots: pivot_rows(report),
        findings: finding_rows(report),
        exploits: exploit_rows(report),
        cracking: crack_rows(report),
        coverage: coverage_rows(report),
        profiles: profile_rows(report),
        timeline: timeline_rows(report),
        operations: operation_rows(report),
        operation_total: report.operations.len(),
        usage_actions: report.usage.actions,
        usage_bytes: report.usage.bytes,
    }
}

fn summary_rows(report: &ConsolidatedReport) -> Vec<SummaryRow> {
    let mut rows = Vec::new();
    for entry in &report.summary.findings_by_severity {
        let (label, css) = severity_display(&entry.severity);
        rows.push(SummaryRow {
            label: label.to_string(),
            css: css.to_string(),
            count: entry.count,
        });
    }
    rows
}

fn host_rows(report: &ConsolidatedReport) -> Vec<HostRow> {
    let mut hosts = Vec::new();
    for host in &report.network.hosts {
        let mut ports = Vec::new();
        for port in &host.ports {
            let service = match &port.service {
                Some(svc) => format_service(svc),
                None => String::new(),
            };
            ports.push(PortRow {
                number: port.number,
                proto: proto_label(port.proto).to_string(),
                state: port_state_label(port.state).to_string(),
                state_css: port_state_css(port.state).to_string(),
                service,
            });
        }
        hosts.push(HostRow {
            ip: host.ip.to_string(),
            role: role_label(host.role).to_string(),
            os: os_label(host.os_guess.as_ref()),
            mac: host.mac.map(|m| m.to_string()).unwrap_or_else(dash),
            hostname: host.hostname.clone().unwrap_or_else(dash),
            compromised: host.compromised,
            ports,
        });
    }
    hosts
}

fn pivot_rows(report: &ConsolidatedReport) -> Vec<PivotRow> {
    let mut pivots = Vec::new();
    for pivot in &report.network.pivots {
        pivots.push(PivotRow {
            from: pivot.from.to_string(),
            to: pivot.to.to_string(),
            via: pivot.via.clone(),
            at: pivot.at.to_rfc3339(),
        });
    }
    pivots
}

fn finding_rows(report: &ConsolidatedReport) -> Vec<FindingRow> {
    let mut findings = Vec::new();
    for finding in &report.findings {
        let port = match finding.port {
            Some(number) => number.to_string(),
            None => dash(),
        };
        findings.push(FindingRow {
            host: finding.host.to_string(),
            port,
            severity: severity_label(finding.severity).to_string(),
            severity_css: severity_css(finding.severity).to_string(),
            cve: finding.cve.clone().unwrap_or_else(dash),
            title: finding.title.clone(),
            description: finding.description.clone(),
            recommendation: finding.recommendation.clone(),
        });
    }
    findings
}

fn exploit_rows(report: &ConsolidatedReport) -> Vec<ExploitRow> {
    let mut exploits = Vec::new();
    for attempt in &report.exploits {
        exploits.push(ExploitRow {
            host: attempt.host.to_string(),
            cve: attempt.cve.clone().unwrap_or_else(dash),
            module: attempt.module.clone(),
            mode: exploit_mode_label(attempt.mode).to_string(),
            outcome: exploit_outcome_label(attempt.outcome).to_string(),
            outcome_css: exploit_outcome_css(attempt.outcome).to_string(),
            confirmed_by: attempt.confirmed_by.clone(),
            evidence: attempt.evidence.clone().unwrap_or_else(dash),
        });
    }
    exploits
}

fn crack_rows(report: &ConsolidatedReport) -> Vec<CrackRow> {
    let mut rows = Vec::new();
    for result in &report.cracking {
        let rate = if result.attempted == 0 {
            0.0
        } else {
            result.cracked as f64 / result.attempted as f64
        };
        let weak_patterns = if result.weak_patterns.is_empty() {
            dash()
        } else {
            result.weak_patterns.join(", ")
        };
        rows.push(CrackRow {
            source: result.source.clone(),
            hash_type: result.hash_type.clone(),
            attempted: result.attempted,
            cracked: result.cracked,
            rate: percent(rate),
            verdict: policy_label(result.policy_verdict).to_string(),
            verdict_css: policy_css(result.policy_verdict).to_string(),
            weak_patterns,
        });
    }
    rows
}

fn coverage_rows(report: &ConsolidatedReport) -> Vec<CoverageRow> {
    let mut rows = Vec::new();
    for cell in &report.coverage.cells {
        rows.push(CoverageRow {
            technique_id: cell.technique_id.clone(),
            technique_name: cell.technique_name.clone(),
            tactic: cell.tactic.clone(),
            profile: profile_label(cell.profile).to_string(),
            detection: detection_label(cell.detection).to_string(),
            detection_css: detection_css(cell.detection).to_string(),
            mttd: mttd_label(cell.mttd_seconds),
            detected_by: cell.detected_by.clone().unwrap_or_else(dash),
        });
    }
    rows
}

fn profile_rows(report: &ConsolidatedReport) -> Vec<ProfileRow> {
    let mut rows = Vec::new();
    for stats in &report.profile_comparison {
        rows.push(ProfileRow {
            profile: profile_label(stats.profile).to_string(),
            total: stats.total,
            detected: stats.detected,
            partial: stats.partial,
            not_detected: stats.not_detected,
            detection_rate: percent(stats.detection_rate),
            mean_mttd: mttd_label(stats.mean_mttd_seconds),
        });
    }
    rows
}

fn timeline_rows(report: &ConsolidatedReport) -> Vec<TimelineRow> {
    let mut rows = Vec::new();
    for event in &report.timeline {
        rows.push(TimelineRow {
            at: event.at.to_rfc3339(),
            phase: event.phase.clone(),
            origin: event.origin.clone(),
            label: event.label.clone(),
            detail: event.detail.clone(),
            correlation: event.correlation.clone().unwrap_or_else(dash),
        });
    }
    rows
}

fn operation_rows(report: &ConsolidatedReport) -> Vec<OperationRow> {
    let mut operations = Vec::new();
    for op in &report.operations {
        let finished = match &op.finished_at {
            Some(ts) => ts.to_rfc3339(),
            None => dash(),
        };
        operations.push(OperationRow {
            key: op.key.clone(),
            kind: op.kind.clone(),
            target: op.target.clone(),
            status: op.status.clone(),
            status_css: status_css(&op.status).to_string(),
            started_at: op.started_at.to_rfc3339(),
            finished_at: finished,
        });
    }
    operations
}

/// Formate un taux (0.0..=1.0) en pourcentage à une décimale.
fn percent(rate: f64) -> String {
    format!("{:.1} %", rate * 100.0)
}

/// Libellé d'un MTTD en secondes, ou tiret si absent.
fn mttd_label(seconds: Option<i64>) -> String {
    match seconds {
        Some(value) => format!("{value} s"),
        None => dash(),
    }
}

/// Libellé français d'un mode d'exploitation.
fn exploit_mode_label(mode: ExploitMode) -> &'static str {
    match mode {
        ExploitMode::Validate => "validation",
        ExploitMode::Exploit => "exploit",
    }
}

/// Libellé français d'une issue d'exploitation.
fn exploit_outcome_label(outcome: ExploitOutcome) -> &'static str {
    match outcome {
        ExploitOutcome::Vulnerable => "vulnérable",
        ExploitOutcome::NotVulnerable => "non vulnérable",
        ExploitOutcome::Success => "réussi",
        ExploitOutcome::Failed => "échoué",
    }
}

/// Classe CSS d'une issue d'exploitation (confirmée vs. négative).
fn exploit_outcome_css(outcome: ExploitOutcome) -> &'static str {
    match outcome {
        ExploitOutcome::Vulnerable | ExploitOutcome::Success => "exp-confirmed",
        ExploitOutcome::NotVulnerable | ExploitOutcome::Failed => "exp-negative",
    }
}

/// Libellé français d'un verdict de politique (depuis l'enum).
fn policy_label(verdict: PolicyVerdict) -> &'static str {
    policy_display(policy_verdict_key(verdict)).0
}

/// Classe CSS d'un verdict de politique (depuis l'enum).
fn policy_css(verdict: PolicyVerdict) -> &'static str {
    policy_display(policy_verdict_key(verdict)).1
}

/// Libellé + classe CSS d'un verdict de politique depuis sa clé stable.
fn policy_display(key: &str) -> (&'static str, &'static str) {
    match key {
        "compliant" => ("conforme", "pol-compliant"),
        "weak" => ("faible", "pol-weak"),
        "non-compliant" => ("non conforme", "pol-noncompliant"),
        _ => ("inconnu", "pol-unknown"),
    }
}

/// Libellé français d'un verdict de détection.
fn detection_label(verdict: DetectionVerdict) -> &'static str {
    match verdict {
        DetectionVerdict::Detected => "détecté",
        DetectionVerdict::NotDetected => "non détecté",
        DetectionVerdict::Partial => "partiel",
        DetectionVerdict::Unknown => "inconnu",
    }
}

/// Classe CSS d'un verdict de détection.
fn detection_css(verdict: DetectionVerdict) -> &'static str {
    match verdict {
        DetectionVerdict::Detected => "det-detected",
        DetectionVerdict::NotDetected => "det-notdetected",
        DetectionVerdict::Partial => "det-partial",
        DetectionVerdict::Unknown => "det-unknown",
    }
}
