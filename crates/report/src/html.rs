//! Rendu **HTML** du rapport Niveau 1 (US-H1), via les templates `askama`
//! compilés et typés (`templates/report.html`).
//!
//! On interpose une **vue de présentation** (`ReportPage` et ses lignes) entre le
//! [`ReportModel`] et le template : toutes les valeurs y sont déjà aplaties en
//! chaînes/nombres lisibles (libellés français des rôles, gravités, états de
//! port…). Le template reste ainsi purement déclaratif, et l'échappement HTML
//! automatique d'`askama` (extension `.html`) neutralise toute injection depuis
//! une bannière, un nom d'hôte ou une description de constat (garde-fou §12).

use askama::Template;

use crate::display::{
    dash, format_service, os_label, port_state_css, port_state_label, proto_label, role_label,
    severity_css, severity_display, severity_label, status_css,
};
use crate::error::ReportError;
use crate::model::ReportModel;

/// Page HTML complète — structure typée adossée à `templates/report.html`.
#[derive(Template)]
#[template(path = "report.html")]
struct ReportPage {
    tool: String,
    engagement: String,
    level: String,
    generated_at: String,
    scope_network: String,
    host_total: usize,
    open_services: usize,
    compromised: usize,
    pivot_total: usize,
    finding_total: usize,
    operation_total: usize,
    summary_rows: Vec<SummaryRow>,
    hosts: Vec<HostRow>,
    pivots: Vec<PivotRow>,
    findings: Vec<FindingRow>,
    operations: Vec<OperationRow>,
    usage_actions: u64,
    usage_bytes: u64,
}

/// Ligne du résumé exécutif : une gravité, son libellé, sa classe CSS, son total.
struct SummaryRow {
    label: String,
    css: String,
    count: usize,
}

/// Ligne d'un hôte de la carte réseau (+ détail de ses ports).
struct HostRow {
    ip: String,
    role: String,
    os: String,
    mac: String,
    hostname: String,
    compromised: bool,
    ports: Vec<PortRow>,
}

/// Ligne d'un port d'un hôte (détail).
struct PortRow {
    number: u16,
    proto: String,
    state: String,
    state_css: String,
    service: String,
}

/// Ligne d'un chemin de pivot (vide en N1, présent pour l'agrégation).
struct PivotRow {
    from: String,
    to: String,
    via: String,
    at: String,
}

/// Ligne d'un constat (détail par finding).
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

/// Ligne d'une opération d'engagement (état de run reproductible).
struct OperationRow {
    key: String,
    kind: String,
    target: String,
    status: String,
    status_css: String,
    started_at: String,
    finished_at: String,
}

/// Rend le rapport en HTML autonome (feuille de style embarquée, aucun accès
/// réseau au rendu). Toute défaillance de template remonte en [`ReportError`].
pub(crate) fn render(model: &ReportModel) -> Result<String, ReportError> {
    let page = page_from(model);
    let html = page.render()?;
    Ok(html)
}

/// Construit la vue de présentation à partir du modèle agrégé.
fn page_from(model: &ReportModel) -> ReportPage {
    let scope_network = if model.network.scope_network.is_empty() {
        "—".to_string()
    } else {
        model.network.scope_network.clone()
    };

    let mut summary_rows = Vec::new();
    for entry in &model.summary.findings_by_severity {
        let (label, css) = severity_display(&entry.severity);
        summary_rows.push(SummaryRow {
            label: label.to_string(),
            css: css.to_string(),
            count: entry.count,
        });
    }

    let mut hosts = Vec::new();
    for host in &model.network.hosts {
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

    let mut pivots = Vec::new();
    for pivot in &model.network.pivots {
        pivots.push(PivotRow {
            from: pivot.from.to_string(),
            to: pivot.to.to_string(),
            via: pivot.via.clone(),
            at: pivot.at.to_rfc3339(),
        });
    }

    let mut findings = Vec::new();
    for finding in &model.findings {
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

    let mut operations = Vec::new();
    for op in &model.operations {
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

    ReportPage {
        tool: model.meta.tool.clone(),
        engagement: model.meta.engagement.clone(),
        level: model.meta.level.clone(),
        generated_at: model.meta.generated_at.to_rfc3339(),
        scope_network,
        host_total: model.summary.host_count,
        open_services: model.summary.open_service_count,
        compromised: model.summary.compromised_count,
        pivot_total: model.summary.pivot_count,
        finding_total: model.summary.finding_count,
        operation_total: model.operations.len(),
        summary_rows,
        hosts,
        pivots,
        findings,
        operations,
        usage_actions: model.usage.actions,
        usage_bytes: model.usage.bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use chrono::{DateTime, Utc};
    use nickmare_core::model::{
        Finding, Host, HostRole, NetworkMap, OsGuess, Port, PortState, Proto, Service, Severity,
    };

    use crate::model::{ReportMeta, ReportModel, UsageView};

    fn ip(addr: &str) -> IpAddr {
        addr.parse().expect("ip de test")
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("horodatage de test")
    }

    fn host_with_hostname(hostname: &str) -> Host {
        Host {
            ip: ip("192.168.1.10"),
            mac: None,
            hostname: Some(hostname.to_string()),
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

    fn model_with(host: Host, findings: Vec<Finding>) -> ReportModel {
        let network = NetworkMap {
            scope_network: "192.168.1.0/24".to_string(),
            hosts: vec![host],
            pivots: Vec::new(),
        };
        let meta = ReportMeta {
            tool: "nickmare 0.2.0".to_string(),
            engagement: "acme".to_string(),
            level: "N1".to_string(),
            generated_at: ts(0),
        };
        ReportModel::new(meta, network, findings, Vec::new(), UsageView::default())
    }

    #[test]
    fn rend_le_resume_la_carte_et_les_findings() {
        let finding = Finding {
            host: ip("192.168.1.10"),
            port: Some(445),
            severity: Severity::High,
            cve: Some("CVE-2017-0144".to_string()),
            title: "SMBv1 exposé".to_string(),
            description: "Service SMBv1 actif.".to_string(),
            recommendation: "Désactiver SMBv1.".to_string(),
        };
        let html = model_with(host_with_hostname("srv.local"), vec![finding])
            .to_html()
            .expect("rendu HTML");

        // Structure HTML de base.
        assert!(html.contains("<!DOCTYPE html>"), "{html}");
        assert!(html.to_lowercase().contains("<html"), "{html}");
        // Résumé exécutif + niveau N1.
        assert!(html.contains("Résumé exécutif"), "{html}");
        assert!(html.contains("N1"), "{html}");
        // Carte réseau présente (DoD).
        assert!(html.contains("Carte réseau"), "{html}");
        assert!(html.contains("192.168.1.0/24"), "{html}");
        assert!(html.contains("srv.local"), "{html}");
        assert!(html.contains("192.168.1.10"), "{html}");
        assert!(html.contains("ssh"), "{html}");
        // Détail du constat.
        assert!(html.contains("SMBv1 exposé"), "{html}");
        assert!(html.contains("CVE-2017-0144"), "{html}");
        assert!(html.contains("Désactiver SMBv1."), "{html}");
    }

    #[test]
    fn echappe_le_html_des_entrees_hostiles() {
        // Un nom d'hôte piégé ne doit jamais produire de balise active : askama
        // échappe les `.html`. Garde-fou anti-injection (§12).
        let html = model_with(host_with_hostname("<script>alert(1)</script>"), Vec::new())
            .to_html()
            .expect("rendu HTML");
        assert!(!html.contains("<script>alert(1)</script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
    }

    #[test]
    fn carte_vide_est_rendue_sans_paniquer() {
        let network = NetworkMap {
            scope_network: String::new(),
            hosts: Vec::new(),
            pivots: Vec::new(),
        };
        let meta = ReportMeta {
            tool: "nickmare 0.2.0".to_string(),
            engagement: "vide".to_string(),
            level: "N1".to_string(),
            generated_at: ts(0),
        };
        let html = ReportModel::new(meta, network, Vec::new(), Vec::new(), UsageView::default())
            .to_html()
            .expect("rendu HTML");
        assert!(html.contains("Carte réseau"), "{html}");
        assert!(html.contains("<!DOCTYPE html>"), "{html}");
    }

    #[test]
    fn rendu_html_est_reproductible() {
        let model = model_with(host_with_hostname("srv.local"), Vec::new());
        assert_eq!(model.to_html().unwrap(), model.to_html().unwrap());
    }
}
