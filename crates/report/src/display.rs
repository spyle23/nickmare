//! Helpers de **présentation** partagés par les deux rendus HTML (le socle N1,
//! module [`crate::html`], et le rapport consolidé N1→N4, module
//! [`crate::consolidated_html`]).
//!
//! Ces fonctions aplatissent les types du modèle en chaînes/libellés français
//! déjà prêts pour le template, afin que les templates `askama` restent purement
//! déclaratifs. L'échappement HTML automatique (`.html`) reste assuré par
//! `askama` au rendu — ces helpers ne produisent que du texte neutre.

use nickmare_core::model::{HostRole, OsGuess, PortState, Proto, Service, Severity};

/// Placeholder « valeur absente ».
pub(crate) fn dash() -> String {
    "—".to_string()
}

/// Libellé compact d'un service : `nom (produit version)`.
pub(crate) fn format_service(service: &Service) -> String {
    let mut line = service.name.clone();
    match (service.product.as_deref(), service.version.as_deref()) {
        (Some(product), Some(version)) => line.push_str(&format!(" ({product} {version})")),
        (Some(product), None) => line.push_str(&format!(" ({product})")),
        (None, Some(version)) => line.push_str(&format!(" (v{version})")),
        (None, None) => {}
    }
    line
}

/// Libellé français du rôle présumé.
pub(crate) fn role_label(role: HostRole) -> &'static str {
    match role {
        HostRole::Gateway => "passerelle",
        HostRole::Server => "serveur",
        HostRole::Workstation => "poste",
        HostRole::Unknown => "rôle inconnu",
    }
}

/// Libellé lisible de l'OS présumé.
pub(crate) fn os_label(os: Option<&OsGuess>) -> String {
    match os {
        None => "OS inconnu".to_string(),
        Some(OsGuess::Linux) => "Linux".to_string(),
        Some(OsGuess::Windows) => "Windows".to_string(),
        Some(OsGuess::MacOs) => "macOS".to_string(),
        Some(OsGuess::Bsd) => "BSD".to_string(),
        Some(OsGuess::Android) => "Android".to_string(),
        Some(OsGuess::Ios) => "iOS".to_string(),
        Some(OsGuess::NetworkDevice) => "équipement réseau".to_string(),
        Some(OsGuess::Other(label)) => label.clone(),
    }
}

/// Libellé français d'un état de port.
pub(crate) fn port_state_label(state: PortState) -> &'static str {
    match state {
        PortState::Open => "ouvert",
        PortState::Closed => "fermé",
        PortState::Filtered => "filtré",
    }
}

/// Classe CSS d'un état de port.
pub(crate) fn port_state_css(state: PortState) -> &'static str {
    match state {
        PortState::Open => "port-open",
        PortState::Closed => "port-closed",
        PortState::Filtered => "port-filtered",
    }
}

/// Libellé d'un protocole de port.
pub(crate) fn proto_label(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

/// Libellé français d'une gravité de constat.
pub(crate) fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "faible",
        Severity::Medium => "moyen",
        Severity::High => "élevé",
        Severity::Critical => "critique",
    }
}

/// Classe CSS d'une gravité de constat.
pub(crate) fn severity_css(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "sev-info",
        Severity::Low => "sev-low",
        Severity::Medium => "sev-medium",
        Severity::High => "sev-high",
        Severity::Critical => "sev-critical",
    }
}

/// Libellé + classe CSS d'une gravité à partir de sa clé stable (résumé).
pub(crate) fn severity_display(key: &str) -> (&'static str, &'static str) {
    match key {
        "critical" => ("critique", "sev-critical"),
        "high" => ("élevé", "sev-high"),
        "medium" => ("moyen", "sev-medium"),
        "low" => ("faible", "sev-low"),
        _ => ("info", "sev-info"),
    }
}

/// Classe CSS d'un statut d'opération persisté.
pub(crate) fn status_css(status: &str) -> &'static str {
    match status {
        "done" => "op-done",
        "incomplete" => "op-incomplete",
        _ => "op-pending",
    }
}
