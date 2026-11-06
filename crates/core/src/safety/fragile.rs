//! Détection de services fragiles (issue #26, cf. `docs/ARCHITECTURE.md` §11.1).
//!
//! Certains équipements se cassent — ou interrompent un service vital — à la
//! moindre sonde agressive : automates industriels (SCADA/ICS), imprimantes,
//! équipements médicaux, vieux agents SNMP. Avant toute interaction active
//! soutenue, on les **repère** (par port bien connu, à défaut par bannière) et
//! on en **bride l'interaction** : interaction minimale, voire refus pur et
//! simple, le tout **journalisé** (via [`crate::audit`]).
//!
//! La détection est **pure** : à partir d'un numéro de port et d'un éventuel
//! service identifié, elle rend un verdict déterministe, sans toucher au réseau.
//! C'est l'orchestrateur qui, au vu de la [`InteractionPolicy`], émet ou non
//! l'action et journalise l'[`Assessment`].

use crate::audit::{AuditRecord, CapabilityLevel};
use crate::model::{Port, Service};

/// Famille d'équipement fragile reconnue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragileCategory {
    /// Automate / supervision industrielle (Modbus, S7, DNP3, BACnet, CIP…).
    ScadaIcs,
    /// Imprimante réseau (JetDirect/raw, LPD, IPP).
    Printer,
    /// Équipement médical (DICOM, HL7).
    Medical,
    /// Agent SNMP ancien (v1/v2c), réputé instable sous charge.
    LegacySnmp,
}

impl FragileCategory {
    /// Libellé lisible de la famille.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            FragileCategory::ScadaIcs => "SCADA/ICS",
            FragileCategory::Printer => "imprimante",
            FragileCategory::Medical => "équipement médical",
            FragileCategory::LegacySnmp => "SNMP ancien (v1/v2c)",
        }
    }

    /// Politique d'interaction imposée par la famille (fail-safe : au doute, on
    /// bride). SCADA/ICS et médical sont **refusés** par défaut (casser une
    /// chaîne de production ou un équipement de soin est inacceptable) ;
    /// imprimantes et vieux SNMP sont limités à une **interaction minimale**.
    #[must_use]
    pub fn policy(self) -> InteractionPolicy {
        match self {
            FragileCategory::ScadaIcs | FragileCategory::Medical => InteractionPolicy::Refuse,
            FragileCategory::Printer | FragileCategory::LegacySnmp => {
                InteractionPolicy::MinimalOnly
            }
        }
    }
}

/// Niveau d'interaction autorisé face à un service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionPolicy {
    /// Interaction normale permise (service non fragile).
    Normal,
    /// Interaction **minimale** seulement (sonde légère, pas d'action soutenue).
    MinimalOnly,
    /// Aucune interaction active : refus.
    Refuse,
}

impl InteractionPolicy {
    /// Résultat journalisé correspondant (`ok` / `minimal` / `refused`).
    #[must_use]
    pub fn audit_result(self) -> &'static str {
        match self {
            InteractionPolicy::Normal => "ok",
            InteractionPolicy::MinimalOnly => "minimal",
            InteractionPolicy::Refuse => "refused",
        }
    }

    /// Vrai si la politique interdit toute interaction active.
    #[must_use]
    pub fn forbids_active(self) -> bool {
        matches!(self, InteractionPolicy::Refuse)
    }
}

/// Verdict de fragilité : famille détectée, politique imposée et justification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub category: FragileCategory,
    pub policy: InteractionPolicy,
    pub rationale: String,
}

impl Assessment {
    fn new(category: FragileCategory, rationale: impl Into<String>) -> Self {
        Self {
            category,
            policy: category.policy(),
            rationale: rationale.into(),
        }
    }

    /// Entrée d'audit du repérage : action `safety.fragile_detected`, résultat
    /// reflétant la politique (`refused` / `minimal`). Toujours journalisé.
    #[must_use]
    pub fn audit_record(
        &self,
        target: impl Into<String>,
        operator: impl Into<String>,
        level: CapabilityLevel,
    ) -> AuditRecord {
        AuditRecord::new(
            operator,
            target,
            "safety.fragile_detected",
            self.policy.audit_result(),
            level,
        )
    }
}

/// Évalue la fragilité d'un service à partir de son **numéro de port** et, à
/// défaut, du service identifié (bannière). Renvoie `None` si rien n'indique un
/// équipement fragile (interaction normale).
#[must_use]
pub fn assess(port: u16, service: Option<&Service>) -> Option<Assessment> {
    if let Some(category) = category_by_port(port) {
        // Un SNMP v3 explicite n'est pas « ancien » : on ne le bride pas.
        if category == FragileCategory::LegacySnmp && snmp_is_v3(service) {
            return None;
        }
        let rationale = format!("port {port} caractéristique : {}", category.label());
        return Some(Assessment::new(category, rationale));
    }
    if let Some(category) = category_by_banner(service) {
        let rationale = format!("bannière caractéristique : {}", category.label());
        return Some(Assessment::new(category, rationale));
    }
    None
}

/// Variante prenant un [`Port`] déjà scanné (numéro + service identifié).
#[must_use]
pub fn assess_port(port: &Port) -> Option<Assessment> {
    assess(port.number, port.service.as_ref())
}

/// Famille déduite du seul numéro de port bien connu.
fn category_by_port(port: u16) -> Option<FragileCategory> {
    match port {
        // Automates / protocoles industriels.
        102 | 502 | 2404 | 20000 | 44818 | 47808 | 1911 | 4911 => Some(FragileCategory::ScadaIcs),
        // Équipements médicaux : DICOM, HL7/MLLP.
        104 | 2575 | 11112 => Some(FragileCategory::Medical),
        // Imprimantes : raw/JetDirect, LPD, IPP.
        515 | 631 | 9100 => Some(FragileCategory::Printer),
        // Agents SNMP (potentiellement anciens).
        161 | 162 => Some(FragileCategory::LegacySnmp),
        _ => None,
    }
}

/// Famille déduite d'une bannière/service identifié, en repli du port.
fn category_by_banner(service: Option<&Service>) -> Option<FragileCategory> {
    let hay = service_haystack(service?);
    const SCADA: [&str; 6] = [
        "modbus",
        "s7comm",
        "siemens s7",
        "dnp3",
        "bacnet",
        "ethernet/ip",
    ];
    const MEDICAL: [&str; 2] = ["dicom", "hl7"];
    const PRINTER: [&str; 4] = ["jetdirect", "laserjet", "printer", "imprimante"];
    if SCADA.iter().any(|needle| hay.contains(needle)) {
        return Some(FragileCategory::ScadaIcs);
    }
    if MEDICAL.iter().any(|needle| hay.contains(needle)) {
        return Some(FragileCategory::Medical);
    }
    if PRINTER.iter().any(|needle| hay.contains(needle)) {
        return Some(FragileCategory::Printer);
    }
    if hay.contains("snmp") && !hay.contains("v3") {
        return Some(FragileCategory::LegacySnmp);
    }
    None
}

/// Vrai si le service identifié se présente explicitement comme SNMP v3.
fn snmp_is_v3(service: Option<&Service>) -> bool {
    service.is_some_and(|svc| service_haystack(svc).contains("v3"))
}

/// Concatène nom/produit/version/bannière en minuscules pour la recherche de
/// mots-clés (défensif : on ne fait que lire des chaînes déjà capturées).
fn service_haystack(service: &Service) -> String {
    let mut hay = service.name.to_lowercase();
    for value in [&service.product, &service.version, &service.banner]
        .into_iter()
        .flatten()
    {
        hay.push(' ');
        hay.push_str(&value.to_lowercase());
    }
    hay
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortState, Proto};

    fn svc(name: &str, version: Option<&str>) -> Service {
        Service {
            name: name.to_string(),
            product: None,
            version: version.map(str::to_string),
            banner: None,
        }
    }

    #[test]
    fn modbus_est_scada_et_refuse() {
        let a = assess(502, None).expect("502 = Modbus");
        assert_eq!(a.category, FragileCategory::ScadaIcs);
        assert_eq!(a.policy, InteractionPolicy::Refuse);
        assert!(a.policy.forbids_active());
    }

    #[test]
    fn dicom_est_medical_et_refuse() {
        let a = assess(104, None).expect("104 = DICOM");
        assert_eq!(a.category, FragileCategory::Medical);
        assert_eq!(a.policy, InteractionPolicy::Refuse);
    }

    #[test]
    fn imprimante_jetdirect_interaction_minimale() {
        let a = assess(9100, None).expect("9100 = raw/JetDirect");
        assert_eq!(a.category, FragileCategory::Printer);
        assert_eq!(a.policy, InteractionPolicy::MinimalOnly);
        assert!(!a.policy.forbids_active());
    }

    #[test]
    fn snmp_v2c_est_ancien_et_bride() {
        let service = svc("snmp", Some("v2c"));
        let a = assess(161, Some(&service)).expect("161 = SNMP");
        assert_eq!(a.category, FragileCategory::LegacySnmp);
        assert_eq!(a.policy, InteractionPolicy::MinimalOnly);
    }

    #[test]
    fn snmp_v3_explicite_nest_pas_bride() {
        let service = svc("snmp", Some("v3"));
        assert!(assess(161, Some(&service)).is_none());
    }

    #[test]
    fn service_banal_nest_pas_fragile() {
        let http = svc("http", Some("1.1"));
        assert!(assess(80, Some(&http)).is_none());
        assert!(assess(22, None).is_none());
    }

    #[test]
    fn detection_par_banniere_en_repli_du_port() {
        // Port non standard mais bannière caractéristique.
        let service = svc("modbus-tcp", None);
        let a = assess(15020, Some(&service)).expect("bannière Modbus");
        assert_eq!(a.category, FragileCategory::ScadaIcs);
    }

    #[test]
    fn assess_port_lit_numero_et_service() {
        let port = Port {
            number: 502,
            proto: Proto::Tcp,
            state: PortState::Open,
            service: None,
        };
        let a = assess_port(&port).expect("502 = Modbus");
        assert_eq!(a.category, FragileCategory::ScadaIcs);
    }

    #[test]
    fn audit_record_reflete_la_politique() {
        let a = assess(502, None).unwrap();
        let record = a.audit_record("192.168.10.9", "op", CapabilityLevel::Recon);
        assert_eq!(record.action, "safety.fragile_detected");
        assert_eq!(record.result, "refused");
        assert_eq!(record.target, "192.168.10.9");

        let printer = assess(515, None).unwrap();
        let rec2 = printer.audit_record("192.168.10.8", "op", CapabilityLevel::Recon);
        assert_eq!(rec2.result, "minimal");
    }
}
