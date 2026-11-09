//! Orchestration de l'exécution d'une technique ATT&CK (N4), **confinée par le
//! gate** et **intégralement tracée côté opérateur** (issue #22, cf.
//! `docs/ARCHITECTURE.md` §4, §9 Phase 8, §11.3, US-G1/G2/G3).
//!
//! # Invariant central : transparence opérateur absolue
//!
//! « Évasion effective vis-à-vis de la **cible**, exécution **toujours en clair**
//! au journal **opérateur**. » Toute technique émise via [`execute_through_gate`]
//! produit, en cas d'autorisation, un [`AttackExecution`](nickmare_core::model::AttackExecution)
//! horodaté en clair **quel que soit le profil** — y compris `stealth` — et une
//! entrée d'audit N4 est **toujours** construite (autorisée *ou* refusée). Le
//! profil ne règle que l'évasion vers la cible (`profile`), jamais le traçage : il
//! n'existe aucune voie d'exécution qui n'émette pas son `AttackExecution` et son
//! audit. C'est la ligne rouge qui distingue cet outil d'un malware (§11.3).
//!
//! # La whitelist reste dans le gate (le « mur »)
//!
//! Ce module **ne porte aucun** garde-fou : la capacité `emulation` et la
//! whitelist `emulation.attack_techniques` sont l'affaire exclusive de
//! [`nickmare_core::gate`] (§3.2, étape 3). Une technique non listée est **refusée
//! avant** toute émission ([`EmulationOutcome::Blocked`] + audit `blocked_technique`),
//! le moteur n'est jamais actionné.
//!
//! # Aucune technique réelle en CI
//!
//! Le moteur est une **abstraction injectable** : en test, [`MockEmulationEngine`]
//! rejoue une émission **déterministe sans vrai payload, sans réseau et sans vraie
//! évasion d'EDR** (§10.2). Les identifiants ATT&CK viennent d'un mapping statique
//! (`techniques.rs`) : jamais d'implémentation d'exploit.

use std::fmt;
use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use nickmare_core::audit::{AuditMode, AuditRecord, CapabilityLevel};
use nickmare_core::gate::{audit_record, Action, Decision, DenyReason, Gate, Request};
use nickmare_core::model::{AdversaryProfile, AttackExecution, DetectionVerdict};
use nickmare_core::scope::Emulation;

use crate::profile::ProfileBehavior;

// --- Erreur -----------------------------------------------------------------

/// Erreur d'une émission de technique. Les retours d'un moteur externe sont
/// faillibles (§12) : jamais de `panic`, tout remonte via `Result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulationError {
    /// Moteur d'émulation absent ou injoignable → niveau émulation **désactivé
    /// proprement**.
    EngineUnavailable(String),
    /// Le moteur a tourné mais a échoué (émission impossible).
    EngineFailed(String),
    /// Usage incohérent, détail tracé.
    Other(String),
}

impl fmt::Display for EmulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmulationError::EngineUnavailable(msg) => {
                write!(f, "moteur d'émulation indisponible : {msg}")
            }
            EmulationError::EngineFailed(msg) => write!(f, "échec d'émission : {msg}"),
            EmulationError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for EmulationError {}

// --- Requête d'émulation ----------------------------------------------------

/// Demande d'exécution d'**une** technique ATT&CK sur un hôte. `target` ancre
/// l'action au périmètre attesté (confinement par le gate) ; `technique_id` est
/// l'identifiant ATT&CK à faire passer par la whitelist du gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackRequest {
    /// Hôte visé (confiné au périmètre par le gate).
    pub target: IpAddr,
    /// Identifiant MITRE ATT&CK (ex. `"T1021"`).
    pub technique_id: String,
    /// Opérateur à l'origine de l'action (tracé).
    pub operator: String,
}

impl AttackRequest {
    /// Construit une requête (cible, identifiant ATT&CK, opérateur).
    #[must_use]
    pub fn new(
        target: IpAddr,
        technique_id: impl Into<String>,
        operator: impl Into<String>,
    ) -> Self {
        Self {
            target,
            technique_id: technique_id.into(),
            operator: operator.into(),
        }
    }
}

// --- Plan & rapport d'émission (frontière du moteur mock) -------------------

/// Plan remis au moteur : la technique, la cible et le **comportement d'évasion**
/// à tenter vis-à-vis de la cible (dérivé du profil). Le plan ne porte aucune
/// consigne de masquage opérateur — la transparence opérateur n'est pas
/// paramétrable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniquePlan {
    /// Hôte visé.
    pub target: IpAddr,
    /// Identifiant ATT&CK émis.
    pub technique_id: String,
    /// Évasion tentée vis-à-vis de la cible (jamais vis-à-vis de l'opérateur).
    pub behavior: ProfileBehavior,
}

/// Rapport **opérateur** d'une émission : une note en clair décrivant ce qui a été
/// émis (jamais un payload réel). Sert de `notes` à l'[`AttackExecution`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionReport {
    /// Trace opérateur en clair de l'émission (ce qui a été tenté vers la cible).
    pub evidence: Option<String>,
}

// --- Trait moteur + mock déterministe ---------------------------------------

/// Abstraction du moteur d'émission d'une technique (N4). À n'actionner
/// qu'**après** un `Decision::Allow` du gate (§4) : le trait n'embarque aucun
/// garde-fou, il émet et laisse `attack.rs` tracer l'[`AttackExecution`].
///
/// `Send + Sync` pour l'usage concurrent sous `tokio` et en objet de trait
/// (`&dyn EmulationEngine`).
#[async_trait]
pub trait EmulationEngine: Send + Sync {
    /// Émet la technique de `plan` (évasion vers la cible selon le profil) et rend
    /// une note opérateur en clair. À n'appeler qu'après un `Allow` du gate.
    async fn emit(&self, plan: &TechniquePlan) -> Result<EmissionReport, EmulationError>;
}

/// Moteur mock : rejoue une émission **déterministe**, sans vrai payload, sans
/// réseau et sans vraie évasion d'EDR. La note opérateur décrit en clair la
/// technique et l'évasion *tentée* vers la cible.
#[derive(Debug, Clone, Default)]
pub struct MockEmulationEngine {
    failing: Option<String>,
}

impl MockEmulationEngine {
    /// Moteur mock nominal (toute émission réussit, de façon déterministe).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Moteur mock qui simule un **échec d'émission** pour une technique donnée
    /// (couvre le chemin d'erreur sans aucune action réelle).
    #[must_use]
    pub fn failing_on(technique_id: impl Into<String>) -> Self {
        Self {
            failing: Some(technique_id.into()),
        }
    }
}

#[async_trait]
impl EmulationEngine for MockEmulationEngine {
    async fn emit(&self, plan: &TechniquePlan) -> Result<EmissionReport, EmulationError> {
        if self.failing.as_deref() == Some(plan.technique_id.as_str()) {
            let msg = format!("émission simulée en échec pour {}", plan.technique_id);
            return Err(EmulationError::EngineFailed(msg));
        }
        let evidence = format!(
            "technique {} émise vers {} ; évasion cible : {}",
            plan.technique_id,
            plan.target,
            plan.behavior.evasion_summary()
        );
        Ok(EmissionReport {
            evidence: Some(evidence),
        })
    }
}

// --- Rappel du contact SOC (US-G2) ------------------------------------------

/// Rappel de coordination **purple team** émis **au démarrage** d'une émulation,
/// **hors mode labo** : qui prévenir côté défense (`blue_team_contact`). En mode
/// labo (apprentissage), aucun SOC tiers n'est à coordonner → pas de rappel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocReminder {
    contact: Option<String>,
}

impl SocReminder {
    /// Rappel à produire au démarrage, pour `emulation` dans le mode `mode`.
    /// Renvoie `None` en mode labo ; en mode standard, renvoie toujours un rappel
    /// (avec le contact s'il est renseigné, sinon un avertissement de contact
    /// manquant — coordination requise malgré tout).
    #[must_use]
    pub fn at_startup(emulation: &Emulation, mode: AuditMode) -> Option<Self> {
        if mode == AuditMode::Lab {
            return None;
        }
        Some(Self {
            contact: emulation.blue_team_contact.clone(),
        })
    }

    /// Contact SOC renseigné, ou `None` s'il manque.
    #[must_use]
    pub fn contact(&self) -> Option<&str> {
        self.contact.as_deref()
    }

    /// Vrai si un contact SOC exploitable est renseigné.
    #[must_use]
    pub fn has_contact(&self) -> bool {
        self.contact.is_some()
    }

    /// Message explicite à présenter/journaliser au démarrage.
    #[must_use]
    pub fn message(&self) -> String {
        match &self.contact {
            Some(contact) => format!("coordination purple team : prévenir le SOC ({contact})"),
            None => "coordination purple team requise : aucun blue_team_contact".to_string(),
        }
    }

    /// Entrée d'audit N4 du rappel (`emulation.soc_reminder`), à consigner au
    /// journal pour prouver que la coordination a bien été rappelée.
    #[must_use]
    pub fn audit_record(&self, operator: impl Into<String>) -> AuditRecord {
        let result = if self.has_contact() {
            "ok"
        } else {
            "missing-contact"
        };
        AuditRecord::new(
            operator,
            "-",
            "emulation.soc_reminder",
            result,
            CapabilityLevel::Emulation,
        )
    }
}

// --- Orchestration confinée au gate -----------------------------------------

/// Issue d'un passage **gate → moteur** pour l'exécution d'une technique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulationOutcome {
    /// Refusé par le gate : le moteur n'a **pas** émis. Porte la raison typée et
    /// l'entrée d'audit `blocked_*` (toujours présente, même en `stealth`).
    Blocked {
        /// Raison du refus (premier contrôle échoué, §3.2).
        reason: DenyReason,
        /// Entrée d'audit `blocked_<code>` à consigner.
        audit: AuditRecord,
    },
    /// Autorisé et émis : l'[`AttackExecution`] tracé en clair (détection encore
    /// `Unknown`, à renseigner par la blue team) et l'audit `emulation.<technique>`.
    Executed {
        /// Exécution tracée côté opérateur (horodatée, en clair, quel que soit le
        /// profil).
        execution: AttackExecution,
        /// Entrée d'audit du verbe métier (`emulation.<technique>`), profil inclus.
        audit: AuditRecord,
    },
}

impl EmulationOutcome {
    /// Vrai si l'exécution a été refusée par le gate.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, EmulationOutcome::Blocked { .. })
    }

    /// L'exécution tracée, si l'action a été autorisée et émise.
    #[must_use]
    pub fn execution(&self) -> Option<&AttackExecution> {
        match self {
            EmulationOutcome::Executed { execution, .. } => Some(execution),
            EmulationOutcome::Blocked { .. } => None,
        }
    }

    /// L'entrée d'audit à journaliser (présente dans les **deux** cas : c'est
    /// l'invariant de transparence opérateur).
    #[must_use]
    pub fn audit(&self) -> &AuditRecord {
        match self {
            EmulationOutcome::Blocked { audit, .. } | EmulationOutcome::Executed { audit, .. } => {
                audit
            }
        }
    }
}

/// Construit l'entrée d'audit N4 d'une action d'émulation, en y attachant
/// **toujours** le profil d'adversaire rejoué (transparence opérateur, §11.3) —
/// aussi bien sur autorisation que sur refus.
fn emulation_audit(
    action: &Action,
    decision: Decision,
    operator: &str,
    mode: AuditMode,
    profile: AdversaryProfile,
) -> AuditRecord {
    let record = audit_record(action, decision, operator, mode);
    record.with_profile(profile)
}

/// Déroule l'exécution d'**une** technique ATT&CK **via le gate** (le « mur »,
/// §3.2/§4), seul chemin vers le moteur.
///
/// Le gate vérifie la capacité `emulation` et la whitelist `attack_techniques`
/// (étape 3), le confinement au périmètre et les plafonds. Sur refus, le moteur
/// **n'est pas** actionné : on renvoie [`EmulationOutcome::Blocked`] + l'audit
/// `blocked_technique`. Sur autorisation, le moteur émet la technique (évasion
/// vers la cible selon `profile`) et l'on trace **systématiquement** un
/// [`AttackExecution`] horodaté `now` en clair — détection initiale `Unknown`, à
/// renseigner ensuite par la blue team (`verdict.rs`).
pub async fn execute_through_gate(
    gate: &mut Gate,
    req: &Request<'_>,
    engine: &dyn EmulationEngine,
    request: &AttackRequest,
    profile: AdversaryProfile,
    now: DateTime<Utc>,
) -> Result<EmulationOutcome, EmulationError> {
    let action = Action::Emulate {
        target: request.target,
        technique: request.technique_id.clone(),
    };
    let decision = gate.check(&action, req);
    let operator = request.operator.as_str();
    let audit = emulation_audit(&action, decision, operator, gate.mode(), profile);
    match decision {
        Decision::Deny(reason) => Ok(EmulationOutcome::Blocked { reason, audit }),
        Decision::Allow => {
            let behavior = ProfileBehavior::for_profile(profile);
            let plan = TechniquePlan {
                target: request.target,
                technique_id: request.technique_id.clone(),
                behavior,
            };
            let report = engine.emit(&plan).await?;
            let execution = AttackExecution {
                technique_id: request.technique_id.clone(),
                host: request.target,
                profile,
                performed_at: now,
                detection: DetectionVerdict::Unknown,
                detected_at: None,
                detected_by: None,
                notes: report.evidence,
            };
            Ok(EmulationOutcome::Executed { execution, audit })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: &str = "operateur@example.test";

    fn ip() -> IpAddr {
        "192.168.10.25".parse().unwrap()
    }

    fn plan_for(profile: AdversaryProfile) -> TechniquePlan {
        TechniquePlan {
            target: ip(),
            technique_id: "T1021".to_string(),
            behavior: ProfileBehavior::for_profile(profile),
        }
    }

    #[tokio::test]
    async fn le_mock_emet_une_note_operateur_en_clair() {
        let engine = MockEmulationEngine::new();
        let plan = plan_for(AdversaryProfile::Stealth);
        let report = engine.emit(&plan).await.unwrap();
        let evidence = report.evidence.expect("note opérateur");
        // Même en stealth, la note opérateur décrit en clair ce qui a été tenté.
        assert!(evidence.contains("T1021"));
        assert!(evidence.contains("192.168.10.25"));
        assert!(evidence.contains("fragmentation"));
    }

    #[tokio::test]
    async fn le_mock_est_deterministe() {
        let engine = MockEmulationEngine::new();
        let plan = plan_for(AdversaryProfile::Balanced);
        let a = engine.emit(&plan).await.unwrap();
        let b = engine.emit(&plan).await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn le_mock_peut_simuler_un_echec_sans_action_reelle() {
        let engine = MockEmulationEngine::failing_on("T1021");
        let plan = plan_for(AdversaryProfile::Noisy);
        let err = engine.emit(&plan).await.unwrap_err();
        assert!(matches!(err, EmulationError::EngineFailed(_)), "{err}");
    }

    fn emulation_with(contact: Option<&str>) -> Emulation {
        Emulation {
            blue_team_contact: contact.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn soc_reminder_absent_en_mode_labo() {
        let emulation = emulation_with(Some("soc@acme.example"));
        assert!(SocReminder::at_startup(&emulation, AuditMode::Lab).is_none());
    }

    #[test]
    fn soc_reminder_rappelle_le_contact_hors_labo() {
        let emulation = emulation_with(Some("soc@acme.example"));
        let maybe = SocReminder::at_startup(&emulation, AuditMode::Standard);
        let reminder = maybe.expect("rappel hors labo");
        assert!(reminder.has_contact());
        assert_eq!(reminder.contact(), Some("soc@acme.example"));
        assert!(reminder.message().contains("soc@acme.example"));
        let rec = reminder.audit_record(OP);
        assert_eq!(rec.action, "emulation.soc_reminder");
        assert_eq!(rec.result, "ok");
        assert_eq!(rec.level, CapabilityLevel::Emulation);
    }

    #[test]
    fn soc_reminder_avertit_si_aucun_contact() {
        let emulation = emulation_with(None);
        let maybe = SocReminder::at_startup(&emulation, AuditMode::Standard);
        let reminder = maybe.expect("rappel hors labo");
        assert!(!reminder.has_contact());
        assert!(reminder.message().contains("aucun blue_team_contact"));
        assert_eq!(reminder.audit_record(OP).result, "missing-contact");
    }

    #[test]
    fn erreurs_s_affichent() {
        let unavailable = EmulationError::EngineUnavailable("x".into()).to_string();
        assert!(unavailable.contains("indisponible"));
        let failed = EmulationError::EngineFailed("code 1".into()).to_string();
        assert!(failed.contains("code 1"));
        let other = EmulationError::Other("détail".into()).to_string();
        assert!(other.contains("détail"));
    }
}
