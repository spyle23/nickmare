//! Voie A — sélection interactive + établissement de cible (issue #10, cf.
//! `docs/ARCHITECTURE.md` §3.0 voie A, §3.2 étapes 0/2/8, US-A1/US-B4).
//!
//! `nickmare target select <cidr>` choisit **un** réseau parmi les résultats de
//! recon et **atteste** l'autorisation de l'opérateur (case explicite). Cette
//! sélection + attestation **génèrent le scope de session** en mémoire,
//! verrouillé sur ce seul réseau : pas de fichier à écrire. `nickmare target
//! host <ip>` désigne ensuite l'**hôte précis** à pénétrer *dans* ce périmètre —
//! il **affine** la cible active, il n'**élargit jamais** le scope.
//!
//! # Ce que la voie A établit — et ce qu'elle ne débloque pas
//!
//! Comme la voie C (labo), ce module **ne réimplémente pas** le gate : il
//! construit un [`Scope`] de session (via [`Scope::from_toml`], qui valide le
//! CIDR et calcule l'empreinte SHA-256) et l'[`Attestation`] correspondante, puis
//! les remet au gate en [`AuditMode::Standard`]. Contrairement au labo, la voie A
//! n'ouvre **pas** d'office les niveaux intrusifs : le scope de session n'active
//! que la **reconnaissance** (N1, défaut sûr §3.1). Toute capacité offensive
//! (N2–N4) reste à activer explicitement et granulairement ailleurs — la voie A
//! se contente d'**établir le périmètre** et d'y **désigner la cible active**.
//!
//! # Invariants de sécurité appliqués ici (§1, §3)
//!
//! - **Attestation obligatoire** (fail-safe) : sans la case d'attestation
//!   explicite, **aucun** scope de session n'est établi ([`TargetError::NotAttested`]).
//!   Pas de sélection sans consentement.
//! - **Scope valide ou rien** : un réseau mal formé (CIDR invalide) ou une fenêtre
//!   incohérente refusent la sélection ([`TargetError::Scope`]). Jamais de
//!   périmètre « à moitié » établi.
//! - **Confinement** (§3.0, §3.2 étape 2) : seul le réseau sélectionné est dans le
//!   périmètre. Les réseaux **vus mais non sélectionnés** (WiFi voisin, autre
//!   sous-réseau) restent hors d'atteinte ; `target host` sur un hôte hors du
//!   réseau attesté est **refusé** et journalisé.
//! - **Traçabilité** (§3.3) : l'attestation est journalisée (`target.attest`,
//!   N1) — la cible, l'identité opérateur et l'horodatage ; l'empreinte SHA-256
//!   lie l'attestation au scope exact (portée par [`Attestation`]).

use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, SecondsFormat, Utc};

use crate::audit::{AuditMode, AuditRecord, CapabilityLevel};
use crate::gate::{Action, Attestation, Decision, Gate, Request};
use crate::scope::{Scope, ScopeError};

// --- Erreurs ----------------------------------------------------------------

/// Raison pour laquelle une sélection de cible est refusée (fail-safe §1 : en cas
/// de doute, on refuse plutôt que d'établir un périmètre douteux ou non consenti).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// La case d'attestation explicite n'a pas été cochée : pas de sélection sans
    /// consentement de l'opérateur (§3.2, étape 8).
    NotAttested,
    /// Le scope de session généré est invalide (CIDR mal formé, fenêtre
    /// incohérente…). Porte l'erreur sous-jacente de validation du scope.
    Scope(ScopeError),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::NotAttested => write!(
                f,
                "attestation requise : confirmez explicitement votre autorisation \
                 sur ce réseau (case d'attestation) avant d'établir le périmètre"
            ),
            TargetError::Scope(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for TargetError {}

// --- Sélection de cible (voie A) --------------------------------------------

/// Périmètre de session établi par la voie A : le [`Scope`] verrouillé sur le
/// réseau sélectionné, l'[`Attestation`] qui le couvre, et le réseau déclaré.
///
/// On l'obtient par [`TargetSelection::select`]. Le gate s'en sert via
/// [`TargetSelection::gate`] (mode [`AuditMode::Standard`]) ; le confinement d'un
/// hôte candidat se vérifie via [`TargetSelection::confine`].
#[derive(Debug, Clone)]
pub struct TargetSelection {
    scope: Scope,
    attestation: Attestation,
    network: String,
}

impl TargetSelection {
    /// Établit un périmètre de session à partir du `network` (CIDR) choisi dans
    /// la recon, de l'`operator` qui atteste, de la case d'attestation `attested`
    /// et de la fenêtre `[valid_from, valid_until]`.
    ///
    /// Construit un [`Scope`] de session (seule la **recon** N1 est activée —
    /// défaut sûr §3.1) en le faisant passer par [`Scope::from_toml`], ce qui
    /// **valide** le CIDR et la fenêtre et **calcule l'empreinte SHA-256**.
    /// L'attestation est liée à cette empreinte exacte et à l'opérateur (étape 8
    /// du gate).
    ///
    /// Refuse (fail-safe) si :
    /// - la case d'attestation n'est pas cochée ([`TargetError::NotAttested`]) —
    ///   pas de sélection sans consentement explicite ;
    /// - le CIDR est mal formé ou la fenêtre incohérente ([`TargetError::Scope`]).
    pub fn select(
        network: impl Into<String>,
        operator: impl Into<String>,
        attested: bool,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, TargetError> {
        if !attested {
            return Err(TargetError::NotAttested);
        }
        let network = network.into();
        let operator = operator.into();
        let toml = build_selection_toml(&network, &operator, valid_from, valid_until);
        let scope = Scope::from_toml(&toml).map_err(TargetError::Scope)?;
        let attestation = Attestation::for_scope(&scope, operator, network.clone());
        Ok(Self {
            scope,
            attestation,
            network,
        })
    }

    /// Le scope de session verrouillé sur le réseau sélectionné.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// L'attestation couvrant ce périmètre (identité, réseau, empreinte SHA-256).
    #[must_use]
    pub fn attestation(&self) -> &Attestation {
        &self.attestation
    }

    /// Le réseau attesté (CIDR), seul membre du périmètre.
    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    /// Un [`Gate`] adossé à ce périmètre, en [`AuditMode::Standard`]. Le scope est
    /// cloné : la sélection reste réutilisable.
    #[must_use]
    pub fn gate(&self) -> Gate {
        Gate::with_scope(self.scope.clone(), AuditMode::Standard)
    }

    /// Enregistrement d'audit de l'attestation (`target.attest`, N1) :
    /// l'établissement du périmètre est journalisé en clair, avec la cible (le
    /// réseau attesté) et l'identité opérateur ; l'horodatage est ajouté par le
    /// journal. L'empreinte SHA-256 qui lie l'attestation au scope exact est
    /// portée par [`TargetSelection::attestation`]. L'appelant l'écrit dans le
    /// journal chaîné (le module reste **pur**, sans I/O).
    #[must_use]
    pub fn attest_record(&self) -> AuditRecord {
        AuditRecord::new(
            self.scope.engagement.operator.clone(),
            self.network.clone(),
            "target.attest",
            "ok",
            CapabilityLevel::Recon,
        )
    }

    /// Vérifie, via le gate (§3.2, étape 2 — confinement), que `host` appartient
    /// au **réseau attesté**. Renvoie la décision du gate pour une observation de
    /// `host` sous cette attestation à l'instant `now` :
    ///
    /// - [`Decision::Allow`] si l'hôte est **dans** le périmètre (cible désignable) ;
    /// - [`Decision::Deny`] (typiquement [`DenyReason::OutOfScope`]) sinon — un
    ///   réseau voisin vu mais non sélectionné reste hors d'atteinte.
    ///
    /// Le scope n'est **jamais** muté (`&self`) : `target host` affine la cible
    /// active, il n'élargit pas le périmètre.
    ///
    /// [`DenyReason::OutOfScope`]: crate::gate::DenyReason::OutOfScope
    #[must_use]
    pub fn confine(&self, host: IpAddr, now: DateTime<Utc>) -> Decision {
        let operator = &self.scope.engagement.operator;
        let req = Request::new(now, operator).with_attestation(&self.attestation);
        self.gate().check(&Action::Recon { target: host }, &req)
    }

    /// Enregistrement d'audit de la désignation d'un hôte (`target host`), dérivé
    /// de la décision de confinement : `target.host`/`ok` si l'hôte est dans le
    /// périmètre, `blocked_<code>`/`blocked` s'il est refusé (hors réseau attesté
    /// → refus **et** trace, US-B4). Niveau N1 (désignation de cible).
    #[must_use]
    pub fn host_record(&self, host: IpAddr, decision: Decision) -> AuditRecord {
        let (verb, result) = match decision {
            Decision::Allow => ("target.host".to_string(), "ok"),
            Decision::Deny(reason) => (format!("blocked_{}", reason.code()), "blocked"),
        };
        AuditRecord::new(
            self.scope.engagement.operator.clone(),
            host.to_string(),
            verb,
            result,
            CapabilityLevel::Recon,
        )
    }
}

// --- Construction du scope de session ---------------------------------------

/// Génère le TOML canonique d'un scope de voie A : **un** réseau attesté, seule
/// la recon (N1) activée (défaut sûr §3.1 ; aucune capacité intrusive ouverte),
/// fenêtre fournie. Passé ensuite à [`Scope::from_toml`] qui valide et empreinte.
/// Les chaînes injectées sont échappées pour rester des chaînes TOML valides
/// (pas d'injection de structure).
fn build_selection_toml(
    network: &str,
    operator: &str,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> String {
    let network = toml_escape(network);
    let operator = toml_escape(operator);
    let from = valid_from.to_rfc3339_opts(SecondsFormat::Secs, true);
    let until = valid_until.to_rfc3339_opts(SecondsFormat::Secs, true);
    format!(
        "[engagement]\n\
         client = \"Sélection interactive (voie A)\"\n\
         reference = \"TARGET-SELECT\"\n\
         authorized_by = \"attestation interactive de l'opérateur (voie A)\"\n\
         operator = \"{operator}\"\n\
         valid_from = \"{from}\"\n\
         valid_until = \"{until}\"\n\
         \n\
         [targets]\n\
         networks = [\"{network}\"]\n\
         \n\
         [capabilities]\n\
         recon = true\n"
    )
}

/// Échappe une chaîne pour une **chaîne de base** TOML : seuls `\` et `"` peuvent
/// briser le littéral et sont neutralisés. Un éventuel caractère de contrôle
/// restant fera échouer le parseur TOML (→ refus, fail-safe) plutôt que d'ouvrir
/// une injection.
fn toml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    use crate::gate::{DenyReason, Progress};
    use crate::model::ExploitMode;
    use crate::scope::Capability;

    /// Opérateur de référence (atteste et agit sous la même identité).
    const OP: &str = "operateur@example.test";

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    /// Instant nominal (dans la fenêtre de la sélection de référence).
    fn now() -> DateTime<Utc> {
        at(2026, 6, 1, 12)
    }

    /// Sélection de référence attestée sur `network`, fenêtre large.
    fn selection(network: &str) -> TargetSelection {
        TargetSelection::select(network, OP, true, at(2026, 1, 1, 0), at(2027, 1, 1, 0)).unwrap()
    }

    // --- Établissement du périmètre (US-A1) ---------------------------------

    #[test]
    fn select_construit_un_scope_et_une_attestation_lies() {
        let s = selection("192.168.56.0/24");
        // Le périmètre couvre exactement le réseau sélectionné (verrouillé).
        assert_eq!(s.network(), "192.168.56.0/24");
        assert_eq!(s.scope().targets.networks, vec!["192.168.56.0/24".to_string()]);
        // L'attestation est liée à l'empreinte exacte du scope et à l'opérateur.
        assert_eq!(s.attestation().scope_fingerprint, s.scope().fingerprint());
        assert_eq!(s.attestation().operator, OP);
        assert_eq!(s.attestation().perimeter, "192.168.56.0/24");
        // Empreinte SHA-256 présente (64 hex) — preuve du périmètre exact.
        assert_eq!(s.scope().fingerprint().len(), 64);
    }

    #[test]
    fn select_n_active_que_la_recon_par_defaut() {
        // Voie A : défaut sûr — seule la recon (N1) est activée ; aucune capacité
        // intrusive ouverte d'office (contrairement au labo).
        let s = selection("10.0.0.0/24");
        let caps = &s.scope().capabilities;
        assert!(caps.allows(Capability::Recon));
        assert!(!caps.allows(Capability::Exploitation));
        assert!(!caps.allows(Capability::Cracking));
        assert!(!caps.allows(Capability::Emulation));
    }

    #[test]
    fn empreinte_reproductible_et_sensible_au_reseau() {
        let a = selection("192.168.56.0/24");
        let b = selection("192.168.56.0/24");
        assert_eq!(a.scope().fingerprint(), b.scope().fingerprint());
        let c = selection("192.168.57.0/24");
        assert_ne!(a.scope().fingerprint(), c.scope().fingerprint());
    }

    #[test]
    fn attestation_journalisee_en_n1_standard() {
        // DoD US-A1 : entrée d'audit d'attestation présente (cible + identité).
        let s = selection("192.168.56.0/24");
        let rec = s.attest_record();
        assert_eq!(rec.action, "target.attest");
        assert_eq!(rec.result, "ok");
        assert_eq!(rec.level, CapabilityLevel::Recon);
        assert_eq!(rec.mode, AuditMode::Standard);
        assert_eq!(rec.operator, OP);
        assert_eq!(rec.target, "192.168.56.0/24");
    }

    // --- Tests négatifs de sécurité §10.4 -----------------------------------

    #[test]
    fn negatif_pas_de_selection_sans_attestation() {
        // §10.4 : attestation obligatoire — sans la case explicite, aucun
        // périmètre n'est établi (fail-safe).
        let err = TargetSelection::select(
            "192.168.56.0/24",
            OP,
            false, // case d'attestation NON cochée
            at(2026, 1, 1, 0),
            at(2027, 1, 1, 0),
        )
        .unwrap_err();
        assert_eq!(err, TargetError::NotAttested);
    }

    #[test]
    fn negatif_pas_de_selection_sans_scope_valide() {
        // §10.4 : pas de sélection sans scope valide — un CIDR mal formé refuse
        // la sélection (jamais de périmètre « à moitié »).
        let err = TargetSelection::select(
            "192.168.56.0/99", // préfixe hors plage
            OP,
            true,
            at(2026, 1, 1, 0),
            at(2027, 1, 1, 0),
        )
        .unwrap_err();
        assert!(matches!(err, TargetError::Scope(ScopeError::Network(_))), "{err}");
    }

    #[test]
    fn negatif_fenetre_incoherente_refuse() {
        // valid_until avant valid_from → refus (fenêtre incohérente).
        let err = TargetSelection::select(
            "192.168.56.0/24",
            OP,
            true,
            at(2027, 1, 1, 0),
            at(2026, 1, 1, 0),
        )
        .unwrap_err();
        assert!(matches!(err, TargetError::Scope(ScopeError::Window(_))), "{err}");
    }

    #[test]
    fn negatif_action_active_sans_selection_refusee_etape0() {
        // §3.2 étape 0 : avant toute sélection, le gate n'a aucun périmètre →
        // toute action active est refusée (NoScope). C'est l'état « avant
        // target select ».
        let mut gate = Gate::without_perimeter();
        let req = Request::new(now(), OP);
        let action = Action::Recon {
            target: ip("192.168.56.10"),
        };
        assert_eq!(gate.check(&action, &req), Decision::Deny(DenyReason::NoScope));
    }

    // --- Confinement : target host (US-B4) ----------------------------------

    #[test]
    fn target_host_dans_le_reseau_atteste_autorise() {
        // Un hôte du réseau attesté est désignable (confiné dans le périmètre).
        let s = selection("192.168.56.0/24");
        let decision = s.confine(ip("192.168.56.10"), now());
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn negatif_target_host_hors_reseau_atteste_refuse() {
        // §10.4 / US-B4 : un hôte HORS du réseau attesté est refusé.
        let s = selection("192.168.56.0/24");
        let decision = s.confine(ip("10.0.0.5"), now());
        assert_eq!(decision, Decision::Deny(DenyReason::OutOfScope));
    }

    #[test]
    fn negatif_reseau_voisin_non_selectionne_hors_scope() {
        // DoD : un sous-réseau voisin VU mais NON sélectionné (ex. WiFi voisin)
        // reste hors d'atteinte — seul le réseau sélectionné est dans le scope.
        let s = selection("192.168.56.0/24");
        // 192.168.99.0/24 : réseau voisin, jamais sélectionné.
        let decision = s.confine(ip("192.168.99.1"), now());
        assert_eq!(decision, Decision::Deny(DenyReason::OutOfScope));
    }

    #[test]
    fn target_host_n_elargit_jamais_le_perimetre() {
        // DoD US-B4 : « target host » affine la cible active sans élargir le
        // scope. Après avoir désigné un hôte (dans ou hors périmètre), le réseau
        // attesté reste inchangé (seul membre du périmètre).
        let s = selection("192.168.56.0/24");
        let _ = s.confine(ip("192.168.56.10"), now()); // dans le périmètre
        let _ = s.confine(ip("10.0.0.5"), now()); // hors périmètre
        assert_eq!(s.scope().targets.networks, vec!["192.168.56.0/24".to_string()]);
        assert_eq!(s.network(), "192.168.56.0/24");
    }

    #[test]
    fn host_record_reflete_la_decision() {
        let s = selection("192.168.56.0/24");
        // Hôte autorisé → target.host / ok.
        let ok = s.host_record(ip("192.168.56.10"), Decision::Allow);
        assert_eq!(ok.action, "target.host");
        assert_eq!(ok.result, "ok");
        assert_eq!(ok.level, CapabilityLevel::Recon);
        assert_eq!(ok.target, "192.168.56.10");
        // Hôte refusé → blocked_target / blocked (US-B4 : refus + audit).
        let ko = s.host_record(ip("10.0.0.5"), Decision::Deny(DenyReason::OutOfScope));
        assert_eq!(ko.action, "blocked_target");
        assert_eq!(ko.result, "blocked");
        assert_eq!(ko.target, "10.0.0.5");
    }

    // --- Le gate de la sélection reste le mur -------------------------------

    #[test]
    fn gate_de_la_selection_admet_la_recon_in_scope_et_refuse_hors_scope() {
        // La sélection donne un gate utilisable : recon active in-scope admise
        // (étapes 0/1/2/8 passent), hors-scope refusée.
        let s = selection("192.168.56.0/24");
        let att = s.attestation().clone();
        let mut gate = s.gate();
        assert_eq!(gate.mode(), AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);
        let in_scope = Action::Recon {
            target: ip("192.168.56.10"),
        };
        assert_eq!(gate.check(&in_scope, &req), Decision::Allow);
        let out_scope = Action::Recon {
            target: ip("172.16.0.1"),
        };
        assert_eq!(
            gate.check(&out_scope, &req),
            Decision::Deny(DenyReason::OutOfScope)
        );
    }

    #[test]
    fn negatif_gate_sans_attestation_refuse_meme_in_scope() {
        // L'attestation (étape 8) reste exigée : sans elle, même un hôte in-scope
        // est refusé.
        let s = selection("192.168.56.0/24");
        let mut gate = s.gate();
        let req = Request::new(now(), OP); // sans attestation
        let action = Action::Recon {
            target: ip("192.168.56.10"),
        };
        assert_eq!(
            gate.check(&action, &req),
            Decision::Deny(DenyReason::AttestationMissing)
        );
    }

    #[test]
    fn precondition_n2_inchangee_depuis_la_selection() {
        // Garde-fou : la voie A n'ouvre pas N2 d'office. Même avec recon aboutie
        // et attestation, une exploitation est refusée (capacité désactivée) —
        // preuve que la sélection n'élargit pas les capacités.
        let s = selection("192.168.56.0/24");
        let att = s.attestation().clone();
        let mut gate = s.gate();
        let mut prog = Progress::new();
        prog.record(ip("192.168.56.10"), Capability::Recon);
        let req = Request::new(now(), OP)
            .with_attestation(&att)
            .with_progress(&prog)
            .confirmed();
        let action = Action::Exploit {
            target: ip("192.168.56.10"),
            mode: ExploitMode::Validate,
        };
        assert_eq!(
            gate.check(&action, &req),
            Decision::Deny(DenyReason::CapabilityDisabled(Capability::Exploitation))
        );
    }
}
