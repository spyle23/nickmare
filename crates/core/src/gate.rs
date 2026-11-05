//! Le **gate** — garde-fous obligatoires, « le mur » (issue #4, cf.
//! `docs/ARCHITECTURE.md` §3.2, §4).
//!
//! # Invariant de sécurité central
//!
//! Le gate est le **seul chemin vers l'exécution** (§4) : aucun module
//! (exploitation, cracking, émulation, scan actif) n'atteint le réseau ou un
//! moteur externe sans avoir obtenu un [`Decision::Allow`] de [`Gate::check`].
//! Les crates de niveau supérieur n'exposent pas de voie parallèle : elles
//! reçoivent un `NetworkProvider`/`ExploitEngine`/`CrackEngine` (cf. `traits`)
//! et ne doivent l'actionner qu'après un `Allow`.
//!
//! **Seule exception, explicitement documentée : la reconnaissance passive**
//! (lister les réseaux/hôtes *à portée*, §3.0, §3.2). Cette observation ne
//! traverse pas les contrôles de cible et **n'appelle pas** le gate. Toute
//! *autre* action — y compris la recon **active** sur un hôte (scan de ports,
//! lecture de bannière) — passe par [`Gate::check`].
//!
//! # Les huit étapes (§3.2)
//!
//! Pour un [`Scope`] établi et une [`Action`], le gate applique, dans l'ordre :
//!
//! 0. **Périmètre établi ?** — refus si aucun scope de session.
//! 1. **Validation temporelle** — `valid_from`/`valid_until` et `allowed_hours`.
//! 2. **Filtre de cible** — la cible appartient au scope **et** pas aux
//!    `exclusions`.
//! 3. **Filtre de capacité** — niveau activé ; l'exploitation exige en plus
//!    `allowed_hosts`, l'émulation une technique listée, le spray en ligne
//!    l'opt-in `online_spray`.
//! 4. **Pré-conditions** — une action de niveau N≥2 exige un résultat de niveau
//!    inférieur déjà obtenu sur la cible.
//! 5. **Confirmation humaine** — en mode `manual`, l'exploitation et le spray en
//!    ligne exigent une confirmation explicite. Levée en **mode labo**.
//! 6. **Garde anti-destruction** — si `destructive_checks = false`, seul le mode
//!    validation passe (jamais de charge destructrice).
//! 7. **Plafonds** — `max_rate_pps` (token bucket), `max_actions`,
//!    `max_attempts_per_account`. Dépassement → refus.
//! 8. **Attestation / consentement** — une attestation enregistrée (cible,
//!    empreinte SHA-256 du scope, opérateur) doit couvrir ce scope.
//!
//! # Fail-safe (§1)
//!
//! En cas de doute, le gate **refuse**. Un refus porte une [`DenyReason`] typée
//! et se transforme en entrée d'audit `blocked_*` via [`audit_record`], jamais
//! silencieux. Les plafonds ne sont **consommés** que lorsque la décision finale
//! est `Allow` : une action refusée ne grignote aucun quota.
//!
//! # Spécificité du mode labo (§3.2, note)
//!
//! Le mode laboratoire ([`AuditMode::Lab`]) agit **uniquement** sur l'étape 3
//! (toutes les capacités N1–N4 sont activées d'office, sans sous-filtre
//! `allowed_hosts`/technique/`online_spray`) et l'étape 5 (confirmation par
//! cible levée). Les étapes 0, 1, 2 (confinement), 4, 6 (anti-destruction) et 7
//! (plafonds) **s'appliquent à l'identique**. Le labo élargit ce qu'on a le
//! droit de faire *dans* le périmètre, jamais le périmètre lui-même.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::audit::{AuditMode, AuditRecord, CapabilityLevel};
use crate::model::ExploitMode;
use crate::scope::{Capability, ExploitRunMode, Scope, TemporalStatus};

// --- Action -----------------------------------------------------------------

/// Action **active** soumise au gate. La reconnaissance passive (réseaux/hôtes à
/// portée) ne passe pas par ici (§3.2).
///
/// Chaque variante porte sa **cible** (un hôte) et les paramètres nécessaires
/// aux contrôles : mode d'exploitation, caractère en ligne et compte visé d'un
/// spray, identifiant ATT&CK d'une émulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Reconnaissance **active** sur un hôte (scan de ports, bannière). N1.
    Recon { target: IpAddr },
    /// Tentative d'exploitation (N2). `mode` distingue preuve (`Validate`) et
    /// exécution potentiellement destructrice (`Exploit`).
    Exploit { target: IpAddr, mode: ExploitMode },
    /// Craquage de credentials (N3). `online` = spray en ligne (risque de
    /// verrouillage) ciblant éventuellement un `account` ; sinon hors-ligne.
    Crack { target: IpAddr, online: bool, account: Option<String> },
    /// Émulation d'adversaire (N4) : exécution d'une technique ATT&CK.
    Emulate { target: IpAddr, technique: String },
}

impl Action {
    /// Hôte visé par l'action.
    #[must_use]
    pub fn target(&self) -> IpAddr {
        match self {
            Action::Recon { target }
            | Action::Exploit { target, .. }
            | Action::Crack { target, .. }
            | Action::Emulate { target, .. } => *target,
        }
    }

    /// Niveau de capacité porté par l'action (filtré à l'étape 3).
    #[must_use]
    pub fn capability(&self) -> Capability {
        match self {
            Action::Recon { .. } => Capability::Recon,
            Action::Exploit { .. } => Capability::Exploitation,
            Action::Crack { .. } => Capability::Cracking,
            Action::Emulate { .. } => Capability::Emulation,
        }
    }

    /// Niveau pour le journal d'audit (N1–N4).
    #[must_use]
    pub fn level(&self) -> CapabilityLevel {
        match self {
            Action::Recon { .. } => CapabilityLevel::Recon,
            Action::Exploit { .. } => CapabilityLevel::Exploitation,
            Action::Crack { .. } => CapabilityLevel::Cracking,
            Action::Emulate { .. } => CapabilityLevel::Emulation,
        }
    }

    /// Verbe métier journalisé lorsqu'une action est **autorisée**.
    #[must_use]
    pub fn verb(&self) -> String {
        match self {
            Action::Recon { .. } => "recon.active".to_string(),
            Action::Exploit { mode: ExploitMode::Validate, .. } => "exploit.validate".to_string(),
            Action::Exploit { mode: ExploitMode::Exploit, .. } => "exploit.run".to_string(),
            Action::Crack { online: true, .. } => "crack.spray".to_string(),
            Action::Crack { online: false, .. } => "crack.offline".to_string(),
            Action::Emulate { technique, .. } => format!("emulation.{technique}"),
        }
    }
}

// --- Décision & raisons typées ----------------------------------------------

/// Verdict du gate pour une action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// L'action est autorisée : tous les contrôles passent.
    Allow,
    /// L'action est refusée, avec la raison typée du **premier** contrôle échoué
    /// (ordre des étapes §3.2).
    Deny(DenyReason),
}

impl Decision {
    /// Vrai si l'action est autorisée.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Raison du refus, ou `None` si autorisé.
    #[must_use]
    pub fn reason(&self) -> Option<DenyReason> {
        match self {
            Decision::Allow => None,
            Decision::Deny(reason) => Some(*reason),
        }
    }
}

/// Raison typée d'un refus. Chaque variante correspond à une étape de §3.2 et
/// porte un [`code`](DenyReason::code) stable pour l'action d'audit `blocked_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Étape 0 — aucun périmètre de session établi.
    NoScope,
    /// Étape 1 — hors de la fenêtre `valid_from`/`valid_until`.
    OutsideWindow(TemporalStatus),
    /// Étape 1 — hors de la fenêtre horaire `allowed_hours`.
    OutsideHours,
    /// Étape 2 — cible hors du périmètre (`networks`/`hosts`).
    OutOfScope,
    /// Étape 2 — cible explicitement exclue (`exclusions`).
    Excluded,
    /// Étape 3 — capacité désactivée dans le scope.
    CapabilityDisabled(Capability),
    /// Étape 3 — exploitation d'un hôte hors `exploitation.allowed_hosts`.
    HostNotAllowed,
    /// Étape 3 — spray en ligne sans l'opt-in `cracking.online_spray`.
    OnlineSprayNotAllowed,
    /// Étape 3 — technique ATT&CK absente de `emulation.attack_techniques`.
    TechniqueNotAllowed,
    /// Étape 4 — pré-condition absente (pas de résultat de niveau inférieur).
    PreconditionMissing,
    /// Étape 5 — confirmation humaine requise et non fournie.
    ConfirmationRequired,
    /// Étape 6 — charge destructrice refusée (`destructive_checks = false`).
    Destructive,
    /// Étape 7 — débit `max_rate_pps` dépassé (token bucket vide).
    RateExceeded,
    /// Étape 7 — plafond `max_actions` atteint.
    MaxActionsExceeded,
    /// Étape 7 — plafond `max_attempts_per_account` atteint.
    MaxAttemptsExceeded,
    /// Étape 8 — attestation/consentement absent ou incohérent avec le scope.
    AttestationMissing,
}

impl DenyReason {
    /// Code stable du refus, suffixe de l'action d'audit `blocked_<code>`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::NoScope => "no_scope",
            DenyReason::OutsideWindow(_) => "window",
            DenyReason::OutsideHours => "hours",
            DenyReason::OutOfScope => "target",
            DenyReason::Excluded => "exclusion",
            DenyReason::CapabilityDisabled(_) => "capability",
            DenyReason::HostNotAllowed => "allowed_hosts",
            DenyReason::OnlineSprayNotAllowed => "online_spray",
            DenyReason::TechniqueNotAllowed => "technique",
            DenyReason::PreconditionMissing => "precondition",
            DenyReason::ConfirmationRequired => "confirmation",
            DenyReason::Destructive => "destructive",
            DenyReason::RateExceeded => "rate",
            DenyReason::MaxActionsExceeded => "max_actions",
            DenyReason::MaxAttemptsExceeded => "max_attempts",
            DenyReason::AttestationMissing => "attestation",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenyReason::NoScope => write!(f, "aucun périmètre de session établi"),
            DenyReason::OutsideWindow(status) => {
                write!(f, "hors fenêtre d'engagement ({status:?})")
            }
            DenyReason::OutsideHours => write!(f, "hors de la fenêtre horaire autorisée"),
            DenyReason::OutOfScope => write!(f, "cible hors du périmètre attesté"),
            DenyReason::Excluded => write!(f, "cible explicitement exclue du périmètre"),
            DenyReason::CapabilityDisabled(cap) => {
                write!(f, "capacité désactivée dans le scope : {cap:?}")
            }
            DenyReason::HostNotAllowed => write!(f, "hôte hors de exploitation.allowed_hosts"),
            DenyReason::OnlineSprayNotAllowed => {
                write!(f, "spray en ligne non autorisé (online_spray = false)")
            }
            DenyReason::TechniqueNotAllowed => {
                write!(f, "technique ATT&CK non listée dans le scope")
            }
            DenyReason::PreconditionMissing => {
                write!(f, "pré-condition manquante (résultat de niveau inférieur)")
            }
            DenyReason::ConfirmationRequired => {
                write!(f, "confirmation humaine requise et non fournie")
            }
            DenyReason::Destructive => {
                write!(f, "charge destructrice refusée (destructive_checks = false)")
            }
            DenyReason::RateExceeded => write!(f, "débit max_rate_pps dépassé"),
            DenyReason::MaxActionsExceeded => write!(f, "plafond max_actions atteint"),
            DenyReason::MaxAttemptsExceeded => {
                write!(f, "plafond max_attempts_per_account atteint")
            }
            DenyReason::AttestationMissing => {
                write!(f, "attestation/consentement absent ou incohérent")
            }
        }
    }
}

// --- Attestation (étape 8) --------------------------------------------------

/// Attestation de consentement enregistrée à l'établissement du périmètre
/// (sélection voie A, attestation de lab voie C, ou chargement voie B).
///
/// Elle lie une identité opérateur, le périmètre attesté et l'empreinte SHA-256
/// du scope exact : un consentement signé pour un autre scope — ou par un autre
/// opérateur — ne couvre pas cette action (§3.2, étape 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub operator: String,
    pub perimeter: String,
    pub scope_fingerprint: String,
}

impl Attestation {
    /// Construit une attestation pour un scope donné, en copiant son empreinte
    /// SHA-256 (lien fort entre consentement et scope exact).
    #[must_use]
    pub fn for_scope(
        scope: &Scope,
        operator: impl Into<String>,
        perimeter: impl Into<String>,
    ) -> Self {
        Self {
            operator: operator.into(),
            perimeter: perimeter.into(),
            scope_fingerprint: scope.fingerprint().to_string(),
        }
    }
}

// --- Progression (étape 4) --------------------------------------------------

/// Résultats déjà obtenus par cible, pour la vérification des pré-conditions
/// (§3.2, étape 4) : une action de niveau N≥2 exige un résultat de niveau
/// strictement inférieur sur la **même** cible.
#[derive(Debug, Clone, Default)]
pub struct Progress {
    completed: HashMap<IpAddr, Vec<Capability>>,
}

impl Progress {
    /// Progression vide (aucun résultat encore obtenu).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enregistre qu'un résultat de capacité `capability` a été obtenu sur
    /// `target` (p. ex. recon aboutie → autorise l'exploitation ultérieure).
    pub fn record(&mut self, target: IpAddr, capability: Capability) -> &mut Self {
        self.completed.entry(target).or_default().push(capability);
        self
    }

    /// Vrai si un résultat de niveau strictement inférieur à `capability` existe
    /// sur `target`.
    fn has_lower_than(&self, target: IpAddr, capability: Capability) -> bool {
        let want = level_ordinal(capability);
        let Some(caps) = self.completed.get(&target) else {
            return false;
        };
        caps.iter().any(|c| level_ordinal(*c) < want)
    }
}

/// Ordinal de niveau d'une capacité (N1=1 … N4=4), pour comparer les niveaux.
fn level_ordinal(capability: Capability) -> u8 {
    match capability {
        Capability::Recon => 1,
        Capability::Exploitation => 2,
        Capability::Cracking => 3,
        Capability::Emulation => 4,
    }
}

// --- Requête (contexte d'exécution d'une action) ----------------------------

/// Contexte d'une demande d'action : instant, opérateur, et l'état runtime
/// nécessaire aux étapes 4 (pré-conditions), 5 (confirmation) et 8 (attestation).
///
/// Les valeurs par défaut sont **sûres** : pas d'attestation, pas de
/// confirmation, pas de progression — de sorte qu'une requête minimale est
/// refusée dès qu'un contrôle l'exige (fail-safe).
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    now: DateTime<Utc>,
    operator: &'a str,
    attestation: Option<&'a Attestation>,
    confirmed: bool,
    progress: Option<&'a Progress>,
}

impl<'a> Request<'a> {
    /// Requête minimale à l'instant `now` pour `operator` : ni attestation, ni
    /// confirmation, ni progression (tout doit être ajouté explicitement).
    #[must_use]
    pub fn new(now: DateTime<Utc>, operator: &'a str) -> Self {
        Self {
            now,
            operator,
            attestation: None,
            confirmed: false,
            progress: None,
        }
    }

    /// Attache l'attestation de consentement (étape 8).
    #[must_use]
    pub fn with_attestation(mut self, attestation: &'a Attestation) -> Self {
        self.attestation = Some(attestation);
        self
    }

    /// Marque la confirmation humaine comme fournie (étape 5).
    #[must_use]
    pub fn confirmed(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// Attache la progression des résultats obtenus (étape 4).
    #[must_use]
    pub fn with_progress(mut self, progress: &'a Progress) -> Self {
        self.progress = Some(progress);
        self
    }
}

// --- Token bucket (étape 7, max_rate_pps) -----------------------------------

/// Seau à jetons pour `max_rate_pps` : capacité = débit, remplissage linéaire au
/// même débit. Chaque action active consomme un jeton. Déterministe vis-à-vis de
/// l'instant fourni (testable sans horloge réelle).
#[derive(Debug, Clone)]
struct TokenBucket {
    capacity: f64,
    rate_per_sec: f64,
    tokens: f64,
    last: Option<DateTime<Utc>>,
}

impl TokenBucket {
    /// Seau plein pour un débit de `pps` paquets/seconde.
    fn new(pps: u32) -> Self {
        let capacity = f64::from(pps);
        Self {
            capacity,
            rate_per_sec: capacity,
            tokens: capacity,
            last: None,
        }
    }

    /// Jetons disponibles à l'instant `now`, après remplissage (sans mutation).
    fn refilled(&self, now: DateTime<Utc>) -> f64 {
        match self.last {
            // Jamais utilisé : le seau est plein.
            None => self.capacity,
            Some(last) => {
                let elapsed_secs = (now - last).num_milliseconds().max(0) as f64 / 1000.0;
                (self.tokens + elapsed_secs * self.rate_per_sec).min(self.capacity)
            }
        }
    }

    /// Vrai s'il reste au moins un jeton à l'instant `now`.
    fn available(&self, now: DateTime<Utc>) -> bool {
        self.refilled(now) >= 1.0
    }

    /// Consomme un jeton à l'instant `now` (remplit puis retranche).
    fn consume(&mut self, now: DateTime<Utc>) {
        self.tokens = (self.refilled(now) - 1.0).max(0.0);
        self.last = Some(now);
    }
}

// --- Le gate ----------------------------------------------------------------

/// Le gate : détient le périmètre, le mode d'engagement et l'état cumulatif des
/// plafonds (débit, nombre d'actions, tentatives par compte). On l'interroge via
/// [`Gate::check`] ; les plafonds ne sont consommés qu'en cas d'autorisation.
#[derive(Debug)]
pub struct Gate {
    scope: Option<Scope>,
    mode: AuditMode,
    rate: Option<TokenBucket>,
    actions_used: u32,
    attempts_per_account: HashMap<String, u32>,
}

impl Gate {
    /// Gate adossé à un périmètre établi, dans le mode donné (`Standard`/`Lab`).
    #[must_use]
    pub fn with_scope(scope: Scope, mode: AuditMode) -> Self {
        // `0` = aucune limite de débit configurée (comme `allowed_hours`
        // absente côté temps) ; on n'installe alors pas de seau.
        let rate = match scope.constraints.max_rate_pps {
            0 => None,
            pps => Some(TokenBucket::new(pps)),
        };
        Self {
            scope: Some(scope),
            mode,
            rate,
            actions_used: 0,
            attempts_per_account: HashMap::new(),
        }
    }

    /// Gate **sans périmètre** : toute action est refusée à l'étape 0
    /// ([`DenyReason::NoScope`]). Représente l'état avant tout
    /// sélection+attestation / `lab start` / chargement de fichier.
    #[must_use]
    pub fn without_perimeter() -> Self {
        Self {
            scope: None,
            mode: AuditMode::Standard,
            rate: None,
            actions_used: 0,
            attempts_per_account: HashMap::new(),
        }
    }

    /// Mode d'engagement courant (reporté dans l'audit).
    #[must_use]
    pub fn mode(&self) -> AuditMode {
        self.mode
    }

    /// Applique les huit contrôles (§3.2) à `action` dans le contexte `req`.
    ///
    /// Renvoie la **première** raison de refus rencontrée dans l'ordre des
    /// étapes, ou [`Decision::Allow`]. En cas d'autorisation **seulement**, les
    /// plafonds sont consommés (jeton de débit, compteurs d'actions/tentatives) :
    /// une action refusée n'entame aucun quota.
    pub fn check(&mut self, action: &Action, req: &Request) -> Decision {
        // Étape 0 — périmètre établi ?
        let Some(scope) = self.scope.as_ref() else {
            return Decision::Deny(DenyReason::NoScope);
        };
        let lab = self.mode == AuditMode::Lab;

        // Étape 1 — validation temporelle.
        match scope.temporal_status(req.now) {
            TemporalStatus::Valid => {}
            other => return Decision::Deny(DenyReason::OutsideWindow(other)),
        }
        if !scope.within_allowed_hours(req.now) {
            return Decision::Deny(DenyReason::OutsideHours);
        }

        // Étape 2 — filtre de cible (confinement + exclusions). Inchangé en labo.
        let target = action.target();
        if target_excluded(scope, target) {
            return Decision::Deny(DenyReason::Excluded);
        }
        if !target_in_scope(scope, target) {
            return Decision::Deny(DenyReason::OutOfScope);
        }

        // Étape 3 — filtre de capacité (ouvert d'office en mode labo).
        if let Some(reason) = capability_denial(scope, action, lab) {
            return Decision::Deny(reason);
        }

        // Étape 4 — pré-conditions (inchangé en labo).
        let capability = action.capability();
        if level_ordinal(capability) >= 2 {
            let met = req.progress.is_some_and(|p| p.has_lower_than(target, capability));
            if !met {
                return Decision::Deny(DenyReason::PreconditionMissing);
            }
        }

        // Étape 5 — confirmation humaine (levée en mode labo).
        if confirmation_required(scope, action, lab) && !req.confirmed {
            return Decision::Deny(DenyReason::ConfirmationRequired);
        }

        // Étape 6 — garde anti-destruction (inchangé en labo).
        if let Action::Exploit { mode, .. } = action {
            let destructive = *mode == ExploitMode::Exploit;
            if destructive && !scope.capabilities.exploitation.destructive_checks {
                return Decision::Deny(DenyReason::Destructive);
            }
        }

        // Étape 7 — plafonds (vérification seule ; consommation après l'étape 8).
        if let Some(bucket) = self.rate.as_ref() {
            if !bucket.available(req.now) {
                return Decision::Deny(DenyReason::RateExceeded);
            }
        }
        let is_exploit = matches!(action, Action::Exploit { .. });
        let max_actions = scope.capabilities.exploitation.max_actions;
        if is_exploit && max_actions > 0 && self.actions_used >= max_actions {
            return Decision::Deny(DenyReason::MaxActionsExceeded);
        }
        let max_attempts = scope.capabilities.cracking.max_attempts_per_account;
        if let Some(account) = online_spray_account(action) {
            let used = self.attempts_per_account.get(account).copied().unwrap_or(0);
            if max_attempts > 0 && used >= max_attempts {
                return Decision::Deny(DenyReason::MaxAttemptsExceeded);
            }
        }

        // Étape 8 — attestation / consentement enregistré (tous modes).
        let consent_ok = match req.attestation {
            None => false,
            Some(att) => {
                let same_scope = att.scope_fingerprint == scope.fingerprint();
                let same_operator = att.operator == req.operator;
                same_scope && same_operator
            }
        };
        if !consent_ok {
            return Decision::Deny(DenyReason::AttestationMissing);
        }

        // Tous les contrôles passent : on **engage** les plafonds maintenant.
        if let Some(bucket) = self.rate.as_mut() {
            bucket.consume(req.now);
        }
        if is_exploit {
            self.actions_used = self.actions_used.saturating_add(1);
        }
        if let Some(account) = online_spray_account(action) {
            let counter = self.attempts_per_account.entry(account.to_string()).or_insert(0);
            *counter = counter.saturating_add(1);
        }

        Decision::Allow
    }
}

// --- Contrôles élémentaires -------------------------------------------------

/// Étape 2 — la cible appartient-elle au périmètre (`hosts` ou `networks`) ?
fn target_in_scope(scope: &Scope, target: IpAddr) -> bool {
    hosts_contains(&scope.targets.hosts, target)
        || networks_contains(&scope.targets.networks, target)
}

/// Étape 2 — la cible est-elle explicitement exclue ? Les exclusions priment sur
/// toute inclusion (§3.1).
fn target_excluded(scope: &Scope, target: IpAddr) -> bool {
    hosts_contains(&scope.targets.exclusions.hosts, target)
        || networks_contains(&scope.targets.exclusions.networks, target)
}

/// Étape 3 — refus éventuel du filtre de capacité. En mode labo, toutes les
/// capacités N1–N4 sont ouvertes et les sous-filtres (`allowed_hosts`,
/// technique, `online_spray`) sont levés : seul le périmètre (étape 2) et les
/// plafonds/anti-destruction (étapes 6-7) confinent.
fn capability_denial(scope: &Scope, action: &Action, lab: bool) -> Option<DenyReason> {
    if lab {
        return None;
    }
    let caps = &scope.capabilities;
    match action {
        // N1 toujours autorisé (recon libre, §1).
        Action::Recon { .. } => None,
        Action::Exploit { target, .. } => {
            if !caps.allows(Capability::Exploitation) {
                return Some(DenyReason::CapabilityDisabled(Capability::Exploitation));
            }
            if !hosts_contains(&caps.exploitation.allowed_hosts, *target) {
                return Some(DenyReason::HostNotAllowed);
            }
            None
        }
        Action::Crack { online, .. } => {
            if !caps.allows(Capability::Cracking) {
                return Some(DenyReason::CapabilityDisabled(Capability::Cracking));
            }
            if *online && !caps.cracking.online_spray {
                return Some(DenyReason::OnlineSprayNotAllowed);
            }
            None
        }
        Action::Emulate { technique, .. } => {
            if !caps.allows(Capability::Emulation) {
                return Some(DenyReason::CapabilityDisabled(Capability::Emulation));
            }
            if !techniques_contains(&caps.emulation.attack_techniques, technique) {
                return Some(DenyReason::TechniqueNotAllowed);
            }
            None
        }
    }
}

/// Étape 5 — l'action exige-t-elle une confirmation humaine ? Levée en labo.
fn confirmation_required(scope: &Scope, action: &Action, lab: bool) -> bool {
    if lab {
        return false;
    }
    match action {
        // Exploitation en mode `manual` : confirmation par cible.
        Action::Exploit { .. } => scope.capabilities.exploitation.mode == ExploitRunMode::Manual,
        // Spray en ligne : toujours interactif (risque de verrouillage).
        Action::Crack { online: true, .. } => true,
        _ => false,
    }
}

/// Compte visé par un spray en ligne, ou `None` pour toute autre action (seul le
/// spray en ligne compte dans `max_attempts_per_account`).
fn online_spray_account(action: &Action) -> Option<&str> {
    match action {
        Action::Crack { online: true, account: Some(account), .. } => Some(account.as_str()),
        _ => None,
    }
}

/// Vrai si une liste d'hôtes (IP littérales) contient `target`.
fn hosts_contains(list: &[String], target: IpAddr) -> bool {
    list.iter().any(|entry| host_eq(entry, target))
}

/// Vrai si l'un des CIDR de la liste contient `target`.
fn networks_contains(list: &[String], target: IpAddr) -> bool {
    list.iter().any(|cidr| ip_in_cidr(target, cidr))
}

/// Vrai si la liste de techniques ATT&CK contient `technique`.
fn techniques_contains(list: &[String], technique: &str) -> bool {
    list.iter().any(|entry| entry.as_str() == technique)
}

/// Vrai si la chaîne d'hôte `entry` (IP littérale) désigne `target`.
fn host_eq(entry: &str, target: IpAddr) -> bool {
    matches!(entry.parse::<IpAddr>(), Ok(ip) if ip == target)
}

/// Appartenance d'une IP à un CIDR « adresse/longueur ». Fail-safe : une entrée
/// mal formée ou d'une autre famille renvoie `false` (jamais d'autorisation par
/// défaut). Les CIDR du scope sont déjà validés en amont (`scope::Scope`).
fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    let Ok(base) = base.parse::<IpAddr>() else {
        return false;
    };
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(ip) & mask) == (u32::from(base) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(ip) & mask) == (u128::from(base) & mask)
        }
        // Familles différentes : une IPv4 n'est jamais dans un CIDR IPv6.
        _ => false,
    }
}

// --- Journalisation des décisions -------------------------------------------

/// Transforme une décision en entrée d'audit **journalisable** (§3.2, §3.3).
///
/// - `Allow` → action = verbe métier ([`Action::verb`]), résultat `"ok"` ;
/// - `Deny(r)` → action = `blocked_<code>` (cf. [`DenyReason::code`]), résultat
///   `"blocked"`.
///
/// Le niveau et la cible proviennent de l'action ; le mode (`standard`/`lab`)
/// est reporté tel quel. L'appelant (orchestrateur) écrit cet enregistrement
/// dans le journal chaîné — le gate reste **pur** (sans I/O).
#[must_use]
pub fn audit_record(
    action: &Action,
    decision: Decision,
    operator: impl Into<String>,
    mode: AuditMode,
) -> AuditRecord {
    let (verb, result) = match decision {
        Decision::Allow => (action.verb(), "ok".to_string()),
        Decision::Deny(reason) => (format!("blocked_{}", reason.code()), "blocked".to_string()),
    };
    let record = AuditRecord::new(
        operator,
        action.target().to_string(),
        verb,
        result,
        action.level(),
    );
    match mode {
        AuditMode::Standard => record,
        AuditMode::Lab => record.in_lab(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeDelta, TimeZone};

    /// Opérateur de référence : la même identité atteste et agit.
    const OP: &str = "operateur@example.test";

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    /// Instant « nominal » : dans la fenêtre d'engagement et dans `allowed_hours`.
    fn now_ok() -> DateTime<Utc> {
        at(2026, 6, 1, 12)
    }

    /// Scope de référence : exploitation (manual, non destructive, un hôte
    /// autorisé, 2 actions max), cracking (spray en ligne opt-in, 3
    /// tentatives/compte), émulation (T1021), débit 200 pps.
    const BASE: &str = "\
[engagement]
client = \"ACME Corp\"
reference = \"PENTEST-2026-014\"
authorized_by = \"DSI ACME\"
operator = \"operateur@example.test\"
valid_from = \"2026-01-01T00:00:00Z\"
valid_until = \"2027-12-31T23:59:59Z\"

[targets]
networks = [\"192.168.10.0/24\"]
hosts = [\"192.168.50.5\"]

[targets.exclusions]
hosts = [\"192.168.10.1\"]
networks = [\"192.168.10.240/28\"]

[constraints]
max_rate_pps = 200
allowed_hours = \"08:00-18:00\"

[capabilities]
recon = true

[capabilities.exploitation]
enabled = true
mode = \"manual\"
destructive_checks = false
allowed_hosts = [\"192.168.10.25\"]
max_actions = 2

[capabilities.cracking]
enabled = true
online_spray = true
max_attempts_per_account = 3

[capabilities.emulation]
enabled = true
attack_techniques = [\"T1021\"]
";

    fn scope() -> Scope {
        Scope::from_toml(BASE).unwrap()
    }

    /// Scope avec une variante textuelle appliquée (p. ex. activer/désactiver
    /// une capacité) — raccourci des nombreux cas négatifs.
    fn scope_with(from: &str, to: &str) -> Scope {
        Scope::from_toml(&BASE.replace(from, to)).unwrap()
    }

    /// Attestation cohérente avec le scope (même opérateur, même empreinte).
    fn attest(scope: &Scope) -> Attestation {
        Attestation::for_scope(scope, OP, "192.168.10.0/24")
    }

    // --- Fabriques d'actions ------------------------------------------------

    fn recon(target: &str) -> Action {
        Action::Recon { target: ip(target) }
    }

    fn exploit(target: &str, mode: ExploitMode) -> Action {
        Action::Exploit { target: ip(target), mode }
    }

    fn crack(target: &str, online: bool, account: Option<&str>) -> Action {
        Action::Crack {
            target: ip(target),
            online,
            account: account.map(String::from),
        }
    }

    fn emulate(target: &str, technique: &str) -> Action {
        Action::Emulate {
            target: ip(target),
            technique: technique.to_string(),
        }
    }

    // --- Fabriques de requêtes (opérateur = OP, instant nominal) ------------

    fn attested(att: &Attestation) -> Request<'_> {
        Request::new(now_ok(), OP).with_attestation(att)
    }

    fn attested_at(now: DateTime<Utc>, att: &Attestation) -> Request<'_> {
        Request::new(now, OP).with_attestation(att)
    }

    fn attested_confirmed(att: &Attestation) -> Request<'_> {
        Request::new(now_ok(), OP).with_attestation(att).confirmed()
    }

    fn attested_prog<'a>(att: &'a Attestation, prog: &'a Progress) -> Request<'a> {
        Request::new(now_ok(), OP).with_attestation(att).with_progress(prog)
    }

    fn full<'a>(att: &'a Attestation, prog: &'a Progress) -> Request<'a> {
        Request::new(now_ok(), OP).with_attestation(att).with_progress(prog).confirmed()
    }

    /// Progression recon aboutie sur un hôte (débloque les pré-conditions N≥2).
    fn recon_done(target: &str) -> Progress {
        let mut p = Progress::new();
        p.record(ip(target), Capability::Recon);
        p
    }

    // --- Étape 0 : périmètre établi -----------------------------------------

    #[test]
    fn etape0_sans_perimetre_tout_est_refuse() {
        let mut gate = Gate::without_perimeter();
        let req = Request::new(now_ok(), OP);
        let out = gate.check(&recon("192.168.10.25"), &req);
        assert_eq!(out, Decision::Deny(DenyReason::NoScope));
    }

    // --- Étape 1 : validation temporelle ------------------------------------

    #[test]
    fn etape1_recon_dans_la_fenetre_autorisee() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        assert_eq!(gate.check(&recon("192.168.10.25"), &attested(&att)), Decision::Allow);
    }

    #[test]
    fn etape1_hors_fenetre_temporelle_refuse() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // Avant valid_from (2026-01-01) → NotYetValid.
        let req = attested_at(at(2025, 6, 1, 12), &att);
        assert_eq!(
            gate.check(&recon("192.168.10.25"), &req),
            Decision::Deny(DenyReason::OutsideWindow(TemporalStatus::NotYetValid))
        );
    }

    #[test]
    fn etape1_hors_fenetre_horaire_refuse() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // 20h UTC hors de 08:00-18:00.
        let req = attested_at(at(2026, 6, 1, 20), &att);
        assert_eq!(
            gate.check(&recon("192.168.10.25"), &req),
            Decision::Deny(DenyReason::OutsideHours)
        );
    }

    // --- Étape 2 : filtre de cible ------------------------------------------

    #[test]
    fn etape2_cible_dans_le_perimetre_autorisee() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // 192.168.50.5 est un hôte listé explicitement.
        assert_eq!(gate.check(&recon("192.168.50.5"), &attested(&att)), Decision::Allow);
    }

    #[test]
    fn etape2_cible_hors_perimetre_refuse() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        assert_eq!(
            gate.check(&recon("10.0.0.1"), &attested(&att)),
            Decision::Deny(DenyReason::OutOfScope)
        );
    }

    #[test]
    fn etape2_cible_exclue_refusee_malgre_le_reseau() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // 192.168.10.1 est dans 192.168.10.0/24 mais explicitement exclu.
        assert_eq!(
            gate.check(&recon("192.168.10.1"), &attested(&att)),
            Decision::Deny(DenyReason::Excluded)
        );
    }

    #[test]
    fn etape2_exclusion_par_sous_reseau() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // 192.168.10.241 ∈ 192.168.10.240/28 (exclusion réseau).
        assert_eq!(
            gate.check(&recon("192.168.10.241"), &attested(&att)),
            Decision::Deny(DenyReason::Excluded)
        );
    }

    // --- Étape 3 : filtre de capacité ---------------------------------------

    #[test]
    fn etape3_exploitation_sur_hote_autorise() {
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = exploit("192.168.10.25", ExploitMode::Validate);
        assert_eq!(gate.check(&action, &full(&att, &prog)), Decision::Allow);
    }

    #[test]
    fn negatif_exploitation_hors_allowed_hosts_refuse() {
        // Contrat §10.4 : exploiter un hôte en scope mais hors allowed_hosts.
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.10.30");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // 192.168.10.30 est en scope mais absent de allowed_hosts.
        let action = exploit("192.168.10.30", ExploitMode::Validate);
        assert_eq!(
            gate.check(&action, &full(&att, &prog)),
            Decision::Deny(DenyReason::HostNotAllowed)
        );
    }

    #[test]
    fn negatif_capacite_desactivee_rend_inatteignable() {
        // Contrat §10.4 : capacité désactivée ⇒ inatteignable quelle que soit la
        // commande. On retire l'exploitation du scope.
        let sc = scope_with(
            "[capabilities.exploitation]\nenabled = true",
            "[capabilities.exploitation]\nenabled = false",
        );
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = exploit("192.168.10.25", ExploitMode::Validate);
        assert_eq!(
            gate.check(&action, &full(&att, &prog)),
            Decision::Deny(DenyReason::CapabilityDisabled(Capability::Exploitation))
        );
    }

    #[test]
    fn negatif_technique_attack_non_listee_refuse() {
        // Contrat §10.4 : technique ATT&CK non listée → refus.
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // T1570 n'est pas listée (seule T1021 autorisée).
        let action = emulate("192.168.10.25", "T1570");
        assert_eq!(
            gate.check(&action, &attested_prog(&att, &prog)),
            Decision::Deny(DenyReason::TechniqueNotAllowed)
        );
    }

    #[test]
    fn etape3_emulation_technique_listee_autorisee() {
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = emulate("192.168.10.25", "T1021");
        assert_eq!(gate.check(&action, &attested_prog(&att, &prog)), Decision::Allow);
    }

    #[test]
    fn negatif_spray_en_ligne_sans_optin_refuse() {
        let sc = scope_with("online_spray = true", "online_spray = false");
        let att = attest(&sc);
        let prog = recon_done("192.168.50.5");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = crack("192.168.50.5", true, Some("admin"));
        assert_eq!(
            gate.check(&action, &full(&att, &prog)),
            Decision::Deny(DenyReason::OnlineSprayNotAllowed)
        );
    }

    #[test]
    fn etape3_crack_hors_ligne_autorise_sans_confirmation() {
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.50.5");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // Pas de confirmation : le craquage hors-ligne n'en exige pas.
        let action = crack("192.168.50.5", false, None);
        assert_eq!(gate.check(&action, &attested_prog(&att, &prog)), Decision::Allow);
    }

    // --- Étape 4 : pré-conditions -------------------------------------------

    #[test]
    fn negatif_exploitation_sans_precondition_refuse() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // Aucune progression recon enregistrée sur la cible.
        let action = exploit("192.168.10.25", ExploitMode::Validate);
        assert_eq!(
            gate.check(&action, &attested_confirmed(&att)),
            Decision::Deny(DenyReason::PreconditionMissing)
        );
    }

    #[test]
    fn etape4_precondition_sur_une_autre_cible_ne_compte_pas() {
        let sc = scope();
        let att = attest(&sc);
        // Recon aboutie sur un AUTRE hôte que la cible.
        let prog = recon_done("192.168.50.5");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = exploit("192.168.10.25", ExploitMode::Validate);
        assert_eq!(
            gate.check(&action, &full(&att, &prog)),
            Decision::Deny(DenyReason::PreconditionMissing)
        );
    }

    #[test]
    fn etape4_recon_ne_demande_aucune_precondition() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // Pas de progression : la recon (N1) passe quand même.
        assert_eq!(gate.check(&recon("192.168.10.25"), &attested(&att)), Decision::Allow);
    }

    // --- Étape 5 : confirmation humaine -------------------------------------

    #[test]
    fn negatif_exploitation_manual_sans_confirmation_refuse() {
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // attested_prog ne confirme pas → refus en mode manual.
        let action = exploit("192.168.10.25", ExploitMode::Validate);
        assert_eq!(
            gate.check(&action, &attested_prog(&att, &prog)),
            Decision::Deny(DenyReason::ConfirmationRequired)
        );
    }

    #[test]
    fn etape5_mode_auto_ne_demande_pas_de_confirmation() {
        let sc = scope_with("mode = \"manual\"", "mode = \"auto\"");
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // Mode auto : pas de confirmation, et pourtant autorisé.
        let action = exploit("192.168.10.25", ExploitMode::Validate);
        assert_eq!(gate.check(&action, &attested_prog(&att, &prog)), Decision::Allow);
    }

    // --- Étape 6 : garde anti-destruction -----------------------------------

    #[test]
    fn negatif_charge_destructrice_refusee() {
        // destructive_checks = false (BASE) ⇒ seul Validate passe.
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = exploit("192.168.10.25", ExploitMode::Exploit);
        assert_eq!(
            gate.check(&action, &full(&att, &prog)),
            Decision::Deny(DenyReason::Destructive)
        );
    }

    #[test]
    fn etape6_exploit_reel_autorise_si_destructive_checks_true() {
        let sc = scope_with("destructive_checks = false", "destructive_checks = true");
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = exploit("192.168.10.25", ExploitMode::Exploit);
        assert_eq!(gate.check(&action, &full(&att, &prog)), Decision::Allow);
    }

    // --- Étape 7 : plafonds -------------------------------------------------

    #[test]
    fn negatif_max_actions_depasse_refuse() {
        // max_actions = 2 : deux exploitations passent, la 3e est refusée.
        let sc = scope_with("destructive_checks = false", "destructive_checks = true");
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = exploit("192.168.10.25", ExploitMode::Validate);
        let req = full(&att, &prog);
        assert_eq!(gate.check(&action, &req), Decision::Allow);
        assert_eq!(gate.check(&action, &req), Decision::Allow);
        let third = gate.check(&action, &req);
        assert_eq!(third, Decision::Deny(DenyReason::MaxActionsExceeded));
    }

    #[test]
    fn negatif_max_attempts_par_compte_depasse_refuse() {
        // max_attempts_per_account = 3 : trois sprays sur le même compte passent,
        // le 4e est refusé ; un autre compte reste libre.
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.50.5");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = full(&att, &prog);
        let admin = crack("192.168.50.5", true, Some("admin"));
        for _ in 0..3 {
            assert_eq!(gate.check(&admin, &req), Decision::Allow);
        }
        let fourth = gate.check(&admin, &req);
        assert_eq!(fourth, Decision::Deny(DenyReason::MaxAttemptsExceeded));
        // Un autre compte dispose de son propre quota.
        let backup = crack("192.168.50.5", true, Some("backup"));
        assert_eq!(gate.check(&backup, &req), Decision::Allow);
    }

    #[test]
    fn negatif_max_rate_pps_depasse_puis_recharge() {
        // Débit 2 pps, seau initialement plein (capacité 2).
        let sc = scope_with("max_rate_pps = 200", "max_rate_pps = 2");
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let action = recon("192.168.10.25");
        let t0 = now_ok();
        let req0 = attested_at(t0, &att);
        // Deux jetons disponibles au même instant.
        assert_eq!(gate.check(&action, &req0), Decision::Allow);
        assert_eq!(gate.check(&action, &req0), Decision::Allow);
        // Le 3e au même instant épuise le seau.
        let third = gate.check(&action, &req0);
        assert_eq!(third, Decision::Deny(DenyReason::RateExceeded));
        // Une seconde plus tard, le seau s'est rempli (2 pps) → de nouveau permis.
        let req1 = attested_at(t0 + TimeDelta::seconds(1), &att);
        assert_eq!(gate.check(&action, &req1), Decision::Allow);
    }

    #[test]
    fn etape7_refus_amont_ne_consomme_pas_le_debit() {
        // Un refus (hors scope) ne doit pas entamer le seau : la cible valide
        // suivante au même instant reste autorisée malgré 5 refus.
        let sc = scope_with("max_rate_pps = 200", "max_rate_pps = 1");
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = attested_at(now_ok(), &att);
        let hors_scope = recon("10.0.0.1");
        for _ in 0..5 {
            assert_eq!(gate.check(&hors_scope, &req), Decision::Deny(DenyReason::OutOfScope));
        }
        // Le seul jeton est encore là pour une action légitime.
        assert_eq!(gate.check(&recon("192.168.10.25"), &req), Decision::Allow);
    }

    // --- Étape 8 : attestation ----------------------------------------------

    #[test]
    fn negatif_sans_attestation_refuse() {
        let sc = scope();
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now_ok(), OP); // pas d'attestation
        assert_eq!(
            gate.check(&recon("192.168.10.25"), &req),
            Decision::Deny(DenyReason::AttestationMissing)
        );
    }

    #[test]
    fn negatif_attestation_pour_un_autre_scope_refuse() {
        // Attestation dont l'empreinte ne correspond pas au scope courant.
        let other = scope_with("ACME Corp", "AUTRE Corp");
        let att = attest(&other); // empreinte de l'AUTRE scope
        let sc = scope();
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        assert_eq!(
            gate.check(&recon("192.168.10.25"), &attested(&att)),
            Decision::Deny(DenyReason::AttestationMissing)
        );
    }

    #[test]
    fn negatif_attestation_autre_operateur_refuse() {
        // Attestation signée par un autre opérateur que celui qui agit.
        let sc = scope();
        let att = Attestation::for_scope(&sc, "intrus@example.test", "192.168.10.0/24");
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // La requête agit sous OP ; l'attestation couvre « intrus » → refus.
        assert_eq!(
            gate.check(&recon("192.168.10.25"), &attested(&att)),
            Decision::Deny(DenyReason::AttestationMissing)
        );
    }

    // --- Ordre des étapes ---------------------------------------------------

    #[test]
    fn ordre_des_etapes_le_premier_echec_prime() {
        // Action hors fenêtre temporelle ET hors scope : la raison renvoyée est
        // celle de l'étape 1 (antérieure à l'étape 2).
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        // Hors fenêtre temporelle (2025 < valid_from) ET hors scope (10.0.0.1).
        let req = attested_at(at(2025, 1, 1, 12), &att);
        let out = gate.check(&recon("10.0.0.1"), &req);
        assert_eq!(out, Decision::Deny(DenyReason::OutsideWindow(TemporalStatus::NotYetValid)));
    }

    // --- Spécificité du mode labo (§3.2 note) -------------------------------

    #[test]
    fn labo_ouvre_la_capacite_et_leve_la_confirmation() {
        // Mode labo : exploitation autorisée même hors allowed_hosts et sans
        // confirmation, tant qu'on reste dans le périmètre.
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.10.30");
        let mut gate = Gate::with_scope(sc, AuditMode::Lab);
        // Hors allowed_hosts, pas de confirmation, pourtant autorisé en labo.
        let action = exploit("192.168.10.30", ExploitMode::Validate);
        assert_eq!(gate.check(&action, &attested_prog(&att, &prog)), Decision::Allow);
    }

    #[test]
    fn labo_garde_le_confinement_au_perimetre() {
        // Le labo élargit les capacités DANS le périmètre, jamais le périmètre.
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("10.0.0.1");
        let mut gate = Gate::with_scope(sc, AuditMode::Lab);
        let action = exploit("10.0.0.1", ExploitMode::Validate); // hors périmètre
        assert_eq!(
            gate.check(&action, &attested_prog(&att, &prog)),
            Decision::Deny(DenyReason::OutOfScope)
        );
    }

    #[test]
    fn labo_garde_l_anti_destruction_et_les_plafonds() {
        // destructive_checks = false reste actif en labo (sûreté conservée).
        let sc = scope();
        let att = attest(&sc);
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Lab);
        let action = exploit("192.168.10.25", ExploitMode::Exploit); // charge destructrice
        assert_eq!(
            gate.check(&action, &attested_prog(&att, &prog)),
            Decision::Deny(DenyReason::Destructive)
        );
    }

    #[test]
    fn labo_exige_toujours_une_attestation() {
        // L'attestation (étape 8) reste requise en labo (le `lab start` atteste).
        let sc = scope();
        let prog = recon_done("192.168.10.25");
        let mut gate = Gate::with_scope(sc, AuditMode::Lab);
        let req = Request::new(now_ok(), OP).with_progress(&prog); // sans attestation
        let action = exploit("192.168.10.25", ExploitMode::Validate);
        let out = gate.check(&action, &req);
        assert_eq!(out, Decision::Deny(DenyReason::AttestationMissing));
    }

    // --- Journalisation des décisions (blocked_*) ---------------------------

    #[test]
    fn audit_refus_produit_une_action_blocked() {
        let action = exploit("192.168.10.30", ExploitMode::Validate);
        let decision = Decision::Deny(DenyReason::HostNotAllowed);
        let rec = audit_record(&action, decision, OP, AuditMode::Standard);
        assert_eq!(rec.action, "blocked_allowed_hosts");
        assert_eq!(rec.result, "blocked");
        assert_eq!(rec.target, "192.168.10.30");
        assert_eq!(rec.level, CapabilityLevel::Exploitation);
        assert_eq!(rec.mode, AuditMode::Standard);
    }

    #[test]
    fn audit_autorisation_produit_le_verbe_metier() {
        let action = emulate("192.168.10.25", "T1021");
        let rec = audit_record(&action, Decision::Allow, OP, AuditMode::Lab);
        assert_eq!(rec.action, "emulation.T1021");
        assert_eq!(rec.result, "ok");
        assert_eq!(rec.level, CapabilityLevel::Emulation);
        assert_eq!(rec.mode, AuditMode::Lab);
    }

    #[test]
    fn audit_chaque_raison_a_un_code_blocked_distinct() {
        // Chaque refus se journalise en blocked_<code> : les codes sont uniques.
        let reasons = [
            DenyReason::NoScope,
            DenyReason::OutsideWindow(TemporalStatus::Expired),
            DenyReason::OutsideHours,
            DenyReason::OutOfScope,
            DenyReason::Excluded,
            DenyReason::CapabilityDisabled(Capability::Cracking),
            DenyReason::HostNotAllowed,
            DenyReason::OnlineSprayNotAllowed,
            DenyReason::TechniqueNotAllowed,
            DenyReason::PreconditionMissing,
            DenyReason::ConfirmationRequired,
            DenyReason::Destructive,
            DenyReason::RateExceeded,
            DenyReason::MaxActionsExceeded,
            DenyReason::MaxAttemptsExceeded,
            DenyReason::AttestationMissing,
        ];
        let mut codes: Vec<&str> = reasons.iter().map(DenyReason::code).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "codes de refus en double");
    }

    #[test]
    fn decision_accesseurs() {
        assert!(Decision::Allow.is_allowed());
        assert_eq!(Decision::Allow.reason(), None);
        let denied = Decision::Deny(DenyReason::NoScope);
        assert!(!denied.is_allowed());
        assert_eq!(denied.reason(), Some(DenyReason::NoScope));
    }

    // --- Helper bas niveau : appartenance CIDR ------------------------------

    #[test]
    fn ip_in_cidr_v4_et_v6() {
        assert!(ip_in_cidr(ip("192.168.10.25"), "192.168.10.0/24"));
        assert!(!ip_in_cidr(ip("192.168.11.25"), "192.168.10.0/24"));
        assert!(ip_in_cidr(ip("10.20.30.40"), "0.0.0.0/0")); // /0 = tout l'espace v4
        assert!(ip_in_cidr(ip("2001:db8::1"), "2001:db8::/32"));
        assert!(!ip_in_cidr(ip("2001:dead::1"), "2001:db8::/32"));
        // Familles croisées : jamais d'appartenance.
        assert!(!ip_in_cidr(ip("192.168.10.25"), "2001:db8::/32"));
        assert!(!ip_in_cidr(ip("2001:db8::1"), "192.168.10.0/24"));
        // Entrées mal formées → false (fail-safe).
        assert!(!ip_in_cidr(ip("192.168.10.25"), "192.168.10.0"));
        assert!(!ip_in_cidr(ip("192.168.10.25"), "pas/un/cidr"));
    }
}
