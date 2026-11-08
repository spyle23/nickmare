//! Abstraction du moteur de craquage N3 et ses **mocks** déterministes, plus
//! l'orchestration confinée par le gate (issue #21, cf.
//! `docs/ARCHITECTURE.md` §4, §5, §9 Phase 7, §11.1, US-F1/F2/F3).
//!
//! # Deux capacités, cadrées par le gate
//!
//! - [`CrackEngine::crack_offline`] — craquage **hors ligne** de hashes capturés
//!   (défaut, US-F1) : délégué à hashcat/John, rend un [`CrackReport`] dont les
//!   secrets sont **masqués** ([`MaskedSecret`]). La valeur livrable est le
//!   [`CrackResult`](nickmare_core::model::CrackResult) — des **statistiques** et
//!   un verdict de politique, jamais les mots de passe en clair.
//! - [`SprayEngine::spray_once`] — spray **en ligne** (US-F3), une capacité
//!   offensive **bornée** : désactivée par défaut, activable seulement via l'opt-in
//!   `online_spray` + confirmation humaine, et strictement plafonnée par
//!   `max_attempts_per_account` (anti-lockout). Tout cela est appliqué par le
//!   **gate** (le « mur », §3.2/§4), jamais par ce module.
//!
//! # Masquage des secrets par défaut (§1, §7, US-F1)
//!
//! [`MaskedSecret`] n'expose **jamais** le clair dans `Debug`, `Display` ni
//! `serde` : il ne fuit ni dans un log, ni dans le rapport. Le clair n'est révélé
//! que derrière une décision explicite et tracée ([`SecretDisclosure`]).
//!
//! # Mocks déterministes (aucun craquage réel en CI, §10.2)
//!
//! [`MockCrackEngine`] et [`MockSprayEngine`] rejouent des verdicts déterministes
//! **sans hashcat, sans John, sans réseau et sans rien craquer de réel**.
//! Injectables partout où un `&dyn CrackEngine` / `&dyn SprayEngine` est attendu.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize, Serializer};

use nickmare_core::audit::AuditRecord;
use nickmare_core::gate::{audit_record, Action, Decision, DenyReason, Gate, Request};
use nickmare_core::model::CrackResult;

use crate::policy::{evaluate, PasswordPolicy};

// --- Erreur -----------------------------------------------------------------

/// Erreur d'une opération de craquage. Les retours d'un moteur externe sont
/// faillibles (§12) : jamais de `panic`, tout remonte via `Result`. Aucun message
/// ne porte de secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrackError {
    /// Outil (hashcat/John) absent ou injoignable → niveau cracking **désactivé
    /// proprement** (§5).
    ToolUnavailable(String),
    /// L'outil a tourné mais a échoué (code de sortie non nul, erreur d'exécution).
    ToolFailed(String),
    /// Sortie de l'outil illisible (format inattendu).
    Parse(String),
    /// Erreur d'E/S locale (fichier temporaire de hashes).
    Io(String),
    /// Usage incohérent, détail tracé (jamais de secret).
    Other(String),
}

impl fmt::Display for CrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrackError::ToolUnavailable(msg) => {
                write!(f, "moteur de craquage indisponible : {msg}")
            }
            CrackError::ToolFailed(msg) => write!(f, "échec du moteur de craquage : {msg}"),
            CrackError::Parse(msg) => write!(f, "sortie de craquage illisible : {msg}"),
            CrackError::Io(msg) => write!(f, "fichier temporaire de hashes : {msg}"),
            CrackError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for CrackError {}

// --- Type de hash & mapping des modes ---------------------------------------

/// Type de hash supporté, avec le **mapping** vers le mode hashcat et le format
/// John (US-F1). Couvre les quatre familles exigées : NTLM, Kerberos, hashes Unix
/// et handshake WPA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashType {
    /// NTLM (comptes Windows).
    Ntlm,
    /// Kerberos (ticket TGS-REP / AS-REP).
    Kerberos,
    /// Hash Unix (`sha512crypt`, `/etc/shadow`).
    Unix,
    /// Handshake WPA/WPA2 (PMKID + EAPOL).
    Wpa,
}

impl HashType {
    /// Mode hashcat (`-m`) correspondant.
    #[must_use]
    pub fn hashcat_mode(self) -> u32 {
        match self {
            HashType::Ntlm => 1000,
            HashType::Kerberos => 13100,
            HashType::Unix => 1800,
            HashType::Wpa => 22000,
        }
    }

    /// Format John (`--format=`) correspondant.
    #[must_use]
    pub fn john_format(self) -> &'static str {
        match self {
            HashType::Ntlm => "nt",
            HashType::Kerberos => "krb5tgs",
            HashType::Unix => "sha512crypt",
            HashType::Wpa => "wpapsk",
        }
    }

    /// Libellé stable pour le rapport ([`CrackResult::hash_type`]).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            HashType::Ntlm => "NTLM",
            HashType::Kerberos => "krb5",
            HashType::Unix => "sha512crypt",
            HashType::Wpa => "WPA",
        }
    }

    /// Analyse un libellé (insensible à la casse). Inconnu → `None` (fail-safe :
    /// on ne devine pas un mode de craquage).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ntlm" | "nt" => Some(HashType::Ntlm),
            "kerberos" | "krb5" | "krb5tgs" | "krb5asrep" => Some(HashType::Kerberos),
            "unix" | "sha512crypt" | "shadow" => Some(HashType::Unix),
            "wpa" | "wpa2" | "wpapsk" | "handshake" => Some(HashType::Wpa),
            _ => None,
        }
    }
}

// --- Secret masqué ----------------------------------------------------------

/// Un mot de passe craqué, **masqué par défaut**. Il ne fuit jamais dans `Debug`,
/// `Display` ni `serde` (US-F1) : seuls sa longueur et un masque sont observables.
/// Le clair n'est révélé que derrière une décision explicite ([`SecretDisclosure`]).
#[derive(Clone, PartialEq, Eq)]
pub struct MaskedSecret {
    secret: String,
}

impl MaskedSecret {
    /// Enveloppe un clair craqué. Il reste masqué tant qu'il n'est pas révélé via
    /// [`MaskedSecret::reveal`].
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    /// Longueur (en caractères) du clair — observable sans le révéler.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secret.chars().count()
    }

    /// Vrai si le clair est vide (mot de passe vide craqué).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }

    /// Révèle le clair — **uniquement** derrière une décision explicite et tracée
    /// (`SecretDisclosure`, opt-in human-confirmed). Sans cette décision, le clair
    /// reste inaccessible ; il n'entre jamais par défaut dans un log ou un rapport.
    #[must_use]
    pub fn reveal(&self, _disclosure: &SecretDisclosure) -> &str {
        &self.secret
    }

    /// Accès **interne au crate** au clair, pour l'évaluation de politique
    /// (détection de patterns faibles). Jamais exporté hors du crate : le clair ne
    /// franchit pas la frontière du module.
    pub(crate) fn expose(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for MaskedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Le clair n'apparaît jamais dans les traces ; seule la longueur fuit.
        write!(f, "MaskedSecret(**** len={})", self.len())
    }
}

impl fmt::Display for MaskedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("****")
    }
}

impl Serialize for MaskedSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Le rapport client ne reçoit que le masque, jamais le clair (US-F1).
        serializer.serialize_str("****")
    }
}

/// Décision **explicite** d'afficher les secrets en clair (opt-in human-confirmed,
/// audité). Sa seule existence constitue le « drapeau explicite + confirmation »
/// exigé avant toute révélation (US-F1) : sans elle, [`MaskedSecret::reveal`] est
/// inappelable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretDisclosure {
    operator: String,
}

impl SecretDisclosure {
    /// Enregistre la décision humaine de révéler les secrets, attribuée à un
    /// opérateur (tracée).
    #[must_use]
    pub fn confirmed_by(operator: impl Into<String>) -> Self {
        Self {
            operator: operator.into(),
        }
    }

    /// Opérateur ayant pris la décision de révélation.
    #[must_use]
    pub fn operator(&self) -> &str {
        &self.operator
    }
}

// --- Requête & rapport de craquage hors ligne -------------------------------

/// Un hash à craquer : le compte associé et le hash brut (le hash est la donnée
/// d'entrée, pas un secret en clair — il n'est jamais restitué dans le rapport).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashEntry {
    /// Compte associé au hash (login).
    pub account: String,
    /// Hash brut à craquer.
    pub hash: String,
}

impl HashEntry {
    /// Construit une entrée (compte, hash).
    #[must_use]
    pub fn new(account: impl Into<String>, hash: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            hash: hash.into(),
        }
    }
}

/// Requête de craquage **hors ligne**. Décrit l'origine de la capture, le type de
/// hash (→ mapping de mode) et les hashes à craquer. `target` ancre l'action au
/// périmètre attesté (confinement par le gate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrackRequest {
    /// Hôte d'où proviennent les hashes (confiné au périmètre par le gate).
    pub target: IpAddr,
    /// Libellé d'origine de la capture (ex. `"dump NTDS lab"`).
    pub source: String,
    /// Type de hash (détermine le mode hashcat / le format John).
    pub hash_type: HashType,
    /// Hashes à craquer.
    pub hashes: Vec<HashEntry>,
    /// Opérateur à l'origine de l'action (tracé).
    pub operator: String,
}

impl CrackRequest {
    /// Requête vide (aucun hash) pour une origine et un type donnés.
    #[must_use]
    pub fn new(
        target: IpAddr,
        source: impl Into<String>,
        hash_type: HashType,
        operator: impl Into<String>,
    ) -> Self {
        Self {
            target,
            source: source.into(),
            hash_type,
            hashes: Vec::new(),
            operator: operator.into(),
        }
    }

    /// Ajoute une entrée à craquer (chaînage de construction).
    #[must_use]
    pub fn with_hash(mut self, entry: HashEntry) -> Self {
        self.hashes.push(entry);
        self
    }

    /// Remplace l'ensemble des hashes à craquer.
    #[must_use]
    pub fn with_hashes(mut self, hashes: Vec<HashEntry>) -> Self {
        self.hashes = hashes;
        self
    }
}

/// Un hash recouvré : le compte + le clair **masqué**. Le clair n'y est accessible
/// que via [`MaskedSecret::reveal`] (décision explicite).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recovered {
    /// Compte dont le mot de passe a été recouvré.
    pub account: String,
    /// Mot de passe recouvré, **masqué** par défaut.
    pub secret: MaskedSecret,
}

impl Recovered {
    /// Construit un recouvrement (compte, secret masqué).
    #[must_use]
    pub fn new(account: impl Into<String>, secret: MaskedSecret) -> Self {
        Self {
            account: account.into(),
            secret,
        }
    }
}

/// Rapport **interne** d'un craquage hors ligne : combien de hashes tentés, et les
/// comptes recouvrés (secrets masqués). Il n'est **pas** le livrable client ; on en
/// dérive un [`CrackResult`](nickmare_core::model::CrackResult) — des statistiques
/// et un verdict de politique — via [`CrackReport::to_crack_result`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrackReport {
    /// Type de hash craqué.
    pub hash_type: HashType,
    /// Origine de la capture.
    pub source: String,
    /// Nombre de hashes soumis au craquage.
    pub attempted: u64,
    /// Comptes recouvrés (secrets masqués).
    pub recovered: Vec<Recovered>,
}

impl CrackReport {
    /// Rapport pour un type/origine et un nombre de hashes tentés, sans
    /// recouvrement.
    #[must_use]
    pub fn new(hash_type: HashType, source: impl Into<String>, attempted: u64) -> Self {
        Self {
            hash_type,
            source: source.into(),
            attempted,
            recovered: Vec::new(),
        }
    }

    /// Attache les comptes recouvrés.
    #[must_use]
    pub fn with_recovered(mut self, recovered: Vec<Recovered>) -> Self {
        self.recovered = recovered;
        self
    }

    /// Nombre de hashes effectivement craqués.
    #[must_use]
    pub fn cracked(&self) -> u64 {
        self.recovered.len() as u64
    }

    /// Dérive le **livrable client** : des statistiques (tentés, craqués) et un
    /// verdict de politique ([`PolicyVerdict`](nickmare_core::model::PolicyVerdict))
    /// avec les patterns faibles — **jamais** de clair (US-F1/F2).
    #[must_use]
    pub fn to_crack_result(&self, policy: &PasswordPolicy) -> CrackResult {
        let assessment = evaluate(self, policy);
        CrackResult {
            source: self.source.clone(),
            hash_type: self.hash_type.label().to_string(),
            attempted: self.attempted,
            cracked: self.cracked(),
            weak_patterns: assessment.weak_patterns,
            policy_verdict: assessment.verdict,
        }
    }
}

// --- Le trait de craquage hors ligne + mock ---------------------------------

/// Abstraction du moteur de craquage **hors ligne** (N3). À n'actionner
/// qu'**après** un `Decision::Allow` du gate (§4) : le trait n'embarque aucun
/// garde-fou, il orchestre et trace un moteur externe (hashcat/John).
///
/// `Send + Sync` pour l'usage concurrent sous `tokio` et en objet de trait
/// (`&dyn CrackEngine`).
#[async_trait]
pub trait CrackEngine: Send + Sync {
    /// Craque hors ligne les hashes de `request` et rend un rapport (secrets
    /// masqués). À n'appeler qu'après un `Allow` du gate pour une
    /// `Action::Crack { online: false, .. }`.
    async fn crack_offline(&self, request: &CrackRequest) -> Result<CrackReport, CrackError>;
}

/// Moteur mock de craquage hors ligne : rejoue un dictionnaire **hash → clair**
/// déterministe, **sans hashcat, sans John, sans réseau**. Un hash non programmé
/// n'est simplement pas recouvré (fail-safe : on n'invente aucun secret).
#[derive(Debug, Clone, Default)]
pub struct MockCrackEngine {
    cracked: HashMap<String, String>,
}

impl MockCrackEngine {
    /// Moteur mock vide (aucun hash connu).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Programme un couple (hash, clair) recouvrable (chaînage de construction).
    #[must_use]
    pub fn with_cracked(mut self, hash: impl Into<String>, plaintext: impl Into<String>) -> Self {
        self.cracked.insert(hash.into(), plaintext.into());
        self
    }
}

#[async_trait]
impl CrackEngine for MockCrackEngine {
    async fn crack_offline(&self, request: &CrackRequest) -> Result<CrackReport, CrackError> {
        let mut recovered = Vec::new();
        for entry in &request.hashes {
            if let Some(plain) = self.cracked.get(&entry.hash) {
                let secret = MaskedSecret::new(plain.clone());
                recovered.push(Recovered::new(entry.account.as_str(), secret));
            }
        }
        let attempted = request.hashes.len() as u64;
        let report = CrackReport::new(request.hash_type, request.source.clone(), attempted)
            .with_recovered(recovered);
        Ok(report)
    }
}

// --- Spray en ligne (capacité offensive bornée) + mock ----------------------

/// Requête d'un spray **en ligne** sur un compte. Le caractère borné (opt-in,
/// confirmation, plafond anti-lockout) est appliqué par le gate, pas ici.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SprayRequest {
    /// Hôte visé (confiné au périmètre par le gate).
    pub target: IpAddr,
    /// Compte visé (clé du plafond `max_attempts_per_account`).
    pub account: String,
    /// Opérateur à l'origine de l'action (tracé).
    pub operator: String,
}

impl SprayRequest {
    /// Construit une requête de spray.
    #[must_use]
    pub fn new(target: IpAddr, account: impl Into<String>, operator: impl Into<String>) -> Self {
        Self {
            target,
            account: account.into(),
            operator: operator.into(),
        }
    }
}

/// Résultat d'**une** tentative de spray : trouvé ou non, secret masqué si trouvé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SprayReport {
    /// Compte visé.
    pub account: String,
    /// Vrai si un mot de passe valide a été trouvé.
    pub found: bool,
    /// Mot de passe trouvé, **masqué** (présent seulement si `found`).
    pub secret: Option<MaskedSecret>,
}

impl SprayReport {
    /// Tentative infructueuse.
    #[must_use]
    pub fn not_found(account: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            found: false,
            secret: None,
        }
    }

    /// Tentative réussie, secret masqué.
    #[must_use]
    pub fn found(account: impl Into<String>, secret: MaskedSecret) -> Self {
        Self {
            account: account.into(),
            found: true,
            secret: Some(secret),
        }
    }
}

/// Abstraction d'**une** tentative de spray en ligne (N3). À n'actionner
/// qu'**après** un `Decision::Allow` du gate, qui applique l'opt-in, la
/// confirmation et le plafond anti-lockout.
#[async_trait]
pub trait SprayEngine: Send + Sync {
    /// Effectue une tentative de spray sur le compte de `request`.
    async fn spray_once(&self, request: &SprayRequest) -> Result<SprayReport, CrackError>;
}

/// Moteur mock de spray : rejoue un dictionnaire **compte → clair** déterministe,
/// sans aucune I/O réseau. Un compte non programmé rend `not_found`.
#[derive(Debug, Clone, Default)]
pub struct MockSprayEngine {
    found: HashMap<String, String>,
}

impl MockSprayEngine {
    /// Moteur mock vide (aucun compte trouvable).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Programme un couple (compte, clair) trouvable (chaînage de construction).
    #[must_use]
    pub fn with_found(mut self, account: impl Into<String>, plaintext: impl Into<String>) -> Self {
        self.found.insert(account.into(), plaintext.into());
        self
    }
}

#[async_trait]
impl SprayEngine for MockSprayEngine {
    async fn spray_once(&self, request: &SprayRequest) -> Result<SprayReport, CrackError> {
        let account = request.account.as_str();
        match self.found.get(&request.account) {
            Some(plain) => {
                let secret = MaskedSecret::new(plain.clone());
                Ok(SprayReport::found(account, secret))
            }
            None => Ok(SprayReport::not_found(account)),
        }
    }
}

// --- Orchestration confinée au gate -----------------------------------------

/// Issue d'un passage **gate → moteur** pour un craquage hors ligne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineOutcome {
    /// Refusé par le gate : le moteur n'a **pas** tourné. Porte la raison typée et
    /// l'entrée d'audit `blocked_*`.
    Blocked {
        /// Raison du refus (premier contrôle échoué, §3.2).
        reason: DenyReason,
        /// Entrée d'audit `blocked_<code>` à consigner.
        audit: AuditRecord,
    },
    /// Autorisé et exécuté : statistiques + verdict de politique, et l'audit `ok`.
    Done {
        /// Livrable client : statistiques + verdict (jamais de clair).
        result: CrackResult,
        /// Entrée d'audit du verbe métier (`crack.offline`).
        audit: AuditRecord,
    },
}

impl OfflineOutcome {
    /// Vrai si le craquage a été refusé par le gate.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, OfflineOutcome::Blocked { .. })
    }

    /// Le livrable client, si l'action a été autorisée et exécutée.
    #[must_use]
    pub fn result(&self) -> Option<&CrackResult> {
        match self {
            OfflineOutcome::Done { result, .. } => Some(result),
            OfflineOutcome::Blocked { .. } => None,
        }
    }

    /// L'entrée d'audit à journaliser (présente dans les deux cas).
    #[must_use]
    pub fn audit(&self) -> &AuditRecord {
        match self {
            OfflineOutcome::Blocked { audit, .. } | OfflineOutcome::Done { audit, .. } => audit,
        }
    }
}

/// Déroule un craquage **hors ligne via le gate** (le « mur », §3.2/§4), seul
/// chemin vers le moteur.
///
/// Le gate vérifie la capacité `cracking` (étape 3), le confinement au périmètre et
/// les plafonds. Sur refus, le moteur **n'est pas** actionné : on renvoie
/// [`OfflineOutcome::Blocked`] et l'audit `blocked_*`. Sur autorisation, le moteur
/// produit un [`CrackReport`] dont on dérive le
/// [`CrackResult`](nickmare_core::model::CrackResult) (statistiques et verdict de
/// politique), rendu dans [`OfflineOutcome::Done`] avec l'audit `crack.offline`.
pub async fn crack_offline_through_gate(
    gate: &mut Gate,
    req: &Request<'_>,
    engine: &dyn CrackEngine,
    request: &CrackRequest,
    policy: &PasswordPolicy,
) -> Result<OfflineOutcome, CrackError> {
    let action = Action::Crack {
        target: request.target,
        online: false,
        account: None,
    };
    let decision = gate.check(&action, req);
    let operator = request.operator.as_str();
    let audit = audit_record(&action, decision, operator, gate.mode());
    match decision {
        Decision::Deny(reason) => Ok(OfflineOutcome::Blocked { reason, audit }),
        Decision::Allow => {
            let report = engine.crack_offline(request).await?;
            let result = report.to_crack_result(policy);
            Ok(OfflineOutcome::Done { result, audit })
        }
    }
}

/// Issue d'un passage **gate → moteur** pour un spray en ligne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SprayOutcome {
    /// Refusé par le gate : aucune tentative émise (capacité off, confirmation
    /// manquante, plafond atteint…). Porte la raison typée + l'audit `blocked_*`.
    Blocked {
        /// Raison du refus (premier contrôle échoué, §3.2).
        reason: DenyReason,
        /// Entrée d'audit `blocked_<code>` à consigner.
        audit: AuditRecord,
    },
    /// Autorisé : une tentative a été émise. Porte le rapport (secret masqué) +
    /// l'audit `crack.spray`.
    Attempted {
        /// Résultat de la tentative (masqué).
        report: SprayReport,
        /// Entrée d'audit du verbe métier (`crack.spray`).
        audit: AuditRecord,
    },
}

impl SprayOutcome {
    /// Vrai si le spray a été refusé par le gate.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, SprayOutcome::Blocked { .. })
    }

    /// Le rapport de tentative, si l'action a été autorisée.
    #[must_use]
    pub fn report(&self) -> Option<&SprayReport> {
        match self {
            SprayOutcome::Attempted { report, .. } => Some(report),
            SprayOutcome::Blocked { .. } => None,
        }
    }

    /// L'entrée d'audit à journaliser (présente dans les deux cas).
    #[must_use]
    pub fn audit(&self) -> &AuditRecord {
        match self {
            SprayOutcome::Blocked { audit, .. } | SprayOutcome::Attempted { audit, .. } => audit,
        }
    }
}

/// Déroule **une** tentative de spray en ligne **via le gate** (le « mur »,
/// §3.2/§4), seul chemin vers le moteur.
///
/// Le gate applique l'opt-in `online_spray` (étape 3), la confirmation humaine
/// (étape 5) et le plafond `max_attempts_per_account` (étape 7, anti-lockout). Sur
/// refus → aucune tentative : [`SprayOutcome::Blocked`] + audit `blocked_*`. Sur
/// autorisation → une tentative, rendue dans [`SprayOutcome::Attempted`] + audit
/// `crack.spray`.
pub async fn spray_through_gate(
    gate: &mut Gate,
    req: &Request<'_>,
    engine: &dyn SprayEngine,
    request: &SprayRequest,
) -> Result<SprayOutcome, CrackError> {
    let action = Action::Crack {
        target: request.target,
        online: true,
        account: Some(request.account.clone()),
    };
    let decision = gate.check(&action, req);
    let operator = request.operator.as_str();
    let audit = audit_record(&action, decision, operator, gate.mode());
    match decision {
        Decision::Deny(reason) => Ok(SprayOutcome::Blocked { reason, audit }),
        Decision::Allow => {
            let report = engine.spray_once(request).await?;
            Ok(SprayOutcome::Attempted { report, audit })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: &str = "operateur@example.test";
    const H_NTLM: &str = "b4b9b02e6f09a9bd760f388b67351e2b";

    fn ip() -> IpAddr {
        "192.168.10.25".parse().unwrap()
    }

    #[test]
    fn mapping_des_modes_couvre_les_quatre_familles() {
        assert_eq!(HashType::Ntlm.hashcat_mode(), 1000);
        assert_eq!(HashType::Kerberos.hashcat_mode(), 13100);
        assert_eq!(HashType::Unix.hashcat_mode(), 1800);
        assert_eq!(HashType::Wpa.hashcat_mode(), 22000);
        assert_eq!(HashType::Ntlm.john_format(), "nt");
        assert_eq!(HashType::Wpa.john_format(), "wpapsk");
        assert_eq!(HashType::Unix.label(), "sha512crypt");
    }

    #[test]
    fn parse_du_type_est_insensible_a_la_casse_et_fail_safe() {
        assert_eq!(HashType::parse("NTLM"), Some(HashType::Ntlm));
        assert_eq!(HashType::parse("  wpa2 "), Some(HashType::Wpa));
        assert_eq!(HashType::parse("krb5tgs"), Some(HashType::Kerberos));
        assert_eq!(HashType::parse("sha512crypt"), Some(HashType::Unix));
        assert_eq!(HashType::parse("inconnu"), None);
    }

    #[test]
    fn le_secret_est_masque_dans_debug_display_et_serde() {
        let clair = "Sup3rSecret!";
        let secret = MaskedSecret::new(clair);
        // Display + Debug masquent.
        assert_eq!(secret.to_string(), "****");
        let debug = format!("{secret:?}");
        assert!(!debug.contains(clair), "fuite Debug : {debug}");
        assert!(debug.contains("****"));
        // serde masque (le rapport JSON ne porte jamais le clair).
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, "\"****\"");
        assert!(!json.contains(clair), "fuite serde : {json}");
        // La longueur reste observable sans révéler.
        assert_eq!(secret.len(), clair.chars().count());
        assert!(!secret.is_empty());
    }

    #[test]
    fn le_clair_n_est_revele_que_derriere_une_decision_explicite() {
        let secret = MaskedSecret::new("Hiver2024!");
        let disclosure = SecretDisclosure::confirmed_by(OP);
        assert_eq!(secret.reveal(&disclosure), "Hiver2024!");
        assert_eq!(disclosure.operator(), OP);
    }

    #[test]
    fn un_rapport_serialise_ne_fait_fuiter_aucun_clair() {
        let secret = MaskedSecret::new("Printemps2023");
        let report = CrackReport::new(HashType::Ntlm, "dump lab", 3)
            .with_recovered(vec![Recovered::new("alice", secret)]);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("Printemps2023"), "fuite : {json}");
        assert!(json.contains("****"));
        assert!(json.contains("alice"));
    }

    #[tokio::test]
    async fn le_mock_hors_ligne_est_deterministe_et_masque() {
        let engine = MockCrackEngine::new().with_cracked(H_NTLM, "Password1");
        let request = CrackRequest {
            target: ip(),
            source: "dump lab".to_string(),
            hash_type: HashType::Ntlm,
            hashes: vec![
                HashEntry::new("alice", H_NTLM),
                HashEntry::new("bob", "ffffffffffffffffffffffffffffffff"),
            ],
            operator: OP.to_string(),
        };
        let a = engine.crack_offline(&request).await.unwrap();
        let b = engine.crack_offline(&request).await.unwrap();
        assert_eq!(a, b, "verdicts déterministes");
        assert_eq!(a.attempted, 2);
        assert_eq!(a.cracked(), 1);
        assert_eq!(a.recovered[0].account, "alice");
        assert_eq!(a.recovered[0].secret.to_string(), "****");
    }

    #[tokio::test]
    async fn le_mock_de_spray_rend_trouve_ou_non() {
        let engine = MockSprayEngine::new().with_found("admin", "Automne2024");
        let trouve = SprayRequest::new(ip(), "admin", OP);
        let absent = SprayRequest::new(ip(), "backup", OP);
        let found = engine.spray_once(&trouve).await.unwrap();
        let miss = engine.spray_once(&absent).await.unwrap();
        assert!(found.found);
        assert_eq!(found.secret.as_ref().unwrap().to_string(), "****");
        assert!(!miss.found);
        assert!(miss.secret.is_none());
    }

    #[tokio::test]
    async fn injectable_en_objet_de_trait() {
        let offline: Box<dyn CrackEngine> = Box::new(MockCrackEngine::new());
        let online: Box<dyn SprayEngine> = Box::new(MockSprayEngine::new());
        let req = CrackRequest::new(ip(), "x", HashType::Ntlm, OP);
        let spray = SprayRequest::new(ip(), "admin", OP);
        assert_eq!(offline.crack_offline(&req).await.unwrap().attempted, 0);
        assert!(!online.spray_once(&spray).await.unwrap().found);
    }

    #[test]
    fn chaque_erreur_s_affiche_sans_secret() {
        let unavailable = CrackError::ToolUnavailable("x".into()).to_string();
        assert!(!unavailable.is_empty());
        let failed = CrackError::ToolFailed("code 1".into()).to_string();
        assert!(failed.contains("code 1"));
        let parse = CrackError::Parse("y".into()).to_string();
        assert!(parse.contains("y"));
        let io = CrackError::Io("z".into()).to_string();
        assert!(io.contains("z"));
        let other = CrackError::Other("détail".into()).to_string();
        assert!(other.contains("détail"));
    }
}
