//! Chargement et validation du fichier de scope (issue #3, cf.
//! `docs/ARCHITECTURE.md` §3 et annexe décision 3).
//!
//! Le [`Scope`] est l'objet consommé par le gate (§3). Trois voies le peuplent
//! (A interactive, B fichier TOML, C labo) mais produisent le **même** objet.
//! Ce module couvre la **voie B** : désérialisation + validation du fichier
//! TOML, et la structure interne commune ([`Scope`] + [`Capabilities`]).
//!
//! Invariants de sécurité appliqués ici (§1, §3) :
//!
//! - **Fail-safe** : un scope mal formé, incohérent ou expiré est **refusé**
//!   (jamais chargé « à moitié »).
//! - **Capacités désactivées par défaut** : toute capacité intrusive
//!   (exploitation, cracking, émulation) est `false` tant qu'elle n'est pas
//!   activée explicitement et granulairement. Seule la reconnaissance (N1,
//!   passive) n'est jamais bridée.
//! - **Intégrité** (décision 3, mode hybride) : empreinte **SHA-256** calculée
//!   et exposée dès la v1 ; si le bloc `[integrity]` est présent, la signature
//!   **ed25519** est **obligatoirement** vérifiée contre une clé de confiance,
//!   sinon le chargement est refusé.

use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Timelike, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::AdversaryProfile;

// --- Erreurs ----------------------------------------------------------------

/// Raison pour laquelle un scope est refusé. Toujours accompagnée d'un message
/// clair destiné à l'opérateur (fail-safe §1 : en cas de doute, on refuse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// TOML syntaxiquement invalide ou champ obligatoire manquant.
    Toml(String),
    /// Réseau `networks`/`exclusions.networks` mal formé (CIDR attendu).
    Network(String),
    /// Hôte `hosts`/`exclusions.hosts`/`allowed_hosts` mal formé (IP attendue).
    Host(String),
    /// Fenêtre d'engagement incohérente (`valid_until` avant `valid_from`).
    Window(String),
    /// Fenêtre horaire `allowed_hours` mal formée.
    Hours(String),
    /// Problème d'intégrité : bloc/clé/signature absent, mal formé ou invalide.
    Integrity(String),
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeError::Toml(msg) => write!(f, "TOML invalide : {msg}"),
            ScopeError::Network(msg) => write!(f, "réseau invalide : {msg}"),
            ScopeError::Host(msg) => write!(f, "hôte invalide : {msg}"),
            ScopeError::Window(msg) => write!(f, "fenêtre d'engagement invalide : {msg}"),
            ScopeError::Hours(msg) => write!(f, "fenêtre horaire invalide : {msg}"),
            ScopeError::Integrity(msg) => write!(f, "intégrité du scope : {msg}"),
        }
    }
}

impl std::error::Error for ScopeError {}

// --- Capacités --------------------------------------------------------------

/// Niveau de capacité porté par une action, filtré par le gate (§3.2, étape 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Niveau 1 — reconnaissance & cartographie (non intrusif).
    Recon,
    /// Niveau 2 — intrusion & exploitation.
    Exploitation,
    /// Niveau 3 — craquage de credentials.
    Cracking,
    /// Niveau 4 — émulation d'adversaire.
    Emulation,
}

// --- Structures du fichier de scope -----------------------------------------

/// Bloc `[engagement]` : identité du mandat et fenêtre de validité.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engagement {
    pub client: String,
    pub reference: String,
    pub authorized_by: String,
    pub operator: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// Bloc `[targets]` : réseaux et hôtes autorisés, plus leurs exclusions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    /// CIDR explicitement autorisés (ex. `"192.168.10.0/24"`).
    #[serde(default)]
    pub networks: Vec<String>,
    /// Hôtes explicitement autorisés (adresses IP).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Exclusions : jamais touchées même si comprises dans un CIDR autorisé.
    #[serde(default)]
    pub exclusions: Exclusions,
}

/// Bloc `[targets.exclusions]` : cibles interdites en toutes circonstances.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusions {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub networks: Vec<String>,
}

/// Bloc `[constraints]` : plafonds et fenêtres opérationnelles.
///
/// Les plafonds sont des entiers **non signés** : « ≥ 0 » est donc garanti par
/// le type, et une valeur négative dans le TOML est rejetée dès la
/// désérialisation (scope mal formé → refus).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    /// Débit maximal en paquets/seconde.
    #[serde(default)]
    pub max_rate_pps: u32,
    /// Fenêtre d'intervention « HH:MM-HH:MM » (UTC). Absente = sans restriction.
    #[serde(default)]
    pub allowed_hours: Option<String>,
    /// `true` = pas de SYN scan brut (connect scan uniquement, sans privilèges).
    #[serde(default)]
    pub tcp_connect_only: bool,
}

impl Constraints {
    /// Analyse `allowed_hours` en fenêtre validée. `Ok(None)` = aucune
    /// restriction horaire ; `Err` = chaîne mal formée.
    pub fn hour_window(&self) -> Result<Option<HourWindow>, ScopeError> {
        match &self.allowed_hours {
            None => Ok(None),
            Some(raw) => HourWindow::parse(raw).map(Some),
        }
    }
}

/// Fenêtre horaire validée, exprimée en minutes depuis minuit (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HourWindow {
    start_min: u16,
    end_min: u16,
}

impl HourWindow {
    fn parse(raw: &str) -> Result<Self, ScopeError> {
        let Some((from, to)) = raw.split_once('-') else {
            let msg = format!("format attendu HH:MM-HH:MM, reçu {raw:?}");
            return Err(ScopeError::Hours(msg));
        };
        let start = parse_hour_minute(from)?;
        let end = parse_hour_minute(to)?;
        if start >= end {
            let msg = format!("le début {from:?} doit précéder la fin {to:?}");
            return Err(ScopeError::Hours(msg));
        }
        Ok(Self {
            start_min: start,
            end_min: end,
        })
    }

    /// Vrai si `minutes` (0..1440) tombe dans la fenêtre `[début, fin)`.
    fn contains(&self, minutes: u16) -> bool {
        minutes >= self.start_min && minutes < self.end_min
    }
}

/// Bloc `[capabilities]` : activation granulaire des niveaux.
///
/// Toutes les capacités intrusives sont **désactivées par défaut**. La
/// reconnaissance (N1) n'est jamais bridée par ce filtre (§1 « recon libre ») :
/// un scope sans aucune capacité activée n'autorise donc **que** la recon.
///
/// Le document d'architecture (§3.1) illustre les capacités par des booléens
/// `exploitation = true` au même niveau que le sous-bloc
/// `[capabilities.exploitation]`. Comme une clé TOML ne peut être à la fois un
/// booléen et une table, l'activation vit **dans** chaque sous-bloc via son
/// champ `enabled` (TOML valide, activation granulaire explicite).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Reconnaissance N1 explicitement incluse (la recon passive reste libre
    /// quoi qu'il arrive — ce champ documente l'inclusion dans un engagement).
    #[serde(default)]
    pub recon: bool,
    #[serde(default)]
    pub exploitation: Exploitation,
    #[serde(default)]
    pub cracking: Cracking,
    #[serde(default)]
    pub emulation: Emulation,
}

impl Capabilities {
    /// Indique si une capacité est autorisée par ce scope.
    ///
    /// Contrat (§1, §3.2) : la reconnaissance est **toujours** autorisée (N1
    /// passif, jamais bridé) ; les niveaux intrusifs ne le sont que si leur
    /// `enabled` respectif est `true`.
    pub fn allows(&self, capability: Capability) -> bool {
        match capability {
            Capability::Recon => true,
            Capability::Exploitation => self.exploitation.enabled,
            Capability::Cracking => self.cracking.enabled,
            Capability::Emulation => self.emulation.enabled,
        }
    }
}

/// Mode d'exploitation (N2). `Manual` (confirmation par cible) par défaut.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExploitRunMode {
    #[default]
    Manual,
    Auto,
}

/// Sous-bloc `[capabilities.exploitation]` (N2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exploitation {
    /// Active le niveau 2. `false` par défaut.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: ExploitRunMode,
    /// `false` = mode validation uniquement, jamais de charge destructrice.
    #[serde(default)]
    pub destructive_checks: bool,
    /// Seuls ces hôtes peuvent être exploités, même si d'autres sont dans
    /// `targets` (§3.2, étape 3).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Plafond d'actions en mode auto (§3.2, étape 7).
    #[serde(default)]
    pub max_actions: u32,
}

/// Sous-bloc `[capabilities.cracking]` (N3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cracking {
    /// Active le niveau 3. `false` par défaut.
    #[serde(default)]
    pub enabled: bool,
    /// `true` = autorise le test en ligne (risque de verrouillage). Opt-in.
    #[serde(default)]
    pub online_spray: bool,
    /// Borne anti-verrouillage de comptes (§3.2, étape 7).
    #[serde(default)]
    pub max_attempts_per_account: u32,
}

/// Sous-bloc `[capabilities.emulation]` (N4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Emulation {
    /// Active le niveau 4. `false` par défaut.
    #[serde(default)]
    pub enabled: bool,
    /// Identifiants ATT&CK autorisés (ex. `"T1021"`). Seuls ceux-ci sont jouables.
    #[serde(default)]
    pub attack_techniques: Vec<String>,
    #[serde(default)]
    pub profile: ScopeProfile,
    /// Contact SOC pour la coordination purple team.
    #[serde(default)]
    pub blue_team_contact: Option<String>,
}

/// Profil d'adversaire tel qu'écrit dans le scope (minuscules), converti vers
/// [`AdversaryProfile`] du modèle. `balanced` par défaut.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeProfile {
    Noisy,
    #[default]
    Balanced,
    Stealth,
}

impl From<ScopeProfile> for AdversaryProfile {
    fn from(profile: ScopeProfile) -> Self {
        match profile {
            ScopeProfile::Noisy => AdversaryProfile::Noisy,
            ScopeProfile::Balanced => AdversaryProfile::Balanced,
            ScopeProfile::Stealth => AdversaryProfile::Stealth,
        }
    }
}

/// Bloc `[integrity]` optionnel (décision 3) : preuve d'autorisation forte.
///
/// Présent → signature `ed25519` **obligatoire** et vérifiée contre une clé de
/// confiance fournie hors fichier ; absent → mode v1 (empreinte SHA-256 seule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Integrity {
    /// Signature ed25519 du scope signable, encodée en hexadécimal (64 octets
    /// → 128 caractères).
    pub signature: String,
}

// --- Validité temporelle ----------------------------------------------------

/// État temporel d'un scope vis-à-vis d'un instant donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalStatus {
    /// `valid_from <= now <= valid_until`.
    Valid,
    /// `now < valid_from` : engagement pas encore ouvert.
    NotYetValid,
    /// `now > valid_until` : engagement expiré.
    Expired,
}

// --- Scope -------------------------------------------------------------------

/// Scope normalisé, consommé par le gate. Construit via [`Scope::from_toml`] ou
/// [`Scope::load`] ; jamais « à moitié » (toute incohérence → [`ScopeError`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub engagement: Engagement,
    #[serde(default)]
    pub targets: Targets,
    #[serde(default)]
    pub constraints: Constraints,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(default)]
    pub integrity: Option<Integrity>,
    /// Empreinte SHA-256 du fichier, calculée après désérialisation (jamais lue
    /// depuis le TOML).
    #[serde(skip)]
    fingerprint: String,
}

impl Scope {
    /// Parse et valide un scope depuis le **texte TOML brut**, puis calcule son
    /// empreinte SHA-256. Ne vérifie **pas** la signature (voir [`Scope::load`])
    /// ni la validité temporelle (voir [`Scope::temporal_status`]), pour rester
    /// reproductible et testable indépendamment de l'horloge et des clés.
    pub fn from_toml(input: &str) -> Result<Self, ScopeError> {
        let parsed: Result<Scope, toml::de::Error> = toml::from_str(input);
        let mut scope = match parsed {
            Ok(scope) => scope,
            Err(err) => return Err(ScopeError::Toml(err.to_string())),
        };
        scope.fingerprint = sha256_hex(input.as_bytes());
        scope.validate()?;
        Ok(scope)
    }

    /// Chargement complet avec politique d'intégrité (décision 3) :
    ///
    /// - bloc `[integrity]` **présent** → une `trusted_key_hex` est
    ///   **obligatoire** et la signature doit être valide, sinon refus ;
    /// - bloc **absent** → mode v1 (empreinte SHA-256 seule), la clé est ignorée.
    pub fn load(input: &str, trusted_key_hex: Option<&str>) -> Result<Self, ScopeError> {
        let scope = Self::from_toml(input)?;
        if scope.integrity.is_some() {
            let Some(key) = trusted_key_hex else {
                let msg = "[integrity] présent : clé de confiance ed25519 requise".to_string();
                return Err(ScopeError::Integrity(msg));
            };
            scope.verify_signature(key)?;
        }
        Ok(scope)
    }

    /// Empreinte SHA-256 du fichier de scope (hexadécimal minuscule, 64
    /// caractères). Reproductible : même fichier → même empreinte.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Vrai si le scope porte un bloc `[integrity]` (donc une signature à vérifier).
    pub fn has_integrity(&self) -> bool {
        self.integrity.is_some()
    }

    /// Octets canoniques **signés** : représentation déterministe du scope
    /// **hors** bloc `[integrity]` (un scope ne peut signer sa propre
    /// signature). Indépendante de la mise en forme/des commentaires du TOML.
    /// C'est exactement ce que le donneur d'ordre signe avec sa clé ed25519.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let view = (
            &self.engagement,
            &self.targets,
            &self.constraints,
            &self.capabilities,
        );
        // La sérialisation de types standards (sans map non ordonnée) est
        // infaillible en pratique ; on retombe sur un vecteur vide par sûreté
        // plutôt que de paniquer (§11.4).
        serde_json::to_vec(&view).unwrap_or_default()
    }

    /// Vérifie la signature ed25519 du scope contre `trusted_key_hex` (clé
    /// publique encodée en hexadécimal, 32 octets → 64 caractères).
    ///
    /// Refuse (fail-safe) si : le bloc `[integrity]` est absent, la clé ou la
    /// signature sont mal formées, la clé est invalide, ou la signature ne
    /// vérifie pas (scope potentiellement altéré).
    pub fn verify_signature(&self, trusted_key_hex: &str) -> Result<(), ScopeError> {
        let Some(integrity) = self.integrity.as_ref() else {
            let msg = "aucun bloc [integrity] à vérifier".to_string();
            return Err(ScopeError::Integrity(msg));
        };
        let Some(key_bytes) = decode_fixed::<32>(trusted_key_hex) else {
            let msg = "clé de confiance mal formée (64 caractères hex attendus)".to_string();
            return Err(ScopeError::Integrity(msg));
        };
        let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
            Ok(key) => key,
            Err(_) => {
                let msg = "clé de confiance ed25519 invalide".to_string();
                return Err(ScopeError::Integrity(msg));
            }
        };
        let Some(sig_bytes) = decode_fixed::<64>(&integrity.signature) else {
            let msg = "signature mal formée (128 caractères hexadécimaux attendus)".to_string();
            return Err(ScopeError::Integrity(msg));
        };
        let signature = Signature::from_bytes(&sig_bytes);
        match verifying_key.verify_strict(&self.signable_bytes(), &signature) {
            Ok(()) => Ok(()),
            Err(_) => {
                let msg = "signature ed25519 invalide (le scope a pu être altéré)".to_string();
                Err(ScopeError::Integrity(msg))
            }
        }
    }

    /// État du scope vis-à-vis de l'instant `now` (fenêtre `[valid_from,
    /// valid_until]`).
    pub fn temporal_status(&self, now: DateTime<Utc>) -> TemporalStatus {
        if now < self.engagement.valid_from {
            TemporalStatus::NotYetValid
        } else if now > self.engagement.valid_until {
            TemporalStatus::Expired
        } else {
            TemporalStatus::Valid
        }
    }

    /// Vrai si `now` tombe dans `allowed_hours`. Sans restriction horaire → vrai.
    /// Fenêtre mal formée → faux (fail-safe), mais ce cas est déjà écarté à la
    /// validation du scope.
    pub fn within_allowed_hours(&self, now: DateTime<Utc>) -> bool {
        match self.constraints.hour_window() {
            Ok(Some(window)) => {
                let minutes = (now.hour() * 60 + now.minute()) as u16;
                window.contains(minutes)
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }

    /// Validation sémantique (hors horloge/clés) : cohérence de la fenêtre,
    /// CIDR/hôtes bien formés, fenêtre horaire bien formée.
    fn validate(&self) -> Result<(), ScopeError> {
        if self.engagement.valid_until < self.engagement.valid_from {
            let msg = format!(
                "valid_until ({}) est antérieur à valid_from ({})",
                self.engagement.valid_until, self.engagement.valid_from
            );
            return Err(ScopeError::Window(msg));
        }
        for network in &self.targets.networks {
            validate_cidr(network)?;
        }
        for network in &self.targets.exclusions.networks {
            validate_cidr(network)?;
        }
        for host in &self.targets.hosts {
            validate_host(host)?;
        }
        for host in &self.targets.exclusions.hosts {
            validate_host(host)?;
        }
        for host in &self.capabilities.exploitation.allowed_hosts {
            validate_host(host)?;
        }
        // Rejette une fenêtre horaire mal formée dès le chargement.
        self.constraints.hour_window()?;
        Ok(())
    }
}

// --- Helpers privés ---------------------------------------------------------

/// Empreinte SHA-256 en hexadécimal minuscule.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    to_hex(digest.as_slice())
}

/// Encode des octets en hexadécimal minuscule.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Décode une chaîne hexadécimale en octets. `None` si longueur impaire ou
/// caractère non hexadécimal.
fn from_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_value(pair[0])?;
            let lo = hex_value(pair[1])?;
            Some((hi << 4) | lo)
        })
        .collect()
}

/// Valeur d'un chiffre hexadécimal ASCII, ou `None`.
fn hex_value(ascii: u8) -> Option<u8> {
    match ascii {
        b'0'..=b'9' => Some(ascii - b'0'),
        b'a'..=b'f' => Some(ascii - b'a' + 10),
        b'A'..=b'F' => Some(ascii - b'A' + 10),
        _ => None,
    }
}

/// Décode une chaîne hexadécimale vers un tableau fixe de `N` octets. `None` si
/// la longueur décodée diffère de `N` ou si l'hexadécimal est invalide.
fn decode_fixed<const N: usize>(input: &str) -> Option<[u8; N]> {
    let bytes = from_hex(input)?;
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Valide un CIDR « adresse/longueur » (IPv4 ou IPv6).
fn validate_cidr(entry: &str) -> Result<(), ScopeError> {
    let Some((addr, prefix)) = entry.split_once('/') else {
        let msg = format!("CIDR attendu (adresse/longueur), reçu {entry:?}");
        return Err(ScopeError::Network(msg));
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        let msg = format!("adresse invalide dans {entry:?}");
        return Err(ScopeError::Network(msg));
    };
    let max: u8 = if ip.is_ipv4() { 32 } else { 128 };
    let Ok(len) = prefix.parse::<u8>() else {
        let msg = format!("longueur de préfixe invalide dans {entry:?}");
        return Err(ScopeError::Network(msg));
    };
    if len > max {
        let msg = format!("préfixe /{len} hors plage (max /{max}) dans {entry:?}");
        return Err(ScopeError::Network(msg));
    }
    Ok(())
}

/// Valide un hôte (adresse IPv4 ou IPv6 littérale).
fn validate_host(entry: &str) -> Result<(), ScopeError> {
    if entry.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let msg = format!("adresse IP invalide : {entry:?}");
    Err(ScopeError::Host(msg))
}

/// Analyse « HH:MM » en minutes depuis minuit (0..=1439).
fn parse_hour_minute(raw: &str) -> Result<u16, ScopeError> {
    let Some((hh, mm)) = raw.split_once(':') else {
        let msg = format!("heure mal formée (HH:MM attendu) : {raw:?}");
        return Err(ScopeError::Hours(msg));
    };
    let Ok(hours) = hh.parse::<u16>() else {
        let msg = format!("heures invalides : {hh:?}");
        return Err(ScopeError::Hours(msg));
    };
    let Ok(minutes) = mm.parse::<u16>() else {
        let msg = format!("minutes invalides : {mm:?}");
        return Err(ScopeError::Hours(msg));
    };
    if hours > 23 || minutes > 59 {
        let msg = format!("heure hors plage : {raw:?}");
        return Err(ScopeError::Hours(msg));
    }
    Ok(hours * 60 + minutes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};

    /// Scope minimal valide, sans bloc `[integrity]` (mode v1).
    const BASE: &str = "\
[engagement]
client = \"ACME Corp\"
reference = \"PENTEST-2026-014\"
authorized_by = \"DSI ACME\"
operator = \"operateur@example.test\"
valid_from = \"2026-01-01T00:00:00Z\"
valid_until = \"2027-12-31T23:59:59Z\"

[targets]
networks = [\"192.168.10.0/24\", \"10.20.0.0/16\"]
hosts = [\"192.168.50.5\"]

[targets.exclusions]
hosts = [\"192.168.10.1\"]

[constraints]
max_rate_pps = 200
allowed_hours = \"08:00-18:00\"

[capabilities]
recon = true

[capabilities.exploitation]
enabled = true
mode = \"manual\"
allowed_hosts = [\"192.168.10.25\"]
max_actions = 50
";

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    // --- Parsing & structure ------------------------------------------------

    #[test]
    fn charge_un_scope_valide() {
        let scope = Scope::from_toml(BASE).unwrap();
        assert_eq!(scope.engagement.client, "ACME Corp");
        assert_eq!(scope.targets.networks.len(), 2);
        assert_eq!(scope.targets.hosts, vec!["192.168.50.5"]);
        assert_eq!(scope.constraints.max_rate_pps, 200);
        assert!(scope.capabilities.exploitation.enabled);
        assert_eq!(scope.capabilities.exploitation.mode, ExploitRunMode::Manual);
        assert!(!scope.has_integrity());
    }

    #[test]
    fn empreinte_64_hex_minuscules() {
        let scope = Scope::from_toml(BASE).unwrap();
        let fp = scope.fingerprint();
        assert_eq!(fp.len(), 64);
        let hexa = fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        assert!(hexa, "empreinte non hexadécimale minuscule : {fp}");
    }

    // --- Capacités désactivées par défaut (DoD) -----------------------------

    #[test]
    fn capacites_desactivees_par_defaut() {
        let caps = Capabilities::default();
        assert!(!caps.exploitation.enabled);
        assert!(!caps.cracking.enabled);
        assert!(!caps.emulation.enabled);
        // Valeurs par défaut sûres.
        assert_eq!(caps.exploitation.mode, ExploitRunMode::Manual);
        assert!(!caps.exploitation.destructive_checks);
        assert!(!caps.cracking.online_spray);
    }

    /// Contrat de sécurité (issue #3 / §10.4) : un scope sans capacité activée
    /// n'autorise **que** la reconnaissance.
    #[test]
    fn sans_capacite_seule_la_recon_est_autorisee() {
        let caps = Capabilities::default();
        assert!(caps.allows(Capability::Recon));
        assert!(!caps.allows(Capability::Exploitation));
        assert!(!caps.allows(Capability::Cracking));
        assert!(!caps.allows(Capability::Emulation));
    }

    #[test]
    fn capacites_absentes_du_toml_restent_desactivees() {
        let minimal = "\
[engagement]
client = \"X\"
reference = \"R\"
authorized_by = \"A\"
operator = \"o@example.test\"
valid_from = \"2026-01-01T00:00:00Z\"
valid_until = \"2027-01-01T00:00:00Z\"
";
        let scope = Scope::from_toml(minimal).unwrap();
        assert!(scope.capabilities.allows(Capability::Recon));
        assert!(!scope.capabilities.allows(Capability::Exploitation));
        assert!(!scope.capabilities.allows(Capability::Cracking));
        assert!(!scope.capabilities.allows(Capability::Emulation));
    }

    // --- Refus des scopes mal formés ----------------------------------------

    #[test]
    fn cidr_malforme_refuse() {
        let bad = BASE.replace("192.168.10.0/24", "192.168.10.0/99");
        let err = Scope::from_toml(&bad).unwrap_err();
        assert!(matches!(err, ScopeError::Network(_)), "{err}");
    }

    #[test]
    fn hote_malforme_refuse() {
        let bad = BASE.replace("192.168.50.5", "pas-une-ip");
        let err = Scope::from_toml(&bad).unwrap_err();
        assert!(matches!(err, ScopeError::Host(_)), "{err}");
    }

    #[test]
    fn toml_syntaxiquement_invalide_refuse() {
        let err = Scope::from_toml("ceci = n'est pas du toml [").unwrap_err();
        assert!(matches!(err, ScopeError::Toml(_)), "{err}");
    }

    #[test]
    fn champ_inconnu_refuse() {
        // `deny_unknown_fields` : un champ inattendu (typo) est refusé plutôt
        // que silencieusement ignoré (défense en profondeur, fail-safe).
        let bad = BASE.replace("max_rate_pps = 200", "max_rate_pps = 200\ninconnu = 1");
        let err = Scope::from_toml(&bad).unwrap_err();
        assert!(matches!(err, ScopeError::Toml(_)), "{err}");
    }

    #[test]
    fn fenetre_incoherente_refuse() {
        let bad = BASE.replace(
            "valid_until = \"2027-12-31T23:59:59Z\"",
            "valid_until = \"2025-01-01T00:00:00Z\"",
        );
        let err = Scope::from_toml(&bad).unwrap_err();
        assert!(matches!(err, ScopeError::Window(_)), "{err}");
    }

    #[test]
    fn allowed_hours_malforme_refuse() {
        let bad = BASE.replace("08:00-18:00", "25:00-26:00");
        let err = Scope::from_toml(&bad).unwrap_err();
        assert!(matches!(err, ScopeError::Hours(_)), "{err}");
    }

    #[test]
    fn plafond_negatif_refuse() {
        // « plafonds ≥ 0 » : un entier signé négatif ne désérialise pas en u32.
        let bad = BASE.replace("max_rate_pps = 200", "max_rate_pps = -5");
        let err = Scope::from_toml(&bad).unwrap_err();
        assert!(matches!(err, ScopeError::Toml(_)), "{err}");
    }

    // --- Validité temporelle ------------------------------------------------

    #[test]
    fn expiration_et_fenetre() {
        let scope = Scope::from_toml(BASE).unwrap();
        assert_eq!(scope.temporal_status(at(2026, 6, 1, 12)), TemporalStatus::Valid);
        assert_eq!(
            scope.temporal_status(at(2025, 1, 1, 0)),
            TemporalStatus::NotYetValid
        );
        assert_eq!(
            scope.temporal_status(at(2030, 1, 1, 0)),
            TemporalStatus::Expired
        );
    }

    #[test]
    fn hors_allowed_hours() {
        let scope = Scope::from_toml(BASE).unwrap();
        // Fenêtre 08:00-18:00 (UTC).
        assert!(scope.within_allowed_hours(at(2026, 6, 1, 10)));
        assert!(!scope.within_allowed_hours(at(2026, 6, 1, 20)));
        assert!(!scope.within_allowed_hours(at(2026, 6, 1, 6)));
    }

    #[test]
    fn sans_allowed_hours_toujours_dans_la_fenetre() {
        let no_hours = BASE.replace("allowed_hours = \"08:00-18:00\"\n", "");
        let scope = Scope::from_toml(&no_hours).unwrap();
        assert!(scope.within_allowed_hours(at(2026, 6, 1, 3)));
    }

    // --- Empreinte SHA-256 --------------------------------------------------

    #[test]
    fn empreinte_reproductible_et_sensible() {
        let a = Scope::from_toml(BASE).unwrap();
        let b = Scope::from_toml(BASE).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());

        let autre = BASE.replace("ACME Corp", "AUTRE Corp");
        let c = Scope::from_toml(&autre).unwrap();
        assert_ne!(a.fingerprint(), c.fingerprint());
    }

    #[test]
    fn sha256_vecteurs_connus() {
        // Vecteurs NIST : SHA-256("") et SHA-256("abc").
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_aller_retour_et_rejets() {
        assert_eq!(to_hex(&[0x00, 0x1a, 0xff]), "001aff");
        assert_eq!(from_hex("001aff").unwrap(), vec![0x00, 0x1a, 0xff]);
        assert!(from_hex("abc").is_none()); // longueur impaire
        assert!(from_hex("zz").is_none()); // non hexadécimal
        assert!(decode_fixed::<2>("001aff").is_none()); // mauvaise longueur
        assert_eq!(decode_fixed::<3>("001aff").unwrap(), [0x00, 0x1a, 0xff]);
    }

    // --- Signature ed25519 (tests négatifs de sécurité §10.4) ---------------

    /// Prépare un scope signé : signe les octets canoniques avec une clé de
    /// graine fixe (déterministe, sans RNG) et renvoie (scope, clé publique hex).
    fn scope_signe() -> (Scope, String) {
        let mut scope = Scope::from_toml(BASE).unwrap();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let signature = signing.sign(&scope.signable_bytes());
        scope.integrity = Some(Integrity {
            signature: to_hex(&signature.to_bytes()),
        });
        let key_hex = to_hex(&signing.verifying_key().to_bytes());
        (scope, key_hex)
    }

    #[test]
    fn signature_valide_acceptee() {
        let (scope, key_hex) = scope_signe();
        assert!(scope.has_integrity());
        assert!(scope.verify_signature(&key_hex).is_ok());
    }

    #[test]
    fn signature_alteree_refusee() {
        let (mut scope, key_hex) = scope_signe();
        // On retourne un octet de la signature.
        let mut sig = scope.integrity.as_ref().unwrap().signature.clone();
        sig.replace_range(0..2, if sig.starts_with("00") { "11" } else { "00" });
        scope.integrity = Some(Integrity { signature: sig });
        let err = scope.verify_signature(&key_hex).unwrap_err();
        assert!(matches!(err, ScopeError::Integrity(_)), "{err}");
    }

    #[test]
    fn signature_mauvaise_cle_refusee() {
        let (scope, _good) = scope_signe();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let wrong_key = to_hex(&other.verifying_key().to_bytes());
        assert!(scope.verify_signature(&wrong_key).is_err());
    }

    #[test]
    fn integrity_presente_sans_cle_refuse_le_chargement() {
        let (scope, _key) = scope_signe();
        // On reconstruit le TOML avec la signature, sans fournir de clé.
        let signed_toml = format!(
            "{BASE}\n[integrity]\nsignature = \"{}\"\n",
            scope.integrity.unwrap().signature
        );
        let err = Scope::load(&signed_toml, None).unwrap_err();
        assert!(matches!(err, ScopeError::Integrity(_)), "{err}");
    }

    #[test]
    fn scope_signe_recharge_avec_cle_valide() {
        // Bout en bout : signer les octets canoniques, écrire la signature dans
        // le TOML, recharger et vérifier contre la clé → la signature tient la
        // re-sérialisation (signable_bytes est stable au parse).
        let (scope, key_hex) = scope_signe();
        let signed_toml = format!(
            "{BASE}\n[integrity]\nsignature = \"{}\"\n",
            scope.integrity.unwrap().signature
        );
        let loaded = Scope::load(&signed_toml, Some(&key_hex)).unwrap();
        assert!(loaded.has_integrity());
    }

    #[test]
    fn integrity_absente_charge_en_mode_v1() {
        // Pas de bloc [integrity] : load réussit sans clé (mode v1, hash seul).
        let scope = Scope::load(BASE, None).unwrap();
        assert!(!scope.has_integrity());
        assert_eq!(scope.fingerprint().len(), 64);
    }

    #[test]
    fn profil_scope_vers_modele() {
        assert_eq!(AdversaryProfile::from(ScopeProfile::Stealth), AdversaryProfile::Stealth);
        assert_eq!(AdversaryProfile::from(ScopeProfile::Noisy), AdversaryProfile::Noisy);
        assert_eq!(ScopeProfile::default(), ScopeProfile::Balanced);
    }
}
