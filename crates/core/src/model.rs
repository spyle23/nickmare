//! Types de données centraux de Nickmare (issue #2, cf. `docs/ARCHITECTURE.md` §7).
//!
//! Ces types sont **purs** (aucune I/O), sérialisables en JSON via `serde`, et
//! partagés par tous les niveaux (recon → scan → exploitation → craquage →
//! émulation → rapport). Le rapport final est une agrégation :
//! `NetworkMap` + `Finding` + `ExploitAttempt` + `CrackResult` + `AttackExecution`.
//!
//! Invariant de confidentialité (§1, §7) : `CrackResult` rapporte par défaut des
//! **statistiques**, jamais les mots de passe en clair.

use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Adresse MAC (6 octets). Type maison : la crate `core` reste sans dépendance
/// réseau. Se sérialise comme un tableau de 6 entiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: Vec<String> = self.0.iter().map(|octet| format!("{octet:02x}")).collect();
        write!(f, "{}", hex.join(":"))
    }
}

// --- Énumérations -----------------------------------------------------------

/// Protocole de transport d'un port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

/// État observé d'un port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Rôle déduit d'un hôte, pour l'annotation de la carte réseau.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostRole {
    Gateway,
    Server,
    Workstation,
    Unknown,
}

/// Estimation du système d'exploitation d'un hôte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsGuess {
    Linux,
    Windows,
    MacOs,
    Bsd,
    Android,
    Ios,
    NetworkDevice,
    /// Famille non reconnue, étiquette libre.
    Other(String),
}

/// Gravité d'un constat, du simple renseignement au critique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Mode d'une tentative d'exploitation (N2). `Validate` prouve l'exploitabilité
/// sans charge destructrice ; `Exploit` exécute, toujours sous validation humaine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitMode {
    Validate,
    Exploit,
}

/// Issue d'une tentative d'exploitation (N2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitOutcome {
    Vulnerable,
    NotVulnerable,
    Success,
    Failed,
}

/// Verdict de politique de mots de passe tiré d'un craquage (N3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyVerdict {
    Compliant,
    Weak,
    NonCompliant,
    Unknown,
}

/// Agressivité/furtivité rejouée lors d'une émulation d'adversaire (N4).
///
/// La furtivité joue vis-à-vis de la **cible** ; l'exécution reste toujours
/// horodatée en clair dans le journal d'audit opérateur (invariant §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdversaryProfile {
    Noisy,
    Balanced,
    Stealth,
}

/// Verdict de détection par la blue team lors d'une émulation (N4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionVerdict {
    Detected,
    NotDetected,
    Partial,
    Unknown,
}

// --- Hôtes & carte réseau ---------------------------------------------------

/// Service applicatif identifié derrière un port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Nom du service (`"ssh"`, `"http"`…).
    pub name: String,
    /// Produit détecté (ex. `"OpenSSH"`).
    pub product: Option<String>,
    /// Version détectée.
    pub version: Option<String>,
    /// Bannière brute, si capturée.
    pub banner: Option<String>,
}

/// Port d'un hôte et son état.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub proto: Proto,
    pub state: PortState,
    pub service: Option<Service>,
}

/// Hôte observé sur le réseau attesté.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub hostname: Option<String>,
    pub os_guess: Option<OsGuess>,
    pub ports: Vec<Port>,
    /// Rôle déduit pour la carte (`Gateway`, `Server`, `Workstation`, `Unknown`).
    pub role: HostRole,
    /// Passe à `true` après une intrusion réussie (N2).
    pub compromised: bool,
    pub first_seen: DateTime<Utc>,
}

/// Chemin de propagation établi entre deux hôtes (support du pivot, N2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PivotLink {
    /// Hôte source, déjà compromis.
    pub from: IpAddr,
    /// Hôte atteint via le pivot.
    pub to: IpAddr,
    /// Technique/relais tracé (ex. `"ssh"`, `"smb"`).
    pub via: String,
    pub at: DateTime<Utc>,
}

/// Carte du réseau : hôtes découverts + chemins de pivot établis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMap {
    /// Réseau attesté (CIDR ou SSID).
    pub scope_network: String,
    pub hosts: Vec<Host>,
    pub pivots: Vec<PivotLink>,
}

// --- Constats & résultats par niveau ----------------------------------------

/// Constat de sécurité rattaché à un hôte (et éventuellement un port).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub host: IpAddr,
    pub port: Option<u16>,
    pub severity: Severity,
    pub cve: Option<String>,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

/// Tentative d'exploitation (N2). Ne contient jamais de charge destructrice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExploitAttempt {
    pub host: IpAddr,
    pub cve: Option<String>,
    /// Référence du module (ex. Metasploit).
    pub module: String,
    pub mode: ExploitMode,
    /// Opérateur ayant validé l'action (human-in-the-loop).
    pub confirmed_by: String,
    pub outcome: ExploitOutcome,
    /// Preuve d'exploitabilité (jamais de charge destructrice).
    pub evidence: Option<String>,
}

/// Résultat d'un craquage (N3).
///
/// Par choix de conception (§7), ce type rapporte des **statistiques** et des
/// patterns faibles, **pas** les mots de passe en clair : aucun champ ne porte
/// de secret déchiffré.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrackResult {
    /// Origine du hash (capture, dump autorisé).
    pub source: String,
    /// Type de hash (`"NTLM"`, `"krb5"`, `"WPA"`, `"sha512crypt"`…).
    pub hash_type: String,
    pub attempted: u64,
    pub cracked: u64,
    /// Patterns faibles observés (ex. `"mot du dico + année"`).
    pub weak_patterns: Vec<String>,
    pub policy_verdict: PolicyVerdict,
}

/// Exécution d'une technique ATT&CK lors d'une émulation d'adversaire (N4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackExecution {
    /// Identifiant MITRE ATT&CK (ex. `"T1021"`).
    pub technique_id: String,
    pub host: IpAddr,
    pub profile: AdversaryProfile,
    /// Horodatage côté opérateur (toujours en clair).
    pub performed_at: DateTime<Utc>,
    pub detection: DetectionVerdict,
    /// Horodatage de l'alerte blue team (→ MTTD).
    pub detected_at: Option<DateTime<Utc>>,
    /// Contrôle/outil de la blue team ayant alerté.
    pub detected_by: Option<String>,
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    /// Round-trip JSON : sérialiser puis désérialiser doit redonner l'identité.
    fn round_trip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("sérialisation");
        let back: T = serde_json::from_str(&json).expect("désérialisation");
        assert_eq!(value, &back);
    }

    fn ip() -> IpAddr {
        "192.168.1.10".parse().unwrap()
    }

    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn service() -> Service {
        Service {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("9.6".to_string()),
            banner: None,
        }
    }

    fn host() -> Host {
        Host {
            ip: ip(),
            mac: Some(MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])),
            hostname: Some("gw.local".to_string()),
            os_guess: Some(OsGuess::Linux),
            ports: vec![Port {
                number: 22,
                proto: Proto::Tcp,
                state: PortState::Open,
                service: Some(service()),
            }],
            role: HostRole::Gateway,
            compromised: false,
            first_seen: ts(),
        }
    }

    #[test]
    fn round_trip_carte_reseau() {
        let map = NetworkMap {
            scope_network: "192.168.1.0/24".to_string(),
            hosts: vec![host()],
            pivots: vec![PivotLink {
                from: ip(),
                to: "192.168.1.20".parse().unwrap(),
                via: "ssh".to_string(),
                at: ts(),
            }],
        };
        round_trip(&map);
    }

    #[test]
    fn round_trip_constats_et_niveaux() {
        round_trip(&Finding {
            host: ip(),
            port: Some(445),
            severity: Severity::High,
            cve: Some("CVE-2017-0144".to_string()),
            title: "SMBv1 exposé".to_string(),
            description: "Service SMBv1 actif.".to_string(),
            recommendation: "Désactiver SMBv1.".to_string(),
        });
        round_trip(&ExploitAttempt {
            host: ip(),
            cve: Some("CVE-2017-0144".to_string()),
            module: "exploit/windows/smb/ms17_010".to_string(),
            mode: ExploitMode::Validate,
            confirmed_by: "operateur".to_string(),
            outcome: ExploitOutcome::Vulnerable,
            evidence: Some("réponse de vérification".to_string()),
        });
        round_trip(&CrackResult {
            source: "capture WPA".to_string(),
            hash_type: "WPA".to_string(),
            attempted: 1_000_000,
            cracked: 3,
            weak_patterns: vec!["mot du dico + année".to_string()],
            policy_verdict: PolicyVerdict::Weak,
        });
        round_trip(&AttackExecution {
            technique_id: "T1021".to_string(),
            host: ip(),
            profile: AdversaryProfile::Stealth,
            performed_at: ts(),
            detection: DetectionVerdict::Partial,
            detected_at: Some(ts()),
            detected_by: Some("EDR".to_string()),
            notes: None,
        });
    }

    #[test]
    fn round_trip_enums() {
        round_trip(&Proto::Udp);
        round_trip(&PortState::Filtered);
        round_trip(&HostRole::Server);
        round_trip(&OsGuess::Other("RouterOS".to_string()));
        round_trip(&Severity::Critical);
        round_trip(&ExploitMode::Exploit);
        round_trip(&ExploitOutcome::Success);
        round_trip(&PolicyVerdict::NonCompliant);
        round_trip(&AdversaryProfile::Balanced);
        round_trip(&DetectionVerdict::NotDetected);
    }

    #[test]
    fn severity_est_ordonnee() {
        assert!(Severity::Critical > Severity::Info);
        assert!(Severity::High > Severity::Medium);
    }

    #[test]
    fn mac_addr_s_affiche_en_hexa() {
        let mac = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
    }
}
