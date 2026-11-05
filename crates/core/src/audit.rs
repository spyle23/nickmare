//! Journal d'audit chaîné append-only (issue #5, cf. `docs/ARCHITECTURE.md`
//! §3.3, §11.3, §12).
//!
//! Invariant de traçabilité (§1) : **furtif vis-à-vis de la cible, jamais
//! vis-à-vis de l'opérateur**. Chaque action émise par l'outil — y compris une
//! technique d'émulation (N4) masquée pour la cible/SIEM en profil `stealth` —
//! est journalisée **en clair** et horodatée côté opérateur. Rien n'échappe au
//! journal : c'est cette asymétrie qui distingue un outil d'engagement d'un
//! malware.
//!
//! Format **JSON Lines** : un événement par ligne, écriture **append-only**.
//! Chaque entrée porte le hash de l'entrée précédente (journal chaîné, §3.3),
//! ce qui rend toute altération a posteriori détectable :
//!
//! - une **ligne modifiée** casse l'égalité entre son contenu et son propre
//!   hash (`HashMismatch`) ;
//! - une **ligne supprimée, insérée ou réordonnée** casse le lien
//!   `prev_hash → hash` entre voisines (`BrokenChain`).
//!
//! Le chaînage rend l'altération **évidente** ; couplé au fichier append-only à
//! permissions restreintes (§12), il garantit qu'un audit peut toujours
//! reconstituer exactement ce qui a été fait. (Comme tout journal chaîné non
//! signé/non ancré, il n'empêche pas à lui seul la réécriture *complète* du
//! suffixe par un attaquant disposant d'un accès en écriture : c'est le rôle des
//! permissions restreintes et de l'append-only OS de l'empêcher.)

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::AdversaryProfile;

/// `prev_hash` de la toute première entrée (genesis) : 64 zéros hexadécimaux,
/// soit un condensat SHA-256 nul. Ancre le début de la chaîne.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Mode d'engagement sous lequel l'action a été émise (§3).
///
/// Sérialisé en minuscules : le mode laboratoire (voie C, §3) apparaît donc
/// comme `"mode":"lab"` dans le journal et le rapport, comme exigé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditMode {
    /// Engagement standard (sélection+attestation voie A, ou fichier voie B).
    Standard,
    /// Mode laboratoire / apprentissage (voie C). Marqué `mode = "lab"`.
    Lab,
}

/// Niveau de capacité de l'action tracée (§2). Permet notamment de prouver que
/// les actions d'émulation (N4) sont présentes au journal, même en `stealth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityLevel {
    /// N1 — reconnaissance & cartographie (y compris attestation de périmètre).
    #[serde(rename = "N1")]
    Recon,
    /// N2 — intrusion & exploitation.
    #[serde(rename = "N2")]
    Exploitation,
    /// N3 — craquage de credentials.
    #[serde(rename = "N3")]
    Cracking,
    /// N4 — émulation d'adversaire (techniques ATT&CK).
    #[serde(rename = "N4")]
    Emulation,
}

/// Entrée du journal d'audit : une action émise, horodatée et chaînée.
///
/// Les champs métier (`timestamp` … `adversary_profile`) décrivent l'action ;
/// `prev_hash`/`hash` assurent le chaînage. Le `hash` couvre **tous** les autres
/// champs, `prev_hash` compris : toute insertion ou réécriture d'un champ
/// invalide donc le condensat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Horodatage UTC de l'émission (toujours en clair, §11.3).
    pub timestamp: DateTime<Utc>,
    /// Identité de l'opérateur ayant émis l'action (human-in-the-loop).
    pub operator: String,
    /// Cible de l'action (IP, CIDR, SSID…) ou `"-"` pour une action sans cible.
    pub target: String,
    /// Action émise, en verbe métier (`"target.attest"`, `"exploit.validate"`,
    /// `"emulation.T1021"`…).
    pub action: String,
    /// Résultat observé côté opérateur (`"ok"`, `"blocked"`, `"vulnerable"`,
    /// `"not-detected"`…). Côté cible une technique peut être masquée ; ici le
    /// résultat réel est consigné en clair.
    pub result: String,
    /// Mode d'engagement (`standard` | `lab`).
    pub mode: AuditMode,
    /// Niveau de capacité de l'action (N1–N4).
    pub level: CapabilityLevel,
    /// Profil d'adversaire rejoué, renseigné pour les actions d'émulation (N4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adversary_profile: Option<AdversaryProfile>,
    /// Hash de l'entrée précédente (chaînage). [`GENESIS_HASH`] pour la première.
    pub prev_hash: String,
    /// Condensat SHA-256 (hex) de cette entrée, couvrant tous les champs
    /// ci-dessus (`prev_hash` inclus).
    pub hash: String,
}

/// Contenu d'une action à journaliser, **sans** les champs calculés
/// (`timestamp`, `prev_hash`, `hash`) : ceux-ci sont remplis par le journal.
///
/// Le constructeur part d'un défaut sûr (`Standard`, pas de profil) ; les
/// méthodes `in_lab` / `with_profile` affinent sans ambiguïté.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub operator: String,
    pub target: String,
    pub action: String,
    pub result: String,
    pub mode: AuditMode,
    pub level: CapabilityLevel,
    pub adversary_profile: Option<AdversaryProfile>,
}

impl AuditRecord {
    /// Construit un enregistrement en mode standard, sans profil d'adversaire.
    pub fn new(
        operator: impl Into<String>,
        target: impl Into<String>,
        action: impl Into<String>,
        result: impl Into<String>,
        level: CapabilityLevel,
    ) -> Self {
        Self {
            operator: operator.into(),
            target: target.into(),
            action: action.into(),
            result: result.into(),
            mode: AuditMode::Standard,
            level,
            adversary_profile: None,
        }
    }

    /// Marque l'action comme émise en mode laboratoire (voie C → `mode = "lab"`).
    #[must_use]
    pub fn in_lab(mut self) -> Self {
        self.mode = AuditMode::Lab;
        self
    }

    /// Attache le profil d'adversaire rejoué (actions d'émulation N4).
    #[must_use]
    pub fn with_profile(mut self, profile: AdversaryProfile) -> Self {
        self.adversary_profile = Some(profile);
        self
    }
}

/// Erreur de vérification de la chaîne d'audit (`line` est 1-indexé).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// Ligne illisible (JSON corrompu / champ absent).
    MalformedLine { line: usize, detail: String },
    /// Le hash recalculé ne correspond pas au hash stocké : la ligne a été
    /// modifiée.
    HashMismatch { line: usize },
    /// Le `prev_hash` ne pointe pas sur le hash de la ligne précédente : une
    /// ligne a été supprimée, insérée ou réordonnée.
    BrokenChain { line: usize },
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::MalformedLine { line, detail } => {
                write!(f, "ligne {line} illisible : {detail}")
            }
            AuditError::HashMismatch { line } => {
                write!(
                    f,
                    "ligne {line} : hash recalculé != hash stocké (altération)"
                )
            }
            AuditError::BrokenChain { line } => {
                write!(f, "ligne {line} : chaîne rompue (prev_hash incohérent)")
            }
        }
    }
}

impl std::error::Error for AuditError {}

/// Journal d'audit chaîné, adossé à un fichier **append-only**.
///
/// Reprend le chaînage à partir du dernier hash présent si le fichier existe
/// déjà (reprise idempotente, §11.2) : on n'écrase jamais, on ajoute.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    last_hash: String,
}

impl AuditLog {
    /// Ouvre (ou crée) le journal au chemin donné en mode append-only, avec des
    /// permissions restreintes (§12 : `0600` sur Unix). Reprend le chaînage
    /// depuis la dernière entrée si le fichier existe.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let last_hash = match last_hash_of(&path) {
            Ok(h) => h,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => GENESIS_HASH.to_string(),
            Err(e) => return Err(e),
        };
        // Crée le fichier (vide) dès l'ouverture, avec les permissions voulues.
        open_append(&path)?;
        Ok(Self { path, last_hash })
    }

    /// Hash de la dernière entrée écrite (ou [`GENESIS_HASH`] si le journal est
    /// vide). C'est le `prev_hash` de la prochaine entrée.
    #[must_use]
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Journalise une action **à l'instant présent** : construit l'entrée
    /// horodatée (`Utc::now()`), la chaîne au dernier hash, l'écrit en append et
    /// renvoie l'entrée consignée.
    pub fn append(&mut self, record: AuditRecord) -> io::Result<AuditEntry> {
        self.append_at(record, Utc::now())
    }

    /// Variante avec horodatage explicite — utile pour fixer l'horodatage
    /// opérateur d'une action N4 (→ MTTD, §11.3) et pour des tests déterministes.
    pub fn append_at(
        &mut self,
        record: AuditRecord,
        timestamp: DateTime<Utc>,
    ) -> io::Result<AuditEntry> {
        let mut entry = AuditEntry {
            timestamp,
            operator: record.operator,
            target: record.target,
            action: record.action,
            result: record.result,
            mode: record.mode,
            level: record.level,
            adversary_profile: record.adversary_profile,
            prev_hash: self.last_hash.clone(),
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();

        // Un événement = une ligne JSON compacte terminée par un `\n`.
        let mut line = serde_json::to_string(&entry).map_err(io::Error::other)?;
        line.push('\n');

        let mut file = open_append(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;

        self.last_hash = entry.hash.clone();
        Ok(entry)
    }
}

impl AuditEntry {
    /// Recalcule le condensat SHA-256 (hex) couvrant tous les champs **sauf** la
    /// valeur de `hash` elle-même.
    ///
    /// La sérialisation JSON d'une `AuditEntry` (uniquement des scalaires, des
    /// chaînes, des énumérations et un `DateTime` — aucun type à ordre non
    /// déterministe) est stable et reproductible : c'est un invariant interne,
    /// d'où le `expect` (§11.4 : panique réservée aux invariants internes).
    fn compute_hash(&self) -> String {
        let mut bare = self.clone();
        bare.hash = String::new();
        let bytes = serde_json::to_vec(&bare).expect("AuditEntry sérialisable");
        let digest = Sha256::digest(&bytes);
        to_hex(digest.as_slice())
    }
}

/// Relit toutes les entrées d'un journal **et valide sa chaîne**. Renvoie les
/// entrées dans l'ordre si la chaîne est intègre, sinon la première anomalie.
///
/// Un fichier absent est traité comme un journal vide (zéro entrée).
pub fn verify_file(path: impl AsRef<Path>) -> Result<Vec<AuditEntry>, AuditError> {
    let file = match File::open(path.as_ref()) {
        Ok(f) => f,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(malformed(0, e)),
    };

    let mut entries = Vec::new();
    for (idx, raw) in BufReader::new(file).lines().enumerate() {
        let line = raw.map_err(|e| malformed(idx + 1, e))?;
        // Les lignes vides (fin de fichier, par ex.) sont ignorées.
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line).map_err(|e| malformed(idx + 1, e))?;
        entries.push(entry);
    }

    verify_entries(&entries)?;
    Ok(entries)
}

/// Valide la chaîne d'une suite d'entrées déjà désérialisées : chaque hash doit
/// correspondre au contenu (détection de **modification**), et chaque
/// `prev_hash` doit pointer sur le hash de l'entrée précédente (détection de
/// **suppression / insertion / réordonnancement**).
pub fn verify_entries(entries: &[AuditEntry]) -> Result<(), AuditError> {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (idx, entry) in entries.iter().enumerate() {
        let line = idx + 1;
        if entry.compute_hash() != entry.hash {
            return Err(AuditError::HashMismatch { line });
        }
        if entry.prev_hash != expected_prev {
            return Err(AuditError::BrokenChain { line });
        }
        expected_prev = entry.hash.clone();
    }
    Ok(())
}

// --- Aides internes ---------------------------------------------------------

/// Construit une erreur `MalformedLine` à partir d'une erreur affichable.
fn malformed(line: usize, e: impl std::fmt::Display) -> AuditError {
    AuditError::MalformedLine {
        line,
        detail: e.to_string(),
    }
}

/// Ouvre le fichier en append + création, avec permissions restreintes sur Unix
/// (§12). Sur Windows, l'ACL par défaut du profil s'applique (pas d'équivalent
/// portable à `chmod` ici).
fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Lit le hash de la dernière entrée non vide du fichier. Propage `NotFound` si
/// le fichier n'existe pas (pour distinguer « vierge » de « erreur »).
fn last_hash_of(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    let mut last: Option<String> = None;
    for raw in BufReader::new(file).lines() {
        let line = raw?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line).map_err(io::Error::other)?;
        last = Some(entry.hash);
    }
    Ok(last.unwrap_or_else(|| GENESIS_HASH.to_string()))
}

/// Encode un condensat en chaîne hexadécimale minuscule (sans dépendance).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// Chemin de journal jetable, isolé par tag et par PID.
    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nm-audit-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.jsonl");
        let _ = std::fs::remove_file(&path);
        path
    }

    fn rec(action: &str, result: &str, level: CapabilityLevel) -> AuditRecord {
        AuditRecord::new("op", "t", action, result, level)
    }

    fn put(log: &mut AuditLog, record: AuditRecord, secs: i64) -> AuditEntry {
        log.append_at(record, ts(secs)).unwrap()
    }

    /// Journal de démonstration : une attestation de périmètre (N1), une
    /// validation d'exploit (N2), une technique d'émulation furtive (N4).
    fn seed_log(path: &Path) -> Vec<AuditEntry> {
        let mut log = AuditLog::open(path).unwrap();
        let e1 = put(
            &mut log,
            rec("target.attest", "ok", CapabilityLevel::Recon),
            1_700_000_000,
        );
        let e2 = put(
            &mut log,
            rec(
                "exploit.validate",
                "vulnerable",
                CapabilityLevel::Exploitation,
            ),
            1_700_000_060,
        );
        let mut r3 = rec(
            "emulation.T1021",
            "not-detected",
            CapabilityLevel::Emulation,
        );
        r3 = r3.in_lab().with_profile(AdversaryProfile::Stealth);
        let e3 = put(&mut log, r3, 1_700_000_120);
        vec![e1, e2, e3]
    }

    #[test]
    fn chaine_de_hash_valide_et_relue() {
        let path = tmp("ok");
        let written = seed_log(&path);

        // Chaînage : la 1re ancre sur le genesis, chaque suivante sur la précédente.
        assert_eq!(written[0].prev_hash, GENESIS_HASH);
        assert_eq!(written[1].prev_hash, written[0].hash);
        assert_eq!(written[2].prev_hash, written[1].hash);

        // Relecture + validation : la chaîne est intègre et rend l'identité.
        let read = verify_file(&path).unwrap();
        assert_eq!(read, written);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn chaque_action_donne_une_ligne_horodatee() {
        let path = tmp("lines");
        let written = seed_log(&path);

        // 3 actions émises = 3 lignes exactement, chacune horodatée.
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), written.len());
        for line in &lines {
            let entry: AuditEntry = serde_json::from_str(line).unwrap();
            assert!(entry.timestamp <= Utc::now());
        }
        // L'attestation de cible (N1) est bien présente.
        assert_eq!(written[0].action, "target.attest");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn action_emulee_masquee_tracee_en_clair_meme_en_stealth() {
        // Invariant §11.3 : furtif pour la cible, transparent pour l'opérateur.
        let path = tmp("n4");
        let written = seed_log(&path);
        let n4 = &written[2];

        // L'entrée N4 est présente, en profil stealth, et consigne le résultat
        // réel (« non détectée par la cible ») en clair.
        assert_eq!(n4.level, CapabilityLevel::Emulation);
        assert_eq!(n4.adversary_profile, Some(AdversaryProfile::Stealth));
        assert_eq!(n4.result, "not-detected");
        assert_eq!(n4.mode, AuditMode::Lab);

        // Et c'est lisible en clair dans le fichier (aucun masquage interne).
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("emulation.T1021"));
        assert!(content.contains("Stealth"));
        assert!(content.contains("\"mode\":\"lab\""));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mode_lab_serialise_en_lab() {
        let path = tmp("mode");
        let mut log = AuditLog::open(&path).unwrap();
        let r = rec("lab.start", "ok", CapabilityLevel::Recon).in_lab();
        put(&mut log, r, 1_700_000_000);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"mode\":\"lab\""));

        std::fs::remove_file(&path).ok();
    }

    // --- Tests négatifs de sécurité (§10.4) : toute altération est détectée ---

    #[test]
    fn negatif_ligne_modifiee_detectee() {
        let path = tmp("mod");
        let entries = seed_log(&path);
        std::fs::remove_file(&path).ok();

        // Un attaquant réécrit le résultat d'une action sans toucher au hash.
        let mut tampered = entries;
        tampered[1].result = "ok".to_string(); // était "vulnerable"
        assert_eq!(
            verify_entries(&tampered),
            Err(AuditError::HashMismatch { line: 2 })
        );
    }

    #[test]
    fn negatif_ligne_supprimee_detectee() {
        let path = tmp("del");
        let entries = seed_log(&path);
        std::fs::remove_file(&path).ok();

        // On retire la 2e entrée : la 3e pointe désormais dans le vide.
        let tampered = vec![entries[0].clone(), entries[2].clone()];
        assert_eq!(
            verify_entries(&tampered),
            Err(AuditError::BrokenChain { line: 2 })
        );
    }

    #[test]
    fn negatif_ligne_inseree_detectee() {
        let path = tmp("ins");
        let entries = seed_log(&path);
        std::fs::remove_file(&path).ok();

        // Entrée « valide en elle-même » (hash cohérent avec son contenu) mais
        // insérée frauduleusement : le lien avec ses voisines est rompu.
        let mut forged = AuditEntry {
            timestamp: ts(1_700_000_030),
            operator: "pirate".to_string(),
            target: "t".to_string(),
            action: "exploit.run".to_string(),
            result: "success".to_string(),
            mode: AuditMode::Standard,
            level: CapabilityLevel::Exploitation,
            adversary_profile: None,
            prev_hash: entries[0].hash.clone(),
            hash: String::new(),
        };
        forged.hash = forged.compute_hash();

        // L'entrée forgée passe le test de hash, mais la ligne suivante
        // (l'ancienne 2e) a un prev_hash qui ne pointe plus sur elle.
        let tampered = vec![
            entries[0].clone(),
            forged,
            entries[1].clone(),
            entries[2].clone(),
        ];
        assert_eq!(
            verify_entries(&tampered),
            Err(AuditError::BrokenChain { line: 3 })
        );
    }

    #[test]
    fn negatif_fichier_corrompu_detecte() {
        let path = tmp("corrupt");
        std::fs::write(&path, "ceci n'est pas du json\n").unwrap();

        match verify_file(&path) {
            Err(AuditError::MalformedLine { line, .. }) => assert_eq!(line, 1),
            other => panic!("attendu MalformedLine, obtenu {other:?}"),
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn append_ne_reecrit_pas_en_place() {
        // Append-only : écrire une 2e entrée ne doit jamais altérer les octets
        // déjà écrits de la 1re — le fichier ne fait que croître.
        let path = tmp("append");
        let mut log = AuditLog::open(&path).unwrap();
        put(&mut log, rec("a1", "ok", CapabilityLevel::Recon), 1);
        let after_first = std::fs::read(&path).unwrap();

        put(&mut log, rec("a2", "ok", CapabilityLevel::Recon), 2);
        let after_second = std::fs::read(&path).unwrap();

        // Le contenu après la 2e écriture commence exactement par celui d'après
        // la 1re (préfixe intact) et est strictement plus long.
        assert!(after_second.len() > after_first.len());
        assert_eq!(&after_second[..after_first.len()], after_first.as_slice());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn reouverture_reprend_la_chaine() {
        // Reprise (§11.2) : rouvrir un journal existant continue le chaînage
        // sans réécrire, et la chaîne complète reste valide.
        let path = tmp("reopen");

        let first = {
            let mut log = AuditLog::open(&path).unwrap();
            put(&mut log, rec("a1", "ok", CapabilityLevel::Recon), 1)
        };

        let second = {
            let mut log = AuditLog::open(&path).unwrap();
            assert_eq!(log.last_hash(), first.hash);
            put(&mut log, rec("a2", "ok", CapabilityLevel::Recon), 2)
        };

        assert_eq!(second.prev_hash, first.hash);
        let read = verify_file(&path).unwrap();
        assert_eq!(read.len(), 2);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn journal_vide_est_valide() {
        let path = tmp("empty");
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(log.last_hash(), GENESIS_HASH);
        assert!(verify_file(&path).unwrap().is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn fichier_a_permissions_restreintes_sur_unix() {
        use std::os::unix::fs::PermissionsExt;

        let path = tmp("perm");
        let _log = AuditLog::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // Seul le propriétaire peut lire/écrire : aucun bit groupe/autres.
        assert_eq!(mode & 0o077, 0, "permissions trop larges : {mode:o}");

        std::fs::remove_file(&path).ok();
    }
}
