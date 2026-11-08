//! Orchestration **hashcat / John** en sous-processus, au-dessus d'une
//! **abstraction injectable** du lanceur de process (issue #21, cf.
//! `docs/ARCHITECTURE.md` §5, §9 Phase 7, §11.1).
//!
//! # Lanceur injectable, zéro sous-processus réel en test
//!
//! Toute invocation d'outil passe par le trait [`ProcessRunner`] (comme le
//! transport MSF de #19). Le backend ([`HashcatBackend`]) **construit** l'invocation
//! (mapping des **modes** NTLM/Kerberos/Unix/WPA) et **parse** la sortie `--show`,
//! sans jamais lancer de process lui-même. En CI, le [`ScriptedRunner`] rejoue des
//! sorties de **fixtures** (`testdata/crack/`) de façon déterministe — **sans
//! hashcat, sans John** (§10.2). Le lanceur réel ([`SystemProcessRunner`], au-dessus
//! de `std::process::Command`) n'est **jamais** exercé en CI.
//!
//! # Détection de présence → désactivation propre (§5)
//!
//! [`detect`] sonde `hashcat --version` / `john --version`. L'outil absent (échec
//! de spawn) → [`ToolAvailability::Unavailable`] avec un message clair : le niveau
//! cracking (N3) se désactive proprement plutôt que d'échouer en plein run.
//!
//! # Teardown garanti des hashes (§11.1)
//!
//! Le fichier temporaire de hashes est un `TempFile` **effacé au `Drop`**, et sa
//! libération est **consignée** via un `TeardownGuard` (`core::safety::teardown`,
//! §11.1) : même en cas d'erreur ou de retour anticipé, aucun hash ne traîne sur
//! le disque.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use nickmare_core::safety::teardown::{ResourceKind, TeardownGuard, TempFile};

use crate::engine::{
    CrackEngine, CrackError, CrackReport, CrackRequest, HashEntry, HashType, MaskedSecret,
    Recovered,
};

// --- Outil & disponibilité --------------------------------------------------

/// Outil de craquage orchestré.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// hashcat (GPU).
    Hashcat,
    /// John the Ripper.
    John,
}

impl ToolKind {
    /// Nom du programme (tel qu'invoqué dans le `PATH`).
    #[must_use]
    pub fn program(self) -> &'static str {
        match self {
            ToolKind::Hashcat => "hashcat",
            ToolKind::John => "john",
        }
    }
}

/// Verdict de la détection de présence d'un outil (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolAvailability {
    /// Outil joignable : version renvoyée, niveau cracking **activable**.
    Available {
        /// Outil détecté.
        tool: ToolKind,
        /// Version annoncée (première ligne de `--version`).
        version: String,
    },
    /// Outil absent/injoignable : niveau cracking **désactivé proprement**, avec un
    /// message clair destiné à l'opérateur.
    Unavailable(String),
}

impl ToolAvailability {
    /// Vrai si l'outil est joignable.
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, ToolAvailability::Available { .. })
    }

    /// Message opérateur en cas d'indisponibilité (sinon `None`).
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        match self {
            ToolAvailability::Available { .. } => None,
            ToolAvailability::Unavailable(msg) => Some(msg),
        }
    }
}

/// Détecte la présence d'un outil via `--version` (sans rien craquer).
///
/// Échec de spawn (outil absent) → [`ToolAvailability::Unavailable`] avec un message
/// clair : le niveau cracking (N3) se désactive proprement plutôt que d'échouer plus
/// tard au milieu d'un run (§5, fail-safe).
#[must_use]
pub fn detect(runner: &dyn ProcessRunner, tool: ToolKind) -> ToolAvailability {
    let invocation = ToolInvocation {
        program: tool.program().to_string(),
        args: vec!["--version".to_string()],
    };
    match runner.run(&invocation) {
        Ok(output) if output.status == 0 => {
            let version = first_line(&output.stdout);
            ToolAvailability::Available { tool, version }
        }
        Ok(output) => {
            let msg = format!(
                "{} présent mais en échec (code {}) — niveau cracking (N3) désactivé",
                tool.program(),
                output.status
            );
            ToolAvailability::Unavailable(msg)
        }
        Err(_) => {
            let msg = format!(
                "{} absent — niveau cracking (N3) désactivé proprement",
                tool.program()
            );
            ToolAvailability::Unavailable(msg)
        }
    }
}

// --- Abstraction injectable du lanceur de process ---------------------------

/// Invocation d'outil : programme + arguments **ordonnés**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocation {
    /// Programme à lancer (ex. `"hashcat"`).
    pub program: String,
    /// Arguments positionnels.
    pub args: Vec<String>,
}

/// Sortie d'un sous-processus : code de retour + flux. Jamais de secret au-delà de
/// ce que l'outil a lui-même écrit (parsé puis masqué en aval).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    /// Code de sortie (`-1` si l'outil a été tué par un signal).
    pub status: i32,
    /// Flux standard (sortie `--show` à parser).
    pub stdout: String,
    /// Flux d'erreur.
    pub stderr: String,
}

impl ProcessOutput {
    /// Sortie en succès (code 0, pas d'erreur) avec le `stdout` donné.
    #[must_use]
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// Sortie explicite (code, stdout, stderr).
    #[must_use]
    pub fn new(status: i32, stdout: impl Into<String>, stderr: impl Into<String>) -> Self {
        Self {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
}

/// Lanceur de sous-processus **injectable** : abstrait l'exécution d'un outil.
///
/// `Send + Sync` pour l'usage concurrent et en objet de trait (`Arc<dyn
/// ProcessRunner>`). L'implémentation réelle ([`SystemProcessRunner`]) lance un vrai
/// process ; en CI, [`ScriptedRunner`] rejoue des fixtures sans rien lancer.
pub trait ProcessRunner: Send + Sync {
    /// Lance une invocation et renvoie sa sortie. Un échec de spawn (outil absent)
    /// **doit** se traduire par [`CrackError::ToolUnavailable`] (désactivation
    /// propre, §5).
    fn run(&self, invocation: &ToolInvocation) -> Result<ProcessOutput, CrackError>;
}

/// Lanceur **de fixtures** : rejoue une sortie prédéfinie par programme et
/// **enregistre** chaque invocation, le tout **sans aucun sous-processus**. Un
/// programme non scripté est traité comme **absent** ([`CrackError::ToolUnavailable`]),
/// fail-safe cohérent avec la désactivation propre (§5).
#[derive(Debug, Default)]
pub struct ScriptedRunner {
    responses: HashMap<String, Result<ProcessOutput, CrackError>>,
    calls: Mutex<Vec<ToolInvocation>>,
}

impl ScriptedRunner {
    /// Lanceur vide (aucun programme scripté).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script la sortie d'un programme (chaînage de construction).
    #[must_use]
    pub fn with(mut self, program: impl Into<String>, output: ProcessOutput) -> Self {
        self.responses.insert(program.into(), Ok(output));
        self
    }

    /// Simule un programme **absent** : toute invocation échoue en spawn
    /// (désactivation propre, §5).
    #[must_use]
    pub fn with_absent(mut self, program: impl Into<String>) -> Self {
        let name = program.into();
        let err = CrackError::ToolUnavailable(format!("{name} introuvable (PATH)"));
        self.responses.insert(name, Err(err));
        self
    }

    /// Instantané des invocations reçues, dans l'ordre.
    #[must_use]
    pub fn calls(&self) -> Vec<ToolInvocation> {
        match self.calls.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// Vrai si le programme a été invoqué au moins une fois.
    #[must_use]
    pub fn called(&self, program: &str) -> bool {
        self.calls().iter().any(|inv| inv.program == program)
    }
}

impl ProcessRunner for ScriptedRunner {
    fn run(&self, invocation: &ToolInvocation) -> Result<ProcessOutput, CrackError> {
        if let Ok(mut log) = self.calls.lock() {
            log.push(invocation.clone());
        }
        match self.responses.get(&invocation.program) {
            Some(Ok(output)) => Ok(output.clone()),
            Some(Err(err)) => Err(err.clone()),
            None => Err(CrackError::ToolUnavailable(format!(
                "programme non scripté : {}",
                invocation.program
            ))),
        }
    }
}

/// Lanceur **réel** (production) au-dessus de `std::process::Command`. **Jamais**
/// exercé en CI : les tests passent par [`ScriptedRunner`]. Un échec de spawn
/// (outil absent du `PATH`) devient [`CrackError::ToolUnavailable`] → désactivation
/// propre (§5).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcessRunner;

impl ProcessRunner for SystemProcessRunner {
    fn run(&self, invocation: &ToolInvocation) -> Result<ProcessOutput, CrackError> {
        let spawned = Command::new(&invocation.program)
            .args(&invocation.args)
            .output();
        let output = spawned.map_err(|e| CrackError::ToolUnavailable(e.to_string()))?;
        let status = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        Ok(ProcessOutput {
            status,
            stdout,
            stderr,
        })
    }
}

// --- Backend de craquage hors ligne -----------------------------------------

/// Backend de craquage **hors ligne** au-dessus d'un [`ProcessRunner`] : implémente
/// [`CrackEngine`] en orchestrant hashcat/John. Trace le nettoyage des fichiers
/// temporaires dans un **registre de teardown** observable (§11.1).
pub struct HashcatBackend {
    runner: Arc<dyn ProcessRunner>,
    tool: ToolKind,
    workdir: PathBuf,
    teardown_ledger: Arc<Mutex<Vec<String>>>,
}

impl HashcatBackend {
    /// Construit le backend au-dessus d'un lanceur injecté. `workdir` accueille le
    /// fichier temporaire de hashes (nettoyé après chaque run).
    #[must_use]
    pub fn new(
        runner: Arc<dyn ProcessRunner>,
        tool: ToolKind,
        workdir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            runner,
            tool,
            workdir: workdir.into(),
            teardown_ledger: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Outil orchestré.
    #[must_use]
    pub fn tool(&self) -> ToolKind {
        self.tool
    }

    /// Instantané du registre de teardown (fichiers temporaires nettoyés).
    #[must_use]
    pub fn teardown_log(&self) -> Vec<String> {
        match self.teardown_ledger.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// Chemin du fichier temporaire de hashes pour cette requête.
    fn hash_file_path(&self, request: &CrackRequest) -> PathBuf {
        let safe: String = request
            .source
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        self.workdir.join(format!("nm-hashes-{safe}.tmp"))
    }

    /// Construit l'invocation `--show` (mapping du mode) pour le fichier `path`.
    fn show_invocation(&self, request: &CrackRequest, path: &Path) -> ToolInvocation {
        let file = path.display().to_string();
        let args = match self.tool {
            ToolKind::Hashcat => vec![
                "-m".to_string(),
                request.hash_type.hashcat_mode().to_string(),
                "--show".to_string(),
                file,
            ],
            ToolKind::John => vec![
                format!("--format={}", request.hash_type.john_format()),
                "--show".to_string(),
                file,
            ],
        };
        ToolInvocation {
            program: self.tool.program().to_string(),
            args,
        }
    }

    /// Exécute le craquage : écrit les hashes dans un fichier temporaire (nettoyé
    /// quoi qu'il arrive, §11.1), lance l'outil, parse la sortie `--show`.
    fn run_crack(&self, request: &CrackRequest) -> Result<CrackReport, CrackError> {
        std::fs::create_dir_all(&self.workdir).map_err(|e| CrackError::Io(e.to_string()))?;

        // Teardown garanti : le fichier temp est supprimé (TempFile, RAII) et sa
        // libération consignée, même sur retour anticipé (`?`) ou panique.
        let mut guard = TeardownGuard::with_ledger(Arc::clone(&self.teardown_ledger));
        let path = self.hash_file_path(request);
        let contents = encode_hashes(self.tool, &request.hashes);
        let temp = TempFile::create_with(&path, contents.as_bytes())
            .map_err(|e| CrackError::Io(e.to_string()))?;
        guard.register(temp.path().display().to_string(), ResourceKind::TempFile);

        let invocation = self.show_invocation(request, temp.path());
        let output = self.runner.run(&invocation)?;
        if output.status != 0 && output.stdout.trim().is_empty() {
            return Err(CrackError::ToolFailed(format!(
                "{} a renvoyé le code {}",
                self.tool.program(),
                output.status
            )));
        }

        let recovered = parse_show(self.tool, request, &output.stdout);
        let attempted = request.hashes.len() as u64;
        let report = CrackReport::new(request.hash_type, request.source.clone(), attempted)
            .with_recovered(recovered);

        // Nettoyage explicite immédiat (le `Drop` de `temp` reste idempotent).
        guard.release();
        Ok(report)
    }
}

#[async_trait]
impl CrackEngine for HashcatBackend {
    async fn crack_offline(&self, request: &CrackRequest) -> Result<CrackReport, CrackError> {
        self.run_crack(request)
    }
}

// --- Encodage & parsing (fail-safe, jamais de panic) ------------------------

/// Encode les hashes dans le format attendu par l'outil : une ligne par hash pour
/// hashcat, `compte:hash` pour John.
fn encode_hashes(tool: ToolKind, hashes: &[HashEntry]) -> String {
    let mut out = String::new();
    for entry in hashes {
        match tool {
            ToolKind::Hashcat => out.push_str(&entry.hash),
            ToolKind::John => {
                out.push_str(&entry.account);
                out.push(':');
                out.push_str(&entry.hash);
            }
        }
        out.push('\n');
    }
    out
}

/// Parse la sortie `--show` selon l'outil, en reliant chaque clair recouvré à son
/// compte. Les secrets sont **masqués** dès leur capture ([`MaskedSecret`]).
#[must_use]
pub fn parse_show(tool: ToolKind, request: &CrackRequest, stdout: &str) -> Vec<Recovered> {
    match tool {
        ToolKind::Hashcat => parse_hashcat_show(&request.hashes, stdout),
        ToolKind::John => parse_john_show(&request.hashes, stdout),
    }
}

/// Parse la sortie `hashcat --show` (`hash:clair`). On relie par **hash connu** (le
/// hash peut contenir des `:`, p. ex. WPA/krb5) : robuste, sans découpage fragile.
#[must_use]
pub fn parse_hashcat_show(hashes: &[HashEntry], stdout: &str) -> Vec<Recovered> {
    let mut recovered = Vec::new();
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        for entry in hashes {
            let prefix = format!("{}:", entry.hash);
            if let Some(plain) = line.strip_prefix(&prefix) {
                let secret = MaskedSecret::new(plain);
                recovered.push(Recovered::new(entry.account.as_str(), secret));
                break;
            }
        }
    }
    recovered
}

/// Parse la sortie `john --show` (`compte:clair`). On ne retient que les lignes dont
/// le compte est **connu** : les lignes de résumé de John (« N password hashes
/// cracked ») sont ignorées (fail-safe).
#[must_use]
pub fn parse_john_show(hashes: &[HashEntry], stdout: &str) -> Vec<Recovered> {
    let mut recovered = Vec::new();
    for line in stdout.lines() {
        let Some((account, plain)) = line.split_once(':') else {
            continue;
        };
        if plain.is_empty() {
            continue;
        }
        if hashes.iter().any(|entry| entry.account == account) {
            let secret = MaskedSecret::new(plain);
            recovered.push(Recovered::new(account, secret));
        }
    }
    recovered
}

/// Première ligne non vide d'une sortie, nettoyée (pour la version détectée).
fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: &str = "operateur@example.test";
    const NTLM_SHOW: &str = include_str!("../testdata/crack/hashcat_ntlm_show.txt");
    const JOHN_SHA512: &str = include_str!("../testdata/crack/john_sha512_show.txt");

    const H_ALICE: &str = "b4b9b02e6f09a9bd760f388b67351e2b";
    const H_BOB: &str = "8846f7eaee8fb117ad06bdd830b7586c";
    const H_CAROL: &str = "ffffffffffffffffffffffffffffffff";

    fn ip() -> std::net::IpAddr {
        "192.168.10.25".parse().unwrap()
    }

    /// Requête NTLM : deux hashes recouvrables (alice, bob) + un absent (carol).
    fn ntlm_request() -> CrackRequest {
        CrackRequest {
            target: ip(),
            source: "dump lab".to_string(),
            hash_type: HashType::Ntlm,
            hashes: vec![
                HashEntry::new("alice", H_ALICE),
                HashEntry::new("bob", H_BOB),
                HashEntry::new("carol", H_CAROL),
            ],
            operator: OP.to_string(),
        }
    }

    /// Répertoire de travail jetable, isolé par tag et par PID.
    fn workdir(tag: &str) -> PathBuf {
        let name = format!("nm-crack-{tag}-{}", std::process::id());
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parse_hashcat_ntlm_mappe_les_comptes() {
        let request = ntlm_request();
        let recovered = parse_hashcat_show(&request.hashes, NTLM_SHOW);
        assert_eq!(recovered.len(), 2);
        let alice = recovered.iter().find(|r| r.account == "alice").unwrap();
        assert_eq!(alice.secret.to_string(), "****");
        // carol (hash absent de la sortie) n'est pas recouvré.
        assert!(!recovered.iter().any(|r| r.account == "carol"));
    }

    #[test]
    fn parse_john_sha512_filtre_les_lignes_de_resume() {
        let hashes = [
            HashEntry::new("root", "hashA"),
            HashEntry::new("service", "hashB"),
        ];
        let recovered = parse_john_show(&hashes, JOHN_SHA512);
        assert_eq!(recovered.len(), 2);
        let accounts: Vec<&str> = recovered.iter().map(|r| r.account.as_str()).collect();
        assert!(accounts.contains(&"root"));
        assert!(accounts.contains(&"service"));
    }

    #[test]
    fn detect_present_rend_la_version() {
        let output = ProcessOutput::ok("v6.2.6\n");
        let runner = ScriptedRunner::new().with("hashcat", output);
        let availability = detect(&runner, ToolKind::Hashcat);
        assert!(availability.is_available());
        assert!(availability.message().is_none());
    }

    #[test]
    fn detect_absent_desactive_proprement() {
        let runner = ScriptedRunner::new().with_absent("john");
        let availability = detect(&runner, ToolKind::John);
        assert!(!availability.is_available());
        let message = availability.message().unwrap();
        assert!(message.contains("cracking"));
        assert!(message.contains("désactivé"));
    }

    #[test]
    fn scripted_runner_enregistre_les_invocations() {
        let output = ProcessOutput::ok("");
        let runner = ScriptedRunner::new().with("hashcat", output);
        let invocation = ToolInvocation {
            program: "hashcat".to_string(),
            args: vec!["--version".to_string()],
        };
        let out = runner.run(&invocation).unwrap();
        assert_eq!(out.status, 0);
        assert!(runner.called("hashcat"));
        assert!(!runner.called("john"));
    }

    #[tokio::test]
    async fn backend_craque_puis_nettoie_le_fichier_temp() {
        let output = ProcessOutput::ok(NTLM_SHOW);
        let runner = ScriptedRunner::new().with("hashcat", output);
        let dir = workdir("ntlm");
        let backend = HashcatBackend::new(Arc::new(runner), ToolKind::Hashcat, &dir);
        let request = ntlm_request();

        let report = backend.crack_offline(&request).await.unwrap();
        assert_eq!(report.attempted, 3);
        assert_eq!(report.cracked(), 2);
        for rec in &report.recovered {
            assert_eq!(rec.secret.to_string(), "****");
        }

        // Teardown garanti (§11.1) : plus aucun fichier, libération consignée.
        let remaining = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(remaining, 0, "fichier temp non nettoyé");
        let ledger = backend.teardown_log();
        let logged = ledger.iter().any(|l| l.contains("fichier-temp"));
        assert!(logged, "teardown non consigné : {ledger:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn outil_absent_desactive_proprement_et_nettoie() {
        let runner = ScriptedRunner::new().with_absent("hashcat");
        let dir = workdir("absent");
        let backend = HashcatBackend::new(Arc::new(runner), ToolKind::Hashcat, &dir);
        let request = ntlm_request();

        let err = backend.crack_offline(&request).await.unwrap_err();
        assert!(matches!(err, CrackError::ToolUnavailable(_)), "{err}");
        // Même en erreur, le fichier temp est nettoyé (teardown garanti).
        let remaining = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(remaining, 0, "fichier temp non nettoyé");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
