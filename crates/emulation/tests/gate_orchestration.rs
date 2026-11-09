//! Intégration N4 : émulation d'adversaire **confinée par le gate** et
//! **intégralement tracée côté opérateur**, éprouvée contre un **mock**
//! déterministe — sans vrai payload, sans réseau, sans vraie évasion d'EDR (issue
//! #22 ; `docs/ARCHITECTURE.md` §4, §11.3 ; `docs/TESTING.md` §10.4). On déroule la
//! chaîne via [`execute_through_gate`], seul chemin vers le moteur, et l'on vérifie
//! la DoD US-G1/G2/G3 :
//!
//! - technique **listée** autorisée → `AttackExecution` tracé en clair + audit
//!   `emulation.<technique>` (profil inclus) ;
//! - technique **hors `attack_techniques`** → refus + audit `blocked_technique` ;
//! - capacité émulation désactivée → refus + audit `blocked_capability` ;
//! - **invariant** : en profil `stealth`, l'audit N4 et l'`AttackExecution` sont
//!   présents et **relus en clair** depuis le journal opérateur ;
//! - verdict blue team → **MTTD** + matrice de couverture + comparaison de profils ;
//! - rappel du contact SOC (`blue_team_contact`) au démarrage hors mode labo.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits, #27) n'y valent pas — un `unwrap` qui
// échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::path::PathBuf;

use chrono::{DateTime, TimeZone, Utc};

use nickmare_core::audit::{verify_file, AuditLog, AuditMode, CapabilityLevel};
use nickmare_core::gate::{Attestation, Gate, Progress, Request};
use nickmare_core::model::{AdversaryProfile, DetectionVerdict};
use nickmare_core::scope::{Capability, Scope};

use nickmare_emulation::attack::{self, AttackRequest, MockEmulationEngine, SocReminder};
use nickmare_emulation::techniques::TechniqueCatalog;
use nickmare_emulation::verdict::{apply_verdict, CoverageMatrix, DetectionReport};

const OP: &str = "operateur@example.test";
const TARGET: &str = "192.168.10.25";

/// Scope de référence : émulation activée, techniques T1021/T1046 autorisées,
/// profil stealth, contact SOC renseigné, fenêtre 08:00-18:00, débit 200 pps.
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

[constraints]
max_rate_pps = 200
allowed_hours = \"08:00-18:00\"

[capabilities]
recon = true

[capabilities.emulation]
enabled = true
attack_techniques = [\"T1021\", \"T1046\"]
profile = \"stealth\"
blue_team_contact = \"soc@acme.example\"
";

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap()
}

fn at(hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
    let dt = Utc.with_ymd_and_hms(2026, 6, 1, hour, minute, second);
    dt.unwrap()
}

fn scope() -> Scope {
    Scope::from_toml(BASE).unwrap()
}

fn scope_with(from: &str, to: &str) -> Scope {
    Scope::from_toml(&BASE.replace(from, to)).unwrap()
}

fn attest(scope: &Scope) -> Attestation {
    Attestation::for_scope(scope, OP, "192.168.10.0/24")
}

/// Progression recon aboutie sur `target` (débloque la pré-condition N≥2).
fn recon_done(target: &str) -> Progress {
    let mut progress = Progress::new();
    progress.record(ip(target), Capability::Recon);
    progress
}

/// Chemin de journal jetable, isolé par tag et par PID.
fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nm-emulation-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&path);
    path
}

// --- US-G1 : whitelist stricte + traçage ------------------------------------

#[tokio::test]
async fn technique_listee_autorisee_est_tracee() {
    let engine = MockEmulationEngine::new();
    let sc = scope();
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP)
        .with_attestation(&att)
        .with_progress(&prog);
    let request = AttackRequest::new(ip(TARGET), "T1021", OP);

    let outcome = attack::execute_through_gate(
        &mut gate,
        &req,
        &engine,
        &request,
        AdversaryProfile::Balanced,
        now(),
    )
    .await
    .unwrap();

    assert!(!outcome.is_blocked());
    let execution = outcome.execution().expect("exécution tracée");
    assert_eq!(execution.technique_id, "T1021");
    assert_eq!(execution.performed_at, now());
    assert_eq!(execution.detection, DetectionVerdict::Unknown);
    assert!(execution.notes.is_some(), "note opérateur en clair");

    assert_eq!(outcome.audit().action, "emulation.T1021");
    assert_eq!(outcome.audit().result, "ok");
    assert_eq!(outcome.audit().level, CapabilityLevel::Emulation);
}

#[tokio::test]
async fn technique_non_listee_refusee_avec_audit() {
    // T1562 est connue du catalogue mais ABSENTE de attack_techniques du scope.
    let engine = MockEmulationEngine::new();
    let sc = scope();
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP)
        .with_attestation(&att)
        .with_progress(&prog);
    let request = AttackRequest::new(ip(TARGET), "T1562", OP);

    let outcome = attack::execute_through_gate(
        &mut gate,
        &req,
        &engine,
        &request,
        AdversaryProfile::Stealth,
        now(),
    )
    .await
    .unwrap();

    assert!(outcome.is_blocked());
    assert_eq!(outcome.audit().action, "blocked_technique");
    assert_eq!(outcome.audit().result, "blocked");
    assert_eq!(outcome.audit().level, CapabilityLevel::Emulation);
    // Même refusé, l'audit porte le profil rejoué (transparence opérateur).
    let profile = outcome.audit().adversary_profile;
    assert_eq!(profile, Some(AdversaryProfile::Stealth));
    assert!(outcome.execution().is_none());

    // Et le refus est journalisable en clair.
    let path = tmp("blocked");
    let mut log = AuditLog::open(&path).unwrap();
    log.append_at(outcome.audit().clone(), now()).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("blocked_technique"));
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn capacite_emulation_desactivee_refuse() {
    let engine = MockEmulationEngine::new();
    let sc = scope_with("enabled = true", "enabled = false");
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP)
        .with_attestation(&att)
        .with_progress(&prog);
    let request = AttackRequest::new(ip(TARGET), "T1021", OP);

    let outcome = attack::execute_through_gate(
        &mut gate,
        &req,
        &engine,
        &request,
        AdversaryProfile::Noisy,
        now(),
    )
    .await
    .unwrap();

    assert!(outcome.is_blocked());
    assert_eq!(outcome.audit().action, "blocked_capability");
    assert!(outcome.execution().is_none());
}

// --- Invariant central : furtif pour la cible, transparent pour l'opérateur --

#[tokio::test]
async fn stealth_trace_en_clair_cote_operateur_meme_masque_pour_la_cible() {
    // Invariant §11.3 : en profil stealth, l'audit N4 ET l'AttackExecution sont
    // présents et relisibles EN CLAIR depuis le journal opérateur.
    let engine = MockEmulationEngine::new();
    let sc = scope();
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP)
        .with_attestation(&att)
        .with_progress(&prog);
    let request = AttackRequest::new(ip(TARGET), "T1021", OP);

    let outcome = attack::execute_through_gate(
        &mut gate,
        &req,
        &engine,
        &request,
        AdversaryProfile::Stealth,
        now(),
    )
    .await
    .unwrap();

    // L'exécution est tracée, horodatée, profil stealth — malgré l'évasion cible.
    let execution = outcome
        .execution()
        .expect("exécution tracée même en stealth");
    assert_eq!(execution.profile, AdversaryProfile::Stealth);
    assert_eq!(execution.performed_at, now());

    // L'audit N4 porte le verbe métier en clair et le profil stealth.
    let audit = outcome.audit();
    assert_eq!(audit.action, "emulation.T1021");
    assert_eq!(audit.level, CapabilityLevel::Emulation);
    assert_eq!(audit.adversary_profile, Some(AdversaryProfile::Stealth));

    // Écrit au journal opérateur, horodaté, puis relu EN CLAIR depuis le fichier.
    let path = tmp("stealth");
    let mut log = AuditLog::open(&path).unwrap();
    log.append_at(audit.clone(), now()).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("emulation.T1021"), "verbe en clair");
    assert!(content.contains("Stealth"), "profil en clair");
    assert!(content.contains("\"N4\""), "niveau N4 en clair");

    // La chaîne d'audit reste intègre (aucun masquage interne).
    let entries = verify_file(&path).unwrap();
    assert_eq!(entries.len(), 1);
    std::fs::remove_file(&path).ok();
}

// --- US-G2/G3 : MTTD, matrice, comparaison de profils -----------------------

#[tokio::test]
async fn bout_en_bout_verdict_mttd_matrice_et_profils() {
    let engine = MockEmulationEngine::new();
    let sc = scope();
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP)
        .with_attestation(&att)
        .with_progress(&prog);

    // T1021 en profil bruyant (sera détecté), T1046 en furtif (non détecté).
    let request_noisy = AttackRequest::new(ip(TARGET), "T1021", OP);
    let outcome_noisy = attack::execute_through_gate(
        &mut gate,
        &req,
        &engine,
        &request_noisy,
        AdversaryProfile::Noisy,
        now(),
    )
    .await
    .unwrap();
    let mut exec_noisy = outcome_noisy.execution().cloned().expect("exec noisy");
    let report = DetectionReport::detected(at(12, 0, 30), "EDR");
    apply_verdict(&mut exec_noisy, &report);

    let request_stealth = AttackRequest::new(ip(TARGET), "T1046", OP);
    let outcome_stealth = attack::execute_through_gate(
        &mut gate,
        &req,
        &engine,
        &request_stealth,
        AdversaryProfile::Stealth,
        now(),
    )
    .await
    .unwrap();
    let mut exec_stealth = outcome_stealth.execution().cloned().expect("exec stealth");
    apply_verdict(&mut exec_stealth, &DetectionReport::not_detected());

    let catalog = TechniqueCatalog::embedded().unwrap();
    let matrix = CoverageMatrix::build(&[exec_noisy, exec_stealth], &catalog);
    assert_eq!(matrix.len(), 2);

    // Matrice exportable en JSON (US-G2), techniques et tactiques présentes.
    let json = matrix.to_json().unwrap();
    assert!(json.contains("T1021"));
    assert!(json.contains("T1046"));
    assert!(json.contains("Lateral Movement"));

    // MTTD calculé depuis l'horodatage d'alerte (US-G2).
    let noisy_stats = matrix.stats_for(AdversaryProfile::Noisy);
    assert_eq!(noisy_stats.mean_mttd_seconds, Some(30));

    // Comparaison des taux de détection entre profils (US-G3) : la furtivité passe.
    let stealth_stats = matrix.stats_for(AdversaryProfile::Stealth);
    assert!(stealth_stats.detection_rate < noisy_stats.detection_rate);
    assert_eq!(matrix.compare_profiles().len(), 2);
}

// --- US-G2 : rappel du contact SOC hors labo --------------------------------

#[test]
fn rappel_contact_soc_hors_labo() {
    let sc = scope();
    let maybe = SocReminder::at_startup(&sc.capabilities.emulation, AuditMode::Standard);
    let reminder = maybe.expect("rappel hors labo");
    assert!(reminder.has_contact());
    assert_eq!(reminder.contact(), Some("soc@acme.example"));
    assert!(reminder.message().contains("soc@acme.example"));

    // En mode labo, aucun SOC tiers à coordonner : pas de rappel.
    let lab = SocReminder::at_startup(&sc.capabilities.emulation, AuditMode::Lab);
    assert!(lab.is_none());
}
