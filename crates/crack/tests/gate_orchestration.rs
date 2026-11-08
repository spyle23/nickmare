//! Intégration N3 : craquage **confiné par le gate**, éprouvé contre des **mocks**
//! déterministes — sans hashcat, sans John, sans réseau (issue #21 ;
//! `docs/ARCHITECTURE.md` §4, §10.2 ; `docs/TESTING.md` §10.4). On déroule la
//! chaîne via [`crack_offline_through_gate`] / [`spray_through_gate`], seul chemin
//! vers un moteur, et l'on vérifie la DoD US-F1/F2/F3 :
//!
//! - **offline** (défaut) autorisé → statistiques + verdict de politique, audit
//!   `crack.offline`, **aucun clair** dans le rapport ;
//! - capacité cracking **désactivée** → `Blocked` + audit `blocked_capability` ;
//! - **spray en ligne** sans l'opt-in `online_spray` → refus + audit
//!   `blocked_online_spray` (désactivé par défaut) ;
//! - spray **sans confirmation** → refus + audit `blocked_confirmation` ;
//! - dépassement de `max_attempts_per_account` → **arrêt** + audit
//!   `blocked_max_attempts` (anti-lockout).

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits, #27) n'y valent pas — un `unwrap` qui
// échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;

use chrono::{DateTime, TimeZone, Utc};

use nickmare_core::audit::AuditMode;
use nickmare_core::gate::{Attestation, Gate, Progress, Request};
use nickmare_core::model::PolicyVerdict;
use nickmare_core::scope::{Capability, Scope};

use nickmare_crack::engine;
use nickmare_crack::policy::PasswordPolicy;

const OP: &str = "operateur@example.test";
const TARGET: &str = "192.168.10.25";
const H_ALICE: &str = "b4b9b02e6f09a9bd760f388b67351e2b";
const BOB_HASH: &str = "ffffffffffffffffffffffffffffffff";
const CAROL_HASH: &str = "11111111111111111111111111111111";

/// Scope de référence : cracking activé, spray en ligne opt-in, 3 tentatives/compte,
/// fenêtre 08:00-18:00, débit 200 pps.
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

[capabilities.cracking]
enabled = true
online_spray = true
max_attempts_per_account = 3
";

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap()
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

/// Requête offline : alice (recouvrable) + bob/carol (non recouvrables).
fn offline_request() -> engine::CrackRequest {
    engine::CrackRequest {
        target: ip(TARGET),
        source: "dump NTDS lab".to_string(),
        hash_type: engine::HashType::Ntlm,
        hashes: vec![
            engine::HashEntry::new("alice", H_ALICE),
            engine::HashEntry::new("bob", BOB_HASH),
            engine::HashEntry::new("carol", CAROL_HASH),
        ],
        operator: OP.to_string(),
    }
}

// --- US-F1/F2 : craquage hors ligne autorisé --------------------------------

#[tokio::test]
async fn offline_autorise_rend_des_statistiques_sans_clair() {
    let cracker = engine::MockCrackEngine::new().with_cracked(H_ALICE, "Summer2024");
    let sc = scope();
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP)
        .with_attestation(&att)
        .with_progress(&prog);
    let request = offline_request();
    let policy = PasswordPolicy::default();

    let outcome = engine::crack_offline_through_gate(&mut gate, &req, &cracker, &request, &policy)
        .await
        .unwrap();

    assert!(!outcome.is_blocked());
    assert_eq!(outcome.audit().action, "crack.offline");
    assert_eq!(outcome.audit().result, "ok");

    let result = outcome.result().expect("craquage autorisé");
    assert_eq!(result.attempted, 3);
    assert_eq!(result.cracked, 1);
    assert_eq!(result.policy_verdict, PolicyVerdict::Weak);
    let has_year = result.weak_patterns.iter().any(|p| p.contains("année"));
    assert!(has_year, "patterns : {:?}", result.weak_patterns);

    // Le livrable client ne contient aucun clair (US-F1).
    let json = serde_json::to_string(result).unwrap();
    assert!(!json.contains("Summer2024"), "fuite de clair : {json}");
}

#[tokio::test]
async fn capacite_cracking_desactivee_refuse_avec_audit() {
    let cracker = engine::MockCrackEngine::new().with_cracked(H_ALICE, "Summer2024");
    let sc = scope_with(
        "[capabilities.cracking]\nenabled = true",
        "[capabilities.cracking]\nenabled = false",
    );
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP)
        .with_attestation(&att)
        .with_progress(&prog);
    let request = offline_request();
    let policy = PasswordPolicy::default();

    let outcome = engine::crack_offline_through_gate(&mut gate, &req, &cracker, &request, &policy)
        .await
        .unwrap();

    assert!(outcome.is_blocked());
    assert_eq!(outcome.audit().action, "blocked_capability");
    assert_eq!(outcome.audit().result, "blocked");
    assert!(outcome.result().is_none());
}

// --- US-F3 : spray en ligne borné (tests négatifs §10.4) --------------------

/// Requête de gate « tout vert » pour un spray (attestée + recon + confirmée).
fn confirmed<'a>(att: &'a Attestation, prog: &'a Progress) -> Request<'a> {
    Request::new(now(), OP)
        .with_attestation(att)
        .with_progress(prog)
        .confirmed()
}

#[tokio::test]
async fn spray_sans_optin_online_refuse_avec_audit() {
    // online_spray = false : le spray en ligne est désactivé par défaut (US-F3).
    let sprayer = engine::MockSprayEngine::new().with_found("admin", "P@ss");
    let sc = scope_with("online_spray = true", "online_spray = false");
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = confirmed(&att, &prog);
    let spray = engine::SprayRequest::new(ip(TARGET), "admin", OP);

    let outcome = engine::spray_through_gate(&mut gate, &req, &sprayer, &spray)
        .await
        .unwrap();

    assert!(outcome.is_blocked());
    assert_eq!(outcome.audit().action, "blocked_online_spray");
    assert_eq!(outcome.audit().result, "blocked");
    assert!(outcome.report().is_none());
}

#[tokio::test]
async fn spray_sans_confirmation_est_refuse() {
    // Le spray en ligne exige une confirmation humaine (anti-lockout, US-F3).
    let sprayer = engine::MockSprayEngine::new().with_found("admin", "P@ss");
    let sc = scope();
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    // Attestée + recon, mais PAS confirmée.
    let req = Request::new(now(), OP)
        .with_attestation(&att)
        .with_progress(&prog);
    let spray = engine::SprayRequest::new(ip(TARGET), "admin", OP);

    let outcome = engine::spray_through_gate(&mut gate, &req, &sprayer, &spray)
        .await
        .unwrap();

    assert!(outcome.is_blocked());
    assert_eq!(outcome.audit().action, "blocked_confirmation");
}

#[tokio::test]
async fn depassement_max_attempts_arrete_proprement_avec_audit() {
    // max_attempts_per_account = 3 : trois sprays passent, le 4e est refusé net.
    let sprayer = engine::MockSprayEngine::new().with_found("admin", "P@ss");
    let sc = scope();
    let att = attest(&sc);
    let prog = recon_done(TARGET);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = confirmed(&att, &prog);
    let spray = engine::SprayRequest::new(ip(TARGET), "admin", OP);

    for _ in 0..3 {
        let outcome = engine::spray_through_gate(&mut gate, &req, &sprayer, &spray)
            .await
            .unwrap();
        assert!(!outcome.is_blocked(), "les 3 premières tentatives passent");
        assert_eq!(outcome.audit().action, "crack.spray");
    }

    let fourth = engine::spray_through_gate(&mut gate, &req, &sprayer, &spray)
        .await
        .unwrap();
    assert!(fourth.is_blocked());
    assert_eq!(fourth.audit().action, "blocked_max_attempts");
    assert!(fourth.report().is_none());
}
