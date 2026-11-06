//! Suite **négative** transverse de sécurité (issue #28, §10.4 ; filet
//! secondaire, `docs/TESTING.md` §2).
//!
//! Chaque action qui **sortirait** du périmètre autorisé doit être **refusée**
//! par le gate (le « mur », §3.2/§4) **et journalisée** en clair (audit chaîné
//! `blocked_*`, §3.3) — jamais silencieusement. On re-éprouve ici, de façon
//! transverse et sur les capacités **qui existent**, le contrat de CI :
//!
//! - dépasser le plafond `max_rate_pps` → refus + audit ;
//! - viser une cible hors `targets` → refus + audit ;
//! - exploiter un hôte en scope mais hors `exploitation.allowed_hosts` → refus ;
//! - **désactiver une capacité la rend inatteignable** quelle que soit la
//!   commande (le gate est l'unique chemin, §4) ;
//! - mode `manual` **bloque** sans confirmation (le module mock ne tourne pas) ;
//! - `destructive_checks = false` **rejette** un module destructeur (mock) ;
//! - scan/identification hors scope → refus **sans lire une seule bannière**.
//!
//! > Les legs N2–N4 (vrai moteur d'exploitation #19, craquage #21, émulation
//! > #22) sont **différés** (jalon #17 non franchi) : les décisions du gate pour
//! > ces actions existent déjà, les **moteurs** réels s'y brancheront en
//! > Phases 6/7/8 derrière ce même gate.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'appliquent pas ici — un `unwrap` qui échoue EST le signal d'échec attendu,
// et les helpers hors #[test] échappent au allow-in-tests de clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use chrono::{DateTime, TimeZone, Utc};

use nickmare_core::audit::{verify_file, AuditEntry, AuditLog, AuditMode, CapabilityLevel};
use nickmare_core::gate::{
    audit_record, Action, Attestation, Decision, DenyReason, Gate, Progress, Request,
};
use nickmare_core::model::ExploitMode;
use nickmare_core::scope::{Capability, Scope};

/// Opérateur de référence : la même identité atteste et agit.
const OP: &str = "operateur@example.test";

/// Scope de référence (identique à celui des tests unitaires du gate) :
/// exploitation `manual` non destructrice, un seul hôte autorisé, cracking avec
/// spray en ligne opt-in, émulation T1021, débit 200 pps, fenêtre 08:00-18:00.
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

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

/// Instant nominal : dans la fenêtre d'engagement ET dans `allowed_hours`.
fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap()
}

fn scope() -> Scope {
    Scope::from_toml(BASE).unwrap()
}

/// Scope avec une variante textuelle appliquée (activer/désactiver une capacité,
/// baisser un plafond…).
fn scope_with(from: &str, to: &str) -> Scope {
    Scope::from_toml(&BASE.replace(from, to)).unwrap()
}

/// Attestation cohérente avec le scope (même opérateur, même empreinte).
fn attest(sc: &Scope) -> Attestation {
    Attestation::for_scope(sc, OP, "192.168.10.0/24")
}

fn recon(target: &str) -> Action {
    Action::Recon { target: ip(target) }
}

fn exploit(target: &str, mode: ExploitMode) -> Action {
    Action::Exploit {
        target: ip(target),
        mode,
    }
}

fn crack(target: &str, online: bool) -> Action {
    Action::Crack {
        target: ip(target),
        online,
        account: None,
    }
}

fn emulate(target: &str, technique: &str) -> Action {
    Action::Emulate {
        target: ip(target),
        technique: technique.to_string(),
    }
}

/// Progression recon aboutie sur un hôte (débloque les pré-conditions N≥2).
fn recon_done(target: &str) -> Progress {
    let mut p = Progress::new();
    p.record(ip(target), Capability::Recon);
    p
}

// --- Contrat « refus + journalisation » (§10.4, §3.3) -----------------------

/// Séquence pour isoler chaque journal d'audit jetable (tests parallèles).
static LOG_SEQ: AtomicU32 = AtomicU32::new(0);

/// Journalise un **refus** dans un journal d'audit chaîné jetable, puis vérifie
/// que la chaîne relue est intègre et contient exactement cette entrée. Prouve
/// que le refus n'est **jamais silencieux** (§10.4). Renvoie l'entrée écrite.
fn journalise(action: &Action, decision: Decision, mode: AuditMode) -> AuditEntry {
    assert!(!decision.is_allowed(), "journalise n'attend qu'un refus");

    let seq = LOG_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("nm-sectests-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&path);

    let record = audit_record(action, decision, OP, mode);
    let mut log = AuditLog::open(&path).unwrap();
    let entry = log.append_at(record, now()).unwrap();

    // La chaîne relue est intègre et rend exactement cette entrée.
    let read = verify_file(&path).unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0], entry);

    // Un refus est tracé en `blocked_<code>` / result = "blocked" (jamais "ok").
    assert!(
        entry.action.starts_with("blocked_"),
        "action tracée = {}",
        entry.action
    );
    assert_eq!(entry.result, "blocked");

    std::fs::remove_file(&path).ok();
    std::fs::remove_dir(&dir).ok();
    entry
}

/// Vérifie en un geste : refus attendu + journalisation `blocked_<code>`.
fn refuse_et_journalise(gate: &mut Gate, req: &Request, action: &Action, attendu: DenyReason) {
    let decision = gate.check(action, req);
    assert_eq!(decision, Decision::Deny(attendu), "décision inattendue");
    let entry = journalise(action, decision, gate.mode());
    assert_eq!(entry.action, format!("blocked_{}", attendu.code()));
}

// --- Dépassement de plafond : débit `max_rate_pps` --------------------------

#[test]
fn plafond_debit_depasse_refuse_et_journalise() {
    // Débit 1 pps, seau initialement plein (capacité 1) : la 1re recon passe, la
    // 2e au même instant épuise le seau → refus + audit `blocked_rate`.
    let sc = scope_with("max_rate_pps = 200", "max_rate_pps = 1");
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP).with_attestation(&att);
    let action = recon("192.168.10.25");

    assert_eq!(gate.check(&action, &req), Decision::Allow);
    refuse_et_journalise(&mut gate, &req, &action, DenyReason::RateExceeded);
}

// --- Hors périmètre ---------------------------------------------------------

#[test]
fn cible_hors_scope_refuse_et_journalise() {
    let sc = scope();
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP).with_attestation(&att);
    // 10.0.0.1 n'est ni un hôte ni dans un réseau attesté.
    refuse_et_journalise(&mut gate, &req, &recon("10.0.0.1"), DenyReason::OutOfScope);
}

#[test]
fn cible_exclue_refuse_malgre_le_reseau() {
    let sc = scope();
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP).with_attestation(&att);
    // 192.168.10.1 ∈ 192.168.10.0/24 mais explicitement exclu : les exclusions
    // priment (§3.1).
    refuse_et_journalise(
        &mut gate,
        &req,
        &recon("192.168.10.1"),
        DenyReason::Excluded,
    );
}

// --- Exploitation hors `allowed_hosts` (sans vrai moteur, §10.4) ------------

#[test]
fn exploitation_hors_allowed_hosts_refuse_et_journalise() {
    let sc = scope();
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    // Hôte en scope (192.168.10.30 ∈ /24) mais hors allowed_hosts (= .25).
    let req = Request::new(now(), OP).with_attestation(&att);
    refuse_et_journalise(
        &mut gate,
        &req,
        &exploit("192.168.10.30", ExploitMode::Validate),
        DenyReason::HostNotAllowed,
    );
}

// --- « Désactiver une capacité la rend inatteignable » (DoD §10.4) ----------
//
// Le gate est l'unique chemin vers un moteur (§4) : désactiver une capacité
// dans le scope la rend inatteignable QUELLE QUE SOIT la commande qui l'invoque.
// On couvre ici chaque capacité intrusive existante au niveau du gate ; les
// moteurs réels (Phases 6/7/8) se brancheront derrière ces mêmes décisions.

#[test]
fn exploitation_desactivee_rend_inatteignable() {
    let sc = scope_with(
        "[capabilities.exploitation]\nenabled = true",
        "[capabilities.exploitation]\nenabled = false",
    );
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    // Même sur l'hôte autrefois autorisé (.25), avec recon aboutie et confirmée :
    // la capacité désactivée tranche en amont (étape 3).
    let prog = recon_done("192.168.10.25");
    let req = Request::new(now(), OP).with_attestation(&att);
    let req = req.with_progress(&prog).confirmed();
    refuse_et_journalise(
        &mut gate,
        &req,
        &exploit("192.168.10.25", ExploitMode::Validate),
        DenyReason::CapabilityDisabled(Capability::Exploitation),
    );
}

#[test]
fn cracking_desactive_rend_inatteignable() {
    let sc = scope_with(
        "[capabilities.cracking]\nenabled = true",
        "[capabilities.cracking]\nenabled = false",
    );
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let prog = recon_done("192.168.50.5");
    let req = Request::new(now(), OP).with_attestation(&att);
    let req = req.with_progress(&prog);
    // Craquage hors-ligne sur un hôte en scope : refusé car capacité coupée.
    refuse_et_journalise(
        &mut gate,
        &req,
        &crack("192.168.50.5", false),
        DenyReason::CapabilityDisabled(Capability::Cracking),
    );
}

#[test]
fn emulation_desactivee_rend_inatteignable() {
    let sc = scope_with(
        "[capabilities.emulation]\nenabled = true",
        "[capabilities.emulation]\nenabled = false",
    );
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let prog = recon_done("192.168.10.25");
    let req = Request::new(now(), OP).with_attestation(&att);
    let req = req.with_progress(&prog);
    // Même une technique autrefois listée (T1021) devient injouable.
    refuse_et_journalise(
        &mut gate,
        &req,
        &emulate("192.168.10.25", "T1021"),
        DenyReason::CapabilityDisabled(Capability::Emulation),
    );
}

#[test]
fn technique_attack_non_listee_refuse() {
    // Émulation activée mais technique absente d'`attack_techniques` : refus.
    let sc = scope();
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let prog = recon_done("192.168.10.25");
    let req = Request::new(now(), OP).with_attestation(&att);
    let req = req.with_progress(&prog);
    refuse_et_journalise(
        &mut gate,
        &req,
        &emulate("192.168.10.25", "T1570"),
        DenyReason::TechniqueNotAllowed,
    );
}

// --- Mode `manual` + garde anti-destruction, contre un module mock ----------
//
// Le gate est le SEUL chemin vers le moteur (§4) : le module (ici un simple
// compteur d'invocations, mock, là où tournera le vrai module Metasploit en
// Phase 6) ne doit tourner QUE sur une décision `Allow`. On prouve qu'un refus
// ne l'atteint jamais.

/// Oriente une action offensive comme le fera l'orchestrateur réel : le moteur
/// (mock) n'est invoqué qu'après un `Allow` du gate. Renvoie la décision.
fn run_via_gate(
    gate: &mut Gate,
    req: &Request,
    action: &Action,
    module_calls: &mut u32,
) -> Decision {
    let decision = gate.check(action, req);
    if decision.is_allowed() {
        *module_calls += 1; // le module destructeur (mock) ne tourne que sur Allow.
    }
    decision
}

#[test]
fn mode_manual_bloque_sans_confirmation_et_le_module_ne_tourne_pas() {
    let sc = scope(); // exploitation.mode = "manual"
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let prog = recon_done("192.168.10.25");
    // Attestée + pré-condition OK, mais SANS confirmation.
    let req = Request::new(now(), OP).with_attestation(&att);
    let req = req.with_progress(&prog);
    let action = exploit("192.168.10.25", ExploitMode::Validate);

    let mut module_calls = 0;
    let decision = run_via_gate(&mut gate, &req, &action, &mut module_calls);
    assert_eq!(decision, Decision::Deny(DenyReason::ConfirmationRequired));
    assert_eq!(module_calls, 0, "aucun module ne tourne sans confirmation");
    let entry = journalise(&action, decision, gate.mode());
    assert_eq!(entry.action, "blocked_confirmation");
    assert_eq!(entry.level, CapabilityLevel::Exploitation);
}

#[test]
fn module_destructeur_refuse_quand_destructive_checks_false() {
    // destructive_checks = false (BASE) : un module destructeur (mode Exploit)
    // est refusé en amont ; le module mock ne tourne pas, même tout confirmé.
    let sc = scope();
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let prog = recon_done("192.168.10.25");
    let req = Request::new(now(), OP).with_attestation(&att);
    let req = req.with_progress(&prog).confirmed();
    let action = exploit("192.168.10.25", ExploitMode::Exploit);

    let mut module_calls = 0;
    let decision = run_via_gate(&mut gate, &req, &action, &mut module_calls);
    assert_eq!(decision, Decision::Deny(DenyReason::Destructive));
    assert_eq!(module_calls, 0, "aucune charge destructrice émise");
    let entry = journalise(&action, decision, gate.mode());
    assert_eq!(entry.action, "blocked_destructive");
}

#[test]
fn le_filet_ne_bloque_pas_dans_le_perimetre() {
    // Règle d'or §10.4 : le filet ne doit JAMAIS empêcher l'action LÉGITIME dans
    // le périmètre. Un exploit sur l'hôte autorisé, en mode auto, recon aboutie,
    // confirmé et attesté, passe — le module mock tourne bien une fois.
    let sc = scope_with("mode = \"manual\"", "mode = \"auto\"");
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let prog = recon_done("192.168.10.25");
    let req = Request::new(now(), OP).with_attestation(&att);
    let req = req.with_progress(&prog);
    let action = exploit("192.168.10.25", ExploitMode::Validate);

    let mut module_calls = 0;
    let decision = run_via_gate(&mut gate, &req, &action, &mut module_calls);
    assert_eq!(
        decision,
        Decision::Allow,
        "action légitime indûment bloquée"
    );
    assert_eq!(module_calls, 1, "le module doit tourner dans le périmètre");
}

// --- Confinement du scan / de l'identification (recon active N1) ------------

#[tokio::test]
async fn scan_hors_scope_refuse_sans_lire_de_banniere() {
    use nickmare_core::model::{Port, PortState, Proto};
    use nickmare_core::traits::MockNetworkProvider;
    use nickmare_net::service_id::{identify_gated, IdentifyReport};

    // Provider mock vide : si une bannière était lue hors scope, ce serait un
    // bug de confinement. Le gate refuse AVANT toute lecture (fail-safe).
    let provider = MockNetworkProvider::default();
    let sc = scope();
    let att = attest(&sc);
    let mut gate = Gate::with_scope(sc, AuditMode::Standard);
    let req = Request::new(now(), OP).with_attestation(&att);
    let ports = vec![Port {
        number: 22,
        proto: Proto::Tcp,
        state: PortState::Open,
        service: None,
    }];

    let report = identify_gated(
        &mut gate,
        &req,
        OP,
        &provider,
        ip("10.0.0.9"), // hors du réseau attesté
        &ports,
        0,
    )
    .await;

    match report {
        IdentifyReport::Refused { reason, record } => {
            assert_eq!(reason, DenyReason::OutOfScope);
            assert_eq!(record.action, "blocked_target");
            assert_eq!(record.result, "blocked");
        }
        IdentifyReport::Allowed { .. } => panic!("un hôte hors scope ne doit pas être sondé"),
    }
}
