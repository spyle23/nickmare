//! Tests de reprise §11.4 (issue #26, cf. `docs/ARCHITECTURE.md` §11.2/§11.4).
//!
//! Interruption d'un run puis `resume` → **ni perte ni doublon**, y compris côté
//! journal d'audit. On orchestre un mini-run au-dessus du store d'état
//! (mock [`InMemoryStore`]) couplé au journal d'audit chaîné de `core` :
//!
//! - une étape déjà terminée, rejouée, est **sautée** (begin `AlreadyCompleted`)
//!   → pas de seconde action **ni de seconde entrée d'audit** (idempotence) ;
//! - une action **en vol** au moment de la coupure est récupérée `Incomplete` à
//!   la reprise (jamais « réussie » en silence), puis relancée proprement.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'appliquent pas ici — un `unwrap` qui échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Utc};
use nickmare_core::audit::{verify_file, AuditLog, AuditRecord, CapabilityLevel};
use nickmare_core::engagement::{resume, BeginOutcome, EngagementStore, InMemoryStore, OpStatus};

fn t(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap()
}

fn tmp_audit(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nm-resume-it-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&path);
    path
}

/// Exécute une étape idempotente : si elle est déjà terminée, on la saute (pas
/// d'action ni d'audit) ; sinon on « émet » (mock : rien), on **journalise une
/// seule fois**, puis on marque l'opération terminée. Renvoie `true` si exécutée.
fn execute(
    store: &mut InMemoryStore,
    log: &mut AuditLog,
    key: &str,
    kind: &str,
    target: &str,
    now: DateTime<Utc>,
) -> bool {
    let outcome = store.begin(key, kind, target, now).unwrap();
    if !outcome.should_execute() {
        return false;
    }
    let record = AuditRecord::new(
        "operateur",
        target,
        "recon.active",
        "ok",
        CapabilityLevel::Recon,
    );
    log.append(record).unwrap();
    store.complete(key, now).unwrap();
    true
}

#[test]
fn rejouer_une_etape_terminee_ne_double_pas_l_audit() {
    let path = tmp_audit("nodup");
    let mut log = AuditLog::open(&path).unwrap();
    let mut store = InMemoryStore::new();

    // Première exécution : action émise + 1 entrée d'audit.
    assert!(execute(
        &mut store,
        &mut log,
        "scan:a",
        "scan",
        "10.0.0.1",
        t(1)
    ));
    // Rejeu à l'identique : sautée (idempotence) — aucune nouvelle entrée.
    assert!(!execute(
        &mut store,
        &mut log,
        "scan:a",
        "scan",
        "10.0.0.1",
        t(2)
    ));

    let entries = verify_file(&path).unwrap();
    assert_eq!(
        entries.len(),
        1,
        "exactement une entrée d'audit, pas de doublon"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn interruption_puis_resume_sans_perte_ni_doublon() {
    let path = tmp_audit("resume");
    let mut log = AuditLog::open(&path).unwrap();
    let mut store = InMemoryStore::new();

    // Étape 1 terminée (émise + auditée).
    execute(&mut store, &mut log, "scan:a", "scan", "10.0.0.1", t(1));

    // Étape 2 « en vol » : on la déclare (begin) puis le run est coupé AVANT
    // l'émission/l'audit/la complétion — rien n'est journalisé pour elle.
    store
        .begin("exploit:b", "exploit", "10.0.0.1", t(2))
        .unwrap();

    // --- Coupure, puis reprise ---
    let plan = resume(&mut store, t(10)).unwrap();
    assert!(plan.is_completed("scan:a"), "l'étape 1 est acquise");
    assert_eq!(plan.recovered, vec!["exploit:b".to_string()]);

    // L'action en vol est Incomplete, jamais « réussie » en silence.
    let ops = store.operations().unwrap();
    let b = ops.iter().find(|o| o.key == "exploit:b").unwrap();
    assert_eq!(b.status, OpStatus::Incomplete);

    // On relance : l'étape 1 terminée est sautée (pas de re-sollicitation ni de
    // doublon d'audit), l'étape 2 incomplète est bel et bien ré-exécutée.
    assert!(!execute(
        &mut store,
        &mut log,
        "scan:a",
        "scan",
        "10.0.0.1",
        t(11)
    ));
    let resumed = store
        .begin("exploit:b", "exploit", "10.0.0.1", t(12))
        .unwrap();
    assert_eq!(resumed, BeginOutcome::Resumed);
    let record = AuditRecord::new(
        "operateur",
        "10.0.0.1",
        "exploit.validate",
        "vulnerable",
        CapabilityLevel::Exploitation,
    );
    log.append(record).unwrap();
    store.complete("exploit:b", t(13)).unwrap();

    // Bilan : 2 actions distinctes, 2 entrées d'audit (aucune perte, aucun doublon),
    // et la chaîne d'audit reste intègre.
    let entries = verify_file(&path).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].action, "recon.active");
    assert_eq!(entries[1].action, "exploit.validate");

    std::fs::remove_file(&path).ok();
}
