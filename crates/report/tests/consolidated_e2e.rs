//! Tests d'intégration du **rapport consolidé** N1→N4 (issue #23, US-H1).
//!
//! On exerce l'API publique depuis l'extérieur du crate, comme le ferait le
//! binaire `nickmare` : construction directe d'un [`ConsolidatedReport`] et
//! chargement depuis un store mock (`InMemoryStore`) via les clés réservées. Deux
//! garde-fous de sécurité sont prouvés ici :
//!
//! 1. **Masquage des secrets** — un clair craqué qui transite par le vrai chemin
//!    de `crates/crack` (`MaskedSecret` → `CrackReport::to_crack_result`) ne fuit
//!    **jamais** dans le rapport consolidé, ni en HTML ni en JSON (US-F1) ;
//! 2. **Anti-injection** — un nom d'hôte / une preuve piégés sont échappés par
//!    `askama` (garde-fou §12), aucune balise active n'est produite.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits, #27) n'y valent pas — un `unwrap` qui
// échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use nickmare_core::engagement::{EngagementStore, InMemoryStore};
use nickmare_core::model::{
    AdversaryProfile, AttackExecution, CrackResult, DetectionVerdict, ExploitAttempt, ExploitMode,
    ExploitOutcome, Finding, Host, HostRole, NetworkMap, OsGuess, PivotLink, Port, PortState,
    Proto, Service, Severity,
};
use nickmare_crack::engine::{CrackReport, HashType, MaskedSecret, Recovered};
use nickmare_crack::policy::PasswordPolicy;
use nickmare_emulation::techniques::TechniqueCatalog;
use nickmare_report::{load_consolidated_from_store, ConsolidatedInputs, ConsolidatedReport};
use nickmare_report::{CRACKING_KEY, EXECUTIONS_KEY, EXPLOITS_KEY, FINDINGS_KEY, NETWORK_MAP_KEY};

/// Un clair craqué réaliste (dico + année) : il ne doit JAMAIS apparaître.
const SECRET: &str = "Hiver2024!";

/// Nom d'hôte piégé (tentative d'injection HTML).
const HOSTILE: &str = "<script>alert('xss')</script>";

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
}

fn catalog() -> TechniqueCatalog {
    TechniqueCatalog::embedded().unwrap()
}

/// Un `CrackResult` dérivé du **vrai** chemin de craquage : deux comptes
/// recouvrent le même clair `SECRET` (réutilisation → non conforme). On ne garde
/// que le livrable statistique ; les `MaskedSecret` sont consommés et jetés.
fn cracking_from_real_path() -> CrackResult {
    let recovered = vec![
        Recovered::new("administrateur", MaskedSecret::new(SECRET)),
        Recovered::new("service-sql", MaskedSecret::new(SECRET)),
    ];
    let report = CrackReport::new(HashType::Ntlm, "dump NTDS lab", 20);
    let report = report.with_recovered(recovered);
    report.to_crack_result(&PasswordPolicy::default())
}

/// La section N3 du rapport : un seul jeu de hashes craqués.
fn cracking() -> Vec<CrackResult> {
    vec![cracking_from_real_path()]
}

/// Hôte compromis avec un nom d'hôte piégé (test d'échappement).
fn hostile_host() -> Host {
    Host {
        ip: ip("10.0.0.5"),
        mac: None,
        hostname: Some(HOSTILE.to_string()),
        os_guess: Some(OsGuess::Windows),
        ports: vec![Port {
            number: 445,
            proto: Proto::Tcp,
            state: PortState::Open,
            service: Some(Service {
                name: "smb".to_string(),
                product: Some("Windows".to_string()),
                version: None,
                banner: None,
            }),
        }],
        role: HostRole::Server,
        compromised: true,
        first_seen: ts(0),
    }
}

fn network() -> NetworkMap {
    NetworkMap {
        scope_network: "10.0.0.0/24".to_string(),
        hosts: vec![hostile_host()],
        pivots: vec![PivotLink {
            from: ip("10.0.0.5"),
            to: ip("10.0.0.6"),
            via: "smb".to_string(),
            at: ts(300),
        }],
    }
}

fn findings() -> Vec<Finding> {
    vec![Finding {
        host: ip("10.0.0.5"),
        port: Some(445),
        severity: Severity::Critical,
        cve: Some("CVE-2017-0144".to_string()),
        title: "SMB vulnérable".to_string(),
        description: "Service SMB exploitable.".to_string(),
        recommendation: "Appliquer les correctifs.".to_string(),
    }]
}

/// Exploit confirmé dont la preuve contient aussi une charge piégée (échappement).
fn exploits() -> Vec<ExploitAttempt> {
    vec![ExploitAttempt {
        host: ip("10.0.0.5"),
        cve: Some("CVE-2017-0144".to_string()),
        module: "exploit/windows/smb/ms17_010".to_string(),
        mode: ExploitMode::Exploit,
        confirmed_by: "operateur".to_string(),
        outcome: ExploitOutcome::Success,
        evidence: Some("<img src=x onerror=alert(1)>".to_string()),
    }]
}

fn executions() -> Vec<AttackExecution> {
    vec![AttackExecution {
        technique_id: "T1021".to_string(),
        host: ip("10.0.0.5"),
        profile: AdversaryProfile::Stealth,
        performed_at: ts(600),
        detection: DetectionVerdict::Detected,
        detected_at: Some(ts(645)),
        detected_by: Some("EDR".to_string()),
        notes: None,
    }]
}

fn inputs() -> ConsolidatedInputs {
    ConsolidatedInputs {
        network: network(),
        findings: findings(),
        operations: Vec::new(),
        usage: Default::default(),
        exploits: exploits(),
        cracking: cracking(),
        executions: executions(),
    }
}

fn report() -> ConsolidatedReport {
    let meta = nickmare_report::ReportMeta {
        tool: "nickmare 0.2.0".to_string(),
        engagement: "lab".to_string(),
        level: "N1-N4".to_string(),
        generated_at: ts(1000),
    };
    ConsolidatedReport::new(meta, inputs(), &catalog())
}

#[test]
fn masked_secret_ne_fuit_jamais_a_la_source() {
    // Rappel du contrat de `crates/crack` que le rapport réutilise : le masque
    // tient à l'affichage ET à la sérialisation.
    let masked = MaskedSecret::new(SECRET);
    assert_eq!(masked.to_string(), "****");
    let recovered = Recovered::new("administrateur", MaskedSecret::new(SECRET));
    let json = serde_json::to_string(&recovered).unwrap();
    assert!(json.contains("****"), "{json}");
    assert!(!json.contains(SECRET), "le clair fuit à la source : {json}");
}

#[test]
fn rapport_consolide_ne_fuit_aucun_clair_html_ni_json() {
    let report = report();
    let html = report.to_html().unwrap();
    let json = report.to_json().unwrap();

    // Garde-fou central (US-F1) : aucun clair craqué dans l'un ou l'autre rendu.
    assert!(!html.contains(SECRET), "le clair fuit en HTML");
    assert!(!json.contains(SECRET), "le clair fuit en JSON");

    // La section N3 reste informative : statistiques + verdict de politique.
    assert!(html.contains("Craquage"), "{html}");
    assert!(html.contains("dump NTDS lab"), "{html}");
    assert!(html.contains("non conforme"), "{html}");
    // Le JSON porte le verdict et les compteurs, jamais le secret.
    assert!(json.contains("non-compliant"), "{json}");
    assert!(json.contains("\"cracked\""), "{json}");
}

#[test]
fn rapport_consolide_echappe_les_entrees_hostiles() {
    let html = report().to_html().unwrap();
    // Nom d'hôte et preuve piégés : aucune balise active, versions échappées.
    assert!(!html.contains(HOSTILE), "injection via hostname : {html}");
    assert!(!html.contains("<img src=x onerror=alert(1)>"), "{html}");
    assert!(html.contains("&lt;script&gt;"), "{html}");
}

#[test]
fn rapport_consolide_rend_toutes_les_sections() {
    let html = report().to_html().unwrap();
    assert!(html.contains("Résumé exécutif"), "{html}");
    assert!(html.contains("Carte réseau annotée"), "{html}");
    assert!(html.contains("COMPROMIS"), "{html}");
    assert!(html.contains("Exploits confirmés"), "{html}");
    assert!(html.contains("Matrice ATT&amp;CK"), "{html}");
    assert!(html.contains("Timeline horodatée"), "{html}");
    assert!(html.contains("Niveaux N1-N4"), "{html}");
    // Matrice : la technique émise et son MTTD (645 - 600 = 45 s) figurent.
    assert!(html.contains("T1021"), "{html}");
    assert!(html.contains("45 s"), "{html}");
}

/// Store mock peuplé selon les clés réservées (tous niveaux).
fn seeded_store() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    let map = serde_json::to_string(&network()).unwrap();
    let find = serde_json::to_string(&findings()).unwrap();
    let expl = serde_json::to_string(&exploits()).unwrap();
    let crack = serde_json::to_string(&cracking()).unwrap();
    let exec = serde_json::to_string(&executions()).unwrap();
    store.put_result(NETWORK_MAP_KEY, &map).unwrap();
    store.put_result(FINDINGS_KEY, &find).unwrap();
    store.put_result(EXPLOITS_KEY, &expl).unwrap();
    store.put_result(CRACKING_KEY, &crack).unwrap();
    store.put_result(EXECUTIONS_KEY, &exec).unwrap();
    store.begin("scan:h", "scan", "10.0.0.5", ts(1)).unwrap();
    store.complete("scan:h", ts(2)).unwrap();
    store.add_usage(3, 512).unwrap();
    store
}

#[test]
fn charge_depuis_le_store_et_reste_sobre_sur_les_secrets() {
    let store = seeded_store();
    let loaded = load_consolidated_from_store(&store, "lab", "nm", ts(1000), &catalog());
    let report = loaded.unwrap();

    assert_eq!(report.meta.level, "N1-N4");
    assert_eq!(report.summary.host_count, 1);
    assert_eq!(report.summary.exploits_confirmed, 1);
    assert_eq!(report.summary.techniques_emitted, 1);
    assert_eq!(report.operations.len(), 1);

    // Même garantie de non-fuite depuis le chemin « store ».
    let html = report.to_html().unwrap();
    let json = report.to_json().unwrap();
    assert!(!html.contains(SECRET), "le clair fuit en HTML (store)");
    assert!(!json.contains(SECRET), "le clair fuit en JSON (store)");

    // Round-trip JSON stable.
    let back = ConsolidatedReport::from_json(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn store_vide_donne_un_rapport_consolide_valide() {
    let store = InMemoryStore::new();
    let loaded = load_consolidated_from_store(&store, "lab", "nm", ts(0), &catalog());
    let report = loaded.unwrap();
    assert_eq!(report.summary.policy_verdict, "unknown");
    assert!(report.timeline.is_empty());
    assert!(report.to_html().is_ok());
    assert!(report.to_json().is_ok());
}
