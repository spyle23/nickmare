//! Binaire `nickmare` — point d'entrée de l'outil.
//!
//! Phase 0, issue #3 : `nickmare scope validate <fichier>` (voie B, cf.
//! `docs/ARCHITECTURE.md` §3). Phase 1, issue #11 : `nickmare lab start <cidr>…`
//! (voie C, mode laboratoire). Les autres commandes (recon, scan, exploitation…)
//! arrivent dans les phases suivantes. Un parseur d'arguments complet (`clap`)
//! sera introduit quand la surface CLI grandira ; ici le dispatch reste
//! volontairement minimal.

use std::process::ExitCode;

use chrono::{DateTime, TimeDelta, Utc};
use nickmare_core::audit::AuditLog;
use nickmare_core::lab::LabSession;
use nickmare_core::scope::{Capability, Scope, TemporalStatus};

/// Durée par défaut de la fenêtre d'un lab (heures) si `--hours` est absent.
const DEFAULT_LAB_HOURS: i64 = 12;

/// Bannière de version, dérivée des métadonnées du paquet.
fn banniere() -> String {
    format!("nickmare {}", env!("CARGO_PKG_VERSION"))
}

fn usage() -> String {
    let lines = [
        "",
        "Usage :",
        "  nickmare scope validate <fichier> [--trusted-key <hex> | --trusted-key-file <chemin>]",
        "  nickmare lab start <cidr> [<cidr>...] [--operator <id>] [--hours <n>]",
        "                      [--confirm-non-isolated] [--audit <chemin>]",
        "",
        "scope validate : valide un fichier de scope (voie B) — résumé + empreinte SHA-256,",
        "                 ou refus clair (code de sortie ≠ 0).",
        "lab start      : établit un périmètre de laboratoire (voie C) sur un ou plusieurs",
        "                 sous-réseaux ; attestation unique, N1–N4 débloqués, mode = \"lab\".",
    ];
    format!("{}\n{}\n", banniere(), lines.join("\n"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch de premier niveau. `Ok` = sortie standard + code 0 ; `Err` =
/// message d'erreur sur stderr + code ≠ 0.
fn run(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("scope") => run_scope(&args[1..]),
        Some("lab") => run_lab(&args[1..]),
        Some("--version" | "-V") => Ok(format!("{}\n", banniere())),
        Some("--help" | "-h") | None => Ok(usage()),
        Some(other) => Err(format!("commande inconnue : {other}\n\n{}", usage())),
    }
}

fn run_scope(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("validate") => run_scope_validate(&args[1..]),
        Some(other) => Err(format!(
            "sous-commande scope inconnue : {other}\n\n{}",
            usage()
        )),
        None => Err(format!("sous-commande scope manquante\n\n{}", usage())),
    }
}

fn run_scope_validate(args: &[String]) -> Result<String, String> {
    let mut path: Option<&str> = None;
    let mut trusted_key: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "--trusted-key" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "option --trusted-key : valeur hexadécimale manquante".to_string()
                })?;
                trusted_key = Some(value.clone());
                index += 2;
            }
            "--trusted-key-file" => {
                let file = args
                    .get(index + 1)
                    .ok_or_else(|| "option --trusted-key-file : chemin manquant".to_string())?;
                let content = std::fs::read_to_string(file)
                    .map_err(|err| format!("lecture de la clé de confiance {file} : {err}"))?;
                trusted_key = Some(content.trim().to_string());
                index += 2;
            }
            other if other.starts_with('-') => {
                return Err(format!("option inconnue : {other}\n\n{}", usage()));
            }
            positional => {
                if path.is_some() {
                    return Err(format!("argument en trop : {positional}\n\n{}", usage()));
                }
                path = Some(positional);
                index += 1;
            }
        }
    }

    let Some(path) = path else {
        return Err(format!("fichier de scope manquant\n\n{}", usage()));
    };
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("impossible de lire {path} : {err}"))?;
    validate_scope(&content, trusted_key.as_deref(), Utc::now())
}

/// Valide le contenu TOML d'un scope et renvoie le résumé affichable, ou un
/// message de refus clair. `now` est injecté pour rendre la validation
/// temporelle testable.
fn validate_scope(
    content: &str,
    trusted_key: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String, String> {
    let scope = Scope::load(content, trusted_key).map_err(|err| format!("scope refusé : {err}"))?;
    match scope.temporal_status(now) {
        TemporalStatus::Expired => {
            return Err(format!(
                "scope refusé : engagement expiré (valide jusqu'au {})",
                scope.engagement.valid_until
            ));
        }
        TemporalStatus::NotYetValid => {
            return Err(format!(
                "scope refusé : engagement pas encore valide (à partir du {})",
                scope.engagement.valid_from
            ));
        }
        TemporalStatus::Valid => {}
    }
    Ok(summarize(&scope, trusted_key))
}

/// Résumé lisible d'un scope valide : identité, périmètre, capacités activées
/// et empreinte SHA-256 (preuve du périmètre exact utilisé, décision 3).
fn summarize(scope: &Scope, trusted_key: Option<&str>) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("Scope VALIDE".to_string());
    lines.push(format!("  Client        : {}", scope.engagement.client));
    lines.push(format!("  Référence     : {}", scope.engagement.reference));
    lines.push(format!(
        "  Autorisé par  : {}",
        scope.engagement.authorized_by
    ));
    lines.push(format!("  Opérateur     : {}", scope.engagement.operator));
    lines.push(format!(
        "  Fenêtre       : {} → {}",
        scope.engagement.valid_from, scope.engagement.valid_until
    ));

    let networks = join_or_dash(&scope.targets.networks);
    let hosts = join_or_dash(&scope.targets.hosts);
    let excl_hosts = join_or_dash(&scope.targets.exclusions.hosts);
    lines.push(format!("  Réseaux       : {networks}"));
    lines.push(format!("  Hôtes         : {hosts}"));
    lines.push(format!("  Exclusions    : {excl_hosts}"));

    if let Some(hours) = &scope.constraints.allowed_hours {
        lines.push(format!("  Heures        : {hours} (UTC)"));
    }
    lines.push(format!(
        "  Débit max     : {} pps",
        scope.constraints.max_rate_pps
    ));

    lines.push(format!("  Capacités     : {}", enabled_caps(scope)));

    let integrity = match (scope.has_integrity(), trusted_key) {
        (true, Some(_)) => "signée ed25519 — signature vérifiée".to_string(),
        (true, None) => "signée ed25519".to_string(),
        (false, _) => "mode v1 (empreinte SHA-256 seule)".to_string(),
    };
    lines.push(format!("  Intégrité     : {integrity}"));
    lines.push(format!("  Empreinte SHA-256 : {}", scope.fingerprint()));

    let mut out = lines.join("\n");
    out.push('\n');
    out
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "—".to_string()
    } else {
        values.join(", ")
    }
}

fn enabled_caps(scope: &Scope) -> String {
    let caps = &scope.capabilities;
    let mut names: Vec<&str> = vec!["recon"];
    if caps.allows(Capability::Exploitation) {
        names.push("exploitation");
    }
    if caps.allows(Capability::Cracking) {
        names.push("cracking");
    }
    if caps.allows(Capability::Emulation) {
        names.push("emulation");
    }
    names.join(", ")
}

// --- Voie C : mode laboratoire (`lab start`) --------------------------------

fn run_lab(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("start") => run_lab_start(&args[1..]),
        Some(other) => Err(format!(
            "sous-commande lab inconnue : {other}\n\n{}",
            usage()
        )),
        None => Err(format!("sous-commande lab manquante\n\n{}", usage())),
    }
}

fn run_lab_start(args: &[String]) -> Result<String, String> {
    let mut networks: Vec<String> = Vec::new();
    let mut operator: Option<String> = None;
    let mut hours: i64 = DEFAULT_LAB_HOURS;
    let mut confirm_non_isolated = false;
    let mut audit_path: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "--operator" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --operator : identité manquante".to_string())?;
                operator = Some(value.clone());
                index += 2;
            }
            "--hours" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --hours : valeur manquante".to_string())?;
                hours = value
                    .parse::<i64>()
                    .map_err(|_| format!("option --hours : entier attendu, reçu {value:?}"))?;
                if hours <= 0 {
                    return Err("option --hours : durée strictement positive attendue".to_string());
                }
                index += 2;
            }
            "--audit" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --audit : chemin manquant".to_string())?;
                audit_path = Some(value.clone());
                index += 2;
            }
            "--confirm-non-isolated" => {
                confirm_non_isolated = true;
                index += 1;
            }
            other if other.starts_with('-') => {
                return Err(format!("option inconnue : {other}\n\n{}", usage()));
            }
            positional => {
                networks.push(positional.to_string());
                index += 1;
            }
        }
    }
    let operator = operator.unwrap_or_else(default_operator);
    lab_start(
        networks,
        operator,
        hours,
        confirm_non_isolated,
        audit_path.as_deref(),
        Utc::now(),
    )
}

/// Établit un périmètre de laboratoire (voie C) et renvoie le résumé affichable,
/// ou un refus clair. `now` est injecté pour rendre la fenêtre déterministe en
/// test. Fail-safe : un réseau à l'air non isolé est refusé tant que la
/// confirmation renforcée n'est pas donnée.
fn lab_start(
    networks: Vec<String>,
    operator: String,
    hours: i64,
    confirm_non_isolated: bool,
    audit_path: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String, String> {
    if networks.is_empty() {
        return Err(format!(
            "mode labo : au moins un <cidr> est requis\n\n{}",
            usage()
        ));
    }
    let valid_until = now + TimeDelta::hours(hours);
    let session = LabSession::start(networks, operator, now, valid_until)
        .map_err(|err| format!("mode labo refusé : {err}"))?;

    // Garde-fou de cohérence : un sous-réseau qui n'a pas l'air privé/isolé exige
    // une confirmation renforcée (avertissement + refus par défaut).
    if session.requires_reinforced_confirmation() && !confirm_non_isolated {
        let list = session.non_isolated_networks().join(", ");
        return Err(format!(
            "mode labo refusé : AVERTISSEMENT — sous-réseau(x) à l'air non privé/isolé (routable) : {list}\n\
             Un lab doit être isolé (RFC1918/ULA/link-local). Si c'est bien votre réseau \
             d'entraînement, relancez avec --confirm-non-isolated."
        ));
    }

    // Journalisation optionnelle du démarrage (mode = "lab") dans un journal chaîné.
    if let Some(path) = audit_path {
        let mut log = AuditLog::open(path)
            .map_err(|err| format!("ouverture du journal d'audit {path} : {err}"))?;
        log.append(session.start_record())
            .map_err(|err| format!("écriture du journal d'audit {path} : {err}"))?;
    }

    Ok(summarize_lab(&session))
}

/// Opérateur par défaut déduit de l'environnement (`USER`/`USERNAME`), sinon un
/// repère générique — l'attestation reste toujours rattachée à une identité.
fn default_operator() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "operateur-labo".to_string())
}

/// Résumé lisible d'un périmètre de lab établi : opérateur, périmètre, fenêtre,
/// capacités débloquées, mode d'audit `lab`, empreinte et attestation.
fn summarize_lab(session: &LabSession) -> String {
    let scope = session.scope();
    let mut lines: Vec<String> = Vec::new();
    lines.push("Mode LABORATOIRE (voie C) — périmètre établi".to_string());
    lines.push(format!("  Opérateur     : {}", scope.engagement.operator));
    lines.push(format!(
        "  Périmètre     : {}",
        session.networks().join(", ")
    ));
    lines.push(format!(
        "  Fenêtre       : {} → {}",
        scope.engagement.valid_from, scope.engagement.valid_until
    ));
    lines.push(
        "  Capacités     : recon, exploitation, cracking, emulation (N1–N4 débloqués)".to_string(),
    );
    lines.push("  Mode d'audit  : lab".to_string());
    lines.push(format!("  Empreinte SHA-256 : {}", scope.fingerprint()));
    lines.push(format!(
        "  Attestation   : {} sur {} (empreinte liée au scope)",
        session.attestation().operator,
        session.attestation().perimeter
    ));
    if session.requires_reinforced_confirmation() {
        lines.push(format!(
            "  ⚠ Réseau non isolé confirmé : {}",
            session.non_isolated_networks().join(", ")
        ));
    }
    lines.push(
        "Confinement : toute action active reste bornée aux sous-réseaux déclarés ; un sous-réseau non déclaré reste hors d'atteinte."
            .to_string(),
    );
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const VALID: &str = include_str!("../../../testdata/scope/valid.toml");
    const EXPIRED: &str = include_str!("../../../testdata/scope/expired.toml");
    const INTEGRITY: &str = include_str!("../../../testdata/scope/integrity.toml");

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 5, 12, 0, 0).unwrap()
    }

    #[test]
    fn banniere_commence_par_nickmare() {
        assert!(banniere().starts_with("nickmare "));
    }

    #[test]
    fn scope_valide_affiche_resume_et_empreinte() {
        let out = validate_scope(VALID, None, now()).unwrap();
        assert!(out.contains("Scope VALIDE"));
        assert!(out.contains("ACME Corp"));
        assert!(out.contains("Empreinte SHA-256 :"));
        // 64 caractères hexadécimaux présents dans la sortie.
        assert!(out.contains("exploitation"));
    }

    #[test]
    fn scope_expire_refuse() {
        let err = validate_scope(EXPIRED, None, now()).unwrap_err();
        assert!(err.contains("expiré"), "{err}");
    }

    #[test]
    fn scope_malforme_refuse() {
        let err = validate_scope("pas [ du toml", None, now()).unwrap_err();
        assert!(err.contains("scope refusé"), "{err}");
    }

    #[test]
    fn scope_signe_sans_cle_refuse() {
        let err = validate_scope(INTEGRITY, None, now()).unwrap_err();
        assert!(err.contains("scope refusé"), "{err}");
        assert!(err.to_lowercase().contains("cl"), "{err}"); // « clé de confiance »
    }

    #[test]
    fn dispatch_sans_argument_affiche_usage() {
        let out = run(&[]).unwrap();
        assert!(out.contains("Usage"));
    }

    #[test]
    fn dispatch_commande_inconnue_erreur() {
        let err = run(&["bidon".to_string()]).unwrap_err();
        assert!(err.contains("commande inconnue"), "{err}");
    }

    // --- Voie C : `lab start` -----------------------------------------------

    #[test]
    fn lab_start_mono_reseau_prive_etablit_le_perimetre() {
        let out = lab_start(
            vec!["192.168.56.0/24".to_string()],
            "apprenant".to_string(),
            12,
            false,
            None,
            now(),
        )
        .unwrap();
        assert!(out.contains("Mode LABORATOIRE"), "{out}");
        assert!(out.contains("192.168.56.0/24"), "{out}");
        assert!(out.contains("N1–N4 débloqués"), "{out}");
        assert!(out.contains("Mode d'audit  : lab"), "{out}");
        assert!(out.contains("Empreinte SHA-256"), "{out}");
    }

    #[test]
    fn lab_start_multi_sous_reseaux() {
        let out = lab_start(
            vec!["10.10.1.0/24".to_string(), "10.10.2.0/24".to_string()],
            "op".to_string(),
            12,
            false,
            None,
            now(),
        )
        .unwrap();
        assert!(out.contains("10.10.1.0/24"), "{out}");
        assert!(out.contains("10.10.2.0/24"), "{out}");
    }

    #[test]
    fn lab_start_reseau_non_isole_refuse_sans_confirmation() {
        let err = lab_start(
            vec!["8.8.8.0/24".to_string()],
            "op".to_string(),
            12,
            false,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("AVERTISSEMENT"), "{err}");
        assert!(err.contains("--confirm-non-isolated"), "{err}");
    }

    #[test]
    fn lab_start_reseau_non_isole_accepte_avec_confirmation_renforcee() {
        let out = lab_start(
            vec!["8.8.8.0/24".to_string()],
            "op".to_string(),
            12,
            true,
            None,
            now(),
        )
        .unwrap();
        assert!(out.contains("Mode LABORATOIRE"), "{out}");
        assert!(out.contains("non isolé confirmé"), "{out}");
    }

    #[test]
    fn lab_start_sans_reseau_refuse() {
        let err = lab_start(vec![], "op".to_string(), 12, false, None, now()).unwrap_err();
        assert!(err.contains("cidr"), "{err}");
    }

    #[test]
    fn lab_start_cidr_malforme_refuse() {
        let err = lab_start(
            vec!["10.0.0.0/99".to_string()],
            "op".to_string(),
            12,
            false,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("refusé"), "{err}");
    }

    #[test]
    fn lab_start_journalise_en_mode_lab() {
        let dir = std::env::temp_dir().join(format!("nm-lab-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let path_str = path.to_str().unwrap();

        let out = lab_start(
            vec!["10.10.1.0/24".to_string()],
            "apprenant".to_string(),
            12,
            false,
            Some(path_str),
            now(),
        )
        .unwrap();
        assert!(out.contains("Mode LABORATOIRE"), "{out}");

        // Le démarrage est journalisé en clair, marqué mode = "lab", et chaîné.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"mode\":\"lab\""), "{content}");
        assert!(content.contains("lab.start"), "{content}");
        assert!(nickmare_core::audit::verify_file(&path).is_ok());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn dispatch_lab_sans_sous_commande_erreur() {
        let err = run(&["lab".to_string()]).unwrap_err();
        assert!(err.contains("sous-commande lab manquante"), "{err}");
    }

    #[test]
    fn dispatch_lab_sous_commande_inconnue_erreur() {
        let err = run(&["lab".to_string(), "bidon".to_string()]).unwrap_err();
        assert!(err.contains("sous-commande lab inconnue"), "{err}");
    }
}
