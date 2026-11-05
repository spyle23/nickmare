//! Binaire `nickmare` — point d'entrée de l'outil.
//!
//! Phase 0, issue #3 : livre la commande `nickmare scope validate <fichier>`
//! (voie B, cf. `docs/ARCHITECTURE.md` §3). Les autres commandes (recon, scan,
//! exploitation…) arrivent dans les phases suivantes. L'orchestration réelle et
//! un parseur d'arguments complet (`clap`) seront introduits quand la surface
//! CLI grandira (Phase 1+) ; ici le dispatch reste volontairement minimal.

use std::process::ExitCode;

use chrono::{DateTime, Utc};
use nickmare_core::scope::{Capability, Scope, TemporalStatus};

/// Bannière de version, dérivée des métadonnées du paquet.
fn banniere() -> String {
    format!("nickmare {}", env!("CARGO_PKG_VERSION"))
}

fn usage() -> String {
    let lines: [&str; 6] = [
        "",
        "Usage :",
        "  nickmare scope validate <fichier> [--trusted-key <hex> | --trusted-key-file <chemin>]",
        "",
        "Valide un fichier de scope (voie B) : affiche le résumé et l'empreinte SHA-256,",
        "ou refuse avec un message clair (code de sortie ≠ 0).",
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
        Some("--version" | "-V") => Ok(format!("{}\n", banniere())),
        Some("--help" | "-h") | None => Ok(usage()),
        Some(other) => Err(format!("commande inconnue : {other}\n\n{}", usage())),
    }
}

fn run_scope(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("validate") => run_scope_validate(&args[1..]),
        Some(other) => Err(format!("sous-commande scope inconnue : {other}\n\n{}", usage())),
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
                let file = args.get(index + 1).ok_or_else(|| {
                    "option --trusted-key-file : chemin manquant".to_string()
                })?;
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
    lines.push(format!("  Autorisé par  : {}", scope.engagement.authorized_by));
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
}
