//! Binaire `nickmare` — point d'entrée de l'outil.
//!
//! Phase 0, issue #3 : `nickmare scope validate <fichier>` (voie B, cf.
//! `docs/ARCHITECTURE.md` §3). Phase 1, issue #11 : `nickmare lab start <cidr>…`
//! (voie C, mode laboratoire). Phase 1, issue #9 : `nickmare map <carte.json>`
//! (vue carte textuelle de la `NetworkMap`, US-B3). Phase 1, issue #10 :
//! `nickmare target select <cidr>` + `nickmare target host <ip>` (voie A,
//! sélection interactive + établissement de cible, US-A1/US-B4). Les autres
//! commandes (recon, scan, exploitation…) arrivent dans les phases suivantes. Un
//! parseur d'arguments complet (`clap`) sera introduit quand la surface CLI
//! grandira ; ici le dispatch reste volontairement minimal.

use std::process::ExitCode;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use nickmare_core::audit::AuditLog;
use nickmare_core::engagement::resume;
use nickmare_core::gate::{Decision, Request};
use nickmare_core::lab::LabSession;
use nickmare_core::model::{Finding, NetworkMap, Port, PortState, Proto, Service, Severity};
use nickmare_core::scope::{Capability, Scope, TemporalStatus};
use nickmare_core::target::TargetSelection;
use nickmare_net::map::render_map;
use nickmare_net::portscan::{scan_gated, ProviderProbe, ScanReport, UdpProbe};
use nickmare_net::provider::{RealNetworkProvider, Timeouts};
use nickmare_net::service_id::{identify_gated, IdentifyReport};
use nickmare_store::SqliteStore;

/// Durée par défaut de la fenêtre d'un lab (heures) si `--hours` est absent.
const DEFAULT_LAB_HOURS: i64 = 12;

/// Durée par défaut de la fenêtre d'une sélection voie A (heures) si `--hours`
/// est absent.
const DEFAULT_SELECT_HOURS: i64 = 12;

/// Délai par défaut (ms) d'une sonde de scan si `--timeout-ms` est absent.
const DEFAULT_SCAN_TIMEOUT_MS: u64 = 1000;

/// Bannière de version, dérivée des métadonnées du paquet.
fn banniere() -> String {
    format!("nickmare {}", env!("CARGO_PKG_VERSION"))
}

fn usage() -> String {
    let lines = [
        "",
        "Usage :",
        "  nickmare scope validate <fichier> [--trusted-key <hex> | --trusted-key-file <chemin>]",
        "  nickmare target select <cidr> --attest [--operator <id>] [--hours <n>] [--audit <chemin>]",
        "  nickmare target host <ip> --network <cidr> --attest [--operator <id>] [--hours <n>]",
        "                       [--audit <chemin>]",
        "  nickmare lab start <cidr> [<cidr>...] [--operator <id>] [--hours <n>]",
        "                      [--confirm-non-isolated] [--audit <chemin>]",
        "  nickmare scan ports <ip> --network <cidr> --attest [--ports <p,p,...>] [--udp]",
        "                      [--rate <pps>] [--operator <id>] [--hours <n>]",
        "                      [--timeout-ms <n>] [--audit <chemin>]",
        "  nickmare service id <ip> --network <cidr> --attest [--ports <p,p,...>]",
        "                      [--rate <pps>] [--operator <id>] [--hours <n>]",
        "                      [--timeout-ms <n>] [--audit <chemin>]",
        "  nickmare resume <engagement.db>",
        "  nickmare map <carte.json>",
        "",
        "scope validate : valide un fichier de scope (voie B) — résumé + empreinte SHA-256,",
        "                 ou refus clair (code de sortie ≠ 0).",
        "target select  : choisit un réseau reconnu et atteste l'autorisation (voie A) →",
        "                 périmètre de session verrouillé sur ce réseau ; --attest obligatoire.",
        "target host    : désigne l'hôte précis à pénétrer dans le réseau attesté ; refus +",
        "                 audit si l'hôte est hors du périmètre (n'élargit jamais le scope).",
        "lab start      : établit un périmètre de laboratoire (voie C) sur un ou plusieurs",
        "                 sous-réseaux ; attestation unique, N1–N4 débloqués, mode = \"lab\".",
        "scan ports     : scanne les ports d'un hôte du réseau attesté (recon active N1) —",
        "                 passe par le gate (refus hors périmètre + audit) ; TCP connect sans",
        "                 privilège par défaut, --udp pour l'UDP basique, débit plafonné --rate.",
        "service id     : identifie les services des ports ouverts d'un hôte attesté (recon",
        "                 active N1) — scan puis lecture de bannières via le gate ; nom +",
        "                 produit + version quand disponible, et constats associés (US-C1).",
        "resume         : reprend un engagement interrompu depuis l'état SQLite persistant",
        "                 (une base par engagement, §11.2) — repart du dernier état cohérent",
        "                 sans re-solliciter la cible ; actions en vol marquées « incomplète ».",
        "map            : affiche la carte réseau (NetworkMap) en texte — hôtes, rôles,",
        "                 services, hôtes compromis et chemins de pivot (US-B3).",
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
        Some("target") => run_target(&args[1..]),
        Some("lab") => run_lab(&args[1..]),
        Some("scan") => run_scan(&args[1..]),
        Some("service") => run_service(&args[1..]),
        Some("resume") => run_resume(&args[1..]),
        Some("map") => run_map(&args[1..]),
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

// --- Voie A : sélection interactive (`target select` / `target host`) -------

fn run_target(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("select") => run_target_select(&args[1..]),
        Some("host") => run_target_host(&args[1..]),
        Some(other) => Err(format!(
            "sous-commande target inconnue : {other}\n\n{}",
            usage()
        )),
        None => Err(format!("sous-commande target manquante\n\n{}", usage())),
    }
}

/// Options communes aux deux sous-commandes `target` (attestation, identité,
/// fenêtre, journal), analysées une fois.
struct TargetOpts {
    operator: Option<String>,
    attested: bool,
    hours: i64,
    audit_path: Option<String>,
}

impl Default for TargetOpts {
    fn default() -> Self {
        Self {
            operator: None,
            attested: false,
            hours: DEFAULT_SELECT_HOURS,
            audit_path: None,
        }
    }
}

/// Analyse une option commune `target` ; renvoie `Ok(Some(index_suivant))` si
/// l'option a été consommée, `Ok(None)` si `arg` n'est pas une option commune
/// (au positionnel de l'appelant de décider), ou une erreur.
fn parse_target_opt(
    opts: &mut TargetOpts,
    args: &[String],
    index: usize,
) -> Result<Option<usize>, String> {
    match args[index].as_str() {
        "--operator" => {
            let value = args
                .get(index + 1)
                .ok_or_else(|| "option --operator : identité manquante".to_string())?;
            opts.operator = Some(value.clone());
            Ok(Some(index + 2))
        }
        "--hours" => {
            let value = args
                .get(index + 1)
                .ok_or_else(|| "option --hours : valeur manquante".to_string())?;
            opts.hours = value
                .parse::<i64>()
                .map_err(|_| format!("option --hours : entier attendu, reçu {value:?}"))?;
            if opts.hours <= 0 {
                return Err("option --hours : durée strictement positive attendue".to_string());
            }
            Ok(Some(index + 2))
        }
        "--audit" => {
            let value = args
                .get(index + 1)
                .ok_or_else(|| "option --audit : chemin manquant".to_string())?;
            opts.audit_path = Some(value.clone());
            Ok(Some(index + 2))
        }
        "--attest" => {
            opts.attested = true;
            Ok(Some(index + 1))
        }
        _ => Ok(None),
    }
}

fn run_target_select(args: &[String]) -> Result<String, String> {
    let mut opts = TargetOpts::default();
    let mut network: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        if let Some(next) = parse_target_opt(&mut opts, args, index)? {
            index = next;
        } else {
            let arg = args[index].as_str();
            if arg == "--network" {
                return Err(format!(
                    "option --network : inutile pour « target select » (le réseau est l'argument positionnel <cidr>)\n\n{}",
                    usage()
                ));
            }
            if arg.starts_with('-') {
                return Err(format!("option inconnue : {arg}\n\n{}", usage()));
            }
            if network.is_some() {
                return Err(format!("argument en trop : {arg}\n\n{}", usage()));
            }
            network = Some(arg.to_string());
            index += 1;
        }
    }

    let Some(network) = network else {
        return Err(format!(
            "réseau à sélectionner manquant : indiquez le <cidr> choisi dans la recon\n\n{}",
            usage()
        ));
    };
    let operator = opts.operator.unwrap_or_else(default_operator);
    target_select(
        network,
        operator,
        opts.attested,
        opts.hours,
        opts.audit_path.as_deref(),
        Utc::now(),
    )
}

/// Établit le périmètre de session (voie A) et renvoie le résumé affichable, ou
/// un refus clair. `now` est injecté pour une fenêtre déterministe en test.
/// Fail-safe : sans attestation explicite, aucun périmètre n'est établi.
fn target_select(
    network: String,
    operator: String,
    attested: bool,
    hours: i64,
    audit_path: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String, String> {
    let valid_until = now + TimeDelta::hours(hours);
    let selection = TargetSelection::select(network, operator, attested, now, valid_until)
        .map_err(|err| format!("sélection refusée : {err}"))?;

    // Journalisation optionnelle de l'attestation (N1, mode standard) dans un
    // journal chaîné : cible + identité opérateur + horodatage (US-A1, US-A4).
    if let Some(path) = audit_path {
        let mut log = AuditLog::open(path)
            .map_err(|err| format!("ouverture du journal d'audit {path} : {err}"))?;
        log.append(selection.attest_record())
            .map_err(|err| format!("écriture du journal d'audit {path} : {err}"))?;
    }

    Ok(summarize_selection(&selection))
}

fn run_target_host(args: &[String]) -> Result<String, String> {
    let mut opts = TargetOpts::default();
    let mut host: Option<String> = None;
    let mut network: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        if let Some(next) = parse_target_opt(&mut opts, args, index)? {
            index = next;
        } else {
            match args[index].as_str() {
                "--network" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "option --network : <cidr> attendu".to_string())?;
                    network = Some(value.clone());
                    index += 2;
                }
                other if other.starts_with('-') => {
                    return Err(format!("option inconnue : {other}\n\n{}", usage()));
                }
                positional => {
                    if host.is_some() {
                        return Err(format!("argument en trop : {positional}\n\n{}", usage()));
                    }
                    host = Some(positional.to_string());
                    index += 1;
                }
            }
        }
    }

    let Some(host) = host else {
        return Err(format!("hôte à désigner manquant (<ip>)\n\n{}", usage()));
    };
    let Some(network) = network else {
        return Err(format!(
            "réseau attesté manquant : précisez --network <cidr> (le réseau sélectionné)\n\n{}",
            usage()
        ));
    };
    let operator = opts.operator.unwrap_or_else(default_operator);
    target_host(
        host,
        network,
        operator,
        opts.attested,
        opts.hours,
        opts.audit_path.as_deref(),
        Utc::now(),
    )
}

/// Désigne l'hôte précis à pénétrer dans le réseau attesté (voie A). Refuse (avec
/// audit) si l'hôte est hors du périmètre. `now` est injecté pour un confinement
/// déterministe en test. N'élargit jamais le scope : « target host » affine
/// seulement la cible active.
fn target_host(
    host: String,
    network: String,
    operator: String,
    attested: bool,
    hours: i64,
    audit_path: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String, String> {
    let host_ip = host
        .parse()
        .map_err(|_| format!("adresse d'hôte invalide : {host}"))?;
    let valid_until = now + TimeDelta::hours(hours);
    let selection = TargetSelection::select(network, operator, attested, now, valid_until)
        .map_err(|err| format!("cible refusée : {err}"))?;

    let decision = selection.confine(host_ip, now);

    // L'issue de la désignation est journalisée dans tous les cas : succès
    // (`target.host`) comme refus hors périmètre (`blocked_target`), US-B4/US-A4.
    if let Some(path) = audit_path {
        let mut log = AuditLog::open(path)
            .map_err(|err| format!("ouverture du journal d'audit {path} : {err}"))?;
        log.append(selection.host_record(host_ip, decision))
            .map_err(|err| format!("écriture du journal d'audit {path} : {err}"))?;
    }

    match decision {
        Decision::Allow => Ok(summarize_host(&selection, host_ip)),
        Decision::Deny(reason) => Err(format!(
            "cible refusée : hôte {host_ip} hors du réseau attesté {} ({reason})",
            selection.network()
        )),
    }
}

/// Résumé lisible d'un périmètre de session voie A : opérateur, réseau, fenêtre,
/// capacités (recon N1), empreinte SHA-256 et attestation. Rappelle le
/// confinement : les réseaux non sélectionnés restent hors d'atteinte.
fn summarize_selection(selection: &TargetSelection) -> String {
    let scope = selection.scope();
    let mut lines: Vec<String> = Vec::new();
    lines.push("Cible établie (voie A) — périmètre de session actif".to_string());
    lines.push(format!("  Opérateur     : {}", scope.engagement.operator));
    lines.push(format!("  Réseau        : {}", selection.network()));
    lines.push(format!(
        "  Fenêtre       : {} → {}",
        scope.engagement.valid_from, scope.engagement.valid_until
    ));
    lines.push(
        "  Capacités     : recon (N1) — actions offensives à activer explicitement".to_string(),
    );
    lines.push("  Mode d'audit  : standard".to_string());
    lines.push(format!("  Empreinte SHA-256 : {}", scope.fingerprint()));
    lines.push(format!(
        "  Attestation   : {} sur {} (empreinte liée au scope)",
        selection.attestation().operator,
        selection.attestation().perimeter
    ));
    lines.push(
        "Confinement : seul le réseau sélectionné est dans le périmètre ; les réseaux vus mais non sélectionnés (WiFi voisin, autre sous-réseau) restent hors d'atteinte."
            .to_string(),
    );
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Résumé lisible d'une cible active désignée (voie A). Rappelle que « target
/// host » affine la cible sans élargir le périmètre attesté.
fn summarize_host(selection: &TargetSelection, host: std::net::IpAddr) -> String {
    let scope = selection.scope();
    let mut lines: Vec<String> = Vec::new();
    lines.push("Cible active désignée (voie A)".to_string());
    lines.push(format!("  Hôte actif    : {host}"));
    lines.push(format!("  Réseau attesté : {}", selection.network()));
    lines.push(format!("  Empreinte SHA-256 : {}", scope.fingerprint()));
    lines.push(
        "Le périmètre n'est pas élargi : « target host » n'affine que la cible active à l'intérieur du réseau attesté."
            .to_string(),
    );
    let mut out = lines.join("\n");
    out.push('\n');
    out
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

// --- Scan de ports (`scan ports`) -------------------------------------------

fn run_scan(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("ports") => run_scan_ports(&args[1..]),
        Some(other) => Err(format!(
            "sous-commande scan inconnue : {other}\n\n{}",
            usage()
        )),
        None => Err(format!("sous-commande scan manquante\n\n{}", usage())),
    }
}

/// Options analysées de `scan ports`.
struct ScanOpts {
    host: Option<String>,
    network: Option<String>,
    attested: bool,
    ports: Vec<u16>,
    udp: bool,
    rate_pps: u32,
    operator: Option<String>,
    hours: i64,
    timeout_ms: u64,
    audit_path: Option<String>,
}

impl Default for ScanOpts {
    fn default() -> Self {
        Self {
            host: None,
            network: None,
            attested: false,
            ports: Vec::new(),
            udp: false,
            rate_pps: 0,
            operator: None,
            hours: DEFAULT_SELECT_HOURS,
            timeout_ms: DEFAULT_SCAN_TIMEOUT_MS,
            audit_path: None,
        }
    }
}

fn run_scan_ports(args: &[String]) -> Result<String, String> {
    let mut opts = ScanOpts::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--network" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --network : <cidr> attendu".to_string())?;
                opts.network = Some(value.clone());
                index += 2;
            }
            "--ports" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --ports : liste de ports attendue".to_string())?;
                opts.ports = parse_ports(value)?;
                index += 2;
            }
            "--rate" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --rate : valeur manquante".to_string())?;
                opts.rate_pps = value
                    .parse::<u32>()
                    .map_err(|_| format!("option --rate : entier attendu, reçu {value:?}"))?;
                index += 2;
            }
            "--operator" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --operator : identité manquante".to_string())?;
                opts.operator = Some(value.clone());
                index += 2;
            }
            "--hours" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --hours : valeur manquante".to_string())?;
                opts.hours = value
                    .parse::<i64>()
                    .map_err(|_| format!("option --hours : entier attendu, reçu {value:?}"))?;
                if opts.hours <= 0 {
                    return Err("option --hours : durée strictement positive attendue".to_string());
                }
                index += 2;
            }
            "--timeout-ms" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --timeout-ms : valeur manquante".to_string())?;
                opts.timeout_ms = value
                    .parse::<u64>()
                    .map_err(|_| format!("option --timeout-ms : entier attendu, reçu {value:?}"))?;
                index += 2;
            }
            "--audit" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --audit : chemin manquant".to_string())?;
                opts.audit_path = Some(value.clone());
                index += 2;
            }
            "--attest" => {
                opts.attested = true;
                index += 1;
            }
            "--udp" => {
                opts.udp = true;
                index += 1;
            }
            other if other.starts_with('-') => {
                return Err(format!("option inconnue : {other}\n\n{}", usage()));
            }
            positional => {
                if opts.host.is_some() {
                    return Err(format!("argument en trop : {positional}\n\n{}", usage()));
                }
                opts.host = Some(positional.to_string());
                index += 1;
            }
        }
    }

    let Some(host) = opts.host else {
        return Err(format!("hôte à scanner manquant (<ip>)\n\n{}", usage()));
    };
    let Some(network) = opts.network else {
        return Err(format!(
            "réseau attesté manquant : précisez --network <cidr>\n\n{}",
            usage()
        ));
    };
    let operator = opts.operator.unwrap_or_else(default_operator);
    scan_ports_cmd(
        host,
        network,
        operator,
        opts.attested,
        &opts.ports,
        opts.udp,
        opts.rate_pps,
        opts.hours,
        opts.timeout_ms,
        opts.audit_path.as_deref(),
        Utc::now(),
    )
}

/// Analyse une liste de ports « 22,80,443 » en `Vec<u16>` (vide = ports courants).
fn parse_ports(raw: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let port = token
            .parse::<u16>()
            .map_err(|_| format!("port invalide : {token:?} (attendu 0–65535)"))?;
        ports.push(port);
    }
    Ok(ports)
}

/// Scanne les ports de `host` **dans le réseau attesté**, après vérification par
/// le gate (recon active N1, §3.2). Rétablit le périmètre voie A (attestation),
/// pilote `net::portscan::scan_gated` sur un petit runtime, et journalise l'issue
/// (succès `recon.active` ou refus `blocked_*`). `now` est injecté pour une
/// fenêtre déterministe en test. Fail-safe : sans attestation, rien n'est scanné.
#[allow(clippy::too_many_arguments)]
fn scan_ports_cmd(
    host: String,
    network: String,
    operator: String,
    attested: bool,
    ports: &[u16],
    udp: bool,
    rate_pps: u32,
    hours: i64,
    timeout_ms: u64,
    audit_path: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String, String> {
    let host_ip = host
        .parse()
        .map_err(|_| format!("adresse d'hôte invalide : {host}"))?;
    let valid_until = now + TimeDelta::hours(hours);
    let selection = TargetSelection::select(network, operator, attested, now, valid_until)
        .map_err(|err| format!("scan refusé : {err}"))?;

    // Ré-extrait réseau/opérateur du scope établi (ils ont été consommés ci-dessus).
    let network = selection.network().to_string();
    let operator = selection.scope().engagement.operator.clone();
    let att = selection.attestation().clone();
    let req = Request::new(now, &operator).with_attestation(&att);
    let mut gate = selection.gate();
    let timeout = Duration::from_millis(timeout_ms.max(1));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|err| format!("initialisation du runtime de scan : {err}"))?;

    // Deux techniques sans privilège : TCP connect (réutilise le provider réel) ou
    // UDP basique. Le SYN brut reste réservé au labo (hors CLI/CI).
    let report = if udp {
        let probe = UdpProbe::new(timeout);
        let fut = scan_gated(&mut gate, &req, &operator, &probe, host_ip, ports, rate_pps);
        runtime.block_on(fut)
    } else {
        let provider = RealNetworkProvider::new().with_timeouts(Timeouts::new(timeout, timeout));
        let probe = ProviderProbe::new(&provider);
        let fut = scan_gated(&mut gate, &req, &operator, &probe, host_ip, ports, rate_pps);
        runtime.block_on(fut)
    };

    // Traçabilité : l'issue du scan est journalisée dans tous les cas (succès ou
    // refus hors périmètre), dans un journal chaîné.
    if let Some(path) = audit_path {
        let mut log = AuditLog::open(path)
            .map_err(|err| format!("ouverture du journal d'audit {path} : {err}"))?;
        log.append(report.record().clone())
            .map_err(|err| format!("écriture du journal d'audit {path} : {err}"))?;
    }

    match report {
        ScanReport::Allowed { ports, .. } => Ok(summarize_scan(host_ip, &network, udp, &ports)),
        ScanReport::Refused { reason, .. } => Err(format!(
            "scan refusé : hôte {host_ip} hors du périmètre attesté {network} ({reason})"
        )),
    }
}

/// Libellé français d'un état de port.
fn port_state_label(state: PortState) -> &'static str {
    match state {
        PortState::Open => "ouvert",
        PortState::Closed => "fermé",
        PortState::Filtered => "filtré",
    }
}

/// Libellé d'un protocole de port.
fn proto_label(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

/// Résumé lisible d'un scan autorisé : technique, liste des ports + états, bilan.
fn summarize_scan(host: std::net::IpAddr, network: &str, udp: bool, ports: &[Port]) -> String {
    let technique = if udp { "udp" } else { "tcp_connect" };
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("Scan de ports — {host} (réseau attesté {network})"));
    lines.push(format!("  Technique  : {technique}"));
    let (mut open, mut closed, mut filtered) = (0u32, 0u32, 0u32);
    for port in ports {
        match port.state {
            PortState::Open => open += 1,
            PortState::Closed => closed += 1,
            PortState::Filtered => filtered += 1,
        }
        let state = port_state_label(port.state);
        lines.push(format!(
            "  {}/{}  {state}",
            port.number,
            proto_label(port.proto)
        ));
    }
    let total = ports.len();
    lines.push(format!(
        "Bilan : {open} ouvert(s), {closed} fermé(s), {filtered} filtré(s) sur {total} port(s)."
    ));
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

// --- Identification de services (`service id`) ------------------------------

fn run_service(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("id") => run_service_id(&args[1..]),
        Some(other) => Err(format!(
            "sous-commande service inconnue : {other}\n\n{}",
            usage()
        )),
        None => Err(format!("sous-commande service manquante\n\n{}", usage())),
    }
}

/// Options analysées de `service id` (mêmes garde-fous que `scan ports`, sans
/// l'UDP : la lecture de bannière est TCP).
struct ServiceOpts {
    host: Option<String>,
    network: Option<String>,
    attested: bool,
    ports: Vec<u16>,
    rate_pps: u32,
    operator: Option<String>,
    hours: i64,
    timeout_ms: u64,
    audit_path: Option<String>,
}

impl Default for ServiceOpts {
    fn default() -> Self {
        Self {
            host: None,
            network: None,
            attested: false,
            ports: Vec::new(),
            rate_pps: 0,
            operator: None,
            hours: DEFAULT_SELECT_HOURS,
            timeout_ms: DEFAULT_SCAN_TIMEOUT_MS,
            audit_path: None,
        }
    }
}

fn run_service_id(args: &[String]) -> Result<String, String> {
    let mut opts = ServiceOpts::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--network" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --network : <cidr> attendu".to_string())?;
                opts.network = Some(value.clone());
                index += 2;
            }
            "--ports" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --ports : liste de ports attendue".to_string())?;
                opts.ports = parse_ports(value)?;
                index += 2;
            }
            "--rate" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --rate : valeur manquante".to_string())?;
                opts.rate_pps = value
                    .parse::<u32>()
                    .map_err(|_| format!("option --rate : entier attendu, reçu {value:?}"))?;
                index += 2;
            }
            "--operator" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --operator : identité manquante".to_string())?;
                opts.operator = Some(value.clone());
                index += 2;
            }
            "--hours" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --hours : valeur manquante".to_string())?;
                opts.hours = value
                    .parse::<i64>()
                    .map_err(|_| format!("option --hours : entier attendu, reçu {value:?}"))?;
                if opts.hours <= 0 {
                    return Err("option --hours : durée strictement positive attendue".to_string());
                }
                index += 2;
            }
            "--timeout-ms" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --timeout-ms : valeur manquante".to_string())?;
                opts.timeout_ms = value
                    .parse::<u64>()
                    .map_err(|_| format!("option --timeout-ms : entier attendu, reçu {value:?}"))?;
                index += 2;
            }
            "--audit" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --audit : chemin manquant".to_string())?;
                opts.audit_path = Some(value.clone());
                index += 2;
            }
            "--attest" => {
                opts.attested = true;
                index += 1;
            }
            other if other.starts_with('-') => {
                return Err(format!("option inconnue : {other}\n\n{}", usage()));
            }
            positional => {
                if opts.host.is_some() {
                    return Err(format!("argument en trop : {positional}\n\n{}", usage()));
                }
                opts.host = Some(positional.to_string());
                index += 1;
            }
        }
    }

    let Some(host) = opts.host else {
        return Err(format!("hôte à identifier manquant (<ip>)\n\n{}", usage()));
    };
    let Some(network) = opts.network else {
        return Err(format!(
            "réseau attesté manquant : précisez --network <cidr>\n\n{}",
            usage()
        ));
    };
    let operator = opts.operator.unwrap_or_else(default_operator);
    service_id_cmd(
        host,
        network,
        operator,
        opts.attested,
        &opts.ports,
        opts.rate_pps,
        opts.hours,
        opts.timeout_ms,
        opts.audit_path.as_deref(),
        Utc::now(),
    )
}

/// Scanne puis identifie les services des ports ouverts de `host` **dans le
/// réseau attesté**, chaque étape passant par le gate (recon active N1, §3.2).
/// `now` est injecté pour une fenêtre déterministe en test. Fail-safe : sans
/// attestation ou hors périmètre, rien n'est scanné ni lu.
#[allow(clippy::too_many_arguments)]
fn service_id_cmd(
    host: String,
    network: String,
    operator: String,
    attested: bool,
    ports: &[u16],
    rate_pps: u32,
    hours: i64,
    timeout_ms: u64,
    audit_path: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String, String> {
    let host_ip = host
        .parse()
        .map_err(|_| format!("adresse d'hôte invalide : {host}"))?;
    let valid_until = now + TimeDelta::hours(hours);
    let selection = TargetSelection::select(network, operator, attested, now, valid_until)
        .map_err(|err| format!("identification refusée : {err}"))?;

    let network = selection.network().to_string();
    let operator = selection.scope().engagement.operator.clone();
    let att = selection.attestation().clone();
    let req = Request::new(now, &operator).with_attestation(&att);
    let mut gate = selection.gate();
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let provider = RealNetworkProvider::new().with_timeouts(Timeouts::new(timeout, timeout));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|err| format!("initialisation du runtime d'identification : {err}"))?;

    // Deux actions de recon active successives, chacune soumise au gate : le scan
    // (TCP connect, réutilise le provider réel) détermine les ports ouverts, puis
    // l'identification lit leurs bannières via le même provider.
    let outcome = runtime.block_on(async {
        let probe = ProviderProbe::new(&provider);
        let scan = scan_gated(&mut gate, &req, &operator, &probe, host_ip, ports, rate_pps).await;
        match scan {
            ScanReport::Refused { reason, record } => Err((reason, record)),
            ScanReport::Allowed {
                ports: scanned,
                record,
            } => {
                let report = identify_gated(
                    &mut gate, &req, &operator, &provider, host_ip, &scanned, rate_pps,
                )
                .await;
                Ok((record, report))
            }
        }
    });

    // Traçabilité : chaque action est journalisée (scan + identification, ou le
    // refus amont), dans un journal chaîné.
    match outcome {
        Err((reason, record)) => {
            journal_records(audit_path, &[record])?;
            Err(format!(
                "identification refusée : hôte {host_ip} hors du périmètre attesté {network} ({reason})"
            ))
        }
        Ok((scan_record, report)) => {
            journal_records(audit_path, &[scan_record, report.record().clone()])?;
            match report {
                IdentifyReport::Allowed {
                    ports, findings, ..
                } => Ok(summarize_service_id(host_ip, &network, &ports, &findings)),
                IdentifyReport::Refused { reason, .. } => {
                    Err(format!("identification refusée : {reason}"))
                }
            }
        }
    }
}

/// Journalise une série d'enregistrements d'audit dans un journal chaîné (si un
/// chemin est fourni).
fn journal_records(
    audit_path: Option<&str>,
    records: &[nickmare_core::audit::AuditRecord],
) -> Result<(), String> {
    let Some(path) = audit_path else {
        return Ok(());
    };
    let mut log = AuditLog::open(path)
        .map_err(|err| format!("ouverture du journal d'audit {path} : {err}"))?;
    for record in records {
        log.append(record.clone())
            .map_err(|err| format!("écriture du journal d'audit {path} : {err}"))?;
    }
    Ok(())
}

/// Libellé français d'une gravité de constat.
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "faible",
        Severity::Medium => "moyen",
        Severity::High => "élevé",
        Severity::Critical => "critique",
    }
}

/// Libellé compact d'un service : `nom [produit [version]]`.
fn service_line(service: &Service) -> String {
    let mut line = service.name.clone();
    match (&service.product, &service.version) {
        (Some(product), Some(version)) => line.push_str(&format!(" {product} {version}")),
        (Some(product), None) => line.push_str(&format!(" {product}")),
        (None, Some(version)) => line.push_str(&format!(" v{version}")),
        (None, None) => {}
    }
    line
}

/// Résumé lisible d'une identification autorisée : services des ports ouverts +
/// constats produits.
fn summarize_service_id(
    host: std::net::IpAddr,
    network: &str,
    ports: &[Port],
    findings: &[Finding],
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "Identification de services — {host} (réseau attesté {network})"
    ));

    let mut identified = 0u32;
    for port in ports {
        if port.state != PortState::Open {
            continue;
        }
        if let Some(service) = &port.service {
            identified += 1;
            lines.push(format!(
                "  {}/{}  {}",
                port.number,
                proto_label(port.proto),
                service_line(service)
            ));
        }
    }
    if identified == 0 {
        lines.push("  (aucun service identifié sur un port ouvert)".to_string());
    }

    lines.push(format!("Constats : {}", findings.len()));
    for finding in findings {
        lines.push(format!(
            "  [{}] {}",
            severity_label(finding.severity),
            finding.title
        ));
    }

    lines.push(format!(
        "Bilan : {identified} service(s) identifié(s), {} constat(s).",
        findings.len()
    ));
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

// --- Reprise d'engagement (`resume`) ----------------------------------------

fn run_resume(args: &[String]) -> Result<String, String> {
    let mut engagement: Option<String> = None;
    let mut db: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "option --db : chemin manquant".to_string())?;
                db = Some(value.clone());
                index += 2;
            }
            other if other.starts_with('-') => {
                return Err(format!("option inconnue : {other}\n\n{}", usage()));
            }
            positional => {
                if engagement.is_some() {
                    return Err(format!("argument en trop : {positional}\n\n{}", usage()));
                }
                engagement = Some(positional.to_string());
                index += 1;
            }
        }
    }

    let Some(path) = db.or(engagement) else {
        return Err(format!("engagement à reprendre manquant\n\n{}", usage()));
    };
    resume_engagement(&path, Utc::now())
}

/// Reprend un engagement depuis sa base SQLite persistante (§11.2) et renvoie le
/// plan de reprise affichable. `now` est injecté pour un test déterministe.
/// Fail-safe : une base absente n'est pas créée à la volée (rien à reprendre →
/// refus clair), pour ne pas masquer une erreur de chemin.
fn resume_engagement(path: &str, now: DateTime<Utc>) -> Result<String, String> {
    if !std::path::Path::new(path).exists() {
        return Err(format!(
            "reprise impossible : aucune base d'engagement à {path} (rien à reprendre)"
        ));
    }
    let mut store = SqliteStore::open(path)
        .map_err(|err| format!("ouverture de la base d'engagement {path} : {err}"))?;
    let plan = resume(&mut store, now).map_err(|err| format!("reprise : {err}"))?;
    Ok(plan.render())
}

// --- Vue carte textuelle (`map`) --------------------------------------------

fn run_map(args: &[String]) -> Result<String, String> {
    let mut path: Option<&str> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
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
        return Err(format!("fichier de carte manquant\n\n{}", usage()));
    };
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("impossible de lire {path} : {err}"))?;
    render_map_json(&content)
}

/// Désérialise une `NetworkMap` (JSON) et en renvoie la vue carte textuelle, ou
/// un refus clair si le contenu est illisible. La construction de la carte (via
/// `discover`) et sa persistance arrivent avec l'implémentation réseau réelle
/// (#8) ; ici on rend une carte déjà produite — logique pure, testable.
fn render_map_json(content: &str) -> Result<String, String> {
    let map: NetworkMap =
        serde_json::from_str(content).map_err(|err| format!("carte réseau illisible : {err}"))?;
    Ok(render_map(&map))
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

    // --- Voie A : `target select` / `target host` ---------------------------

    const SELECT_NET: &str = "192.168.56.0/24";

    /// Chemin de journal jetable, isolé par tag et par PID (tests CLI voie A).
    fn tmp_audit(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nm-target-cli-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn target_select_atteste_etablit_le_perimetre() {
        let out = target_select(
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            12,
            None,
            now(),
        )
        .unwrap();
        assert!(out.contains("Cible établie (voie A)"), "{out}");
        assert!(out.contains(SELECT_NET), "{out}");
        assert!(out.contains("Empreinte SHA-256"), "{out}");
        assert!(out.contains("recon (N1)"), "{out}");
        assert!(out.contains("Mode d'audit  : standard"), "{out}");
        assert!(out.contains("hors d'atteinte"), "{out}");
    }

    #[test]
    fn target_select_sans_attestation_refuse() {
        // §10.4 : attestation obligatoire — sans --attest, pas de périmètre.
        let err = target_select(
            SELECT_NET.to_string(),
            "operateur".to_string(),
            false,
            12,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("sélection refusée"), "{err}");
        assert!(err.contains("attestation"), "{err}");
    }

    #[test]
    fn target_select_cidr_malforme_refuse() {
        // §10.4 : pas de sélection sans scope valide.
        let err = target_select(
            "192.168.56.0/99".to_string(),
            "operateur".to_string(),
            true,
            12,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("refusé"), "{err}");
    }

    #[test]
    fn target_select_journalise_l_attestation() {
        // DoD US-A1 : l'attestation est journalisée (cible + identité), chaînée.
        let path = tmp_audit("select");
        let path_str = path.to_str().unwrap();
        let out = target_select(
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            12,
            Some(path_str),
            now(),
        )
        .unwrap();
        assert!(out.contains("Cible établie (voie A)"), "{out}");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("target.attest"), "{content}");
        assert!(content.contains("\"mode\":\"standard\""), "{content}");
        assert!(content.contains(SELECT_NET), "{content}");
        assert!(nickmare_core::audit::verify_file(&path).is_ok());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn target_host_dans_le_reseau_atteste_designe_la_cible() {
        let out = target_host(
            "192.168.56.10".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            12,
            None,
            now(),
        )
        .unwrap();
        assert!(out.contains("Cible active désignée (voie A)"), "{out}");
        assert!(out.contains("192.168.56.10"), "{out}");
        assert!(out.contains("n'affine que la cible active"), "{out}");
    }

    #[test]
    fn target_host_hors_reseau_atteste_refuse_et_journalise() {
        // §10.4 / US-B4 : hôte hors du réseau attesté → refus + audit blocked.
        let path = tmp_audit("host-deny");
        let path_str = path.to_str().unwrap();
        let err = target_host(
            "10.0.0.5".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            12,
            Some(path_str),
            now(),
        )
        .unwrap_err();
        assert!(err.contains("hors du réseau attesté"), "{err}");

        // Le refus est tracé (blocked_target), et la chaîne reste valide.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("blocked_target"), "{content}");
        assert!(content.contains("\"result\":\"blocked\""), "{content}");
        assert!(nickmare_core::audit::verify_file(&path).is_ok());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn target_host_sans_attestation_refuse() {
        // Pas d'action sans scope établi : sans --attest, rien n'est désigné.
        let err = target_host(
            "192.168.56.10".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            false,
            12,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("cible refusée"), "{err}");
        assert!(err.contains("attestation"), "{err}");
    }

    #[test]
    fn target_host_sans_reseau_erreur() {
        let err = run_target(&["host".to_string(), "192.168.56.10".to_string()]).unwrap_err();
        assert!(err.contains("réseau attesté manquant"), "{err}");
    }

    #[test]
    fn target_host_ip_invalide_erreur() {
        let err = target_host(
            "pas-une-ip".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            12,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("adresse d'hôte invalide"), "{err}");
    }

    #[test]
    fn dispatch_target_sans_sous_commande_erreur() {
        let err = run(&["target".to_string()]).unwrap_err();
        assert!(err.contains("sous-commande target manquante"), "{err}");
    }

    #[test]
    fn dispatch_target_sous_commande_inconnue_erreur() {
        let err = run(&["target".to_string(), "bidon".to_string()]).unwrap_err();
        assert!(err.contains("sous-commande target inconnue"), "{err}");
    }

    #[test]
    fn target_select_via_run_sans_reseau_erreur() {
        let err = run_target(&["select".to_string(), "--attest".to_string()]).unwrap_err();
        assert!(err.contains("réseau à sélectionner manquant"), "{err}");
    }

    // --- Scan de ports : `scan ports` ---------------------------------------

    #[test]
    fn parse_ports_liste_et_vide() {
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        // Espaces et jetons vides tolérés ; liste vide → ports courants (vec vide).
        assert_eq!(parse_ports(" 22 , 443 ").unwrap(), vec![22, 443]);
        assert!(parse_ports("").unwrap().is_empty());
        // Port hors plage → refus clair.
        assert!(parse_ports("99999").is_err());
        assert!(parse_ports("ssh").is_err());
    }

    #[test]
    fn negatif_scan_hors_reseau_atteste_refuse_et_journalise() {
        // §10.4 / US-B2 : scanner un hôte HORS du réseau attesté → refus + audit
        // `blocked_target`, sans la moindre I/O réseau (le gate refuse en amont).
        let path = tmp_audit("scan-deny");
        let path_str = path.to_str().unwrap();
        let err = scan_ports_cmd(
            "10.0.0.5".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            &[22, 80],
            false,
            0,
            12,
            500,
            Some(path_str),
            now(),
        )
        .unwrap_err();
        assert!(err.contains("hors du périmètre attesté"), "{err}");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("blocked_target"), "{content}");
        assert!(content.contains("\"result\":\"blocked\""), "{content}");
        assert!(nickmare_core::audit::verify_file(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn negatif_scan_sans_attestation_refuse() {
        // Sans --attest : aucun périmètre établi, donc rien n'est scanné.
        let err = scan_ports_cmd(
            "192.168.56.10".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            false,
            &[22],
            false,
            0,
            12,
            500,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("scan refusé"), "{err}");
        assert!(err.contains("attestation"), "{err}");
    }

    #[test]
    fn scan_ports_ip_invalide_erreur() {
        let err = scan_ports_cmd(
            "pas-une-ip".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            &[22],
            false,
            0,
            12,
            500,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("adresse d'hôte invalide"), "{err}");
    }

    #[test]
    fn scan_ports_loopback_in_scope_classe_un_port_ouvert() {
        // Scan réel mais en loopback, sans privilège (CI-safe) : un port lié et
        // écouté ressort « ouvert », et le scan passe par le gate (in-scope).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = scan_ports_cmd(
            "127.0.0.1".to_string(),
            "127.0.0.1/32".to_string(),
            "operateur".to_string(),
            true,
            &[port],
            false,
            0,
            12,
            500,
            None,
            now(),
        )
        .unwrap();
        assert!(out.contains("Scan de ports — 127.0.0.1"), "{out}");
        assert!(out.contains("tcp_connect"), "{out}");
        assert!(out.contains(&format!("{port}/tcp  ouvert")), "{out}");
        assert!(out.contains("1 ouvert(s)"), "{out}");
    }

    #[test]
    fn dispatch_scan_sans_sous_commande_erreur() {
        let err = run(&["scan".to_string()]).unwrap_err();
        assert!(err.contains("sous-commande scan manquante"), "{err}");
    }

    #[test]
    fn dispatch_scan_sous_commande_inconnue_erreur() {
        let err = run(&["scan".to_string(), "bidon".to_string()]).unwrap_err();
        assert!(err.contains("sous-commande scan inconnue"), "{err}");
    }

    #[test]
    fn scan_ports_sans_hote_erreur() {
        let err = run_scan(&["ports".to_string()]).unwrap_err();
        assert!(err.contains("hôte à scanner manquant"), "{err}");
    }

    #[test]
    fn scan_ports_sans_reseau_erreur() {
        let err = run_scan(&["ports".to_string(), "192.168.56.10".to_string()]).unwrap_err();
        assert!(err.contains("réseau attesté manquant"), "{err}");
    }

    // --- Identification de services : `service id` --------------------------

    #[test]
    fn dispatch_service_sans_sous_commande_erreur() {
        let err = run(&["service".to_string()]).unwrap_err();
        assert!(err.contains("sous-commande service manquante"), "{err}");
    }

    #[test]
    fn dispatch_service_sous_commande_inconnue_erreur() {
        let err = run(&["service".to_string(), "bidon".to_string()]).unwrap_err();
        assert!(err.contains("sous-commande service inconnue"), "{err}");
    }

    #[test]
    fn service_id_sans_hote_erreur() {
        let err = run_service(&["id".to_string()]).unwrap_err();
        assert!(err.contains("hôte à identifier manquant"), "{err}");
    }

    #[test]
    fn service_id_sans_reseau_erreur() {
        let err = run_service(&["id".to_string(), "192.168.56.10".to_string()]).unwrap_err();
        assert!(err.contains("réseau attesté manquant"), "{err}");
    }

    #[test]
    fn service_id_ip_invalide_erreur() {
        let err = service_id_cmd(
            "pas-une-ip".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            &[22],
            0,
            12,
            500,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("adresse d'hôte invalide"), "{err}");
    }

    #[test]
    fn negatif_service_id_hors_reseau_refuse_et_journalise() {
        // §10.4 : identifier un service sur un hôte HORS périmètre → refus + audit
        // `blocked_target`, sans la moindre I/O réseau (le gate refuse en amont).
        let path = tmp_audit("service-deny");
        let path_str = path.to_str().unwrap();
        let err = service_id_cmd(
            "10.0.0.5".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            true,
            &[22, 80],
            0,
            12,
            500,
            Some(path_str),
            now(),
        )
        .unwrap_err();
        assert!(err.contains("hors du périmètre attesté"), "{err}");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("blocked_target"), "{content}");
        assert!(content.contains("\"result\":\"blocked\""), "{content}");
        assert!(nickmare_core::audit::verify_file(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn negatif_service_id_sans_attestation_refuse() {
        let err = service_id_cmd(
            "192.168.56.10".to_string(),
            SELECT_NET.to_string(),
            "operateur".to_string(),
            false,
            &[22],
            0,
            12,
            500,
            None,
            now(),
        )
        .unwrap_err();
        assert!(err.contains("identification refusée"), "{err}");
        assert!(err.contains("attestation"), "{err}");
    }

    #[test]
    fn service_id_loopback_in_scope_identifie_un_service() {
        // Identification réelle mais en loopback, sans privilège (CI-safe) : un
        // port lié mais muet ressort « ouvert » et son service est nommé par le
        // port (bannière silencieuse → dégradation propre, pas de panique).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = service_id_cmd(
            "127.0.0.1".to_string(),
            "127.0.0.1/32".to_string(),
            "operateur".to_string(),
            true,
            &[port],
            0,
            12,
            500,
            None,
            now(),
        )
        .unwrap();
        assert!(
            out.contains("Identification de services — 127.0.0.1"),
            "{out}"
        );
        assert!(out.contains("1 service(s) identifié(s)"), "{out}");
        // Port éphémère : aucun nom usuel → « unknown », sans panique.
        assert!(out.contains(&format!("{port}/tcp  unknown")), "{out}");
    }

    // --- Vue carte textuelle : `map` ----------------------------------------

    const MAP: &str = include_str!("../../../testdata/mock/network_map.json");

    #[test]
    fn map_rend_la_carte_hotes_compromis_et_pivots() {
        let out = render_map_json(MAP).unwrap();
        assert!(
            out.contains("Carte réseau — périmètre 192.168.56.0/24"),
            "{out}"
        );
        // Hôtes et leurs champs.
        assert!(out.contains("192.168.56.1 — passerelle"), "{out}");
        assert!(out.contains("gw.lab"), "{out}");
        assert!(out.contains("192.168.56.10 — serveur"), "{out}");
        assert!(out.contains("22/tcp ssh (OpenSSH 9.6)"), "{out}");
        assert!(out.contains("80/tcp http (nginx)"), "{out}");
        // Hôte compromis et chemin de pivot visuellement distincts.
        assert!(out.contains("[COMPROMIS]"), "{out}");
        assert!(
            out.contains("192.168.56.10 → 192.168.56.20  (via ssh"),
            "{out}"
        );
    }

    #[test]
    fn map_json_malforme_refuse() {
        let err = render_map_json("{ pas du json").unwrap_err();
        assert!(err.contains("carte réseau illisible"), "{err}");
    }

    #[test]
    fn map_sans_fichier_erreur() {
        let err = run_map(&[]).unwrap_err();
        assert!(err.contains("fichier de carte manquant"), "{err}");
    }

    #[test]
    fn map_fichier_introuvable_erreur() {
        let err = run_map(&["chemin/inexistant/carte.json".to_string()]).unwrap_err();
        assert!(err.contains("impossible de lire"), "{err}");
    }

    // --- Reprise d'engagement (`resume`) ------------------------------------

    #[test]
    fn resume_base_absente_refuse_proprement() {
        let err = resume_engagement("chemin/inexistant/engagement.db", now()).unwrap_err();
        assert!(err.contains("rien à reprendre"), "{err}");
    }

    #[test]
    fn resume_sans_argument_erreur() {
        let err = run_resume(&[]).unwrap_err();
        assert!(err.contains("engagement à reprendre manquant"), "{err}");
    }

    #[test]
    fn resume_repart_du_dernier_etat_coherent() {
        use nickmare_core::engagement::EngagementStore;

        let dir = std::env::temp_dir().join(format!("nm-resume-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engagement.db");
        let _ = std::fs::remove_file(&path);
        let path_str = path.to_str().unwrap();

        // On fabrique l'état d'un run interrompu : une opération terminée, une en
        // vol au moment de la coupure.
        {
            let mut store = SqliteStore::open(path_str).unwrap();
            store.begin("scan:a", "scan", "a", now()).unwrap();
            store.complete("scan:a", now()).unwrap();
            store.begin("exploit:b", "exploit", "b", now()).unwrap();
        }

        let out = resume_engagement(path_str, now()).unwrap();
        assert!(out.contains("dernier état cohérent"), "{out}");
        // Une terminée sautée, une récupérée incomplète à reprendre.
        assert!(out.contains("Terminées (sautées, cible non re-sollicitée) : 1"), "{out}");
        assert!(out.contains("exploit:b"), "{out}");

        std::fs::remove_file(&path).ok();
    }
}
