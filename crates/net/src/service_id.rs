//! Identification de services — reconnaissance **active** de niveau 1 (issue #13,
//! cf. `docs/ARCHITECTURE.md` §2 N1, §9 Phase 3, US-C1, §12).
//!
//! L'identification de services **prolonge** le scan de ports (#12) sans rien en
//! réimplémenter : elle **consomme** les résultats d'un scan (les [`Port`]
//! ouverts) et les **bannières déjà capturées** par le [`NetworkProvider`] (#8),
//! plutôt que de rouvrir des sockets en direct. Toute sonde de service active
//! passe donc par le provider (socket confinée au gate), jamais par ce module.
//!
//! # Un cœur **pur** et défensif
//!
//! La lecture d'une bannière produit des octets qui viennent du réseau : ils sont
//! **hostiles par principe** (§12). Le cœur du module est donc un ensemble de
//! fonctions **pures** ([`identify_service`], [`identify_from_text`],
//! [`clean_banner`], [`well_known_service`]) qui :
//!
//! - décodent la bannière en *lossy* (jamais de panique sur de l'UTF-8 invalide),
//! - la **bornent** et la nettoient de ses octets de contrôle,
//! - en extraient `name` / `product` / `version` par empreinte défensive (SSH,
//!   HTTP, FTP, SMTP, POP3, IMAP + repli générique), sans jamais `unwrap`er une
//!   donnée externe ni indexer un octet au hasard.
//!
//! Une bannière tronquée, vide ou malformée ne panique jamais : elle **dégrade
//! proprement** vers le nom de service déduit du port (ou `"unknown"`), sans
//! `product`/`version`.
//!
//! # Une orchestration **confinée au gate**
//!
//! [`identify_gated`] applique ce cœur aux ports ouverts d'un hôte : comme
//! [`scan_gated`](crate::portscan::scan_gated), elle passe par
//! [`Gate::check`](nickmare_core::gate::Gate::check) (périmètre, fenêtre,
//! attestation, plafonds) **avant** la moindre lecture de bannière, et un refus
//! produit un audit `blocked_*` sans lire une seule bannière (fail-safe). Les
//! bannières sont lues via le provider (recon active, TCP uniquement) et cadencées
//! par le **même** seau à jetons que le gate ([`RateLimiter`]).
//!
//! # Alimentation de la carte et des findings
//!
//! Les [`Port`] renvoyés portent leur [`Service`] identifié : ils s'agrègent tels
//! quels dans la [`NetworkMap`](nickmare_core::model::NetworkMap) via
//! [`merge_host`](crate::map::merge_host). En parallèle, [`service_findings`]
//! produit les [`Finding`] correspondants (un constat d'information par service,
//! plus un constat de gravité pour les protocoles **en clair**). La corrélation
//! CVE des versions obtenues est l'étape suivante (crate `cve`, Phase 3).

use std::net::IpAddr;
use std::time::Duration;

use chrono::Utc;

use nickmare_core::audit::AuditRecord;
use nickmare_core::gate::{audit_record, Action, Decision, DenyReason, Gate, Request};
use nickmare_core::model::{Finding, Port, PortState, Proto, Service, Severity};
use nickmare_core::traits::NetworkProvider;

use crate::discovery::RateLimiter;

/// Nombre maximal de caractères conservés d'une bannière nettoyée : une entrée
/// hostile ne gonfle ni la mémoire ni l'affichage (§12).
const BANNER_TEXT_CAP: usize = 256;

// --- Nom de service usuel par port ------------------------------------------

/// Nom de service usuel associé à un port (identification « au port », repli
/// quand aucune bannière exploitable n'est obtenue). `None` si le port n'est pas
/// dans la table usuelle (le service sera alors `"unknown"`).
#[must_use]
pub fn well_known_service(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "dns",
        80 | 8000 | 8008 | 8080 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 | 8443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1723 => "pptp",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => return None,
    })
}

// --- Nettoyage défensif d'une bannière --------------------------------------

/// Décode puis **nettoie** une bannière brute pour l'affichage : décodage *lossy*
/// (UTF-8 invalide toléré), octets de contrôle remplacés par des espaces, espaces
/// consécutifs fusionnés, bornage à [`BANNER_TEXT_CAP`] caractères. Renvoie `None`
/// si rien d'imprimable n'en ressort. **Pure**, ne panique jamais (§12).
#[must_use]
pub fn clean_banner(bytes: &[u8]) -> Option<String> {
    sanitize(&String::from_utf8_lossy(bytes))
}

/// Nettoie une chaîne déjà décodée (cf. [`clean_banner`]).
fn sanitize(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut kept = 0usize;
    let mut last_space = false;
    for ch in raw.chars() {
        let c = if ch.is_control() { ' ' } else { ch };
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        out.push(c);
        kept += 1;
        if kept >= BANNER_TEXT_CAP {
            break;
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// --- Identification d'un service --------------------------------------------

/// Identifie le service d'un port à partir d'une bannière **brute** (octets
/// réseau hostiles). Décode en *lossy* puis délègue à [`identify_from_text`].
/// **Pure**, ne panique jamais, même sur une bannière tronquée ou binaire.
#[must_use]
pub fn identify_service(port: u16, banner: Option<&[u8]>) -> Service {
    let raw = banner.map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    build_service(port, raw.as_deref())
}

/// Identifie le service d'un port à partir d'une bannière **déjà décodée** (texte
/// capturé par le provider). C'est la voie empruntée par [`identify_gated`] :
/// elle **consomme** la bannière du `Service` renvoyé par
/// [`NetworkProvider::read_banner`] sans rouvrir de socket. **Pure**.
#[must_use]
pub fn identify_from_text(port: u16, banner: Option<&str>) -> Service {
    build_service(port, banner)
}

/// Construit le [`Service`] : empreinte sur la bannière brute (qui préserve les
/// sauts de ligne pour l'analyse des en-têtes HTTP) et bannière nettoyée pour
/// l'affichage. Sans bannière exploitable, dégrade vers le nom déduit du port.
fn build_service(port: u16, raw: Option<&str>) -> Service {
    let Some(raw) = raw else {
        return name_only(port);
    };
    let Some(display) = sanitize(raw) else {
        return name_only(port);
    };
    let fp = fingerprint(raw);
    let name = fp
        .name
        .map(str::to_string)
        .or_else(|| well_known_service(port).map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    Service {
        name,
        product: fp.product,
        version: fp.version,
        banner: Some(display),
    }
}

/// Service nommé par le seul port (bannière absente/vide, port ouvert mais muet).
fn name_only(port: u16) -> Service {
    Service {
        name: well_known_service(port).unwrap_or("unknown").to_string(),
        product: None,
        version: None,
        banner: None,
    }
}

// --- Empreinte protocolaire (pure, défensive) -------------------------------

/// Empreinte tirée d'une bannière : nom de protocole reconnu (le cas échéant) et
/// couple produit/version extrait.
struct Fingerprint {
    name: Option<&'static str>,
    product: Option<String>,
    version: Option<String>,
}

impl Fingerprint {
    fn named(name: &'static str, pv: (Option<String>, Option<String>)) -> Self {
        Self {
            name: Some(name),
            product: pv.0,
            version: pv.1,
        }
    }

    fn anonymous(pv: (Option<String>, Option<String>)) -> Self {
        Self {
            name: None,
            product: pv.0,
            version: pv.1,
        }
    }
}

/// Reconnaît le protocole et en extrait produit/version. Les signatures sont des
/// **heuristiques prudentes** : en cas de doute, le nom reste `None` (le port
/// tranchera) et produit/version restent absents, jamais inventés.
fn fingerprint(raw: &str) -> Fingerprint {
    let head = raw.trim_start();

    // SSH : « SSH-<proto>-<logiciel> [commentaires] » (RFC 4253).
    if head.starts_with("SSH-") {
        return Fingerprint::named("ssh", parse_ssh(head));
    }

    // HTTP : ligne de statut « HTTP/… » ou en-tête « Server: … ».
    if head.starts_with("HTTP/") || server_header_value(raw).is_some() {
        return Fingerprint::named("http", parse_http(raw));
    }

    // POP3 : salutation « +OK <produit> … » (produit souvent sans version).
    if head.starts_with("+OK") {
        return Fingerprint::named("pop3", parse_greeting(head, 1));
    }

    // IMAP : salutation « * OK … » / « * PREAUTH … » / « * BYE … ».
    if head.starts_with("* OK") || head.starts_with("* PREAUTH") || head.starts_with("* BYE") {
        return Fingerprint::named("imap", scan_product_version(head));
    }

    // Protocoles à code de réponse numérique (FTP/SMTP : « 220 … »).
    if first_token(head).is_some_and(is_reply_code) {
        let upper = head.to_ascii_uppercase();
        if upper.contains("FTP") {
            return Fingerprint::named("ftp", scan_product_version(head));
        }
        if upper.contains("SMTP") {
            return Fingerprint::named("smtp", parse_smtp(head));
        }
        return Fingerprint::anonymous(scan_product_version(head));
    }

    // Repli générique : on tente produit/version, le port donnera le nom.
    Fingerprint::anonymous(scan_product_version(head))
}

/// Analyse une bannière SSH « SSH-2.0-OpenSSH_9.6p1 Ubuntu-… ».
fn parse_ssh(head: &str) -> (Option<String>, Option<String>) {
    let Some(rest) = head.strip_prefix("SSH-") else {
        return (None, None);
    };
    // rest = « 2.0-OpenSSH_9.6p1 … » ; le logiciel suit le premier '-'.
    let Some((_proto, software)) = rest.split_once('-') else {
        return (None, None);
    };
    let Some(token) = software.split_whitespace().next() else {
        return (None, None);
    };
    // « OpenSSH_9.6p1 » → produit avant '_', version après.
    if let Some((product, version)) = token.split_once('_') {
        (non_empty(product), normalize_version(version))
    } else {
        (non_empty(token), None)
    }
}

/// Analyse une réponse HTTP : valeur de l'en-tête `Server` → produit/version.
fn parse_http(raw: &str) -> (Option<String>, Option<String>) {
    let Some(value) = server_header_value(raw).filter(|v| !v.is_empty()) else {
        return (None, None);
    };
    let token = value.split_whitespace().next().unwrap_or(value);
    if let Some((product, version)) = token.split_once('/') {
        (non_empty(product), normalize_version(version))
    } else {
        (non_empty(token), None)
    }
}

/// Analyse une salutation SMTP ; à défaut de version, le produit suit souvent le
/// mot-clé `ESMTP`/`SMTP` (« 220 mail ESMTP Postfix »).
fn parse_smtp(head: &str) -> (Option<String>, Option<String>) {
    let (mut product, version) = scan_product_version(head);
    if product.is_none() {
        let tokens: Vec<&str> = head.split_whitespace().collect();
        for (i, token) in tokens.iter().enumerate() {
            let upper = token.to_ascii_uppercase();
            if (upper == "ESMTP" || upper == "SMTP") && i + 1 < tokens.len() {
                product = producty_name(tokens[i + 1]);
                break;
            }
        }
    }
    (product, version)
}

/// Valeur de l'en-tête `Server:` d'une réponse HTTP (insensible à la casse), ou
/// `None`. Parcours **par ligne**, sans indexer un octet au hasard (§12).
fn server_header_value(raw: &str) -> Option<&str> {
    raw.split('\n')
        .map(str::trim)
        .find_map(|line| strip_prefix_ci(line, "server:"))
        .map(str::trim)
}

/// Balaie un texte pour en extraire un couple produit/version plausible : un
/// jeton « produit/version », ou un jeton de version précédé d'un produit.
fn scan_product_version(text: &str) -> (Option<String>, Option<String>) {
    let tokens: Vec<&str> = text.split_whitespace().collect();

    // Forme compacte « produit/version » (ex. « nginx/1.24.0 »).
    for &token in &tokens {
        if let Some((product, version)) = token.split_once('/') {
            if let Some(version) = normalize_version(version) {
                if let Some(product) = producty_name(product) {
                    return (Some(product), Some(version));
                }
            }
        }
    }

    // Jeton de version isolé, éventuellement précédé d'un nom de produit.
    for (i, &token) in tokens.iter().enumerate() {
        if looks_like_version(token) {
            if let Some(version) = normalize_version(token) {
                let product = i.checked_sub(1).and_then(|p| producty_name(tokens[p]));
                return (product, Some(version));
            }
        }
    }

    (None, None)
}

/// Analyse une salutation (POP3) : d'abord le scan produit/version, et à défaut
/// de version, le premier jeton « produit » après les `skip` jetons de salutation
/// (ex. « +OK **Dovecot** ready » → produit `Dovecot`, sans version).
fn parse_greeting(head: &str, skip: usize) -> (Option<String>, Option<String>) {
    let (product, version) = scan_product_version(head);
    if product.is_some() {
        return (product, version);
    }
    let product = head.split_whitespace().skip(skip).find_map(producty_name);
    (product, version)
}

// --- Petits utilitaires d'analyse (purs, sans panique) ----------------------

/// Premier jeton séparé par des blancs.
fn first_token(s: &str) -> Option<&str> {
    s.split_whitespace().next()
}

/// Vrai si le jeton est un code de réponse à trois chiffres (FTP/SMTP).
fn is_reply_code(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 3 && bytes[..3].iter().all(u8::is_ascii_digit)
}

/// Retire le préfixe `prefix` (ASCII) de `s`, insensible à la casse, sans jamais
/// découper un caractère multi-octets (§12 : entrée hostile).
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let (pb, sb) = (prefix.as_bytes(), s.as_bytes());
    if sb.len() >= pb.len() && sb[..pb.len()].eq_ignore_ascii_case(pb) {
        // Les `pb.len()` premiers octets sont ASCII (comparés à `prefix`), donc
        // `pb.len()` est une frontière de caractère valide : découpe sûre.
        Some(&s[pb.len()..])
    } else {
        None
    }
}

/// `Some(s)` si non vide, sinon `None`.
fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Un jeton « ressemble-t-il » à une version : commence par un chiffre, contient
/// un point, n'est fait que de caractères de version (bornes ponctuelles ôtées).
fn looks_like_version(token: &str) -> bool {
    let t = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    t.chars().next().is_some_and(|c| c.is_ascii_digit())
        && t.contains('.')
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Normalise une version candidate : ponctuation de bord ôtée, doit commencer par
/// un chiffre. `None` si ce n'en est pas une.
fn normalize_version(v: &str) -> Option<String> {
    let t = v.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        Some(t.to_string())
    } else {
        None
    }
}

/// Nom de produit nettoyé d'un jeton (lettres au début, longueur ≥ 2), ou `None`.
fn producty_name(s: &str) -> Option<String> {
    let t = s.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if t.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && t.chars().count() >= 2 {
        Some(t.to_string())
    } else {
        None
    }
}

// --- Constats de sécurité (findings) ----------------------------------------

/// Recommandation du constat d'information d'un service identifié (la corrélation
/// CVE des versions vient ensuite, crate `cve`).
const INFO_RECOMMENDATION: &str =
    "Vérifier que ce service est exposé intentionnellement et maintenu à jour (corrélation CVE à suivre).";

/// Produit les [`Finding`] tirés d'un service identifié sur `host:port` :
///
/// - un constat **d'information** décrivant le service (nom, produit, version,
///   bannière) — base de la corrélation CVE à venir ;
/// - pour un protocole **en clair** (telnet, ftp, http, pop3, imap, smtp), un
///   constat supplémentaire de gravité (transmission non chiffrée).
///
/// **Pure** : n'ouvre aucune socket, se calcule à partir du seul [`Service`].
#[must_use]
pub fn service_findings(host: IpAddr, port: u16, service: &Service) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut description = format!("Service {} détecté sur le port {port}.", service.name);
    if let Some(product) = &service.product {
        description.push_str(&format!(" Produit : {product}."));
    }
    if let Some(version) = &service.version {
        description.push_str(&format!(" Version : {version}."));
    }
    if let Some(banner) = &service.banner {
        description.push_str(&format!(" Bannière : {banner}"));
    }
    findings.push(Finding {
        host,
        port: Some(port),
        severity: Severity::Info,
        cve: None,
        title: format!("Service identifié : {}", service_label(service)),
        description,
        recommendation: INFO_RECOMMENDATION.to_string(),
    });

    if let Some(severity) = cleartext_severity(&service.name) {
        findings.push(Finding {
            host,
            port: Some(port),
            severity,
            cve: None,
            title: format!("Service en clair : {}", service.name),
            description: format!(
                "Le service {} transmet identifiants et données sans chiffrement.",
                service.name
            ),
            recommendation: cleartext_recommendation(&service.name),
        });
    }

    findings
}

/// Libellé compact d'un service pour un titre : « ssh OpenSSH 9.6p1 ».
fn service_label(service: &Service) -> String {
    let mut label = service.name.clone();
    match (&service.product, &service.version) {
        (Some(product), Some(version)) => label.push_str(&format!(" {product} {version}")),
        (Some(product), None) => label.push_str(&format!(" {product}")),
        (None, Some(version)) => label.push_str(&format!(" v{version}")),
        (None, None) => {}
    }
    label
}

/// Gravité d'un service transmettant en clair, ou `None` s'il est chiffré/neutre.
fn cleartext_severity(name: &str) -> Option<Severity> {
    match name {
        // Telnet expose un shell d'administration en clair : plus grave.
        "telnet" => Some(Severity::Medium),
        "ftp" | "http" | "pop3" | "imap" | "smtp" => Some(Severity::Low),
        _ => None,
    }
}

/// Recommandation associée à un service en clair (variante chiffrée conseillée).
fn cleartext_recommendation(name: &str) -> String {
    let alternative = match name {
        "telnet" => "SSH",
        "ftp" => "FTPS ou SFTP",
        "http" => "HTTPS (TLS)",
        "pop3" => "POP3S (TLS)",
        "imap" => "IMAPS (TLS)",
        "smtp" => "SMTP avec STARTTLS (ou SMTPS)",
        _ => "une variante chiffrée",
    };
    format!(
        "Remplacer {name} par {alternative}, ou en restreindre l'accès : ce service circule en clair."
    )
}

// --- Orchestration confinée au gate -----------------------------------------

/// Issue d'une identification de services **soumise au gate** (§3.2). Comme
/// [`ScanReport`](crate::portscan::ScanReport), un enregistrement d'audit est
/// produit dans les deux cas : l'identification ne contourne jamais la traçabilité.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifyReport {
    /// Cible autorisée : ports (les ouverts enrichis de leur [`Service`]), les
    /// [`Finding`] correspondants, et l'audit `recon.active`/`ok`.
    Allowed {
        /// Ports fournis, les ouverts portant désormais leur service identifié.
        ports: Vec<Port>,
        /// Constats tirés des services identifiés (information + clair).
        findings: Vec<Finding>,
        /// Enregistrement d'audit `recon.active`/`ok` à journaliser.
        record: AuditRecord,
    },
    /// Cible **refusée** par le gate : raison typée + audit `blocked_*`. **Aucune
    /// bannière n'est lue** (fail-safe).
    Refused {
        /// Raison typée du refus (première étape §3.2 échouée).
        reason: DenyReason,
        /// Enregistrement d'audit `blocked_<code>`/`blocked` à journaliser.
        record: AuditRecord,
    },
}

impl IdentifyReport {
    /// Vrai si l'identification a été autorisée.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, IdentifyReport::Allowed { .. })
    }

    /// Les ports (enrichis) si autorisé, sinon `None`.
    #[must_use]
    pub fn ports(&self) -> Option<&[Port]> {
        match self {
            IdentifyReport::Allowed { ports, .. } => Some(ports),
            IdentifyReport::Refused { .. } => None,
        }
    }

    /// Les constats produits (vide en cas de refus).
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        match self {
            IdentifyReport::Allowed { findings, .. } => findings,
            IdentifyReport::Refused { .. } => &[],
        }
    }

    /// L'enregistrement d'audit produit (succès **ou** refus).
    #[must_use]
    pub fn record(&self) -> &AuditRecord {
        match self {
            IdentifyReport::Allowed { record, .. } | IdentifyReport::Refused { record, .. } => {
                record
            }
        }
    }
}

/// Identifie les services des ports **ouverts** de `target`, **après vérification
/// par le gate**.
///
/// Déroulé (invariant de sécurité §3.2) :
/// 1. le gate évalue `Action::Recon { target }` (périmètre, fenêtre, attestation,
///    plafonds) ; un refus renvoie [`IdentifyReport::Refused`] **sans lire une
///    seule bannière** et avec son audit `blocked_*` ;
/// 2. si autorisé, chaque port **ouvert en TCP** voit sa bannière lue via le
///    `provider` (recon active confinée : aucune socket n'est ouverte ici),
///    cadencée à `max_rate_pps` via [`RateLimiter`], puis identifiée ;
/// 3. les ports sont renvoyés (ouverts enrichis de leur [`Service`], les autres
///    inchangés), accompagnés des [`Finding`] et de l'audit `recon.active`.
///
/// Les ports fermés/filtrés et les ports UDP ne déclenchent aucune lecture (une
/// bannière TCP n'a pas de sens sur un port UDP) : ils gardent un service déduit
/// du seul port, sans bannière.
pub async fn identify_gated<P>(
    gate: &mut Gate,
    req: &Request<'_>,
    operator: &str,
    provider: &P,
    target: IpAddr,
    ports: &[Port],
    max_rate_pps: u32,
) -> IdentifyReport
where
    P: NetworkProvider + ?Sized,
{
    let action = Action::Recon { target };
    let decision = gate.check(&action, req);
    let record = audit_record(&action, decision, operator, gate.mode());

    if let Decision::Deny(reason) = decision {
        // Fail-safe : aucune bannière n'est lue sur un refus.
        return IdentifyReport::Refused { reason, record };
    }

    let mut limiter = RateLimiter::new(max_rate_pps);
    let mut enriched = Vec::with_capacity(ports.len());
    let mut findings = Vec::new();

    for port in ports {
        if port.state != PortState::Open {
            enriched.push(port.clone());
            continue;
        }

        let service = if port.proto == Proto::Tcp {
            pace(&mut limiter).await;
            // On **consomme** la bannière capturée par le provider (sa socket est
            // la seule voie active) ; une erreur/un silence dégrade proprement.
            let captured = match provider.read_banner(target, port.number).await {
                Ok(Some(service)) => service.banner,
                Ok(None) | Err(_) => None,
            };
            identify_from_text(port.number, captured.as_deref())
        } else {
            identify_from_text(port.number, None)
        };

        findings.extend(service_findings(target, port.number, &service));
        enriched.push(Port {
            service: Some(service),
            ..port.clone()
        });
    }

    enriched.sort_by_key(|port| port.number);
    IdentifyReport::Allowed {
        ports: enriched,
        findings,
        record,
    }
}

/// Attend qu'un jeton de débit se libère (plafonnement `max_rate_pps`), au besoin.
async fn pace(limiter: &mut RateLimiter) {
    if !limiter.is_limited() {
        return;
    }
    while !limiter.try_acquire(Utc::now()) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone};
    use nickmare_core::audit::AuditMode;
    use nickmare_core::gate::Attestation;
    use nickmare_core::model::Host;
    use nickmare_core::scope::Scope;
    use nickmare_core::traits::{NetResult, NetworkProvider};

    const OP: &str = "operateur@example.test";

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    // --- Empreinte sur des bannières réelles --------------------------------

    #[test]
    fn identifie_ssh_produit_et_version() {
        let service = identify_service(22, Some(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1\r\n"));
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(service.version.as_deref(), Some("9.6p1"));
        assert_eq!(
            service.banner.as_deref(),
            Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1")
        );
    }

    #[test]
    fn identifie_ssh_dropbear_sans_version_dediee() {
        let service = identify_service(22, Some(b"SSH-2.0-dropbear_2022.83"));
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product.as_deref(), Some("dropbear"));
        assert_eq!(service.version.as_deref(), Some("2022.83"));
    }

    #[test]
    fn identifie_http_server_header() {
        let service = identify_service(
            80,
            Some(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n"),
        );
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("nginx"));
        assert_eq!(service.version.as_deref(), Some("1.24.0"));
    }

    #[test]
    fn identifie_http_apache_avec_parentheses() {
        let service = identify_service(
            80,
            Some(b"HTTP/1.1 404 Not Found\r\nServer: Apache/2.4.58 (Ubuntu)\r\n\r\n"),
        );
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("Apache"));
        assert_eq!(service.version.as_deref(), Some("2.4.58"));
    }

    #[test]
    fn http_sans_server_header_reste_http_sans_produit() {
        let service = identify_service(80, Some(b"HTTP/1.1 400 Bad Request\r\n\r\n"));
        assert_eq!(service.name, "http");
        // La version de protocole « 1.1 » ne doit JAMAIS être prise pour un produit.
        assert!(service.product.is_none());
        assert!(service.version.is_none());
    }

    #[test]
    fn identifie_ftp_vsftpd() {
        let service = identify_service(21, Some(b"220 (vsFTPd 3.0.5)\r\n"));
        assert_eq!(service.name, "ftp");
        assert_eq!(service.product.as_deref(), Some("vsFTPd"));
        assert_eq!(service.version.as_deref(), Some("3.0.5"));
    }

    #[test]
    fn identifie_ftp_proftpd() {
        let service = identify_service(21, Some(b"220 ProFTPD 1.3.5 Server ready.\r\n"));
        assert_eq!(service.name, "ftp");
        assert_eq!(service.product.as_deref(), Some("ProFTPD"));
        assert_eq!(service.version.as_deref(), Some("1.3.5"));
    }

    #[test]
    fn identifie_smtp_postfix_sans_version() {
        let service = identify_service(25, Some(b"220 mail.example.com ESMTP Postfix\r\n"));
        assert_eq!(service.name, "smtp");
        assert_eq!(service.product.as_deref(), Some("Postfix"));
        assert!(service.version.is_none());
    }

    #[test]
    fn identifie_smtp_exim_par_le_port_meme_sans_mot_cle() {
        // Pas de mot-clé SMTP dans la bannière : le port 25 donne le nom, le scan
        // générique récupère produit + version.
        let service = identify_service(25, Some(b"220 Exim 4.96 ready\r\n"));
        assert_eq!(service.name, "smtp");
        assert_eq!(service.product.as_deref(), Some("Exim"));
        assert_eq!(service.version.as_deref(), Some("4.96"));
    }

    #[test]
    fn identifie_pop3_dovecot() {
        let service = identify_service(110, Some(b"+OK Dovecot ready.\r\n"));
        assert_eq!(service.name, "pop3");
        assert_eq!(service.product.as_deref(), Some("Dovecot"));
    }

    #[test]
    fn identifie_imap_par_salutation() {
        let service = identify_service(143, Some(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n"));
        assert_eq!(service.name, "imap");
    }

    #[test]
    fn port_connu_sans_banniere_donne_le_nom_seul() {
        // Port ouvert mais muet : service nommé par le port, sans produit/version.
        let service = identify_service(3389, None);
        assert_eq!(service.name, "rdp");
        assert!(service.product.is_none());
        assert!(service.banner.is_none());
    }

    #[test]
    fn port_inconnu_sans_signature_est_unknown() {
        let service = identify_service(50_000, None);
        assert_eq!(service.name, "unknown");
    }

    #[test]
    fn banniere_sur_port_atypique_prime_sur_le_port() {
        // Une bannière SSH sur le port 8080 reste identifiée « ssh » (la bannière
        // prime sur le nom usuel du port).
        let service = identify_service(8080, Some(b"SSH-2.0-OpenSSH_8.9\r\n"));
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
    }

    // --- Robustesse : bannières malformées / tronquées (fuzz léger) ---------

    #[test]
    fn bannieres_malformees_ne_paniquent_pas() {
        let cas: &[&[u8]] = &[
            b"",
            b"   \r\n\t  ",
            b"SSH-",
            b"SSH-2.0-",
            b"SSH-2.0",
            b"\xff\xfe\x00\x01binaire",
            b"HTTP/",
            b"Server:",
            b"220",
            b"+OK",
            b"* OK",
            &[0u8; 2048],
            b"version 9.9.9 sans produit evident",
        ];
        for &bytes in cas {
            // Aucune de ces entrées ne doit paniquer, et le port reste nommé.
            let service = identify_service(22, Some(bytes));
            assert!(!service.name.is_empty(), "nom jamais vide pour {bytes:?}");
        }
    }

    #[test]
    fn utf8_invalide_est_decode_sans_panique() {
        let service = identify_service(80, Some(&[0x53, 0x53, 0x48, 0x2d, 0xff, 0xfe, 0x80]));
        // « SSH- » suivi d'octets invalides : décodage lossy, pas de panique.
        assert_eq!(service.name, "ssh");
    }

    #[test]
    fn fuzz_leger_pseudo_aleatoire_ne_panique_jamais() {
        // Générateur congruentiel linéaire déterministe (sans dépendance externe).
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..512 {
            let len = (state % 300) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                bytes.push((state >> 33) as u8);
            }
            let port = (state % 65_536) as u16;
            let service = identify_service(port, Some(bytes.as_slice()));
            // Invariant : jamais de panique, toujours un nom non vide.
            assert!(!service.name.is_empty());
        }
    }

    #[test]
    fn clean_banner_borne_nettoie_et_fusionne_les_espaces() {
        assert!(clean_banner(b"").is_none());
        assert!(clean_banner(b"\r\n\t  ").is_none());
        assert_eq!(
            clean_banner(b"  SSH-2.0-OpenSSH\r\n\r\n").as_deref(),
            Some("SSH-2.0-OpenSSH")
        );
        // Les octets de contrôle internes deviennent un seul espace.
        assert_eq!(clean_banner(b"a\r\n\t\0b").as_deref(), Some("a b"));
        // Bornage : jamais plus de BANNER_TEXT_CAP caractères.
        let long = vec![b'x'; 4096];
        let cleaned = clean_banner(&long).unwrap();
        assert!(cleaned.chars().count() <= BANNER_TEXT_CAP);
    }

    #[test]
    fn well_known_service_couvre_les_ports_usuels() {
        assert_eq!(well_known_service(22), Some("ssh"));
        assert_eq!(well_known_service(443), Some("https"));
        assert_eq!(well_known_service(3306), Some("mysql"));
        assert_eq!(well_known_service(65_000), None);
    }

    // --- Findings -----------------------------------------------------------

    #[test]
    fn findings_decrivent_le_service_et_signalent_le_clair() {
        let service = identify_service(23, Some(b"Welcome to the telnet service\r\n"));
        // Nom déduit du port 23 (pas de signature telnet dédiée).
        assert_eq!(service.name, "telnet");
        let findings = service_findings(ip("192.168.10.5"), 23, &service);
        // Un constat d'information + un constat « en clair » (telnet = Medium).
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("telnet"));
        assert_eq!(findings[0].port, Some(23));
        assert_eq!(findings[1].severity, Severity::Medium);
        assert!(findings[1].title.contains("en clair"));
    }

    #[test]
    fn findings_service_chiffre_ne_signale_pas_le_clair() {
        let service = identify_service(22, Some(b"SSH-2.0-OpenSSH_9.6p1\r\n"));
        let findings = service_findings(ip("192.168.10.5"), 22, &service);
        assert_eq!(
            findings.len(),
            1,
            "ssh chiffré : pas de constat « en clair »"
        );
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].description.contains("OpenSSH"));
        assert!(findings[0].description.contains("9.6p1"));
    }

    // --- Orchestration confinée au gate -------------------------------------

    const SCOPE_TOML: &str = "\
[engagement]
client = \"Lab\"
reference = \"SERVICEID-13\"
authorized_by = \"self\"
operator = \"operateur@example.test\"
valid_from = \"2026-01-01T00:00:00Z\"
valid_until = \"2027-12-31T23:59:59Z\"

[targets]
networks = [\"192.168.10.0/24\"]

[capabilities]
recon = true
";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap()
    }

    fn scope() -> Scope {
        Scope::from_toml(SCOPE_TOML).unwrap()
    }

    fn attest(scope: &Scope) -> Attestation {
        Attestation::for_scope(scope, OP, "192.168.10.0/24")
    }

    fn open_tcp(number: u16) -> Port {
        Port {
            number,
            proto: Proto::Tcp,
            state: PortState::Open,
            service: None,
        }
    }

    /// Provider bouchonné : rejoue des bannières scriptées et **compte** les
    /// lectures (preuve qu'un refus n'en déclenche aucune). Aucune socket.
    #[derive(Debug, Default)]
    struct FakeProvider {
        banners: HashMap<(IpAddr, u16), String>,
        reads: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl NetworkProvider for FakeProvider {
        async fn discover_hosts(&self, _network: &str) -> NetResult<Vec<Host>> {
            Ok(Vec::new())
        }
        async fn scan_ports(&self, _host: IpAddr, _ports: &[u16]) -> NetResult<Vec<Port>> {
            Ok(Vec::new())
        }
        async fn read_banner(&self, host: IpAddr, port: u16) -> NetResult<Option<Service>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            match self.banners.get(&(host, port)) {
                Some(banner) => Ok(Some(Service {
                    name: "raw".to_string(),
                    product: None,
                    version: None,
                    banner: Some(banner.clone()),
                })),
                None => Ok(None),
            }
        }
    }

    #[tokio::test]
    async fn identification_enrichit_les_ports_ouverts_et_produit_des_findings() {
        let target = ip("192.168.10.25");
        let mut banners = HashMap::new();
        banners.insert((target, 22), "SSH-2.0-OpenSSH_9.6p1".to_string());
        let http = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n";
        banners.insert((target, 80), http.to_string());
        let provider = FakeProvider {
            banners,
            reads: Arc::new(AtomicUsize::new(0)),
        };

        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);

        // 22 et 80 ouverts ; 443 fermé (ne doit pas être identifié).
        let ports = vec![
            open_tcp(22),
            open_tcp(80),
            Port {
                number: 443,
                proto: Proto::Tcp,
                state: PortState::Closed,
                service: None,
            },
        ];

        let report = identify_gated(&mut gate, &req, OP, &provider, target, &ports, 0).await;
        let enriched = report.ports().expect("identification autorisée");

        let ssh = enriched.iter().find(|p| p.number == 22).unwrap();
        let ssh_service = ssh.service.as_ref().expect("service ssh identifié");
        assert_eq!(ssh_service.name, "ssh");
        assert_eq!(ssh_service.version.as_deref(), Some("9.6p1"));

        let http = enriched.iter().find(|p| p.number == 80).unwrap();
        assert_eq!(
            http.service.as_ref().unwrap().product.as_deref(),
            Some("nginx")
        );

        // Le port fermé n'est jamais identifié.
        let closed = enriched.iter().find(|p| p.number == 443).unwrap();
        assert!(closed.service.is_none());

        // Des findings sont produits et l'audit est un succès de recon active.
        assert!(!report.findings().is_empty());
        assert_eq!(report.record().action, "recon.active");
        assert_eq!(report.record().result, "ok");
    }

    #[tokio::test]
    async fn negatif_identification_hors_scope_refuse_sans_lire_de_banniere() {
        // §10.4 : cible hors périmètre → refus + audit, AUCUNE bannière lue.
        let reads = Arc::new(AtomicUsize::new(0));
        let provider = FakeProvider {
            banners: HashMap::new(),
            reads: Arc::clone(&reads),
        };
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);

        let ports = vec![open_tcp(22)];
        let report = identify_gated(
            &mut gate,
            &req,
            OP,
            &provider,
            ip("10.0.0.5"), // hors du réseau attesté
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
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "aucune bannière lue sur un refus (fail-safe)"
        );
    }

    #[tokio::test]
    async fn negatif_identification_sans_attestation_refuse() {
        // Sans attestation (étape 8), l'identification est refusée même in-scope.
        let reads = Arc::new(AtomicUsize::new(0));
        let provider = FakeProvider {
            banners: HashMap::new(),
            reads: Arc::clone(&reads),
        };
        let sc = scope();
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP); // sans attestation

        let ports = vec![open_tcp(22)];
        let report = identify_gated(
            &mut gate,
            &req,
            OP,
            &provider,
            ip("192.168.10.25"),
            &ports,
            0,
        )
        .await;
        assert!(!report.is_allowed());
        assert_eq!(report.record().action, "blocked_attestation");
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn port_ouvert_muet_degrade_vers_le_nom_du_port() {
        // Port ouvert sans bannière connue : service nommé par le port, sans panique.
        let target = ip("192.168.10.25");
        let provider = FakeProvider {
            banners: HashMap::new(), // read_banner renverra Ok(None)
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);

        let ports = vec![open_tcp(23)];
        let report = identify_gated(&mut gate, &req, OP, &provider, target, &ports, 0).await;
        let enriched = report.ports().unwrap();
        let telnet = enriched[0].service.as_ref().unwrap();
        assert_eq!(telnet.name, "telnet");
        assert!(telnet.banner.is_none());
    }
}
