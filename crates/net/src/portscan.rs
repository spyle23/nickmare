//! Scan de ports — reconnaissance **active** de niveau 1 (issue #12, cf.
//! `docs/ARCHITECTURE.md` §2 N1, §3.2, §9 Phase 2, US-B2).
//!
//! Ce module couvre les trois techniques de scan du ticket et, surtout, les
//! **confine au gate** : contrairement à la découverte passive (#7, qui ne
//! traverse pas le gate), scanner les ports d'un hôte est une action **active**
//! (`Action::Recon`, cf. `gate.rs`). Toute cible passe donc par
//! [`Gate::check`](nickmare_core::gate::Gate::check) avant la moindre sonde :
//! périmètre, fenêtre, attestation et plafonds s'appliquent, et un refus produit
//! un enregistrement d'audit `blocked_*` sans émettre un seul paquet (fail-safe).
//!
//! # Trois techniques, une seule classification
//!
//! - **TCP connect** ([`ProviderProbe`]) — sans privilège, portable Windows +
//!   Linux. Elle **réutilise** l'implémentation réseau réelle (#8) via le trait
//!   [`NetworkProvider`] : on ne rouvre aucune socket en direct, on délègue au
//!   provider déjà éprouvé. C'est le mode `tcp_connect_only`.
//! - **UDP basique** ([`UdpProbe`]) — sans privilège, portable, via
//!   `std::net::UdpSocket` (testable en loopback).
//! - **SYN demi-ouvert** ([`SynProbe`], **Linux + privilégié**) — construction et
//!   analyse **pures** des segments (testées partout, sans socket), l'émission
//!   brute (`SOCK_RAW`, `IPPROTO_TCP`) étant réservée au labo isolé (§10.3), comme
//!   l'ICMP brut de #8 : ni compilée ni exécutée hors Linux, hors CI.
//!
//! Les trois techniques convergent vers les états [`PortState`] `Open` / `Closed`
//! / `Filtered`, via des fonctions de classification **pures** ([`classify_syn`],
//! [`classify_udp`]) testées sans aucune I/O.
//!
//! # Débit plafonné
//!
//! L'émission des sondes est cadencée par `max_rate_pps` au moyen du **même**
//! seau à jetons que le gate et la découverte ([`RateLimiter`]) — aucune
//! réimplémentation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use nickmare_core::audit::AuditRecord;
use nickmare_core::gate::{audit_record, Action, Decision, DenyReason, Gate, Request};
use nickmare_core::model::{Port, PortState, Proto};
use nickmare_core::traits::NetworkProvider;

use crate::discovery::RateLimiter;
use crate::privilege::Privilege;

/// Délai minimal d'une opération socket : une durée nulle fait échouer
/// `set_read_timeout`. On relève toute valeur nulle à 1 ms (fail-safe, §11.4).
const MIN_TIMEOUT: Duration = Duration::from_millis(1);

/// Charge utile neutre d'une sonde UDP (un service peut n'y jamais répondre : le
/// scan UDP « basique » conclut alors à `open|filtered`).
const UDP_PROBE_PAYLOAD: &[u8] = b"\x00";

/// Borne une durée à au moins [`MIN_TIMEOUT`] (jamais nulle).
fn bounded(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        MIN_TIMEOUT
    } else {
        timeout
    }
}

// --- Drapeaux TCP (octet 13 de l'en-tête) -----------------------------------

/// Drapeau TCP `FIN`.
pub const TCP_FIN: u8 = 0x01;
/// Drapeau TCP `SYN`.
pub const TCP_SYN: u8 = 0x02;
/// Drapeau TCP `RST`.
pub const TCP_RST: u8 = 0x04;
/// Drapeau TCP `ACK`.
pub const TCP_ACK: u8 = 0x10;

// --- Techniques de scan -----------------------------------------------------

/// Technique de scan de ports retenue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTechnique {
    /// TCP connect : sans privilège, portable (le mode `tcp_connect_only`).
    TcpConnect,
    /// TCP SYN demi-ouvert : nécessite `CAP_NET_RAW`/root (Linux, labo).
    Syn,
    /// UDP basique : sans privilège, portable.
    Udp,
}

impl ScanTechnique {
    /// Étiquette stable (traçabilité/audit).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ScanTechnique::TcpConnect => "tcp_connect",
            ScanTechnique::Syn => "syn",
            ScanTechnique::Udp => "udp",
        }
    }
}

/// Choisit la technique effective (**fail-safe**) : le SYN brut n'est retenu que
/// si un privilège brut est présent **et** que le mode `tcp_connect_only` ne
/// l'interdit pas ; sinon on se replie sur le connect scan sans privilège. Le
/// scan UDP et le connect ne demandent jamais de privilège et sont conservés.
///
/// Fonction **pure**, testable sans toucher au système : c'est elle qui garantit
/// que `tcp_connect_only` « fonctionne sans privilèges root/admin » (DoD).
#[must_use]
pub fn choose_technique(
    tcp_connect_only: bool,
    privilege: Privilege,
    requested: ScanTechnique,
) -> ScanTechnique {
    match requested {
        ScanTechnique::Syn => {
            if tcp_connect_only || privilege != Privilege::RawCapable {
                ScanTechnique::TcpConnect
            } else {
                ScanTechnique::Syn
            }
        }
        other => other,
    }
}

// --- Classification des états (pure) ----------------------------------------

/// Verdict d'une sonde SYN demi-ouverte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynResponse {
    /// `SYN/ACK` reçu : le port accepte une connexion → ouvert.
    SynAck,
    /// `RST` reçu : le port est fermé (pile active, port sans service).
    Rst,
    /// Aucune réponse appariée avant le délai : filtré/injoignable.
    NoResponse,
}

/// Classe une réponse SYN en [`PortState`]. **Pure**, testable sans socket.
#[must_use]
pub fn classify_syn(response: SynResponse) -> PortState {
    match response {
        SynResponse::SynAck => PortState::Open,
        SynResponse::Rst => PortState::Closed,
        SynResponse::NoResponse => PortState::Filtered,
    }
}

/// Verdict d'une sonde UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpResponse {
    /// Données reçues en retour : un service répond → ouvert.
    Data,
    /// ICMP *port unreachable* (type 3, code 3) : port fermé.
    PortUnreachable,
    /// Autre ICMP injoignable (admin prohibited…) : filtré.
    OtherUnreachable,
    /// Aucune réponse avant le délai : `open|filtered` (rapporté prudemment).
    NoResponse,
}

/// Classe une réponse UDP en [`PortState`]. **Pure**, testable sans socket.
///
/// L'ambiguïté `open|filtered` de l'UDP (aucune réponse) est tranchée côté
/// **fail-safe** : jamais `Open` sans preuve → `Filtered`.
#[must_use]
pub fn classify_udp(response: UdpResponse) -> PortState {
    match response {
        UdpResponse::Data => PortState::Open,
        UdpResponse::PortUnreachable => PortState::Closed,
        UdpResponse::OtherUnreachable | UdpResponse::NoResponse => PortState::Filtered,
    }
}

// --- Segment TCP (construction / analyse pures) -----------------------------

/// Segment TCP analysé (ports + octet de drapeaux). L'analyse est **défensive**
/// (§12) : les octets reçus du réseau sont hostiles, jamais `unwrap`és.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    /// Port source du segment.
    pub src_port: u16,
    /// Port destination du segment.
    pub dst_port: u16,
    /// Octet de drapeaux (bit à bit : [`TCP_SYN`], [`TCP_RST`]…).
    pub flags: u8,
}

impl TcpSegment {
    /// Vrai si `SYN` **et** `ACK` sont posés (réponse d'un port ouvert).
    #[must_use]
    pub fn is_syn_ack(&self) -> bool {
        self.flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK)
    }

    /// Vrai si `RST` est posé (réponse d'un port fermé).
    #[must_use]
    pub fn is_rst(&self) -> bool {
        self.flags & TCP_RST != 0
    }
}

/// Somme de contrôle TCP : pseudo-en-tête IPv4 + segment, via la somme Internet
/// (RFC 1071, réutilisée de [`crate::icmp::checksum`]). Appliquée à un segment
/// dont le champ de contrôle porte déjà la bonne valeur, elle renvoie `0`.
#[must_use]
pub fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp_segment.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0); // zéro réservé
    buf.push(6); // protocole TCP
    buf.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp_segment);
    crate::icmp::checksum(&buf)
}

/// Construit un segment TCP `SYN` (sans option, 20 octets), somme de contrôle
/// posée. C'est la sonde du scan demi-ouvert. **Pure**, testable sans socket.
#[must_use]
pub fn build_syn_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // numéro d'acquittement
    tcp.push(5 << 4); // offset de données = 5 mots (20 octets), réservé = 0
    tcp.push(TCP_SYN); // drapeaux
    tcp.extend_from_slice(&64_240u16.to_be_bytes()); // fenêtre
    tcp.extend_from_slice(&[0, 0]); // place de la somme de contrôle
    tcp.extend_from_slice(&[0, 0]); // pointeur urgent
    let checksum = tcp_checksum(src_ip, dst_ip, &tcp);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    tcp
}

/// Analyse un paquet IPv4 **brut** (en-tête IP + segment TCP, tel que le livre
/// une socket `SOCK_RAW` en réception) et renvoie le [`TcpSegment`] si c'en est
/// un. Parsing **défensif** (§12) : toute troncature ou tout autre protocole
/// renvoie `None`, jamais de panique.
#[must_use]
pub fn parse_ipv4_tcp_reply(packet: &[u8]) -> Option<TcpSegment> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None; // pas de l'IPv4
    }
    let header_len = usize::from(first & 0x0F) * 4;
    if header_len < 20 {
        return None;
    }
    if *packet.get(9)? != 6 {
        return None; // protocole ≠ TCP
    }
    let tcp = packet.get(header_len..)?;
    if tcp.len() < 20 {
        return None;
    }
    Some(TcpSegment {
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        flags: tcp[13],
    })
}

// --- Ports courants ---------------------------------------------------------

/// Les ports TCP les plus couramment exposés (sous-ensemble représentatif du
/// « top ports » usuel). C'est la liste scannée par défaut quand aucune n'est
/// fournie ; un opérateur peut toujours passer sa propre liste (p. ex. les 1000
/// ports courants complets). Les états de chacun sont rapportés (US-B2).
#[must_use]
#[rustfmt::skip]
pub fn common_tcp_ports() -> &'static [u16] {
    &[
        21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144,
        179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
        873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
        2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
        5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080,
        8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
    ]
}

// --- Abstraction de sonde par port ------------------------------------------

/// Sonde un **port unique** et en renvoie l'état classifié. L'abstraction isole
/// la technique (connect/UDP/SYN) de l'orchestration (gate + cadence) : celle-ci
/// se teste ainsi contre une sonde bouchonnée, **sans aucune socket ni
/// privilège** (exactement comme [`ProbeEmitter`](crate::probe::ProbeEmitter)
/// pour la découverte). Ne doit jamais paniquer ni bloquer indéfiniment (§11.4).
#[async_trait]
pub trait PortProbe: Send + Sync {
    /// Sonde `port` sur `target` et renvoie le [`Port`] classifié.
    async fn scan_port(&self, target: IpAddr, port: u16) -> Port;

    /// Étiquette de la technique employée (traçabilité).
    fn technique(&self) -> &'static str;
}

/// Sonde TCP connect **réutilisant le [`NetworkProvider`] réel** (#8) : chaque
/// port est délégué à `scan_ports`, sans rouvrir de socket en direct. C'est le
/// mode portable, sans privilège (`tcp_connect_only`).
pub struct ProviderProbe<'p, P: NetworkProvider + ?Sized> {
    provider: &'p P,
}

impl<'p, P: NetworkProvider + ?Sized> ProviderProbe<'p, P> {
    /// Sonde adossée au `provider` réseau (réel ou mock).
    #[must_use]
    pub fn new(provider: &'p P) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<P: NetworkProvider + ?Sized> PortProbe for ProviderProbe<'_, P> {
    async fn scan_port(&self, target: IpAddr, port: u16) -> Port {
        match self.provider.scan_ports(target, &[port]).await {
            Ok(ports) => ports
                .into_iter()
                .next()
                .unwrap_or_else(|| filtered(port, Proto::Tcp)),
            // Échec réseau : on ne tranche pas « ouvert/fermé » → filtré (§12).
            Err(_) => filtered(port, Proto::Tcp),
        }
    }

    fn technique(&self) -> &'static str {
        "tcp_connect"
    }
}

/// Sonde UDP basique, **sans privilège** et portable (via `std::net::UdpSocket`).
#[derive(Debug, Clone, Copy)]
pub struct UdpProbe {
    timeout: Duration,
}

impl UdpProbe {
    /// Sonde UDP dont chaque datagramme attend une réponse au plus `timeout`.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl PortProbe for UdpProbe {
    async fn scan_port(&self, target: IpAddr, port: u16) -> Port {
        let addr = SocketAddr::new(target, port);
        let timeout = self.timeout;
        // I/O bloquante bornée déportée hors du runtime async.
        let response = tokio::task::spawn_blocking(move || udp_probe(addr, timeout))
            .await
            .unwrap_or(UdpResponse::NoResponse);
        Port {
            number: port,
            proto: Proto::Udp,
            state: classify_udp(response),
            service: None,
        }
    }

    fn technique(&self) -> &'static str {
        "udp"
    }
}

/// Un [`Port`] filtré (état par défaut prudent quand aucune information n'est
/// obtenue : jamais « ouvert » sans preuve).
fn filtered(port: u16, proto: Proto) -> Port {
    Port {
        number: port,
        proto,
        state: PortState::Filtered,
        service: None,
    }
}

/// Sonde UDP **bloquante bornée** d'un `addr` : connecte une socket éphémère,
/// émet une charge neutre, puis attend une réponse sous `timeout`. Jamais de
/// blocage indéfini (§11.4) ni de panique sur une erreur système.
///
/// - données reçues → [`UdpResponse::Data`] ;
/// - ICMP *port unreachable* (remonté en `ConnectionRefused`/`ConnectionReset`
///   sur une socket connectée) → [`UdpResponse::PortUnreachable`] ;
/// - délai dépassé → [`UdpResponse::NoResponse`] (`open|filtered`).
#[must_use]
pub fn udp_probe(addr: SocketAddr, timeout: Duration) -> UdpResponse {
    use std::io::ErrorKind;
    let bind: SocketAddr = match addr.ip() {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = match UdpSocket::bind(bind) {
        Ok(socket) => socket,
        Err(_) => return UdpResponse::OtherUnreachable,
    };
    if socket.connect(addr).is_err() {
        return UdpResponse::OtherUnreachable;
    }
    if socket.set_read_timeout(Some(bounded(timeout))).is_err() {
        return UdpResponse::OtherUnreachable;
    }
    if let Err(err) = socket.send(UDP_PROBE_PAYLOAD) {
        return udp_error(err.kind());
    }
    let mut buf = [0u8; 512];
    match socket.recv(&mut buf) {
        Ok(_) => UdpResponse::Data,
        Err(err) => match err.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => UdpResponse::NoResponse,
            other => udp_error(other),
        },
    }
}

/// Classe une erreur d'I/O UDP : un refus/reset trahit un ICMP *port
/// unreachable* (port fermé) ; tout le reste est un injoignable indéterminé.
fn udp_error(kind: std::io::ErrorKind) -> UdpResponse {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => UdpResponse::PortUnreachable,
        _ => UdpResponse::OtherUnreachable,
    }
}

// --- Orchestration soumise au gate ------------------------------------------

/// Issue d'un scan de ports **soumis au gate** (§3.2). Dans les deux cas un
/// enregistrement d'audit est produit : le scan ne contourne jamais la
/// traçabilité.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanReport {
    /// Cible autorisée : ports classifiés (triés par numéro) + audit `recon.active`.
    Allowed {
        /// Ports scannés et leur état.
        ports: Vec<Port>,
        /// Enregistrement d'audit `recon.active`/`ok` à journaliser.
        record: AuditRecord,
    },
    /// Cible **refusée** par le gate (hors périmètre, hors fenêtre, attestation
    /// absente…) : raison typée + audit `blocked_*`. **Aucune sonde émise**.
    Refused {
        /// Raison typée du refus (première étape §3.2 échouée).
        reason: DenyReason,
        /// Enregistrement d'audit `blocked_<code>`/`blocked` à journaliser.
        record: AuditRecord,
    },
}

impl ScanReport {
    /// Vrai si le scan a été autorisé.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.ports().is_some()
    }

    /// Les ports scannés si autorisé, sinon `None`.
    #[must_use]
    pub fn ports(&self) -> Option<&[Port]> {
        match self {
            ScanReport::Allowed { ports, .. } => Some(ports),
            ScanReport::Refused { .. } => None,
        }
    }

    /// L'enregistrement d'audit produit (succès **ou** refus) : le scan est
    /// toujours tracé.
    #[must_use]
    pub fn record(&self) -> &AuditRecord {
        match self {
            ScanReport::Allowed { record, .. } | ScanReport::Refused { record, .. } => record,
        }
    }
}

/// Scanne les `ports` de `target` **après vérification par le gate**.
///
/// Déroulé (invariant de sécurité §3.2, §4) :
/// 1. le gate évalue `Action::Recon { target }` (périmètre, fenêtre, capacité,
///    plafonds, attestation) ; un refus renvoie [`ScanReport::Refused`] **sans
///    émettre une seule sonde** et avec son audit `blocked_*` ;
/// 2. si autorisé, les sondes sont émises par `scanner` ([`PortProbe`]), cadencées
///    à `max_rate_pps` via [`RateLimiter`] (débit plafonné, US-B1/B2) ;
/// 3. les ports sont renvoyés triés par numéro, avec l'audit `recon.active`.
///
/// `operator` et le mode du gate alimentent l'enregistrement d'audit. Une liste
/// de ports vide scanne [`common_tcp_ports`].
pub async fn scan_gated<S>(
    gate: &mut Gate,
    req: &Request<'_>,
    operator: &str,
    scanner: &S,
    target: IpAddr,
    ports: &[u16],
    max_rate_pps: u32,
) -> ScanReport
where
    S: PortProbe + ?Sized,
{
    let action = Action::Recon { target };
    let decision = gate.check(&action, req);
    let record = audit_record(&action, decision, operator, gate.mode());

    if let Decision::Deny(reason) = decision {
        // Fail-safe : aucune sonde n'est émise sur un refus.
        return ScanReport::Refused { reason, record };
    }

    let targets: &[u16] = if ports.is_empty() {
        common_tcp_ports()
    } else {
        ports
    };
    let mut limiter = RateLimiter::new(max_rate_pps);
    let mut scanned = Vec::with_capacity(targets.len());
    for &port in targets {
        pace(&mut limiter).await;
        scanned.push(scanner.scan_port(target, port).await);
    }
    scanned.sort_by_key(|port| port.number);
    ScanReport::Allowed {
        ports: scanned,
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

// --- Scan SYN brut (Linux + privilégié, labo isolé) -------------------------

#[cfg(target_os = "linux")]
pub use linux::{SynError, SynProbe};

/// Émission SYN brute — Linux + `CAP_NET_RAW`/root uniquement, réservée au labo
/// isolé (§10.3). La logique sensible (segments) est pure et testée ci-dessus ;
/// ici seule l'émission par socket brute vit, jamais exécutée en CI.
///
/// ⚠ Caveat labo : sur un scan SYN brut, le noyau — qui n'a pas ouvert la
/// connexion — répond un `RST` au `SYN/ACK` de la cible. Un scan SYN fiable
/// suppose donc de **filtrer les RST sortants** (p. ex. `iptables`) dans le labo.
#[cfg(target_os = "linux")]
mod linux {
    use std::fmt;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};
    use std::os::unix::io::RawFd;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;

    use nickmare_core::model::{Port, Proto};

    use super::{build_syn_segment, classify_syn, parse_ipv4_tcp_reply, PortProbe, SynResponse};

    /// Séquence initiale arbitraire des sondes SYN (le scan n'ouvre jamais la
    /// connexion, la valeur exacte importe peu).
    const SYN_SEQ: u32 = 0x4E49_434B;

    /// Erreur d'une opération SYN brute.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SynError {
        /// Privilège insuffisant (`EPERM`) : ni `CAP_NET_RAW` ni root.
        InsufficientPrivilege,
        /// Autre erreur socket, message tracé.
        Socket(String),
    }

    impl fmt::Display for SynError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                SynError::InsufficientPrivilege => write!(
                    f,
                    "privilège insuffisant pour une socket TCP brute (CAP_NET_RAW requis)"
                ),
                SynError::Socket(msg) => write!(f, "erreur de socket SYN : {msg}"),
            }
        }
    }

    impl std::error::Error for SynError {}

    /// Socket TCP brute (`AF_INET`, `SOCK_RAW`, `IPPROTO_TCP`). Descripteur fermé
    /// en `Drop` (teardown garanti, §11.1).
    #[derive(Debug)]
    struct RawTcpSocket {
        fd: RawFd,
    }

    impl RawTcpSocket {
        /// Ouvre la socket brute. [`SynError::InsufficientPrivilege`] si le noyau
        /// refuse par `EPERM` (message clair, jamais de panique).
        fn open() -> Result<Self, SynError> {
            // SAFETY: socket(2) n'alloue qu'un descripteur, sans autre effet.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
            if fd >= 0 {
                return Ok(Self { fd });
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                Err(SynError::InsufficientPrivilege)
            } else {
                Err(SynError::Socket(err.to_string()))
            }
        }

        /// Borne la réception par `SO_RCVTIMEO` (§11.4 : aucune lecture infinie).
        fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
            let tv = libc::timeval {
                tv_sec: timeout.as_secs() as libc::time_t,
                tv_usec: timeout.subsec_micros() as libc::suseconds_t,
            };
            // SAFETY: SO_RCVTIMEO attend un `timeval` ; taille fournie exacte.
            let rc = unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    std::ptr::addr_of!(tv).cast::<libc::c_void>(),
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Émet un segment TCP déjà encodé vers `target` (le noyau ajoute l'en-tête
        /// IP ; le port de `sockaddr_in` est ignoré pour une socket brute).
        fn send_to(&self, target: Ipv4Addr, segment: &[u8]) -> io::Result<()> {
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from(target).to_be(),
            };
            // SAFETY: envoi vers un sockaddr_in valide, longueur exacte fournie.
            let sent = unsafe {
                libc::sendto(
                    self.fd,
                    segment.as_ptr().cast::<libc::c_void>(),
                    segment.len(),
                    0,
                    std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Reçoit un paquet (en-tête IP + TCP), borné par `set_read_timeout`.
        fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let ptr = buf.as_mut_ptr().cast::<libc::c_void>();
            let len = buf.len();
            // SAFETY: recv écrit au plus `len` octets dans `buf`.
            let received = unsafe { libc::recv(self.fd, ptr, len, 0) };
            if received < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(received as usize)
        }
    }

    impl Drop for RawTcpSocket {
        fn drop(&mut self) {
            // SAFETY: on ferme le descripteur que nous possédons (teardown RAII).
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    /// Vrai si l'erreur d'I/O est un dépassement de délai de lecture.
    fn is_timeout(err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        )
    }

    /// Détermine l'IP source locale vers `target` sans émettre de paquet (une
    /// `connect` UDP ne fait que fixer le pair par défaut) : nécessaire à la somme
    /// de contrôle du segment SYN.
    fn local_source_ipv4(target: Ipv4Addr) -> Option<Ipv4Addr> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        socket.connect((target, 9)).ok()?;
        match socket.local_addr().ok()?.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }

    /// Un échange SYN borné : émet un `SYN` vers `target:dst_port` et renvoie le
    /// verdict ([`SynResponse`]), bornée par `read_timeout`.
    fn scan_once(
        src_ip: Ipv4Addr,
        target: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        read_timeout: Duration,
    ) -> Result<SynResponse, SynError> {
        let socket = RawTcpSocket::open()?;
        socket
            .set_read_timeout(read_timeout)
            .map_err(|e| SynError::Socket(e.to_string()))?;
        let segment = build_syn_segment(src_ip, target, src_port, dst_port, SYN_SEQ);
        socket
            .send_to(target, &segment)
            .map_err(|e| SynError::Socket(e.to_string()))?;

        let deadline = Instant::now() + read_timeout;
        let mut buf = [0u8; 1500];
        loop {
            if Instant::now() >= deadline {
                return Ok(SynResponse::NoResponse);
            }
            match socket.recv(&mut buf) {
                Ok(received) => {
                    if let Some(seg) = parse_ipv4_tcp_reply(&buf[..received]) {
                        // Apparie la réponse à notre sonde (ports croisés).
                        if seg.src_port == dst_port && seg.dst_port == src_port {
                            if seg.is_syn_ack() {
                                return Ok(SynResponse::SynAck);
                            }
                            if seg.is_rst() {
                                return Ok(SynResponse::Rst);
                            }
                        }
                    }
                    // Paquet non apparié : on poursuit jusqu'au délai.
                }
                Err(err) if is_timeout(&err) => return Ok(SynResponse::NoResponse),
                Err(err) => return Err(SynError::Socket(err.to_string())),
            }
        }
    }

    /// Sonde SYN demi-ouverte (mode privilégié, labo). Chaque port émet un `SYN`
    /// et attend une réponse au plus `read_timeout`.
    #[derive(Debug, Clone, Copy)]
    pub struct SynProbe {
        read_timeout: Duration,
    }

    impl SynProbe {
        /// Sonde SYN dont chaque segment attend une réponse au plus `read_timeout`.
        #[must_use]
        pub fn new(read_timeout: Duration) -> Self {
            Self { read_timeout }
        }

        /// Port source éphémère stable pour ce processus (plage haute).
        fn source_port() -> u16 {
            40_000 + (std::process::id() % 20_000) as u16
        }
    }

    #[async_trait]
    impl PortProbe for SynProbe {
        async fn scan_port(&self, target: IpAddr, port: u16) -> Port {
            let IpAddr::V4(v4) = target else {
                // SYN brut IPv4 uniquement : on ne tranche pas → filtré.
                return super::filtered(port, Proto::Tcp);
            };
            let read_timeout = self.read_timeout;
            let src_port = Self::source_port();
            let task = tokio::task::spawn_blocking(move || match local_source_ipv4(v4) {
                Some(src_ip) => scan_once(src_ip, v4, src_port, port, read_timeout),
                None => Ok(SynResponse::NoResponse),
            });
            let state = match task.await {
                Ok(Ok(response)) => classify_syn(response),
                // Socket en échec (privilège, réseau) ou tâche interrompue : on ne
                // tranche pas → filtré, jamais de panique propagée.
                _ => return super::filtered(port, Proto::Tcp),
            };
            Port {
                number: port,
                proto: Proto::Tcp,
                state,
                service: None,
            }
        }

        fn technique(&self) -> &'static str {
            "syn"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use chrono::{DateTime, TimeZone};
    use nickmare_core::audit::AuditMode;
    use nickmare_core::gate::Attestation;
    use nickmare_core::scope::Scope;
    use nickmare_core::traits::{MockNetworkProvider, MockScenario};

    const OP: &str = "operateur@example.test";

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap()
    }

    /// Scope de session minimal : un réseau attesté, seule la recon activée,
    /// débit par défaut illimité (surchargeable via `with_rate`).
    const SCOPE_TOML: &str = "\
[engagement]
client = \"Lab\"
reference = \"PORTSCAN-12\"
authorized_by = \"self\"
operator = \"operateur@example.test\"
valid_from = \"2026-01-01T00:00:00Z\"
valid_until = \"2027-12-31T23:59:59Z\"

[targets]
networks = [\"192.168.10.0/24\"]

[capabilities]
recon = true
";

    fn scope() -> Scope {
        Scope::from_toml(SCOPE_TOML).unwrap()
    }

    fn scope_with_rate(pps: u32) -> Scope {
        let toml = SCOPE_TOML.replace(
            "[targets]",
            &format!("[constraints]\nmax_rate_pps = {pps}\n\n[targets]"),
        );
        Scope::from_toml(&toml).unwrap()
    }

    fn attest(scope: &Scope) -> Attestation {
        Attestation::for_scope(scope, OP, "192.168.10.0/24")
    }

    // --- Sonde bouchonnée : aucun socket, verdicts scriptés + comptage --------

    #[derive(Debug, Default)]
    struct FakeProbe {
        states: HashMap<u16, PortState>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl PortProbe for FakeProbe {
        async fn scan_port(&self, _target: IpAddr, port: u16) -> Port {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Port {
                number: port,
                proto: Proto::Tcp,
                state: self
                    .states
                    .get(&port)
                    .copied()
                    .unwrap_or(PortState::Filtered),
                service: None,
            }
        }
        fn technique(&self) -> &'static str {
            "fake"
        }
    }

    // --- Classification pure --------------------------------------------------

    #[test]
    fn classification_syn_couvre_les_trois_etats() {
        assert_eq!(classify_syn(SynResponse::SynAck), PortState::Open);
        assert_eq!(classify_syn(SynResponse::Rst), PortState::Closed);
        assert_eq!(classify_syn(SynResponse::NoResponse), PortState::Filtered);
    }

    #[test]
    fn classification_udp_couvre_les_trois_etats() {
        assert_eq!(classify_udp(UdpResponse::Data), PortState::Open);
        assert_eq!(
            classify_udp(UdpResponse::PortUnreachable),
            PortState::Closed
        );
        // open|filtered et autre injoignable : prudemment filtrés (fail-safe).
        assert_eq!(classify_udp(UdpResponse::NoResponse), PortState::Filtered);
        assert_eq!(
            classify_udp(UdpResponse::OtherUnreachable),
            PortState::Filtered
        );
    }

    // --- Choix de technique (tcp_connect_only, privilège) ---------------------

    #[test]
    fn syn_exige_privilege_et_absence_de_tcp_connect_only() {
        // SYN demandé + privilège brut + mode normal → SYN retenu.
        assert_eq!(
            choose_technique(false, Privilege::RawCapable, ScanTechnique::Syn),
            ScanTechnique::Syn
        );
        // tcp_connect_only force le repli connect, même privilégié (DoD).
        assert_eq!(
            choose_technique(true, Privilege::RawCapable, ScanTechnique::Syn),
            ScanTechnique::TcpConnect
        );
        // Sans privilège brut, repli connect (fonctionne sans root/admin).
        assert_eq!(
            choose_technique(false, Privilege::Unprivileged, ScanTechnique::Syn),
            ScanTechnique::TcpConnect
        );
        // Connect et UDP ne requièrent aucun privilège : conservés tels quels.
        assert_eq!(
            choose_technique(true, Privilege::Unprivileged, ScanTechnique::Udp),
            ScanTechnique::Udp
        );
        assert_eq!(
            choose_technique(false, Privilege::Unprivileged, ScanTechnique::TcpConnect),
            ScanTechnique::TcpConnect
        );
    }

    // --- Segment TCP (construction / analyse pures) ---------------------------

    #[test]
    fn syn_segment_bien_forme_et_somme_valide() {
        let src = Ipv4Addr::new(192, 168, 10, 2);
        let dst = Ipv4Addr::new(192, 168, 10, 25);
        let segment = build_syn_segment(src, dst, 40_000, 443, 0x1234_5678);
        assert_eq!(segment.len(), 20);
        assert_eq!(&segment[0..2], &40_000u16.to_be_bytes()); // port source
        assert_eq!(&segment[2..4], &443u16.to_be_bytes()); // port destination
        assert_eq!(segment[12] >> 4, 5); // offset de données = 5 mots
        assert_eq!(segment[13], TCP_SYN); // seul SYN posé
        assert_eq!(tcp_checksum(src, dst, &segment), 0); // somme déjà posée → 0 (RFC 1071)
    }

    #[test]
    fn analyse_une_reponse_syn_ack_et_un_rst() {
        // En-tête IPv4 minimal (version 4, IHL 5 → 20 octets), protocole TCP (6).
        let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 0, 6];
        packet.extend_from_slice(&[0u8; 10]); // reste de l'en-tête IP (20 octets)
        packet.extend_from_slice(&443u16.to_be_bytes()); // port source (la cible)
        packet.extend_from_slice(&40_000u16.to_be_bytes()); // port destination
        packet.extend_from_slice(&[0u8; 8]); // seq + ack
        packet.push(5 << 4); // offset
        packet.push(TCP_SYN | TCP_ACK); // drapeaux
        packet.extend_from_slice(&[0u8; 6]); // fenêtre + somme + urgent
        let seg = parse_ipv4_tcp_reply(&packet).expect("segment TCP");
        assert_eq!(seg.src_port, 443);
        assert_eq!(seg.dst_port, 40_000);
        assert!(seg.is_syn_ack());
        assert!(!seg.is_rst());
        assert_eq!(classify_syn(SynResponse::SynAck), PortState::Open);

        // Même segment mais drapeau RST → port fermé.
        let mut rst = packet.clone();
        rst[33] = TCP_RST; // octet de drapeaux (20 IP + 13)
        let seg = parse_ipv4_tcp_reply(&rst).expect("segment TCP");
        assert!(seg.is_rst());
        assert!(!seg.is_syn_ack());
    }

    #[test]
    fn analyse_tcp_defensive_sans_panique() {
        assert!(parse_ipv4_tcp_reply(&[]).is_none());
        assert!(parse_ipv4_tcp_reply(&[0x45]).is_none()); // paquet tronqué
        let mut udp = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 0, 17]; // octet 9 = 17 → UDP, pas TCP
        udp.extend_from_slice(&[0u8; 30]);
        assert!(parse_ipv4_tcp_reply(&udp).is_none());
    }

    // --- Ports courants -------------------------------------------------------

    #[test]
    fn ports_courants_non_vides_et_tries_sans_doublon() {
        let ports = common_tcp_ports();
        assert!(ports.len() > 50, "liste de ports courants substantielle");
        assert!(ports.contains(&22) && ports.contains(&443) && ports.contains(&3389));
        // Strictement croissante (triée, sans doublon) : facilite la lecture.
        assert!(ports.windows(2).all(|w| w[0] < w[1]));
    }

    // --- Orchestration : le gate confine le scan ------------------------------

    #[tokio::test]
    async fn scan_in_scope_autorise_et_classe_les_ports() {
        // Mock : 22 ouvert, 80 fermé ; 443 inconnu → filtré (défaut prudent).
        let mut scenario = MockScenario::default();
        scenario.ports_by_host.insert(
            ip("192.168.10.25"),
            vec![
                Port {
                    number: 22,
                    proto: Proto::Tcp,
                    state: PortState::Open,
                    service: None,
                },
                Port {
                    number: 80,
                    proto: Proto::Tcp,
                    state: PortState::Closed,
                    service: None,
                },
            ],
        );
        let provider = MockNetworkProvider::new(scenario);
        let probe = ProviderProbe::new(&provider);

        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);

        let report = scan_gated(
            &mut gate,
            &req,
            OP,
            &probe,
            ip("192.168.10.25"),
            &[80, 22, 443],
            0,
        )
        .await;

        let ports = report.ports().expect("scan autorisé");
        // Triés par numéro et classifiés dans les trois états.
        assert_eq!(ports[0].number, 22);
        assert_eq!(ports[0].state, PortState::Open);
        assert_eq!(ports[1].number, 80);
        assert_eq!(ports[1].state, PortState::Closed);
        assert_eq!(ports[2].number, 443);
        assert_eq!(ports[2].state, PortState::Filtered);
        // Audit de succès.
        assert_eq!(report.record().action, "recon.active");
        assert_eq!(report.record().result, "ok");
    }

    #[tokio::test]
    async fn negatif_scan_hors_scope_refuse_et_audite_sans_sonder() {
        // §10.4 : scanner un hôte HORS périmètre → refus + audit, aucune sonde.
        let calls = Arc::new(AtomicUsize::new(0));
        let probe = FakeProbe {
            states: HashMap::new(),
            calls: Arc::clone(&calls),
        };
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);

        let report = scan_gated(
            &mut gate,
            &req,
            OP,
            &probe,
            ip("10.0.0.5"), // hors du réseau attesté
            &[22, 80],
            0,
        )
        .await;

        match report {
            ScanReport::Refused { reason, record } => {
                assert_eq!(reason, DenyReason::OutOfScope);
                assert_eq!(record.action, "blocked_target");
                assert_eq!(record.result, "blocked");
                assert_eq!(record.target, "10.0.0.5");
            }
            ScanReport::Allowed { .. } => panic!("un hôte hors scope ne doit pas être scanné"),
        }
        // Invariant central : aucune sonde émise sur un refus.
        assert_eq!(calls.load(Ordering::SeqCst), 0, "aucune sonde sur refus");
    }

    #[tokio::test]
    async fn negatif_scan_sans_attestation_refuse() {
        // §10.4 : sans attestation (étape 8), le scan est refusé même in-scope.
        let calls = Arc::new(AtomicUsize::new(0));
        let probe = FakeProbe {
            states: HashMap::new(),
            calls: Arc::clone(&calls),
        };
        let sc = scope();
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP); // sans attestation

        let report = scan_gated(&mut gate, &req, OP, &probe, ip("192.168.10.25"), &[22], 0).await;
        assert!(!report.is_allowed(), "sans attestation : refus attendu");
        assert_eq!(report.record().action, "blocked_attestation");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scan_respecte_le_plafond_de_debit() {
        // Débit 2 pps : le 3e port au même instant épuise le seau du gate à
        // l'étape 7 — preuve que le scan consomme un jeton d'action plafonné.
        let sc = scope_with_rate(2);
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);
        let provider = MockNetworkProvider::default();
        let probe = ProviderProbe::new(&provider);

        // Trois scans distincts au même instant : les deux premiers passent, le
        // troisième est refusé pour dépassement de débit (max_rate_pps).
        let target = ip("192.168.10.25");
        let first = scan_gated(&mut gate, &req, OP, &probe, target, &[22], 2).await;
        assert!(first.is_allowed(), "1er scan admis");
        let second = scan_gated(&mut gate, &req, OP, &probe, target, &[22], 2).await;
        assert!(second.is_allowed(), "2e scan admis");
        let third = scan_gated(&mut gate, &req, OP, &probe, target, &[22], 2).await;
        assert!(!third.is_allowed(), "3e scan au même débit : refusé");
        assert_eq!(third.record().action, "blocked_rate");
    }

    #[tokio::test]
    async fn liste_vide_scanne_les_ports_courants() {
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);
        let provider = MockNetworkProvider::default();
        let probe = ProviderProbe::new(&provider);

        let report = scan_gated(&mut gate, &req, OP, &probe, ip("192.168.10.25"), &[], 0).await;
        let ports = report.ports().expect("scan autorisé");
        assert_eq!(ports.len(), common_tcp_ports().len());
    }

    #[tokio::test]
    async fn scan_mille_ports_produit_les_trois_etats() {
        // US-B2 : scanner un millier de ports et les classifier Open/Closed/Filtered.
        let mut states = HashMap::new();
        let mut requested = Vec::with_capacity(1000);
        for port in 1u16..=1000 {
            requested.push(port);
            let state = match port % 3 {
                0 => PortState::Open,
                1 => PortState::Closed,
                _ => PortState::Filtered,
            };
            states.insert(port, state);
        }
        let probe = FakeProbe {
            states,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let sc = scope();
        let att = attest(&sc);
        let mut gate = Gate::with_scope(sc, AuditMode::Standard);
        let req = Request::new(now(), OP).with_attestation(&att);

        let report = scan_gated(
            &mut gate,
            &req,
            OP,
            &probe,
            ip("192.168.10.25"),
            &requested,
            0,
        )
        .await;
        let ports = report.ports().expect("scan autorisé");
        assert_eq!(ports.len(), 1000);
        assert!(ports.iter().any(|p| p.state == PortState::Open));
        assert!(ports.iter().any(|p| p.state == PortState::Closed));
        assert!(ports.iter().any(|p| p.state == PortState::Filtered));
    }

    // --- Sonde UDP portable (loopback, sans privilège) ------------------------

    #[test]
    fn udp_port_ferme_en_loopback_nest_jamais_ouvert() {
        // Un port UDP loopback non lié : ICMP port unreachable (Closed) sous Unix,
        // ou pas de réponse (Filtered) selon l'OS. Ce qui compte et reste
        // portable : il n'est jamais vu « ouvert ».
        let port = {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        };
        let addr = SocketAddr::new(ip("127.0.0.1"), port);
        let response = udp_probe(addr, Duration::from_millis(200));
        assert_ne!(classify_udp(response), PortState::Open);
    }
}
