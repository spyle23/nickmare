//! Implémentation **réelle** du trait [`NetworkProvider`] (#8, cf.
//! `docs/ARCHITECTURE.md` §4, §5, §9 Phase 1, §11.4).
//!
//! `RealNetworkProvider` est l'exact pendant de `MockNetworkProvider` : même
//! trait, donc **interchangeable** (DoD). Il choisit sa stratégie d'émission selon
//! les privilèges détectés ([`crate::privilege`]) — ARP/ICMP brut si `CAP_NET_RAW`,
//! sinon repli `tcp_connect_only` sans root — et borne **chaque** opération réseau
//! par un timeout (§11.4). L'émission de sondes passe par l'abstraction
//! [`ProbeEmitter`] : la découverte se teste ainsi contre un émetteur bouchonné,
//! sans socket ni privilège.
//!
//! Il ne réimplémente **aucune** logique pure déjà livrée par #7 : énumération des
//! cibles ([`enumerate_hosts`]) et plafonnement de débit ([`RateLimiter`]) sont
//! réutilisés tels quels.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use nickmare_core::model::{Host, HostRole, Port, PortState, Proto, Service};
use nickmare_core::traits::{NetError, NetResult, NetworkProvider};

use crate::discovery::{enumerate_hosts, RateLimiter};
use crate::privilege::{detect_privilege, ProbeStrategy};
use crate::probe::{ProbeEmitter, ProbeOutcome, TcpConnectEmitter};
use crate::tcp::{self, BannerOutcome, TcpConnectResult};

/// Ports sondés par défaut pour conclure à la présence d'un hôte (repli TCP).
const DEFAULT_PROBE_PORTS: [u16; 3] = [80, 443, 22];
/// Ports scannés par défaut quand aucune liste n'est fournie à `scan_ports`.
const DEFAULT_SCAN_PORTS: [u16; 8] = [21, 22, 23, 25, 80, 443, 445, 3389];
/// Nombre maximal de sondes de découverte en vol simultanément (borne mémoire/charge).
const DISCOVERY_CONCURRENCY: usize = 64;
/// Plafond d'octets lus pour une bannière (une entrée hostile ne gonfle pas la RAM).
const BANNER_CAP: usize = 512;

/// Délais **bornés** de chaque opération réseau (§11.4 : aucune opération sans
/// timeout). Les valeurs nulles sont relevées par la couche transport ([`crate::tcp`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Délai d'établissement d'une connexion / d'attente d'une réponse de sonde.
    pub connect: Duration,
    /// Délai de lecture d'une bannière une fois connecté.
    pub read: Duration,
}

impl Timeouts {
    /// Délais bornés à l'intervalle `[1 ms, 30 s]` (fail-safe : ni nul ni infini).
    #[must_use]
    pub fn new(connect: Duration, read: Duration) -> Self {
        const MIN: Duration = Duration::from_millis(1);
        const MAX: Duration = Duration::from_secs(30);
        Self {
            connect: connect.clamp(MIN, MAX),
            read: read.clamp(MIN, MAX),
        }
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self::new(Duration::from_secs(2), Duration::from_secs(2))
    }
}

/// Implémentation réseau réelle du [`NetworkProvider`].
pub struct RealNetworkProvider {
    emitter: Arc<dyn ProbeEmitter>,
    timeouts: Timeouts,
    scan_ports: Vec<u16>,
    max_rate_pps: u32,
    strategy: ProbeStrategy,
}

impl RealNetworkProvider {
    /// Provider en mode dégradé **sans privilège** (`tcp_connect_only`), sans
    /// aucune I/O à la construction (pur, pour être `Default`).
    #[must_use]
    pub fn new() -> Self {
        let timeouts = Timeouts::default();
        Self {
            emitter: tcp_emitter(timeouts),
            timeouts,
            scan_ports: DEFAULT_SCAN_PORTS.to_vec(),
            max_rate_pps: 0,
            strategy: ProbeStrategy::TcpConnect,
        }
    }

    /// Provider **détectant les privilèges** : sondes ARP/ICMP si `CAP_NET_RAW`
    /// (Linux), sinon repli `tcp_connect_only`. Cf. [`crate::privilege`].
    #[must_use]
    pub fn autodetect() -> Self {
        let mut provider = Self::new();
        provider.strategy = detect_privilege().strategy();
        provider.emitter = select_emitter(provider.strategy, provider.timeouts);
        provider
    }

    /// Fixe les délais bornés des opérations de scan/lecture.
    #[must_use]
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Fixe le débit plafond des sondes de découverte (`0` = illimité).
    #[must_use]
    pub fn with_rate(mut self, max_rate_pps: u32) -> Self {
        self.max_rate_pps = max_rate_pps;
        self
    }

    /// Remplace la liste de ports scannés par défaut.
    #[must_use]
    pub fn with_scan_ports(mut self, ports: Vec<u16>) -> Self {
        self.scan_ports = ports;
        self
    }

    /// Injecte un émetteur de sondes (teste la découverte sans socket réelle).
    #[must_use]
    pub fn with_emitter(mut self, emitter: Arc<dyn ProbeEmitter>) -> Self {
        self.emitter = emitter;
        self
    }

    /// Stratégie d'émission retenue.
    #[must_use]
    pub fn strategy(&self) -> ProbeStrategy {
        self.strategy
    }

    /// Étiquette du mode d'émission effectif (traçabilité).
    #[must_use]
    pub fn emitter_kind(&self) -> &'static str {
        self.emitter.kind()
    }
}

impl Default for RealNetworkProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Construit l'émetteur correspondant à la stratégie et aux délais.
fn select_emitter(strategy: ProbeStrategy, timeouts: Timeouts) -> Arc<dyn ProbeEmitter> {
    match strategy {
        ProbeStrategy::TcpConnect => tcp_emitter(timeouts),
        ProbeStrategy::Raw => raw_emitter(timeouts),
    }
}

/// Émetteur de repli TCP-connect (sans privilège, portable).
fn tcp_emitter(timeouts: Timeouts) -> Arc<dyn ProbeEmitter> {
    Arc::new(TcpConnectEmitter::new(
        DEFAULT_PROBE_PORTS.to_vec(),
        timeouts.connect,
    ))
}

/// Émetteur brut (ICMP) — Linux uniquement.
#[cfg(target_os = "linux")]
fn raw_emitter(timeouts: Timeouts) -> Arc<dyn ProbeEmitter> {
    Arc::new(crate::icmp::IcmpEmitter::new(timeouts.read))
}

/// Hors Linux, aucun chemin brut : repli `tcp_connect_only` (fail-safe).
#[cfg(not(target_os = "linux"))]
fn raw_emitter(timeouts: Timeouts) -> Arc<dyn ProbeEmitter> {
    tcp_emitter(timeouts)
}

/// Attend qu'un jeton de débit se libère (plafonnement US-B1), au besoin.
async fn pace(limiter: &mut RateLimiter) {
    if !limiter.is_limited() {
        return;
    }
    while !limiter.try_acquire(Utc::now()) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Hôte tout juste découvert (IP + horodatage ; MAC/rôle enrichis plus tard).
fn host_seen(ip: IpAddr) -> Host {
    Host {
        ip,
        mac: None,
        hostname: None,
        os_guess: None,
        ports: Vec::new(),
        role: HostRole::Unknown,
        compromised: false,
        first_seen: Utc::now(),
    }
}

/// Nom de service usuel d'un port (identification fine : Phase 3).
fn service_name_for_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        3306 => "mysql",
        3389 => "rdp",
        _ => "unknown",
    }
}

/// Construit un `Service` à partir d'une bannière éventuelle (texte nettoyé,
/// borné). Les octets réseau sont traités comme hostiles (§12) : décodage lossy.
fn service_from_banner(port: u16, banner: Option<Vec<u8>>) -> Service {
    let banner_text = banner.and_then(|bytes| {
        let decoded = String::from_utf8_lossy(&bytes);
        let cleaned: String = decoded.trim().chars().take(256).collect();
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    });
    Service {
        name: service_name_for_port(port).to_string(),
        product: None,
        version: None,
        banner: banner_text,
    }
}

#[async_trait]
impl NetworkProvider for RealNetworkProvider {
    async fn discover_hosts(&self, network: &str) -> NetResult<Vec<Host>> {
        // Réutilise l'énumération pure de #7 (CIDR → cibles). Entrée invalide →
        // erreur propre, jamais de panique.
        let targets = enumerate_hosts(network).map_err(|err| NetError::Other(err.to_string()))?;
        let mut limiter = RateLimiter::new(self.max_rate_pps);
        let mut found: Vec<Host> = Vec::new();

        for chunk in targets.chunks(DISCOVERY_CONCURRENCY) {
            let mut set = tokio::task::JoinSet::new();
            for &ip in chunk {
                pace(&mut limiter).await;
                let emitter = Arc::clone(&self.emitter);
                set.spawn(async move { (ip, emitter.probe(ip).await) });
            }
            while let Some(joined) = set.join_next().await {
                if let Ok((ip, ProbeOutcome::Alive)) = joined {
                    found.push(host_seen(ip));
                }
            }
        }

        found.sort_by_key(|host| host.ip);
        Ok(found)
    }

    async fn scan_ports(&self, host: IpAddr, ports: &[u16]) -> NetResult<Vec<Port>> {
        let targets: Vec<u16> = if ports.is_empty() {
            self.scan_ports.clone()
        } else {
            ports.to_vec()
        };
        let timeouts = self.timeouts;
        let mut out = Vec::with_capacity(targets.len());
        for port in targets {
            let addr = SocketAddr::new(host, port);
            let task = tokio::task::spawn_blocking(move || tcp::connect(addr, timeouts.connect));
            let state = match task.await {
                Ok(TcpConnectResult::Connected) => PortState::Open,
                Ok(TcpConnectResult::Refused) => PortState::Closed,
                // Timeout, échec système ou tâche interrompue : on ne tranche pas
                // « ouvert/fermé » → filtré (jamais de panique).
                Ok(TcpConnectResult::TimedOut | TcpConnectResult::Failed(_)) | Err(_) => {
                    PortState::Filtered
                }
            };
            out.push(Port {
                number: port,
                proto: Proto::Tcp,
                state,
                service: None,
            });
        }
        Ok(out)
    }

    async fn read_banner(&self, host: IpAddr, port: u16) -> NetResult<Option<Service>> {
        let addr = SocketAddr::new(host, port);
        let timeouts = self.timeouts;
        let task = tokio::task::spawn_blocking(move || {
            tcp::read_banner(addr, timeouts.connect, timeouts.read, BANNER_CAP)
        });
        let outcome = match task.await {
            Ok(outcome) => outcome,
            Err(err) => return Err(NetError::Other(format!("tâche interrompue : {err}"))),
        };

        match outcome {
            BannerOutcome::Read(bytes) => Ok(Some(service_from_banner(port, Some(bytes)))),
            // Port ouvert mais muet : le service existe, sans bannière capturée.
            BannerOutcome::Silent => Ok(Some(service_from_banner(port, None))),
            BannerOutcome::Refused => Ok(None),
            BannerOutcome::TimedOut => Err(NetError::Timeout),
            BannerOutcome::Failed(msg) => Err(NetError::Other(msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Émetteur bouchonné : rejoue des verdicts scriptés, sans aucune socket.
    #[derive(Debug, Default)]
    struct FakeEmitter {
        verdicts: HashMap<IpAddr, ProbeOutcome>,
    }

    #[async_trait]
    impl ProbeEmitter for FakeEmitter {
        async fn probe(&self, target: IpAddr) -> ProbeOutcome {
            let outcome = self.verdicts.get(&target).copied();
            outcome.unwrap_or(ProbeOutcome::Unreachable)
        }
        fn kind(&self) -> &'static str {
            "fake"
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn timeouts_bornes_jamais_nuls_ni_infinis() {
        let t = Timeouts::new(Duration::ZERO, Duration::from_secs(600));
        assert_eq!(t.connect, Duration::from_millis(1));
        assert_eq!(t.read, Duration::from_secs(30));
    }

    #[test]
    fn construction_par_defaut_est_degradee_et_sans_io() {
        let provider = RealNetworkProvider::new();
        assert_eq!(provider.strategy(), ProbeStrategy::TcpConnect);
        assert_eq!(provider.emitter_kind(), "tcp_connect_only");
    }

    #[tokio::test]
    async fn decouverte_contre_un_emetteur_bouchonne() {
        let mut verdicts = HashMap::new();
        verdicts.insert(ip("192.168.1.1"), ProbeOutcome::Alive);
        verdicts.insert(ip("192.168.1.2"), ProbeOutcome::Unreachable);
        verdicts.insert(ip("192.168.1.3"), ProbeOutcome::Alive);
        let emitter = Arc::new(FakeEmitter { verdicts });
        let provider = RealNetworkProvider::new().with_emitter(emitter);

        let hosts = provider.discover_hosts("192.168.1.0/24").await.unwrap();
        // Seuls les hôtes « vivants » sont retenus, triés par IP.
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip, ip("192.168.1.1"));
        assert_eq!(hosts[1].ip, ip("192.168.1.3"));
        assert!(hosts[0].mac.is_none(), "pas de MAC en mode TCP dégradé");
    }

    #[tokio::test]
    async fn reseau_invalide_refuse_sans_paniquer() {
        let provider = RealNetworkProvider::new();
        let err = provider.discover_hosts("pas-un-cidr").await.unwrap_err();
        assert!(matches!(err, NetError::Other(_)));
        // Réseau trop vaste pour un sweep : refus propre (logique pure de #7).
        assert!(provider.discover_hosts("10.0.0.0/8").await.is_err());
    }

    #[test]
    fn service_depuis_banniere_nettoie_et_borne() {
        let service = service_from_banner(22, Some(b"  SSH-2.0-OpenSSH_9.6\r\n".to_vec()));
        assert_eq!(service.name, "ssh");
        assert_eq!(service.banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
        // Port ouvert mais muet : service nommé, sans bannière.
        let silent = service_from_banner(80, None);
        assert_eq!(silent.name, "http");
        assert!(silent.banner.is_none());
        // Bannière vide après nettoyage → aucune bannière.
        let blank = service_from_banner(443, Some(b"   \r\n".to_vec()));
        assert!(blank.banner.is_none());
    }
}
