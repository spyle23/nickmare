//! Découverte réseau — reconnaissance **passive** de niveau 1 (issue #7, cf.
//! `docs/ARCHITECTURE.md` §2 N1, §3.0/§3.2, §9 Phase 1, US-A0/US-B1).
//!
//! Ce module couvre deux volets de la recon passive :
//!
//! 1. **Listing des réseaux à portée** ([`reachable_networks`]) — les
//!    sous-réseaux filaires joignables, déduits des interfaces locales (le
//!    listing WiFi est traité en Phase 4).
//! 2. **Découverte d'hôtes** ([`discover`], [`discover_map`]) — ARP sweep sur un
//!    `/24` + ping ICMP, exposée derrière le trait [`NetworkProvider`] : en CI,
//!    on la teste contre `MockNetworkProvider`, sans aucune socket réelle.
//!
//! # Strictement passif, sans scope, sans gate
//!
//! Lister les réseaux/hôtes **à portée** est de l'observation passive : cela ne
//! traverse **pas** le gate (§3.0/§3.2, seule exception documentée) et ne demande
//! **aucun** périmètre établi (US-A0). Aucune action active n'est déclenchée ici.
//!
//! # Débit plafonné (`max_rate_pps`)
//!
//! Même passive, l'émission des sondes ARP/ICMP est bornée par `max_rate_pps`
//! (US-B1). Le plafonnement s'appuie sur le **même** seau à jetons que le gate
//! (`nickmare_core::rate::TokenBucket`), via [`RateLimiter`] — aucune
//! réimplémentation. [`Discovery::sweep_duration`] en déduit, de façon
//! déterministe, la durée d'un sweep (un `/24` tient largement sous 10 s).
//!
//! # Frontière avec l'implémentation réelle (issue #8)
//!
//! L'émission réelle des trames ARP/ICMP et l'énumération des interfaces via les
//! sockets du système arrivent avec l'implémentation réelle du `NetworkProvider`
//! (#8, Linux d'abord). Ici, toute la **logique** — calcul CIDR, plafonnement,
//! construction de la carte — est pure et testable sans réseau ni privilèges.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use chrono::{DateTime, Utc};

use nickmare_core::model::{Host, NetworkMap};
use nickmare_core::rate::TokenBucket;
use nickmare_core::traits::{NetResult, NetworkProvider};

/// Préfixe le plus large accepté pour un *sweep* d'hôtes. Énumérer un réseau
/// plus vaste qu'un `/16` (≥ 65 534 hôtes) n'a pas de sens pour un ARP sweep et
/// exposerait à une explosion mémoire sur une entrée hostile ou erronée : par
/// **fail-safe** (§1, §12), on refuse plutôt que d'énumérer l'injustifiable.
const MIN_SWEEP_PREFIX: u8 = 16;

// --- Erreurs ----------------------------------------------------------------

/// Erreur de la logique de découverte. Les entrées (CIDR, interfaces) peuvent
/// être malformées ou hostiles (§12) : on les refuse proprement, jamais de
/// panique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// CIDR illisible (ni `adresse/longueur`, ou adresse invalide).
    InvalidCidr(String),
    /// Famille d'adresse non gérée pour un sweep (ARP est IPv4 ; IPv6 → #8+).
    UnsupportedFamily(String),
    /// Longueur de préfixe hors de `0..=32`.
    PrefixTooLarge(u8),
    /// Réseau trop vaste pour un sweep raisonnable (préfixe < [`MIN_SWEEP_PREFIX`]).
    NetworkTooLarge(u8),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::InvalidCidr(cidr) => write!(f, "CIDR invalide : {cidr}"),
            DiscoveryError::UnsupportedFamily(cidr) => {
                write!(f, "adresse non-IPv4 pour un sweep : {cidr}")
            }
            DiscoveryError::PrefixTooLarge(prefix) => {
                write!(f, "préfixe invalide : /{prefix} (> /32)")
            }
            DiscoveryError::NetworkTooLarge(prefix) => {
                write!(f, "réseau trop vaste pour un sweep : /{prefix}")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

// --- Listing des réseaux filaires à portée ----------------------------------

/// Interface réseau locale observée (recon passive). L'énumération réelle des
/// interfaces du système arrive avec #8 ; ce type est l'entrée pure de la
/// logique de listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInterface {
    /// Nom système (`eth0`, `Ethernet`…).
    pub name: String,
    /// Adresse portée par l'interface.
    pub ip: IpAddr,
    /// Longueur de préfixe du réseau directement connecté (`24` pour un `/24`).
    pub prefix: u8,
}

impl LocalInterface {
    /// Interface IPv4 (raccourci de construction).
    #[must_use]
    pub fn v4(name: impl Into<String>, ip: Ipv4Addr, prefix: u8) -> Self {
        Self {
            name: name.into(),
            ip: IpAddr::V4(ip),
            prefix,
        }
    }
}

/// Un sous-réseau filaire joignable, déduit d'une interface locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachableNetwork {
    /// Interface par laquelle le réseau est joignable.
    pub interface: String,
    /// Sous-réseau en notation CIDR (`192.168.1.0/24`).
    pub cidr: String,
}

/// Liste les sous-réseaux filaires **joignables** à partir des interfaces
/// locales (`recon networks`, US-A0). Strictement passif : simple déduction à
/// partir des adresses d'interface, aucune émission.
///
/// Sont ignorés : loopback, adresse non spécifiée, lien-local, préfixe absurde,
/// et IPv4 uniquement (le WiFi et l'IPv6 viennent plus tard). Les doublons de
/// sous-réseau sont fusionnés (première interface gagnante), en préservant
/// l'ordre d'apparition.
#[must_use]
pub fn reachable_networks(interfaces: &[LocalInterface]) -> Vec<ReachableNetwork> {
    let mut out: Vec<ReachableNetwork> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for iface in interfaces {
        let IpAddr::V4(v4) = iface.ip else {
            continue; // IPv6 : hors de ce ticket (ARP est IPv4).
        };
        if v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() {
            continue;
        }
        if iface.prefix == 0 || iface.prefix > 32 {
            continue;
        }
        let base = u32::from(v4) & mask_v4(iface.prefix);
        let cidr = format!("{}/{}", Ipv4Addr::from(base), iface.prefix);
        if seen.insert(cidr.clone()) {
            out.push(ReachableNetwork {
                interface: iface.name.clone(),
                cidr,
            });
        }
    }
    out
}

// --- Énumération des cibles d'un sweep (calcul CIDR pur) ---------------------

/// Énumère les adresses d'hôtes d'un CIDR IPv4 — les cibles d'un ARP sweep.
///
/// L'adresse réseau et l'adresse de diffusion sont exclues pour les préfixes
/// `≤ /30` ; un `/31` renvoie ses deux adresses (RFC 3021) et un `/32` l'adresse
/// seule. Un `/24` donne donc exactement 254 hôtes (`.1`…`.254`). L'entrée est
/// normalisée sur l'adresse réseau : `192.168.1.42/24` et `192.168.1.0/24`
/// énumèrent la même plage.
///
/// # Erreurs
///
/// [`DiscoveryError`] si le CIDR est illisible, IPv6, de préfixe invalide, ou
/// trop vaste pour un sweep (cf. [`MIN_SWEEP_PREFIX`]).
pub fn enumerate_hosts(cidr: &str) -> Result<Vec<IpAddr>, DiscoveryError> {
    let (base, prefix) = parse_cidr_v4(cidr)?;
    if prefix < MIN_SWEEP_PREFIX {
        return Err(DiscoveryError::NetworkTooLarge(prefix));
    }
    let base = u32::from(base);
    let addresses: Vec<u32> = match prefix {
        32 => vec![base],
        31 => vec![base, base + 1],
        _ => {
            let total: u32 = 1u32 << (32 - u32::from(prefix));
            // Exclut l'adresse réseau (base) et la diffusion (base + total - 1).
            (1..total - 1).map(|offset| base + offset).collect()
        }
    };
    Ok(addresses
        .into_iter()
        .map(|addr| IpAddr::V4(Ipv4Addr::from(addr)))
        .collect())
}

/// Parse `adresse/longueur` IPv4 et renvoie `(adresse réseau normalisée, préfixe)`.
/// Parsing défensif (§12) : toute entrée malformée est refusée, jamais de panique.
fn parse_cidr_v4(cidr: &str) -> Result<(Ipv4Addr, u8), DiscoveryError> {
    let Some((addr, prefix)) = cidr.split_once('/') else {
        return Err(DiscoveryError::InvalidCidr(cidr.to_string()));
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return Err(DiscoveryError::InvalidCidr(cidr.to_string()));
    };
    if prefix > 32 {
        return Err(DiscoveryError::PrefixTooLarge(prefix));
    }
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return Err(DiscoveryError::InvalidCidr(cidr.to_string()));
    };
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err(DiscoveryError::UnsupportedFamily(cidr.to_string())),
    };
    let base = Ipv4Addr::from(u32::from(v4) & mask_v4(prefix));
    Ok((base, prefix))
}

/// Masque réseau IPv4 pour une longueur de préfixe `0..=32`.
fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

// --- Limitation de débit (réutilise le seau du gate) ------------------------

/// Limiteur de débit des sondes de découverte, bâti sur le **même** seau à
/// jetons que le gate (`nickmare_core::rate::TokenBucket`). Un débit de `0` =
/// aucune limite (toute sonde est admise), cohérent avec la convention du gate.
///
/// Déterministe vis-à-vis de l'instant fourni : testable sans horloge réelle.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    bucket: Option<TokenBucket>,
    max_rate_pps: u32,
}

impl RateLimiter {
    /// Limiteur pour un débit de `max_rate_pps` sondes/seconde (`0` = illimité).
    #[must_use]
    pub fn new(max_rate_pps: u32) -> Self {
        let bucket = match max_rate_pps {
            0 => None,
            pps => Some(TokenBucket::new(pps)),
        };
        Self {
            bucket,
            max_rate_pps,
        }
    }

    /// Vrai si un plafond de débit est effectivement appliqué.
    #[must_use]
    pub fn is_limited(&self) -> bool {
        self.bucket.is_some()
    }

    /// Tente d'émettre une sonde à l'instant `now` : consomme un jeton et renvoie
    /// `true` s'il en restait, `false` si le débit est saturé (sonde à différer).
    pub fn try_acquire(&mut self, now: DateTime<Utc>) -> bool {
        match self.bucket.as_mut() {
            None => true,
            Some(bucket) => {
                if bucket.available(now) {
                    bucket.consume(now);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Durée déterministe pour émettre `probe_count` sondes à ce débit (cf.
    /// [`sweep_duration`]).
    #[must_use]
    pub fn sweep_duration(&self, probe_count: usize) -> Duration {
        sweep_duration(probe_count, self.max_rate_pps)
    }
}

/// Durée pour émettre `probe_count` sondes au débit `max_rate_pps`, seau plein au
/// départ (capacité = débit). Le premier lot de `max_rate_pps` sondes part sans
/// attendre ; le reste est cadencé au débit. `0` pps (illimité) ⇒ durée nulle.
///
/// C'est la traduction directe du modèle du seau à jetons, sans horloge réelle :
/// elle sert à prouver qu'un `/24` (254 hôtes) reste très en-deçà des 10 s de
/// l'US-B1, quel que soit un débit raisonnable.
#[must_use]
pub fn sweep_duration(probe_count: usize, max_rate_pps: u32) -> Duration {
    if max_rate_pps == 0 || probe_count == 0 {
        return Duration::ZERO;
    }
    let capacity = max_rate_pps as usize;
    if probe_count <= capacity {
        Duration::ZERO
    } else {
        let paced = (probe_count - capacity) as f64;
        Duration::from_secs_f64(paced / f64::from(max_rate_pps))
    }
}

// --- Orchestration de la découverte (contre un NetworkProvider) -------------

/// Paramètres d'un sweep de découverte : le débit plafond. Fournit la
/// planification (cibles, durée) et le limiteur associé. L'exécution réelle du
/// sweep s'appuie sur un [`NetworkProvider`] via [`discover`]/[`discover_map`].
#[derive(Debug, Clone)]
pub struct Discovery {
    max_rate_pps: u32,
}

impl Discovery {
    /// Découverte plafonnée à `max_rate_pps` sondes/seconde (`0` = illimité).
    #[must_use]
    pub fn new(max_rate_pps: u32) -> Self {
        Self { max_rate_pps }
    }

    /// Découverte sans limite de débit (`max_rate_pps = 0`).
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Débit plafond configuré (pps ; `0` = illimité).
    #[must_use]
    pub fn max_rate_pps(&self) -> u32 {
        self.max_rate_pps
    }

    /// Limiteur de débit neuf (seau plein) pour ce débit.
    #[must_use]
    pub fn limiter(&self) -> RateLimiter {
        RateLimiter::new(self.max_rate_pps)
    }

    /// Cibles du sweep ARP pour un CIDR (cf. [`enumerate_hosts`]).
    ///
    /// # Erreurs
    ///
    /// Propage [`DiscoveryError`] si le CIDR est invalide ou trop vaste.
    pub fn sweep_targets(&self, cidr: &str) -> Result<Vec<IpAddr>, DiscoveryError> {
        enumerate_hosts(cidr)
    }

    /// Durée déterministe du sweep ARP du CIDR à ce débit.
    ///
    /// # Erreurs
    ///
    /// Propage [`DiscoveryError`] si le CIDR est invalide ou trop vaste.
    pub fn sweep_duration(&self, cidr: &str) -> Result<Duration, DiscoveryError> {
        Ok(sweep_duration(enumerate_hosts(cidr)?.len(), self.max_rate_pps))
    }
}

/// Découvre les hôtes actifs d'un réseau via le `provider` (ARP/ICMP sous le
/// capot ; `MockNetworkProvider` en test), triés par adresse pour un résultat
/// déterministe. Passif : aucun scope, aucun gate.
///
/// # Erreurs
///
/// Propage l'erreur réseau du provider ([`NetError`](nickmare_core::traits::NetError)).
pub async fn discover<P>(provider: &P, network: &str) -> NetResult<Vec<Host>>
where
    P: NetworkProvider + ?Sized,
{
    let mut hosts = provider.discover_hosts(network).await?;
    hosts.sort_by_key(|host| host.ip);
    Ok(hosts)
}

/// Découvre les hôtes et en construit la [`NetworkMap`] (IP + MAC alimentant la
/// carte). La carte ne porte encore aucun pivot (N2, Phase 6).
///
/// # Erreurs
///
/// Propage l'erreur réseau du provider.
pub async fn discover_map<P>(provider: &P, network: &str) -> NetResult<NetworkMap>
where
    P: NetworkProvider + ?Sized,
{
    let hosts = discover(provider, network).await?;
    Ok(build_map(network, hosts))
}

/// Construit une [`NetworkMap`] à partir d'hôtes découverts (sans pivot).
#[must_use]
pub fn build_map(network: &str, hosts: Vec<Host>) -> NetworkMap {
    NetworkMap {
        scope_network: network.to_string(),
        hosts,
        pivots: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(addr: &str) -> Ipv4Addr {
        addr.parse().unwrap()
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    // --- Énumération CIDR ---------------------------------------------------

    #[test]
    fn slash24_donne_254_hotes_sans_reseau_ni_diffusion() {
        let hosts = enumerate_hosts("192.168.1.0/24").unwrap();
        assert_eq!(hosts.len(), 254, "un /24 = 254 hôtes utilisables");
        assert_eq!(hosts[0], ip("192.168.1.1"));
        assert_eq!(hosts[253], ip("192.168.1.254"));
        assert!(!hosts.contains(&ip("192.168.1.0")), "adresse réseau exclue");
        assert!(
            !hosts.contains(&ip("192.168.1.255")),
            "adresse de diffusion exclue"
        );
    }

    #[test]
    fn adresse_hote_est_normalisee_sur_le_reseau() {
        // Donner une adresse d'hôte plutôt que l'adresse réseau énumère la même
        // plage (on masque les bits hôte).
        let depuis_hote = enumerate_hosts("192.168.1.42/24").unwrap();
        let depuis_reseau = enumerate_hosts("192.168.1.0/24").unwrap();
        assert_eq!(depuis_hote, depuis_reseau);
    }

    #[test]
    fn prefixes_etroits_slash30_slash31_slash32() {
        assert_eq!(enumerate_hosts("10.0.0.0/30").unwrap().len(), 2);
        // /31 (RFC 3021) : les deux adresses sont utilisables.
        assert_eq!(
            enumerate_hosts("10.0.0.0/31").unwrap(),
            vec![ip("10.0.0.0"), ip("10.0.0.1")]
        );
        // /32 : un seul hôte.
        assert_eq!(
            enumerate_hosts("10.0.0.5/32").unwrap(),
            vec![ip("10.0.0.5")]
        );
    }

    #[test]
    fn cidr_invalide_refuse_sans_paniquer() {
        assert_eq!(
            enumerate_hosts("pas-un-cidr"),
            Err(DiscoveryError::InvalidCidr("pas-un-cidr".to_string()))
        );
        assert_eq!(
            enumerate_hosts("192.168.1.0"),
            Err(DiscoveryError::InvalidCidr("192.168.1.0".to_string()))
        );
        assert_eq!(
            enumerate_hosts("192.168.1.0/40"),
            Err(DiscoveryError::PrefixTooLarge(40))
        );
    }

    #[test]
    fn ipv6_non_gere_pour_un_sweep() {
        let err = enumerate_hosts("2001:db8::/64").unwrap_err();
        assert!(matches!(err, DiscoveryError::UnsupportedFamily(_)));
    }

    #[test]
    fn reseau_trop_vaste_refuse() {
        // Un /8 (~16 M d'adresses) n'est pas un sweep raisonnable → refus.
        assert_eq!(
            enumerate_hosts("10.0.0.0/8"),
            Err(DiscoveryError::NetworkTooLarge(8))
        );
    }

    // --- Listing des réseaux à portée ---------------------------------------

    #[test]
    fn reachable_filtre_loopback_et_derive_le_cidr() {
        let ifaces = vec![
            LocalInterface::v4("lo", v4("127.0.0.1"), 8),
            LocalInterface::v4("eth0", v4("192.168.1.42"), 24),
            LocalInterface::v4("eth1", v4("10.20.30.40"), 16),
            LocalInterface::v4("eth2", v4("169.254.1.1"), 16), // lien-local
            LocalInterface {
                name: "wg0".to_string(),
                ip: ip("fe80::1"),
                prefix: 64,
            }, // IPv6
        ];
        let nets = reachable_networks(&ifaces);
        assert_eq!(nets.len(), 2, "loopback, lien-local et IPv6 écartés");
        assert_eq!(nets[0].cidr, "192.168.1.0/24");
        assert_eq!(nets[0].interface, "eth0");
        assert_eq!(nets[1].cidr, "10.20.0.0/16");
    }

    #[test]
    fn reachable_fusionne_les_sous_reseaux_dupliques() {
        let ifaces = vec![
            LocalInterface::v4("eth0", v4("192.168.1.10"), 24),
            LocalInterface::v4("eth1", v4("192.168.1.20"), 24), // même sous-réseau
        ];
        let nets = reachable_networks(&ifaces);
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].interface, "eth0", "première interface gagnante");
    }

    // --- Limitation de débit (vérifiable au seau à jetons) ------------------

    #[test]
    fn limiteur_plafonne_puis_recharge() {
        // Débit 2 pps, seau plein : deux sondes au même instant, la 3e refusée,
        // puis rechargement au fil du temps.
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.is_limited());
        let now = t0();
        assert!(limiter.try_acquire(now));
        assert!(limiter.try_acquire(now));
        assert!(!limiter.try_acquire(now), "débit saturé au même instant");
        // Une seconde plus tard, le seau s'est rempli (2 pps).
        let later = now + chrono::TimeDelta::seconds(1);
        assert!(limiter.try_acquire(later));
        assert!(limiter.try_acquire(later));
        assert!(!limiter.try_acquire(later));
    }

    #[test]
    fn debit_zero_est_illimite() {
        let mut limiter = RateLimiter::new(0);
        assert!(!limiter.is_limited());
        let now = t0();
        for _ in 0..1000 {
            assert!(limiter.try_acquire(now), "illimité : toujours admis");
        }
    }

    // --- Durée de sweep (US-B1 : /24 < 10 s) --------------------------------

    #[test]
    fn sweep_dun_slash24_tient_largement_sous_10s() {
        // À 200 pps (débit par défaut de l'exemple de scope §3.1), un /24 est
        // balayé en une fraction de seconde.
        let d = Discovery::new(200);
        let duree = d.sweep_duration("192.168.1.0/24").unwrap();
        assert!(duree < Duration::from_secs(10), "sweep /24 = {duree:?}");
        // Même à un débit prudent de 50 pps, on reste sous 10 s.
        assert!(sweep_duration(254, 50) < Duration::from_secs(10));
    }

    #[test]
    fn sweep_duration_suit_le_modele_du_seau() {
        // Illimité ⇒ nul.
        assert_eq!(sweep_duration(254, 0), Duration::ZERO);
        // Tout tient dans le seau plein (count ≤ capacité) ⇒ nul.
        assert_eq!(sweep_duration(10, 10), Duration::ZERO);
        assert_eq!(sweep_duration(300, 300), Duration::ZERO);
        // Au-delà : (count − capacité) / débit secondes.
        assert_eq!(sweep_duration(11, 10), Duration::from_secs_f64(0.1));
        assert_eq!(sweep_duration(5, 2), Duration::from_secs_f64(1.5));
    }

    #[test]
    fn discovery_expose_les_cibles_du_sweep() {
        let d = Discovery::new(200);
        assert_eq!(d.max_rate_pps(), 200);
        assert_eq!(d.sweep_targets("192.168.1.0/24").unwrap().len(), 254);
        assert!(d.limiter().is_limited());
        let illimite = Discovery::unlimited().sweep_duration("192.168.1.0/24");
        assert_eq!(illimite.unwrap(), Duration::ZERO);
    }

    #[test]
    fn build_map_porte_le_reseau_et_aucun_pivot() {
        let map = build_map("192.168.1.0/24", Vec::new());
        assert_eq!(map.scope_network, "192.168.1.0/24");
        assert!(map.hosts.is_empty());
        assert!(map.pivots.is_empty());
    }
}
