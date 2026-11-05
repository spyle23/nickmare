//! Énumération réelle des interfaces réseau locales (#8).
//!
//! C'est l'entrée réelle qui alimente la logique **pure** de listing des réseaux
//! à portée livrée par #7 ([`crate::discovery::reachable_networks`]) : on ne
//! réimplémente rien, on branche seulement la découverte système des interfaces
//! derrière elle.
//!
//! Linux d'abord (via `getifaddrs`, cf. ticket « Linux d'abord ») ; sur les autres
//! plateformes, l'énumération renvoie [`InterfaceError::Unsupported`] — proprement,
//! sans panique (Windows via Npcap suivra).

use std::fmt;

use crate::discovery::{reachable_networks, LocalInterface, ReachableNetwork};

/// Erreur d'énumération des interfaces. Jamais de panique : toute défaillance
/// système est remontée ici (§11.4, §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceError {
    /// Énumération non implémentée sur cette plateforme (hors Linux pour l'instant).
    Unsupported,
    /// Échec de l'appel système d'énumération, message tracé.
    Enumeration(String),
}

impl fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterfaceError::Unsupported => {
                write!(f, "énumération d'interfaces non supportée sur cette plateforme")
            }
            InterfaceError::Enumeration(msg) => {
                write!(f, "échec d'énumération des interfaces : {msg}")
            }
        }
    }
}

impl std::error::Error for InterfaceError {}

/// Énumère les interfaces IPv4 locales (Linux, via `getifaddrs`).
///
/// # Erreurs
///
/// [`InterfaceError::Enumeration`] si l'appel système échoue.
#[cfg(target_os = "linux")]
pub fn enumerate_interfaces() -> Result<Vec<LocalInterface>, InterfaceError> {
    use std::ffi::CStr;
    use std::net::{IpAddr, Ipv4Addr};

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs alloue une liste chaînée, libérée plus bas par freeifaddrs.
    let rc = unsafe { libc::getifaddrs(&mut head) };
    if rc != 0 {
        return Err(InterfaceError::Enumeration(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    let mut out = Vec::new();
    let mut cursor = head;
    // SAFETY: on suit la liste jusqu'au pointeur nul fourni par la libc ; chaque
    // nœud reste valide tant que `head` n'est pas libéré.
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;

        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr pointe un sockaddr valide ; on ne lit que sa famille.
        let family = unsafe { (*entry.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET {
            continue; // IPv6 et couche liaison : hors de ce ticket (ARP est IPv4).
        }

        // SAFETY: la famille AF_INET garantit un sockaddr_in derrière ifa_addr.
        let sockaddr = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
        let ip = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));

        let prefix = if entry.ifa_netmask.is_null() {
            32
        } else {
            // SAFETY: quand présent, le masque est lui aussi un sockaddr_in.
            let mask = unsafe { &*entry.ifa_netmask.cast::<libc::sockaddr_in>() };
            u32::from_be(mask.sin_addr.s_addr).count_ones() as u8
        };

        // SAFETY: ifa_name est une chaîne C terminée par un octet nul.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();

        out.push(LocalInterface {
            name,
            ip: IpAddr::V4(ip),
            prefix,
        });
    }

    // SAFETY: libère la liste allouée par getifaddrs (teardown, §11.1).
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Énumère les interfaces (plateformes hors Linux) : non supporté pour l'instant.
///
/// # Erreurs
///
/// Toujours [`InterfaceError::Unsupported`] (Windows via Npcap arrivera).
#[cfg(not(target_os = "linux"))]
pub fn enumerate_interfaces() -> Result<Vec<LocalInterface>, InterfaceError> {
    Err(InterfaceError::Unsupported)
}

/// Réseaux filaires **à portée**, déduits des interfaces réelles : branche
/// l'énumération système sur la logique pure de #7 (loopback / lien-local / IPv6
/// écartés, doublons fusionnés). Strictement passif, sans scope ni gate (§3.0).
///
/// # Erreurs
///
/// Propage l'erreur de [`enumerate_interfaces`].
pub fn reachable_from_system() -> Result<Vec<ReachableNetwork>, InterfaceError> {
    Ok(reachable_networks(&enumerate_interfaces()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn enumere_au_moins_la_loopback_sous_linux() {
        use std::net::IpAddr;
        let ifaces = enumerate_interfaces().expect("énumération Linux");
        // Tout hôte Linux possède au moins l'interface loopback 127.0.0.1.
        let loopback = IpAddr::from([127, 0, 0, 1]);
        let has_loopback = ifaces.iter().any(|iface| iface.ip == loopback);
        assert!(has_loopback, "la loopback doit figurer parmi {ifaces:?}");

        // Le listing à portée écarte justement la loopback (logique pure de #7).
        let reachable = reachable_from_system().expect("listing à portée");
        let none_loopback = reachable.iter().all(|net| !net.cidr.starts_with("127."));
        assert!(none_loopback);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn hors_linux_non_supporte_sans_paniquer() {
        assert_eq!(enumerate_interfaces(), Err(InterfaceError::Unsupported));
        assert_eq!(reachable_from_system(), Err(InterfaceError::Unsupported));
    }

    #[test]
    fn message_d_erreur_lisible() {
        assert!(!InterfaceError::Unsupported.to_string().is_empty());
        let enum_err = InterfaceError::Enumeration("boom".into());
        assert!(enum_err.to_string().contains("boom"));
    }
}
