//! ICMP écho (« ping ») — construction/analyse **pures** des paquets et émission
//! brute Linux (#8, cf. `docs/ARCHITECTURE.md` §5, §12).
//!
//! La logique sensible — somme de contrôle, encodage de la requête, analyse
//! défensive d'une réponse — est **pure** et testée sur toutes les plateformes,
//! sans aucune socket (§10.1, §12 : les octets reçus du réseau sont hostiles). La
//! socket brute (`SOCK_RAW`, `IPPROTO_ICMP`) qui émet réellement ces octets est
//! **Linux + privilégiée** : elle n'est ni compilée ni exécutée hors Linux, et
//! son usage réel relève du labo isolé (§10.3), pas de la CI.

/// Type ICMP d'une requête d'écho.
pub const ICMP_ECHO_REQUEST: u8 = 8;
/// Type ICMP d'une réponse d'écho.
pub const ICMP_ECHO_REPLY: u8 = 0;

/// Somme de contrôle Internet (RFC 1071) sur un tampon d'octets. Le repli des
/// retenues est fait en entier puis complémenté : appliquée à un paquet dont le
/// champ de contrôle est déjà posé, elle renvoie `0`.
#[must_use]
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut pairs = data.chunks_exact(2);
    for pair in &mut pairs {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = pairs.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Construit une requête d'écho ICMP (type 8) avec identifiant, numéro de séquence
/// et charge utile, somme de contrôle posée.
#[must_use]
pub fn build_echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.push(ICMP_ECHO_REQUEST);
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // place de la somme de contrôle
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(payload);
    let checksum = checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Réponse d'écho ICMP analysée (identifiant + séquence, pour apparier la requête).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoReply {
    /// Identifiant renvoyé (doit correspondre à celui émis).
    pub identifier: u16,
    /// Numéro de séquence renvoyé.
    pub sequence: u16,
}

/// Analyse un paquet IPv4 **brut** (en-tête IP + message ICMP, tel que le livre une
/// socket `SOCK_RAW` en réception) et renvoie la réponse d'écho si c'en est une.
///
/// Parsing **défensif** (§12) : toute troncature ou tout autre type renvoie `None`,
/// jamais de panique sur une entrée hostile.
#[must_use]
pub fn parse_ipv4_echo_reply(packet: &[u8]) -> Option<EchoReply> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None; // pas de l'IPv4
    }
    let header_len = usize::from(first & 0x0F) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    let icmp = &packet[header_len..];
    if icmp[0] != ICMP_ECHO_REPLY || icmp[1] != 0 {
        return None;
    }
    Some(EchoReply {
        identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
        sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
    })
}

#[cfg(target_os = "linux")]
pub use linux::{IcmpEmitter, IcmpError, IcmpSocket};

/// Émission ICMP brute — Linux + `CAP_NET_RAW` uniquement.
#[cfg(target_os = "linux")]
mod linux {
    use std::fmt;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::io::RawFd;
    use std::time::Duration;

    use async_trait::async_trait;

    use super::{build_echo_request, parse_ipv4_echo_reply};
    use crate::probe::{ProbeEmitter, ProbeOutcome};

    /// Erreur d'une opération ICMP brute.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum IcmpError {
        /// Privilège insuffisant (`EPERM`) : pas de `CAP_NET_RAW` ni de root.
        InsufficientPrivilege,
        /// Autre erreur socket, message tracé.
        Socket(String),
    }

    impl fmt::Display for IcmpError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                IcmpError::InsufficientPrivilege => write!(
                    f,
                    "privilège insuffisant pour une socket ICMP brute (CAP_NET_RAW requis)"
                ),
                IcmpError::Socket(msg) => write!(f, "erreur de socket ICMP : {msg}"),
            }
        }
    }

    impl std::error::Error for IcmpError {}

    /// Socket ICMP brute (`AF_INET`, `SOCK_RAW`, `IPPROTO_ICMP`). Le descripteur
    /// est fermé en `Drop` (teardown garanti, §11.1).
    #[derive(Debug)]
    pub struct IcmpSocket {
        fd: RawFd,
    }

    impl IcmpSocket {
        /// Ouvre la socket brute. Renvoie [`IcmpError::InsufficientPrivilege`] si le
        /// noyau refuse par `EPERM` (message clair, jamais de panique — DoD).
        pub fn open() -> Result<Self, IcmpError> {
            // SAFETY: socket(2) n'alloue qu'un descripteur, sans autre effet.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
            if fd >= 0 {
                return Ok(Self { fd });
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                Err(IcmpError::InsufficientPrivilege)
            } else {
                Err(IcmpError::Socket(err.to_string()))
            }
        }

        /// Borne la réception par `SO_RCVTIMEO` (§11.4 : aucune lecture infinie).
        pub fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
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

        /// Émet un paquet ICMP déjà encodé vers `target`.
        pub fn send_echo(&self, target: Ipv4Addr, packet: &[u8]) -> io::Result<()> {
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from(target).to_be(),
            };
            // SAFETY: envoi vers un sockaddr_in valide, longueur exacte fournie.
            let sent = unsafe {
                libc::sendto(
                    self.fd,
                    packet.as_ptr().cast::<libc::c_void>(),
                    packet.len(),
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

        /// Reçoit un paquet (en-tête IP + ICMP), borné par `set_read_timeout`.
        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
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

    impl Drop for IcmpSocket {
        fn drop(&mut self) {
            // SAFETY: on ferme le descripteur que nous possédons (teardown RAII).
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    /// Un échange écho borné : `Ok(true)` si une réponse appariée arrive avant le
    /// délai, `Ok(false)` si le délai expire sans réponse, `Err` si la socket échoue.
    fn ping_once(target: Ipv4Addr, read_timeout: Duration) -> Result<bool, IcmpError> {
        let socket = IcmpSocket::open()?;
        socket
            .set_read_timeout(read_timeout)
            .map_err(|e| IcmpError::Socket(e.to_string()))?;
        let identifier = (std::process::id() & 0xFFFF) as u16;
        let sequence = 1;
        let packet = build_echo_request(identifier, sequence, b"nickmare");
        socket
            .send_echo(target, &packet)
            .map_err(|e| IcmpError::Socket(e.to_string()))?;

        let mut buf = [0u8; 1500];
        let received = match socket.recv(&mut buf) {
            Ok(len) => len,
            // Délai dépassé : pas de réponse, mais pas une erreur.
            Err(err) if is_timeout(&err) => return Ok(false),
            Err(err) => return Err(IcmpError::Socket(err.to_string())),
        };
        let reply = parse_ipv4_echo_reply(&buf[..received]);
        Ok(reply.is_some_and(|r| r.identifier == identifier && r.sequence == sequence))
    }

    /// Vrai si l'erreur d'I/O est un dépassement de délai de lecture.
    fn is_timeout(err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        )
    }

    /// Émetteur de sondes ICMP brutes (le mode privilégié de la découverte).
    #[derive(Debug, Clone)]
    pub struct IcmpEmitter {
        read_timeout: Duration,
    }

    impl IcmpEmitter {
        /// Émetteur dont chaque écho attend une réponse au plus `read_timeout`.
        #[must_use]
        pub fn new(read_timeout: Duration) -> Self {
            Self { read_timeout }
        }
    }

    #[async_trait]
    impl ProbeEmitter for IcmpEmitter {
        async fn probe(&self, target: IpAddr) -> ProbeOutcome {
            let IpAddr::V4(v4) = target else {
                return ProbeOutcome::Unreachable; // ICMPv6 : hors de ce ticket.
            };
            let read_timeout = self.read_timeout;
            let task = tokio::task::spawn_blocking(move || ping_once(v4, read_timeout));
            match task.await {
                Ok(Ok(true)) => ProbeOutcome::Alive,
                Ok(Ok(false)) => ProbeOutcome::TimedOut,
                // Socket en échec (privilège, réseau) ou tâche interrompue :
                // injoignable, jamais de panique propagée.
                _ => ProbeOutcome::Unreachable,
            }
        }

        fn kind(&self) -> &'static str {
            "icmp_echo"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn somme_de_controle_d_un_paquet_pose_vaut_zero() {
        let packet = build_echo_request(0x1234, 7, b"charge");
        // Recalculée sur un paquet dont la somme est déjà posée → 0 (RFC 1071).
        assert_eq!(checksum(&packet), 0);
    }

    #[test]
    fn requete_d_echo_bien_encodee() {
        let packet = build_echo_request(0xABCD, 0x0102, b"xy");
        assert_eq!(packet[0], ICMP_ECHO_REQUEST);
        assert_eq!(packet[1], 0);
        assert_eq!(&packet[4..6], &[0xAB, 0xCD]); // identifiant
        assert_eq!(&packet[6..8], &[0x01, 0x02]); // séquence
        assert_eq!(&packet[8..], b"xy"); // charge utile
    }

    #[test]
    fn analyse_une_reponse_d_echo_ipv4() {
        // En-tête IPv4 minimal (version 4, IHL 5 → 20 octets) + réponse d'écho.
        let mut packet = vec![0x45];
        packet.extend_from_slice(&[0u8; 19]); // reste de l'en-tête IP
        packet.extend_from_slice(&[ICMP_ECHO_REPLY, 0, 0, 0]); // type/code/somme
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // identifiant
        packet.extend_from_slice(&0x0009u16.to_be_bytes()); // séquence
        let reply = parse_ipv4_echo_reply(&packet).expect("réponse d'écho");
        assert_eq!(reply.identifier, 0x1234);
        assert_eq!(reply.sequence, 9);
    }

    #[test]
    fn parsing_defensif_sans_panique() {
        assert!(parse_ipv4_echo_reply(&[]).is_none());
        // Paquet tronqué : refusé.
        assert!(parse_ipv4_echo_reply(&[0x45]).is_none());
        // Une requête (type 8) n'est pas une réponse.
        let mut request = vec![0x45];
        request.extend_from_slice(&[0u8; 19]);
        request.extend_from_slice(&[ICMP_ECHO_REQUEST, 0, 0, 0, 0, 0, 0, 0]);
        assert!(parse_ipv4_echo_reply(&request).is_none());
    }
}
