//! Transport TCP sans privilège — le socle du repli `tcp_connect_only` (#8, cf.
//! `docs/ARCHITECTURE.md` §5 « Note privilèges », §11.4).
//!
//! Ces fonctions sont **bloquantes** mais **toujours bornées** : `connect_timeout`
//! et `set_read_timeout` garantissent qu'aucune opération ne se bloque
//! indéfiniment (§11.4). Elles s'appuient uniquement sur `std::net` (portable
//! Windows + Linux, aucune dépendance, aucun privilège) ; le provider les déporte
//! du runtime via `spawn_blocking`. La **classification** d'une erreur d'I/O est
//! une fonction pure, testable sans aucune socket.

use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Durée minimale d'un timeout : `connect_timeout`/`set_read_timeout` refusent une
/// durée nulle. On relève toute valeur nulle à 1 ms (fail-safe, jamais de panique).
const MIN_TIMEOUT: Duration = Duration::from_millis(1);

/// Issue classifiée d'une tentative de connexion TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpConnectResult {
    /// Connexion établie : le port est ouvert et l'hôte est vivant.
    Connected,
    /// Connexion refusée (RST) : le port est fermé, mais l'hôte est bien vivant.
    Refused,
    /// Délai de connexion dépassé : port filtré ou hôte silencieux.
    TimedOut,
    /// Autre échec (réseau injoignable, erreur système), message tracé.
    Failed(String),
}

/// Issue d'une lecture de bannière.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BannerOutcome {
    /// Port ouvert, octets de bannière capturés (jamais vides).
    Read(Vec<u8>),
    /// Port ouvert mais muet : rien reçu avant le délai de lecture.
    Silent,
    /// Connexion refusée : aucun service à ce port.
    Refused,
    /// Délai de connexion dépassé.
    TimedOut,
    /// Autre échec, message tracé.
    Failed(String),
}

/// Classe une erreur d'I/O de connexion en [`TcpConnectResult`]. Fonction **pure**,
/// testable sans socket : une erreur venant du système n'est jamais `unwrap`ée (§12).
#[must_use]
pub fn classify_connect_error(err: &std::io::Error) -> TcpConnectResult {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::ConnectionRefused => TcpConnectResult::Refused,
        // `connect_timeout` signale le dépassement par `TimedOut` ou, sur certaines
        // plateformes, par `WouldBlock` : les deux valent timeout.
        ErrorKind::TimedOut | ErrorKind::WouldBlock => TcpConnectResult::TimedOut,
        _ => TcpConnectResult::Failed(err.to_string()),
    }
}

/// Ramène une durée nulle à [`MIN_TIMEOUT`] (une durée nulle ferait paniquer les
/// primitives socket).
fn bounded(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        MIN_TIMEOUT
    } else {
        timeout
    }
}

/// Tente une connexion TCP **bloquante bornée** vers `addr`. Jamais de blocage
/// indéfini : le retour est garanti sous `timeout` (§11.4).
#[must_use]
pub fn connect(addr: SocketAddr, timeout: Duration) -> TcpConnectResult {
    match TcpStream::connect_timeout(&addr, bounded(timeout)) {
        Ok(_stream) => TcpConnectResult::Connected, // teardown RAII immédiat (§11.1).
        Err(err) => classify_connect_error(&err),
    }
}

/// Se connecte puis lit au plus `cap` octets de bannière, chaque étape bornée par
/// son timeout. Jamais de panique sur une entrée réseau hostile (§12).
#[must_use]
pub fn read_banner(
    addr: SocketAddr,
    connect_timeout: Duration,
    read_timeout: Duration,
    cap: usize,
) -> BannerOutcome {
    use std::io::ErrorKind;
    let mut stream = match TcpStream::connect_timeout(&addr, bounded(connect_timeout)) {
        Ok(stream) => stream,
        Err(err) => {
            return match err.kind() {
                ErrorKind::ConnectionRefused => BannerOutcome::Refused,
                ErrorKind::TimedOut | ErrorKind::WouldBlock => BannerOutcome::TimedOut,
                _ => BannerOutcome::Failed(err.to_string()),
            };
        }
    };
    if let Err(err) = stream.set_read_timeout(Some(bounded(read_timeout))) {
        return BannerOutcome::Failed(err.to_string());
    }
    let mut buf = vec![0u8; cap];
    match stream.read(&mut buf) {
        Ok(0) => BannerOutcome::Silent, // pair fermé sans rien envoyer.
        Ok(read) => {
            buf.truncate(read);
            BannerOutcome::Read(buf)
        }
        // Timeout de lecture : port ouvert mais muet, pas une erreur.
        Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            BannerOutcome::Silent
        }
        Err(err) => BannerOutcome::Failed(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    fn classify(kind: ErrorKind) -> TcpConnectResult {
        classify_connect_error(&std::io::Error::from(kind))
    }

    #[test]
    fn classe_les_erreurs_sans_socket() {
        use ErrorKind::{ConnectionRefused, TimedOut, WouldBlock};
        assert_eq!(classify(ConnectionRefused), TcpConnectResult::Refused);
        assert_eq!(classify(TimedOut), TcpConnectResult::TimedOut);
        assert_eq!(classify(WouldBlock), TcpConnectResult::TimedOut);
        assert!(matches!(
            classify(ErrorKind::AddrNotAvailable),
            TcpConnectResult::Failed(_)
        ));
    }

    #[test]
    fn un_timeout_nul_est_releve_sans_paniquer() {
        // `bounded` protège les primitives socket d'une durée nulle.
        assert_eq!(bounded(Duration::ZERO), MIN_TIMEOUT);
        assert_eq!(bounded(Duration::from_secs(3)), Duration::from_secs(3));
    }
}
