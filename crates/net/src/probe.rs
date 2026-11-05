//! Abstraction d'**émission de sondes** de présence d'hôte (#8).
//!
//! La découverte réelle émet des sondes pour savoir si un hôte répond. Le moyen
//! dépend des privilèges (ARP/ICMP brut avec `CAP_NET_RAW`, sinon TCP-connect) :
//! on l'isole donc **derrière un trait**, exactement comme `NetworkProvider`
//! isole le réseau du reste. Bénéfice direct pour la CI (cf. consigne « feature-gate
//! ou abstraction ») : la logique d'orchestration de la découverte se teste contre
//! un émetteur bouchonné, **sans aucune socket réelle ni privilège**.
//!
//! L'émetteur TCP-connect ([`TcpConnectEmitter`]) est le repli **sans privilège**,
//! portable Windows + Linux ; l'émetteur ICMP brut vit dans [`crate::icmp`]
//! (Linux, privilégié).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;

use crate::tcp::{self, TcpConnectResult};

/// Verdict d'une sonde de présence envoyée vers un hôte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// L'hôte a répondu (réponse ARP/ICMP, connexion acceptée ou refusée par RST).
    Alive,
    /// Aucune réponse : l'hôte est considéré injoignable.
    Unreachable,
    /// Délai dépassé sans réponse (hôte potentiellement filtré/lent).
    TimedOut,
}

/// Émetteur de sondes de présence. `Send + Sync` pour être partagé (`Arc<dyn …>`)
/// entre les tâches concurrentes du sweep.
#[async_trait]
pub trait ProbeEmitter: Send + Sync {
    /// Sonde un hôte et renvoie son verdict de présence. Ne doit jamais paniquer
    /// ni bloquer indéfiniment (chaque I/O est bornée par un timeout, §11.4).
    async fn probe(&self, target: IpAddr) -> ProbeOutcome;

    /// Étiquette du mode d'émission (pour la traçabilité : `tcp_connect_only`, …).
    fn kind(&self) -> &'static str;
}

/// Émetteur de repli **sans privilège** : conclut qu'un hôte est vivant dès qu'un
/// de ses ports sondés accepte la connexion **ou** la refuse par RST (les deux
/// prouvent une pile active). N'est « injoignable » que si aucun port ne répond.
#[derive(Debug, Clone)]
pub struct TcpConnectEmitter {
    ports: Vec<u16>,
    timeout: Duration,
}

impl TcpConnectEmitter {
    /// Émetteur sondant `ports` avec un `timeout` de connexion par port.
    #[must_use]
    pub fn new(ports: Vec<u16>, timeout: Duration) -> Self {
        Self { ports, timeout }
    }
}

impl Default for TcpConnectEmitter {
    fn default() -> Self {
        Self::new(vec![80, 443, 22], Duration::from_millis(800))
    }
}

#[async_trait]
impl ProbeEmitter for TcpConnectEmitter {
    async fn probe(&self, target: IpAddr) -> ProbeOutcome {
        let ports = self.ports.clone();
        let timeout = self.timeout;
        // I/O bloquante bornée déportée hors du runtime async.
        let task = tokio::task::spawn_blocking(move || {
            let mut saw_timeout = false;
            for port in ports {
                match tcp::connect(SocketAddr::new(target, port), timeout) {
                    TcpConnectResult::Connected | TcpConnectResult::Refused => {
                        return ProbeOutcome::Alive;
                    }
                    TcpConnectResult::TimedOut => saw_timeout = true,
                    TcpConnectResult::Failed(_) => {}
                }
            }
            if saw_timeout {
                ProbeOutcome::TimedOut
            } else {
                ProbeOutcome::Unreachable
            }
        });
        // Une tâche interrompue (panique interne du pool) vaut « injoignable »,
        // jamais une panique propagée.
        task.await.unwrap_or(ProbeOutcome::Unreachable)
    }

    fn kind(&self) -> &'static str {
        "tcp_connect_only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn loopback() -> IpAddr {
        IpAddr::from([127, 0, 0, 1])
    }

    #[tokio::test]
    async fn port_ouvert_rend_lhote_vivant() {
        // Un listener local accepte : le port répond → hôte vivant.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            // Accepte une connexion puis relâche (teardown).
            let _ = listener.accept();
        });
        let emitter = TcpConnectEmitter::new(vec![port], Duration::from_millis(500));
        assert_eq!(emitter.probe(loopback()).await, ProbeOutcome::Alive);
        assert_eq!(emitter.kind(), "tcp_connect_only");
    }

    // Restreint aux plateformes où un port fermé de loopback refuse par RST de
    // façon déterministe (Unix). Sous Windows, un tel port peut au contraire faire
    // expirer la connexion (SYN silencieusement rejeté) : le repli TCP y verrait
    // l'hôte « timeout » et non « vivant ». Ce comportement OS-dépendant n'invalide
    // pas la logique (refus ⇒ hôte vivant), vérifiée par ailleurs.
    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn port_ferme_en_loopback_rend_lhote_vivant() {
        // On réserve un port puis on le libère : la loopback refuse alors par RST,
        // ce qui prouve une pile active (hôte vivant), de façon déterministe.
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let emitter = TcpConnectEmitter::new(vec![port], Duration::from_millis(500));
        assert_eq!(emitter.probe(loopback()).await, ProbeOutcome::Alive);
    }
}
