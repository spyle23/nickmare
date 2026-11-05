//! Détection de privilèges réseau et choix de la stratégie de sondage (#8, cf.
//! `docs/ARCHITECTURE.md` §5 « Note privilèges », §12 « Minimiser les privilèges »).
//!
//! L'émission ARP/ICMP brute exige `CAP_NET_RAW` (ou root) sous Linux ; sans ce
//! privilège, l'outil **ne panique pas** : il bascule sur le mode dégradé
//! `tcp_connect_only` avec un message clair (DoD du ticket). La décision est
//! prise ici, en amont de toute socket.
//!
//! La détection réelle (Linux) est volontairement **fail-safe** : en cas de
//! doute, on se déclare non privilégié (le pire effet est un repli inutilement
//! prudent, jamais une émission brute non autorisée). La vérification finale et
//! autoritaire reste l'échec `EPERM` à l'ouverture de la socket brute.

/// Capacité réseau détectée pour le processus courant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Sockets brutes disponibles (root ou `CAP_NET_RAW`) → ARP/ICMP possibles.
    RawCapable,
    /// Aucun privilège brut → repli obligatoire sur `tcp_connect_only`.
    Unprivileged,
}

/// Stratégie d'émission des sondes de découverte retenue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStrategy {
    /// Sondes brutes ARP/ICMP (nécessitent `CAP_NET_RAW`).
    Raw,
    /// Repli TCP-connect, sans privilège (portable).
    TcpConnect,
}

impl Privilege {
    /// Stratégie de sondage correspondante.
    #[must_use]
    pub fn strategy(self) -> ProbeStrategy {
        match self {
            Privilege::RawCapable => ProbeStrategy::Raw,
            Privilege::Unprivileged => ProbeStrategy::TcpConnect,
        }
    }

    /// Message opérateur clair expliquant le mode retenu (DoD : « message clair »).
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Privilege::RawCapable => {
                "privilèges réseau bruts présents (root ou CAP_NET_RAW) : sondes ARP/ICMP actives."
            }
            Privilege::Unprivileged => {
                "aucun privilège réseau brut (ni root ni CAP_NET_RAW) : repli sur le mode dégradé \
                 tcp_connect_only, sans ARP/ICMP (cf. docs/ARCHITECTURE.md §5)."
            }
        }
    }
}

/// Rang du bit `CAP_NET_RAW` dans le masque de capacités Linux.
const CAP_NET_RAW_BIT: u32 = 13;

/// Vrai si le masque de capacités effectives (champ `CapEff:` hexadécimal de
/// `/proc/self/status`) contient `CAP_NET_RAW`. Fonction **pure**, testable sans
/// toucher au système : une valeur illisible vaut « pas la capacité » (fail-safe).
#[must_use]
pub fn cap_eff_has_net_raw(cap_eff_hex: &str) -> bool {
    match u64::from_str_radix(cap_eff_hex.trim(), 16) {
        Ok(mask) => mask & (1u64 << CAP_NET_RAW_BIT) != 0,
        Err(_) => false,
    }
}

/// Détecte le privilège réseau du processus courant (Linux).
///
/// Root a toujours `CAP_NET_RAW` effectif ; sinon, on lit `/proc/self/status`
/// pour gérer le cas d'un binaire doté de la capacité par `setcap` sans être root.
#[cfg(target_os = "linux")]
#[must_use]
pub fn detect_privilege() -> Privilege {
    // SAFETY: `geteuid` ne prend aucun argument et n'a pas d'effet de bord.
    if unsafe { libc::geteuid() } == 0 {
        return Privilege::RawCapable;
    }
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                if cap_eff_has_net_raw(hex) {
                    return Privilege::RawCapable;
                }
            }
        }
    }
    Privilege::Unprivileged
}

/// Détecte le privilège réseau (plateformes hors Linux).
///
/// Aucun chemin brut n'est implémenté hors Linux (Windows via Npcap arrivera) :
/// on se déclare non privilégié, ce qui force le repli `tcp_connect_only`.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn detect_privilege() -> Privilege {
    Privilege::Unprivileged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_eff_detecte_net_raw() {
        // 1 << 13 == 0x2000.
        assert!(cap_eff_has_net_raw("0000000000002000"));
        assert!(cap_eff_has_net_raw("0000003fffffffff")); // masque « tout »
        assert!(!cap_eff_has_net_raw("0000000000001fff")); // bits 0..12 seulement
        assert!(!cap_eff_has_net_raw("0000000000000000"));
    }

    #[test]
    fn cap_eff_illisible_est_fail_safe() {
        assert!(!cap_eff_has_net_raw("pas-de-l-hexa"));
        assert!(!cap_eff_has_net_raw(""));
    }

    #[test]
    fn strategie_decoule_du_privilege() {
        assert_eq!(Privilege::RawCapable.strategy(), ProbeStrategy::Raw);
        assert_eq!(
            Privilege::Unprivileged.strategy(),
            ProbeStrategy::TcpConnect
        );
    }

    #[test]
    fn detection_ne_panique_jamais_et_sexplique() {
        // On n'affirme rien sur la valeur (dépend de l'environnement CI) : on
        // prouve seulement l'absence de panique et un message non vide.
        let privilege = detect_privilege();
        assert!(!privilege.explain().is_empty());
    }
}
