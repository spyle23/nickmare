//! ARP — construction/analyse **pures** des trames d'un sweep de voisinage (#8,
//! cf. `docs/ARCHITECTURE.md` §2 N1, §9 Phase 1).
//!
//! L'ARP sweep est la découverte de référence **sur le même sous-réseau** : on
//! diffuse un « who-has <ip> » et un hôte vivant répond en révélant son adresse
//! MAC (qui alimente ensuite la [`NetworkMap`](nickmare_core::model::NetworkMap)).
//!
//! Comme pour l'ICMP, la logique d'encodage/décodage est **pure** et testée sans
//! aucune socket. L'émission réelle se fait au niveau liaison (socket `AF_PACKET`,
//! Linux + privilégiée) : ce transport brut est volontairement laissé à
//! l'itération suivante (il réclame l'index d'interface et un `sockaddr_ll`), la
//! partie délicate — le format des trames — étant déjà ici, prouvée.

use std::net::Ipv4Addr;

/// EtherType d'une trame ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// Type matériel « Ethernet » dans l'en-tête ARP.
pub const HTYPE_ETHERNET: u16 = 1;
/// Type protocole « IPv4 » dans l'en-tête ARP.
pub const PTYPE_IPV4: u16 = 0x0800;
/// Opération ARP : requête.
pub const ARP_REQUEST: u16 = 1;
/// Opération ARP : réponse.
pub const ARP_REPLY: u16 = 2;

/// Longueur d'une trame Ethernet + ARP IPv4 (14 + 28 octets).
pub const ARP_FRAME_LEN: usize = 42;

/// Construit la trame Ethernet complète d'une requête ARP « who-has `target_ip` »,
/// diffusée (destination `ff:ff:ff:ff:ff:ff`) depuis `src_mac`/`src_ip`.
#[must_use]
pub fn build_request_frame(src_mac: [u8; 6], src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
    // En-tête Ethernet.
    frame.extend_from_slice(&[0xFF; 6]); // destination : diffusion
    frame.extend_from_slice(&src_mac); // source
    frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    // Charge utile ARP.
    frame.extend_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    frame.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
    frame.push(6); // longueur adresse matérielle
    frame.push(4); // longueur adresse protocole
    frame.extend_from_slice(&ARP_REQUEST.to_be_bytes());
    frame.extend_from_slice(&src_mac); // expéditeur MAC
    frame.extend_from_slice(&src_ip.octets()); // expéditeur IP
    frame.extend_from_slice(&[0u8; 6]); // cible MAC : inconnue
    frame.extend_from_slice(&target_ip.octets()); // cible IP
    frame
}

/// Réponse ARP analysée : qui (MAC) possède quelle IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpReply {
    /// Adresse IPv4 de l'expéditeur.
    pub sender_ip: Ipv4Addr,
    /// Adresse MAC de l'expéditeur.
    pub sender_mac: [u8; 6],
}

/// Analyse une trame Ethernet et en extrait une **réponse** ARP, s'il y en a une.
///
/// Parsing **défensif** (§12) : trame trop courte, EtherType ou opération
/// inattendus → `None`, jamais de panique sur une trame hostile.
#[must_use]
pub fn parse_reply(frame: &[u8]) -> Option<ArpReply> {
    if frame.len() < ARP_FRAME_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_ARP {
        return None;
    }
    if u16::from_be_bytes([frame[20], frame[21]]) != ARP_REPLY {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&frame[22..28]);
    let sender_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    Some(ArpReply {
        sender_ip,
        sender_mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn requete_bien_formee() {
        let mac = [0x02, 0x00, 0x00, 0x11, 0x22, 0x33];
        let frame = build_request_frame(mac, ip(192, 168, 1, 10), ip(192, 168, 1, 254));
        assert_eq!(frame.len(), ARP_FRAME_LEN);
        assert_eq!(&frame[0..6], &[0xFF; 6], "destination diffusion");
        assert_eq!(&frame[6..12], &mac, "source MAC");
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_ARP);
        assert_eq!(u16::from_be_bytes([frame[20], frame[21]]), ARP_REQUEST);
        assert_eq!(&frame[38..42], &[192, 168, 1, 254], "IP cible");
    }

    #[test]
    fn analyse_une_reponse() {
        // On fabrique une réponse ARP cohérente puis on la relit.
        let mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut frame = build_request_frame(mac, ip(10, 0, 0, 5), ip(10, 0, 0, 1));
        frame[20..22].copy_from_slice(&ARP_REPLY.to_be_bytes());
        let reply = parse_reply(&frame).expect("réponse ARP");
        assert_eq!(reply.sender_ip, ip(10, 0, 0, 5));
        assert_eq!(reply.sender_mac, mac);
    }

    #[test]
    fn parsing_defensif_sans_panique() {
        assert!(parse_reply(&[]).is_none());
        // Trame tronquée : refusée.
        assert!(parse_reply(&[0u8; 10]).is_none());
        // Une requête (opération 1) n'est pas une réponse.
        let frame = build_request_frame([0; 6], ip(1, 1, 1, 1), ip(2, 2, 2, 2));
        assert!(parse_reply(&frame).is_none());
    }
}
