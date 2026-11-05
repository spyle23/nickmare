//! Vue **carte textuelle** de la [`NetworkMap`] + mise à jour incrémentale
//! (issue #9, cf. `docs/ARCHITECTURE.md` §4, §7, décision 6, US-B3).
//!
//! La `NetworkMap` matérialise « je vois les machines, je choisis où j'entre ».
//! Sa **construction** à partir d'une découverte vit déjà dans
//! [`discovery`](crate::discovery) (`discover_map`/`build_map`, issue #7) : ce
//! module ne la réimplémente pas. Il apporte deux choses complémentaires et
//! **pures** (aucune I/O) :
//!
//! 1. **Mise à jour incrémentale** ([`merge_host`]/[`merge_hosts`]) — agréger les
//!    hôtes au fil de la découverte dans une carte existante, par *upsert* sur
//!    l'IP, de façon **idempotente** : re-fusionner les mêmes hôtes ne change
//!    plus rien. Une fois N2 présent, [`record_pivot`] trace de même les chemins
//!    de propagation.
//! 2. **Vue textuelle** ([`render_map`]/[`MapView`]) — un rendu lisible de la
//!    carte (périmètre, hôtes et leurs champs, chemins de pivot), avec les hôtes
//!    **compromis** et les **pivots** présentés distinctement (DoD US-B3). La TUI
//!    `ratatui` enrichira cette vue en Phase 9 ; la même structuration alimente
//!    l'export du rapport HTML (Phase 5).

use std::fmt;

use nickmare_core::model::{
    Host, HostRole, NetworkMap, OsGuess, PivotLink, Port, PortState, Proto,
};

// --- Mise à jour incrémentale (agrégation au fil de la découverte) ----------

/// Fusionne une série d'hôtes nouvellement observés dans la carte (cf.
/// [`merge_host`]). Idempotent : fusionner deux fois la même série laisse la
/// carte inchangée après la première passe.
pub fn merge_hosts<I>(map: &mut NetworkMap, incoming: I)
where
    I: IntoIterator<Item = Host>,
{
    for host in incoming {
        merge_host(map, host);
    }
}

/// *Upsert* d'un hôte dans la carte, identifié par son IP.
///
/// - IP déjà connue → l'hôte existant est **enrichi** (cf. [`enrich_host`]) :
///   on complète les champs facultatifs nouvellement connus (MAC, hostname, OS,
///   rôle), on conserve la première observation la plus ancienne, on n'annule
///   jamais une compromission acquise et on fusionne les ports.
/// - IP nouvelle → l'hôte est inséré.
///
/// Les hôtes restent **triés par IP** pour un rendu déterministe. L'opération
/// est idempotente : refaire le même `merge_host` ne modifie plus la carte.
pub fn merge_host(map: &mut NetworkMap, incoming: Host) {
    match map.hosts.iter().position(|host| host.ip == incoming.ip) {
        Some(index) => enrich_host(&mut map.hosts[index], incoming),
        None => map.hosts.push(incoming),
    }
    map.hosts.sort_by_key(|host| host.ip);
}

/// Trace un chemin de pivot dans la carte (support N2, Phase 6), sans doublon :
/// un pivot déjà présent (même source, cible et relais) n'est pas réinséré.
/// Idempotent, l'ordre chronologique d'insertion est préservé.
pub fn record_pivot(map: &mut NetworkMap, pivot: PivotLink) {
    let already_known = map
        .pivots
        .iter()
        .any(|known| known.from == pivot.from && known.to == pivot.to && known.via == pivot.via);
    if !already_known {
        map.pivots.push(pivot);
    }
}

/// Enrichit un hôte connu avec une nouvelle observation, sans jamais perdre
/// d'information acquise. Conçu pour être **idempotent** sur une observation
/// identique.
fn enrich_host(existing: &mut Host, incoming: Host) {
    // Garder la première apparition la plus ancienne.
    if incoming.first_seen < existing.first_seen {
        existing.first_seen = incoming.first_seen;
    }
    // Compléter les champs facultatifs dès qu'une nouvelle valeur est connue.
    if incoming.mac.is_some() {
        existing.mac = incoming.mac;
    }
    if incoming.hostname.is_some() {
        existing.hostname = incoming.hostname;
    }
    if incoming.os_guess.is_some() {
        existing.os_guess = incoming.os_guess;
    }
    // Le rôle n'est précisé que s'il était encore inconnu (pas de régression).
    if existing.role == HostRole::Unknown {
        existing.role = incoming.role;
    }
    // Une compromission acquise (N2) ne se perd jamais.
    existing.compromised = existing.compromised || incoming.compromised;
    // Fusionner les ports observés (upsert par numéro + protocole).
    for port in incoming.ports {
        merge_port(&mut existing.ports, port);
    }
}

/// *Upsert* d'un port dans la liste d'un hôte, par couple `(numéro, protocole)`.
/// Les ports restent triés (numéro puis protocole) pour un rendu déterministe.
fn merge_port(ports: &mut Vec<Port>, incoming: Port) {
    match ports
        .iter()
        .position(|port| port.number == incoming.number && port.proto == incoming.proto)
    {
        Some(index) => {
            let existing = &mut ports[index];
            existing.state = incoming.state;
            if incoming.service.is_some() {
                existing.service = incoming.service;
            }
        }
        None => ports.push(incoming),
    }
    ports.sort_by_key(|port| (port.number, proto_rank(port.proto)));
}

/// Ordre stable des protocoles pour le tri des ports (TCP avant UDP).
fn proto_rank(proto: Proto) -> u8 {
    match proto {
        Proto::Tcp => 0,
        Proto::Udp => 1,
    }
}

// --- Vue carte textuelle ----------------------------------------------------

/// Vue affichable d'une [`NetworkMap`] : enveloppe empruntée implémentant
/// [`fmt::Display`]. Évite de copier la carte pour la rendre et permet
/// `format!("{}", MapView(&map))` comme `print!("{}", MapView(&map))`.
pub struct MapView<'a>(pub &'a NetworkMap);

impl fmt::Display for MapView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let map = self.0;
        let compromised = map.hosts.iter().filter(|host| host.compromised).count();

        writeln!(f, "Carte réseau — périmètre {}", map.scope_network)?;
        writeln!(
            f,
            "Bilan : {} hôte(s) · {compromised} compromis · {} pivot(s)",
            map.hosts.len(),
            map.pivots.len()
        )?;
        writeln!(f)?;

        writeln!(f, "Hôtes :")?;
        if map.hosts.is_empty() {
            writeln!(f, "  (aucun hôte découvert)")?;
        } else {
            for host in &map.hosts {
                write_host(f, host)?;
            }
        }
        writeln!(f)?;

        writeln!(f, "Pivots (chemins de propagation) :")?;
        if map.pivots.is_empty() {
            writeln!(f, "  (aucun chemin de pivot établi)")?;
        } else {
            for pivot in &map.pivots {
                writeln!(
                    f,
                    "  {} → {}  (via {}, {})",
                    pivot.from,
                    pivot.to,
                    pivot.via,
                    pivot.at.to_rfc3339()
                )?;
            }
        }
        Ok(())
    }
}

/// Rend la carte réseau en texte lisible (cf. [`MapView`]). La sortie se termine
/// par un saut de ligne, prête à être imprimée telle quelle.
#[must_use]
pub fn render_map(map: &NetworkMap) -> String {
    MapView(map).to_string()
}

/// Écrit le bloc d'un hôte : une ligne d'en-tête (marqueur de compromission, IP,
/// rôle) puis les champs indentés (hostname, OS, MAC, services ouverts).
fn write_host(f: &mut fmt::Formatter<'_>, host: &Host) -> fmt::Result {
    // Marqueur visuel : un hôte compromis saute aux yeux (colonne de gauche +
    // étiquette), distinct des hôtes simplement découverts (US-B3).
    let (marker, tag) = if host.compromised {
        ("!", "  [COMPROMIS]")
    } else {
        (" ", "")
    };
    let hostname = host.hostname.as_deref().unwrap_or("—");
    writeln!(f, "{marker} {} — {}{tag}", host.ip, role_label(host.role))?;
    writeln!(f, "      hostname : {hostname}")?;
    writeln!(f, "      OS       : {}", os_label(host.os_guess.as_ref()))?;
    writeln!(f, "      MAC      : {}", mac_label(host))?;
    writeln!(f, "      services : {}", services_label(host))?;
    Ok(())
}

/// Libellé lisible du rôle présumé.
fn role_label(role: HostRole) -> &'static str {
    match role {
        HostRole::Gateway => "passerelle",
        HostRole::Server => "serveur",
        HostRole::Workstation => "poste",
        HostRole::Unknown => "rôle inconnu",
    }
}

/// Libellé lisible de l'OS présumé (`—` si inconnu).
fn os_label(os: Option<&OsGuess>) -> String {
    match os {
        None => "OS inconnu".to_string(),
        Some(OsGuess::Linux) => "Linux".to_string(),
        Some(OsGuess::Windows) => "Windows".to_string(),
        Some(OsGuess::MacOs) => "macOS".to_string(),
        Some(OsGuess::Bsd) => "BSD".to_string(),
        Some(OsGuess::Android) => "Android".to_string(),
        Some(OsGuess::Ios) => "iOS".to_string(),
        Some(OsGuess::NetworkDevice) => "équipement réseau".to_string(),
        Some(OsGuess::Other(label)) => label.clone(),
    }
}

/// Libellé de la MAC (`—` si inconnue).
fn mac_label(host: &Host) -> String {
    match host.mac {
        Some(mac) => mac.to_string(),
        None => "—".to_string(),
    }
}

/// Liste lisible des **services ouverts** d'un hôte, ou une mention explicite si
/// aucun port ouvert n'a été observé.
fn services_label(host: &Host) -> String {
    let open: Vec<String> = host
        .ports
        .iter()
        .filter(|port| port.state == PortState::Open)
        .map(format_port)
        .collect();
    if open.is_empty() {
        "aucun port ouvert détecté".to_string()
    } else {
        open.join(", ")
    }
}

/// Formate un port ouvert : `numéro/proto service (produit version)`.
fn format_port(port: &Port) -> String {
    let proto = match port.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let mut line = format!("{}/{proto}", port.number);
    if let Some(service) = &port.service {
        line.push(' ');
        line.push_str(&service.name);
        let detail = match (service.product.as_deref(), service.version.as_deref()) {
            (Some(product), Some(version)) => format!(" ({product} {version})"),
            (Some(product), None) => format!(" ({product})"),
            (None, Some(version)) => format!(" (v{version})"),
            (None, None) => String::new(),
        };
        line.push_str(&detail);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use chrono::{DateTime, Utc};
    use nickmare_core::model::{MacAddr, Service};

    use crate::discovery::build_map;

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    fn ssh_port() -> Port {
        Port {
            number: 22,
            proto: Proto::Tcp,
            state: PortState::Open,
            service: Some(Service {
                name: "ssh".to_string(),
                product: Some("OpenSSH".to_string()),
                version: Some("9.6".to_string()),
                banner: None,
            }),
        }
    }

    fn gateway() -> Host {
        Host {
            ip: ip("192.168.1.1"),
            mac: Some(MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])),
            hostname: Some("gw.local".to_string()),
            os_guess: Some(OsGuess::NetworkDevice),
            ports: Vec::new(),
            role: HostRole::Gateway,
            compromised: false,
            first_seen: t(0),
        }
    }

    fn server() -> Host {
        Host {
            ip: ip("192.168.1.10"),
            mac: None,
            hostname: Some("srv.local".to_string()),
            os_guess: Some(OsGuess::Linux),
            ports: vec![ssh_port()],
            role: HostRole::Server,
            compromised: false,
            first_seen: t(5),
        }
    }

    // --- Vue textuelle ------------------------------------------------------

    #[test]
    fn rend_le_perimetre_les_hotes_et_leurs_champs() {
        let map = build_map("192.168.1.0/24", vec![gateway(), server()]);
        let view = render_map(&map);

        assert!(
            view.contains("Carte réseau — périmètre 192.168.1.0/24"),
            "{view}"
        );
        assert!(view.contains("Bilan : 2 hôte(s)"), "{view}");
        // Hôtes et leurs champs (IP, rôle, hostname, OS, MAC, services).
        assert!(view.contains("192.168.1.1 — passerelle"), "{view}");
        assert!(view.contains("gw.local"), "{view}");
        assert!(view.contains("équipement réseau"), "{view}");
        assert!(view.contains("00:1a:2b:3c:4d:5e"), "{view}");
        assert!(view.contains("192.168.1.10 — serveur"), "{view}");
        assert!(view.contains("Linux"), "{view}");
        // Un hôte sans MAC connue affiche un tiret, pas un plantage.
        assert!(view.contains("MAC      : —"), "{view}");
        // Service ouvert formaté avec produit + version.
        assert!(view.contains("22/tcp ssh (OpenSSH 9.6)"), "{view}");
    }

    #[test]
    fn carte_vide_est_rendue_sans_paniquer() {
        let map = build_map("10.0.0.0/24", Vec::new());
        let view = render_map(&map);
        assert!(
            view.contains("Bilan : 0 hôte(s) · 0 compromis · 0 pivot(s)"),
            "{view}"
        );
        assert!(view.contains("(aucun hôte découvert)"), "{view}");
        assert!(view.contains("(aucun chemin de pivot établi)"), "{view}");
    }

    #[test]
    fn hotes_compromis_et_pivots_sont_distincts() {
        let mut compromised = server();
        compromised.compromised = true;
        let map = NetworkMap {
            scope_network: "192.168.1.0/24".to_string(),
            hosts: vec![gateway(), compromised],
            pivots: vec![PivotLink {
                from: ip("192.168.1.10"),
                to: ip("192.168.1.20"),
                via: "ssh".to_string(),
                at: t(600),
            }],
        };
        let view = render_map(&map);

        // Le compromis porte l'étiquette distinctive ; la passerelle non.
        assert!(
            view.contains("192.168.1.10 — serveur  [COMPROMIS]"),
            "{view}"
        );
        assert!(!view.contains("passerelle  [COMPROMIS]"), "{view}");
        assert!(
            view.contains("Bilan : 2 hôte(s) · 1 compromis · 1 pivot(s)"),
            "{view}"
        );
        // Le pivot apparaît dans sa propre section, avec relais et horodatage.
        assert!(
            view.contains("192.168.1.10 → 192.168.1.20  (via ssh"),
            "{view}"
        );
    }

    #[test]
    fn services_affiche_mention_si_aucun_port_ouvert() {
        let map = build_map("192.168.1.0/24", vec![gateway()]);
        let view = render_map(&map);
        assert!(
            view.contains("services : aucun port ouvert détecté"),
            "{view}"
        );
    }

    #[test]
    fn ports_fermes_ne_sont_pas_listes_comme_services() {
        let mut host = server();
        host.ports = vec![Port {
            number: 80,
            proto: Proto::Tcp,
            state: PortState::Closed,
            service: None,
        }];
        let map = build_map("192.168.1.0/24", vec![host]);
        let view = render_map(&map);
        assert!(
            view.contains("services : aucun port ouvert détecté"),
            "{view}"
        );
        assert!(!view.contains("80/tcp"), "{view}");
    }

    // --- Mise à jour incrémentale ------------------------------------------

    #[test]
    fn merge_agrege_et_trie_les_hotes_par_ip() {
        let mut map = build_map("192.168.1.0/24", Vec::new());
        // Inséré dans le désordre : la carte doit rester triée par IP.
        merge_host(&mut map, server());
        merge_host(&mut map, gateway());
        assert_eq!(map.hosts.len(), 2);
        assert_eq!(map.hosts[0].ip, ip("192.168.1.1"));
        assert_eq!(map.hosts[1].ip, ip("192.168.1.10"));
    }

    #[test]
    fn merge_incremental_est_idempotent() {
        // Construire une carte à partir de fixtures d'hôtes, puis refusionner les
        // mêmes hôtes : la carte ne doit plus changer (DoD : mise à jour idempotente).
        let mut map = build_map("192.168.1.0/24", Vec::new());
        merge_hosts(&mut map, vec![gateway(), server()]);
        let snapshot = map.clone();
        merge_hosts(&mut map, vec![gateway(), server()]);
        assert_eq!(map, snapshot, "re-fusionner les mêmes hôtes ne change rien");
    }

    #[test]
    fn merge_enrichit_sans_perdre_d_information() {
        // Première observation : IP seule, rôle inconnu, pas de MAC/hostname.
        let partial = Host {
            ip: ip("192.168.1.10"),
            mac: None,
            hostname: None,
            os_guess: None,
            ports: Vec::new(),
            role: HostRole::Unknown,
            compromised: true,
            first_seen: t(100),
        };
        let mut map = build_map("192.168.1.0/24", vec![partial]);

        // Observation enrichie plus tard (MAC, hostname, OS, rôle, ports), mais
        // non marquée compromise : la compromission acquise doit survivre.
        let mut later = server();
        later.mac = Some(MacAddr([1, 2, 3, 4, 5, 6]));
        later.first_seen = t(50); // plus ancienne que la précédente
        merge_host(&mut map, later);

        assert_eq!(map.hosts.len(), 1, "même IP : pas de doublon");
        let host = &map.hosts[0];
        assert_eq!(host.role, HostRole::Server, "rôle inconnu → précisé");
        assert_eq!(host.hostname.as_deref(), Some("srv.local"));
        assert_eq!(host.os_guess, Some(OsGuess::Linux));
        assert_eq!(host.mac, Some(MacAddr([1, 2, 3, 4, 5, 6])));
        assert_eq!(
            host.first_seen,
            t(50),
            "première apparition la plus ancienne"
        );
        assert!(host.compromised, "une compromission acquise ne se perd pas");
        assert_eq!(host.ports.len(), 1, "ports fusionnés");
    }

    #[test]
    fn merge_fusionne_les_ports_sans_doublon() {
        let mut map = build_map("192.168.1.0/24", vec![server()]);
        // Ré-observer le port 22 (service ré-identifié) + un nouveau port 443.
        let mut update = server();
        update.ports = vec![
            Port {
                number: 443,
                proto: Proto::Tcp,
                state: PortState::Open,
                service: Some(Service {
                    name: "https".to_string(),
                    product: None,
                    version: None,
                    banner: None,
                }),
            },
            ssh_port(),
        ];
        merge_host(&mut map, update);
        let host = &map.hosts[0];
        assert_eq!(host.ports.len(), 2, "port 22 upserté, 443 ajouté");
        // Ports triés par numéro : 22 avant 443.
        assert_eq!(host.ports[0].number, 22);
        assert_eq!(host.ports[1].number, 443);
    }

    #[test]
    fn record_pivot_est_idempotent() {
        let mut map = build_map("192.168.1.0/24", Vec::new());
        let pivot = PivotLink {
            from: ip("192.168.1.10"),
            to: ip("192.168.1.20"),
            via: "ssh".to_string(),
            at: t(600),
        };
        record_pivot(&mut map, pivot.clone());
        record_pivot(&mut map, pivot);
        assert_eq!(map.pivots.len(), 1, "un pivot identique n'est pas dupliqué");
    }
}
