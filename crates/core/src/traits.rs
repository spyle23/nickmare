//! Traits d'abstraction et implémentations mock (issue #6, cf. `docs/ARCHITECTURE.md`
//! §4, §10.2).
//!
//! Ces traits rendent la logique testable **sans réseau, sans privilèges et sans
//! rien exploiter de réel** : en CI, un mock rejoue des réponses déterministes
//! chargées depuis des fixtures (`testdata/`). Les implémentations réelles
//! arrivent dans les crates `net` (Phase 1+), `exploit` (Phase 6) et `crack`
//! (Phase 7).

use std::collections::HashMap;
use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::model::{CrackResult, Host, Port, Service};

/// Erreur d'une opération réseau abstraite. Les entrées venant du réseau sont
/// hostiles par principe (§12) : les implémentations réelles ne doivent jamais
/// `unwrap` sur des données externes, mais renvoyer une de ces variantes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// Hôte injoignable.
    Unreachable(IpAddr),
    /// Délai dépassé.
    Timeout,
    /// Autre erreur, message tracé.
    Other(String),
}

/// Résultat d'une opération réseau abstraite.
pub type NetResult<T> = Result<T, NetError>;

/// Abstraction de la couche réseau (recon active : découverte, scan, bannières).
///
/// `Send + Sync` pour permettre les scans concurrents sous `tokio`, et l'usage
/// en objet de trait (`Box<dyn NetworkProvider>`) comme en générique.
#[async_trait]
pub trait NetworkProvider: Send + Sync {
    /// Découvre les hôtes actifs du réseau attesté (CIDR ou SSID).
    async fn discover_hosts(&self, network: &str) -> NetResult<Vec<Host>>;

    /// Scanne les ports demandés d'un hôte (liste vide = tous ceux connus).
    async fn scan_ports(&self, host: IpAddr, ports: &[u16]) -> NetResult<Vec<Port>>;

    /// Lit la bannière d'un service sur un port (identification de service).
    async fn read_banner(&self, host: IpAddr, port: u16) -> NetResult<Option<Service>>;
}

/// Abstraction du moteur d'exploitation (N2) : finalisée dans le module
/// [`exploit`](crate::exploit) (trait + mock déterministe, issue #18, Phase 6).
/// Réexportée ici pour conserver le point d'accès « traits d'abstraction »
/// (`NetworkProvider` / `ExploitEngine` / `CrackEngine`, §4/§6).
pub use crate::exploit::ExploitEngine;

/// Abstraction du moteur de craquage (N3). Esquisse : l'implémentation réelle
/// (orchestration hashcat/John) arrive en Phase 7.
#[async_trait]
pub trait CrackEngine: Send + Sync {
    /// Lance un craquage hors-ligne et renvoie des statistiques (jamais de secret).
    async fn run(&self, source: &str, hash_type: &str) -> NetResult<CrackResult>;
}

// --- Mock déterministe ------------------------------------------------------

/// Une bannière rejouée par le mock pour un couple (hôte, port).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BannerEntry {
    pub host: IpAddr,
    pub port: u16,
    pub service: Service,
}

/// Table de réponses d'un scénario mock, chargeable depuis une fixture JSON
/// (`testdata/`). Chaque champ est optionnel pour autoriser des scénarios partiels.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockScenario {
    /// Hôtes découverts, par réseau attesté.
    #[serde(default)]
    pub hosts_by_network: HashMap<String, Vec<Host>>,
    /// Ports connus, par hôte.
    #[serde(default)]
    pub ports_by_host: HashMap<IpAddr, Vec<Port>>,
    /// Bannières connues, par couple (hôte, port).
    #[serde(default)]
    pub banners: Vec<BannerEntry>,
}

/// Implémentation mock de `NetworkProvider` : renvoie **exactement** les fixtures
/// fournies, de façon déterministe et sans aucune I/O réseau. Injectable partout
/// où un `NetworkProvider` est attendu (générique ou objet de trait).
#[derive(Debug, Clone, Default)]
pub struct MockNetworkProvider {
    scenario: MockScenario,
}

impl MockNetworkProvider {
    /// Construit le mock à partir d'un scénario en mémoire.
    pub fn new(scenario: MockScenario) -> Self {
        Self { scenario }
    }

    /// Construit le mock depuis une fixture JSON (contenu, pas un chemin).
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        Ok(Self::new(serde_json::from_str(json)?))
    }
}

#[async_trait]
impl NetworkProvider for MockNetworkProvider {
    async fn discover_hosts(&self, network: &str) -> NetResult<Vec<Host>> {
        let table = &self.scenario.hosts_by_network;
        Ok(table.get(network).cloned().unwrap_or_default())
    }

    async fn scan_ports(&self, host: IpAddr, ports: &[u16]) -> NetResult<Vec<Port>> {
        let table = &self.scenario.ports_by_host;
        let known = table.get(&host).cloned().unwrap_or_default();
        let selected: Vec<Port> = known
            .into_iter()
            .filter(|port| ports.is_empty() || ports.contains(&port.number))
            .collect();
        Ok(selected)
    }

    async fn read_banner(&self, host: IpAddr, port: u16) -> NetResult<Option<Service>> {
        let banners = &self.scenario.banners;
        let found = banners
            .iter()
            .find(|entry| entry.host == host && entry.port == port)
            .map(|entry| entry.service.clone());
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PortState;

    const FIXTURE: &str = include_str!("../../../testdata/mock/recon_simple.json");

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    #[tokio::test]
    async fn recon_complete_contre_le_mock() {
        let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();

        // Découverte : la fixture déclare 2 hôtes sur ce réseau.
        let hosts = provider.discover_hosts("192.168.1.0/24").await.unwrap();
        assert_eq!(hosts.len(), 2);

        // Scan de ports du serveur.
        let target = ip("192.168.1.10");
        let ports = provider.scan_ports(target, &[22, 80, 443]).await.unwrap();
        let ssh = ports.iter().find(|p| p.number == 22).unwrap();
        assert_eq!(ssh.state, PortState::Open);

        // Lecture de bannière → identification du service.
        let banner = provider.read_banner(target, 22).await.unwrap();
        assert_eq!(banner.unwrap().name, "ssh");
    }

    #[tokio::test]
    async fn mock_renvoie_exactement_les_fixtures() {
        let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();
        let ports = provider.scan_ports(ip("192.168.1.10"), &[]).await.unwrap();
        // Liste vide = tous les ports connus de la fixture (22 et 80).
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].number, 22);
        assert_eq!(ports[1].number, 80);
        assert_eq!(ports[1].state, PortState::Closed);
    }

    #[tokio::test]
    async fn reseau_ou_hote_inconnu_renvoie_vide() {
        let provider = MockNetworkProvider::new(MockScenario::default());
        let hosts = provider.discover_hosts("10.0.0.0/8").await.unwrap();
        let ports = provider.scan_ports(ip("10.0.0.1"), &[22]).await.unwrap();
        let banner = provider.read_banner(ip("10.0.0.1"), 22).await.unwrap();
        assert!(hosts.is_empty());
        assert!(ports.is_empty());
        assert!(banner.is_none());
    }

    // Prouve l'injectabilité en générique : toute impl de NetworkProvider convient.
    async fn compter_hotes<P: NetworkProvider>(provider: &P, network: &str) -> usize {
        provider.discover_hosts(network).await.unwrap().len()
    }

    #[tokio::test]
    async fn provider_injectable_en_generique_et_en_objet_de_trait() {
        let provider = MockNetworkProvider::from_json(FIXTURE).unwrap();
        assert_eq!(compter_hotes(&provider, "192.168.1.0/24").await, 2);

        // Injectable aussi en objet de trait (async-trait rend le trait object-safe).
        let dynamique: Box<dyn NetworkProvider> =
            Box::new(MockNetworkProvider::from_json(FIXTURE).unwrap());
        let hosts = dynamique.discover_hosts("192.168.1.0/24").await.unwrap();
        assert_eq!(hosts.len(), 2);
    }
}
