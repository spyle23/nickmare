//! Abstraction **injectable** du client NVD en ligne (issue #14, cf.
//! `docs/ARCHITECTURE.md` §4, §5, §12 ; décision 2 : API NVD **+** cache local).
//!
//! # Pourquoi une abstraction
//!
//! La corrélation ([`crate::correlate`]) fonctionne entièrement **hors ligne** sur
//! le cache local : elle n'appelle **jamais** le réseau. Le seul point qui touche
//! Internet est le **rafraîchissement explicite** du cache ([`crate::cache::refresh`]).
//! Pour que la CI reste **sans réseau** (et par principe de testabilité, §10.2),
//! ce point passe par le trait [`NvdClient`], exactement comme la couche réseau
//! passe par [`NetworkProvider`](nickmare_core::traits::NetworkProvider) :
//!
//! - en test, on injecte un client **bouchonné** ([`StubNvdClient`],
//!   [`OfflineNvdClient`]) qui rejoue une réponse scriptée ou simule l'absence de
//!   réseau — aucune socket ouverte ;
//! - l'implémentation réseau réelle (client HTTP `reqwest` vers l'API NVD 2.0,
//!   avec la clé API en en-tête) est une opération **hors CI**, branchée derrière
//!   ce même trait. Elle n'est pas compilée ici pour garder l'arbre de
//!   dépendances léger et MSRV-safe (toolchain épinglée 1.83, sans Cargo.lock).
//!
//! # Clé API — jamais en clair (§12)
//!
//! La clé API NVD se lit **uniquement** depuis l'environnement
//! ([`api_key_from_env`]) ; elle n'est jamais committée, jamais journalisée, et
//! son type [`ApiKey`] **masque** sa valeur à l'affichage `Debug`.

use std::fmt;

use async_trait::async_trait;

use crate::error::CveResult;

/// Variable d'environnement portant la clé API NVD (§12).
pub const API_KEY_ENV: &str = "NVD_API_KEY";

/// Paramètres d'un lot de flux NVD à récupérer. Minimal et sans secret : la clé
/// API n'y figure pas (elle est ajoutée par l'implémentation réelle, en en-tête).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedQuery {
    /// Filtre par mot-clé (produit), le cas échéant.
    pub keyword: Option<String>,
    /// Pagination : nombre de résultats par page (`0` = défaut du serveur).
    pub results_per_page: u32,
}

impl FeedQuery {
    /// Requête ciblant un produit par mot-clé.
    #[must_use]
    pub fn for_keyword(keyword: impl Into<String>) -> Self {
        Self {
            keyword: Some(keyword.into()),
            results_per_page: 0,
        }
    }
}

/// Abstraction du client NVD en ligne : récupère un **lot brut** du flux (JSON,
/// format API 2.0) qui sera parsé défensivement par [`crate::nvd::parse_feed`].
///
/// `Send + Sync` et objet-sûr (`Box<dyn NvdClient>`) pour l'usage concurrent et
/// l'injection, comme les autres traits du projet.
#[async_trait]
pub trait NvdClient: Send + Sync {
    /// Récupère le flux NVD correspondant à `query`. L'implémentation réelle fait
    /// une requête HTTP ; les bouchons renvoient une réponse scriptée ou une
    /// erreur réseau, sans aucune I/O.
    async fn fetch_feed(&self, query: &FeedQuery) -> CveResult<String>;
}

/// Client bouchonné rejouant une **réponse scriptée** (JSON NVD), sans réseau.
/// Injecté dans les tests pour prouver le chemin de rafraîchissement.
#[derive(Debug, Clone)]
pub struct StubNvdClient {
    response: String,
}

impl StubNvdClient {
    /// Bouchon renvoyant toujours `response` (un flux NVD JSON).
    #[must_use]
    pub fn new(response: impl Into<String>) -> Self {
        Self {
            response: response.into(),
        }
    }
}

#[async_trait]
impl NvdClient for StubNvdClient {
    async fn fetch_feed(&self, _query: &FeedQuery) -> CveResult<String> {
        Ok(self.response.clone())
    }
}

/// Client bouchonné simulant l'**absence de réseau** : échoue toujours. Sert à
/// prouver que le rafraîchissement dégrade proprement et que la corrélation
/// continue sur le cache local (repli hors ligne, US-C2).
#[derive(Debug, Clone, Default)]
pub struct OfflineNvdClient;

#[async_trait]
impl NvdClient for OfflineNvdClient {
    async fn fetch_feed(&self, _query: &FeedQuery) -> CveResult<String> {
        Err(crate::error::CveError::Network(
            "aucun réseau disponible".to_string(),
        ))
    }
}

// --- Clé API (jamais en clair) ----------------------------------------------

/// Clé API NVD. Son type **masque** la valeur à l'affichage `Debug` pour éviter
/// toute fuite accidentelle dans les logs (§12).
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey(String);

impl ApiKey {
    /// Expose la valeur (pour construire l'en-tête HTTP). À ne jamais journaliser.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Masque la valeur : jamais de secret en clair, même en débogage.
        f.write_str("ApiKey(***)")
    }
}

/// Lit la clé API NVD depuis l'environnement ([`API_KEY_ENV`]), ou `None` si elle
/// est absente ou vide. Jamais committée, jamais journalisée (§12).
#[must_use]
pub fn api_key_from_env() -> Option<ApiKey> {
    sanitize_api_key(std::env::var(API_KEY_ENV).ok())
}

/// Nettoie une clé brute : `None` / vide / blancs → `None` ; sinon rognée.
/// Extrait pur (sans I/O) pour être testé sans toucher à l'environnement global.
fn sanitize_api_key(raw: Option<String>) -> Option<ApiKey> {
    let value = raw?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(ApiKey(trimmed.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_rejoue_la_reponse_sans_reseau() {
        let client = StubNvdClient::new(r#"{"vulnerabilities": []}"#);
        let feed = client.fetch_feed(&FeedQuery::default()).await.unwrap();
        assert!(feed.contains("vulnerabilities"));
    }

    #[tokio::test]
    async fn client_hors_ligne_echoue_proprement() {
        let client = OfflineNvdClient;
        let err = client
            .fetch_feed(&FeedQuery::for_keyword("openssh"))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::CveError::Network(_)));
    }

    #[test]
    fn cle_api_absente_ou_vide_est_ignoree() {
        assert!(sanitize_api_key(None).is_none());
        assert!(sanitize_api_key(Some(String::new())).is_none());
        assert!(sanitize_api_key(Some("   ".to_string())).is_none());
        let key = sanitize_api_key(Some("  abc123  ".to_string())).unwrap();
        assert_eq!(key.as_str(), "abc123");
    }

    #[test]
    fn cle_api_ne_fuite_pas_en_debug() {
        let key = ApiKey("super-secret-token".to_string());
        let shown = format!("{key:?}");
        assert!(!shown.contains("super-secret-token"));
        assert_eq!(shown, "ApiKey(***)");
    }
}
