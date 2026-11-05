//! Cache/miroir NVD **local** : persistance et rafraîchissement (issue #14,
//! décision 2 : API NVD **+** cache local ; US-C2 « fonctionne hors ligne »).
//!
//! Le cache est le format persistant de la [`CveDatabase`] ([`crate::model`]).
//! C'est la **seule** source lue par la corrélation : une fois peuplé, tout
//! fonctionne hors ligne ([`load_from_path`]). Le rafraîchissement
//! ([`refresh`]) est l'**unique** opération réseau, explicite, injectée via le
//! trait [`NvdClient`](crate::client::NvdClient) — donc testable sans réseau et
//! absente de la CI.

use std::path::Path;

use crate::client::{FeedQuery, NvdClient};
use crate::error::{CveError, CveResult};
use crate::model::CveDatabase;
use crate::nvd;

/// Charge la base/cache depuis un fichier JSON (schéma [`CveDatabase`]).
///
/// Erreur [`CveError::Io`] si le fichier est illisible, [`CveError::Parse`] s'il
/// est corrompu. Ne panique jamais (le cache local reste une entrée à valider).
pub fn load_from_path(path: impl AsRef<Path>) -> CveResult<CveDatabase> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CveError::Io(format!("{} : {e}", path.display())))?;
    load_from_str(&raw)
}

/// Désérialise une base/cache depuis une chaîne JSON (schéma [`CveDatabase`]).
pub fn load_from_str(json: &str) -> CveResult<CveDatabase> {
    serde_json::from_str(json).map_err(|e| CveError::Parse(e.to_string()))
}

/// Charge la base depuis `path`, ou une base **vide** si le fichier n'existe pas.
///
/// C'est le repli hors ligne le plus permissif : sans cache, la corrélation ne
/// renvoie simplement aucun constat plutôt que d'échouer. Un fichier présent mais
/// corrompu reste une erreur (on ne masque pas une base abîmée).
pub fn load_or_empty(path: impl AsRef<Path>) -> CveResult<CveDatabase> {
    let path = path.as_ref();
    if path.exists() {
        load_from_path(path)
    } else {
        Ok(CveDatabase::new())
    }
}

/// Écrit la base/cache dans un fichier JSON (indenté, schéma [`CveDatabase`]).
pub fn save_to_path(db: &CveDatabase, path: impl AsRef<Path>) -> CveResult<()> {
    let path = path.as_ref();
    let json = serde_json::to_string_pretty(db).map_err(|e| CveError::Parse(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| CveError::Io(format!("{} : {e}", path.display())))
}

/// **Rafraîchit** la base depuis NVD via le `client` injecté : récupère le flux
/// brut puis le parse défensivement ([`nvd::parse_feed`]).
///
/// C'est la seule opération qui touche le réseau (via l'implémentation réelle du
/// client, hors CI). Une erreur réseau est **propagée** telle quelle : l'appelant
/// choisit alors de conserver le cache existant (repli hors ligne). Le résultat
/// n'est pas écrit sur disque ici — c'est à l'appelant d'appeler [`save_to_path`]
/// s'il veut le persister.
pub async fn refresh<C>(client: &C, query: &FeedQuery) -> CveResult<CveDatabase>
where
    C: NvdClient + ?Sized,
{
    let raw = client.fetch_feed(query).await?;
    Ok(nvd::parse_feed(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::client::{OfflineNvdClient, StubNvdClient};
    use crate::correlate::correlate_service;
    use nickmare_core::model::Service;

    const CACHE: &str = include_str!("../../../testdata/cve/cache_sample.json");
    const FEED: &str = include_str!("../../../testdata/cve/nvd_feed_sample.json");

    fn ip(addr: &str) -> std::net::IpAddr {
        addr.parse().unwrap()
    }

    fn service(name: &str, product: &str, version: &str) -> Service {
        Service {
            name: name.to_string(),
            product: Some(product.to_string()),
            version: Some(version.to_string()),
            banner: None,
        }
    }

    #[test]
    fn charge_le_cache_local_et_correle_hors_ligne() {
        // US-C2 : tout le chemin de corrélation tient sur le cache, sans réseau.
        let db = load_from_str(CACHE).expect("cache local valide");
        assert!(!db.is_empty());
        let svc = service("ssh", "OpenSSH", "9.1");
        let findings = correlate_service(ip("192.168.56.10"), Some(22), &svc, &db);
        assert!(!findings.is_empty(), "le cache local doit suffire à corréler");
    }

    #[test]
    fn round_trip_disque() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nickmare-cve-cache-{}.json", std::process::id()));
        let db = load_from_str(CACHE).unwrap();
        save_to_path(&db, &path).expect("écriture");
        let reread = load_from_path(&path).expect("relecture");
        assert_eq!(db, reread);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fichier_absent_donne_une_base_vide_mais_corrompu_echoue() {
        let missing = std::env::temp_dir().join("nickmare-cve-inexistant-xyz.json");
        let _ = std::fs::remove_file(&missing);
        assert!(load_or_empty(&missing).unwrap().is_empty());
        // Un fichier corrompu n'est pas masqué.
        assert!(load_from_str("{ pas du json").is_err());
    }

    #[tokio::test]
    async fn refresh_via_stub_parse_le_flux_sans_reseau() {
        let client = StubNvdClient::new(FEED);
        let db = refresh(&client, &FeedQuery::for_keyword("openssh"))
            .await
            .expect("le stub renvoie un flux valide");
        assert!(!db.is_empty());
        assert!(db.records.iter().any(|r| r.id == "CVE-2023-38408"));
    }

    #[tokio::test]
    async fn refresh_hors_ligne_echoue_et_le_cache_reste_utilisable() {
        // Le réseau est absent : refresh échoue, mais le cache déjà chargé sert
        // toujours (repli hors ligne).
        let offline = OfflineNvdClient;
        let err = refresh(&offline, &FeedQuery::default()).await.unwrap_err();
        assert!(matches!(err, CveError::Network(_)));

        let db = load_from_str(CACHE).unwrap();
        let svc = service("ssh", "OpenSSH", "9.1");
        assert!(!correlate_service(ip("192.168.56.10"), Some(22), &svc, &db).is_empty());
    }

    #[tokio::test]
    async fn refresh_accepte_un_client_en_objet_de_trait() {
        // Prouve l'injectabilité en objet de trait (comme MockNetworkProvider).
        let client: Box<dyn NvdClient> = Box::new(StubNvdClient::new(FEED));
        let db = refresh(client.as_ref(), &FeedQuery::default()).await.unwrap();
        assert!(!db.is_empty());
    }
}
