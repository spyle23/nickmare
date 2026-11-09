//! Mapping **statique (JSON)** des techniques MITRE ATT&CK émulables (N4, issue
//! #22, cf. `docs/ARCHITECTURE.md` §9 Phase 8, §11.3, US-G1/G2).
//!
//! # Un catalogue de métadonnées, pas d'exploits
//!
//! Ce module charge un **catalogue statique** (JSON embarqué à la compilation)
//! qui associe à chaque identifiant ATT&CK un **nom** et une **tactique**. Il ne
//! contient **aucune implémentation offensive** : uniquement des identifiants et
//! des libellés servant à annoter la matrice de couverture (`verdict.rs`).
//!
//! # La whitelist reste dans le gate
//!
//! Le catalogue **n'autorise rien** : savoir quelles techniques sont *exécutables*
//! est l'affaire exclusive du gate, qui ne laisse passer que les identifiants
//! listés dans `emulation.attack_techniques` du scope (§3.2, étape 3). Ce module
//! fournit seulement les métadonnées d'affichage ; une technique émise mais
//! absente du catalogue reste tracée (transparence opérateur), simplement sans
//! libellé enrichi.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Catalogue JSON embarqué à la compilation (identifiants ATT&CK + libellés).
const EMBEDDED_CATALOG: &str = include_str!("../techniques/attack_techniques.json");

// --- Erreur -----------------------------------------------------------------

/// Raison pour laquelle un catalogue de techniques est refusé (fail-safe §1 : un
/// catalogue mal formé ou incohérent est rejeté, jamais chargé « à moitié »).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    /// JSON syntaxiquement invalide ou champ obligatoire manquant.
    Parse(String),
    /// Deux entrées partagent le même identifiant ATT&CK.
    Duplicate(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogError::Parse(msg) => write!(f, "catalogue ATT&CK illisible : {msg}"),
            CatalogError::Duplicate(id) => {
                write!(f, "technique ATT&CK en double dans le catalogue : {id}")
            }
        }
    }
}

impl std::error::Error for CatalogError {}

// --- Métadonnées d'une technique --------------------------------------------

/// Métadonnées d'une technique ATT&CK : identifiant, nom et tactique. Aucune
/// implémentation — purement descriptif, pour annoter la matrice de couverture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechniqueInfo {
    /// Identifiant MITRE ATT&CK (ex. `"T1021"`), conservé en `String` (jamais une
    /// variante d'enum en majuscules, pour éviter `clippy::upper_case_acronyms`).
    pub id: String,
    /// Nom lisible (ex. `"Remote Services"`).
    pub name: String,
    /// Tactique ATT&CK (ex. `"Lateral Movement"`).
    pub tactic: String,
    /// Description courte, orientée test de détection.
    #[serde(default)]
    pub description: String,
}

/// Vue de désérialisation du fichier JSON (la version + la liste des techniques).
#[derive(Debug, Deserialize)]
struct CatalogFile {
    #[serde(default)]
    version: String,
    techniques: Vec<TechniqueInfo>,
}

// --- Catalogue --------------------------------------------------------------

/// Catalogue statique des techniques ATT&CK connues de Nickmare, indexé par
/// identifiant. Construit via [`TechniqueCatalog::embedded`] (catalogue par
/// défaut) ou [`TechniqueCatalog::from_json`] (catalogue fourni, pour les tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniqueCatalog {
    version: String,
    by_id: BTreeMap<String, TechniqueInfo>,
}

impl TechniqueCatalog {
    /// Charge le catalogue **embarqué** (JSON statique compilé dans le binaire).
    pub fn embedded() -> Result<Self, CatalogError> {
        Self::from_json(EMBEDDED_CATALOG)
    }

    /// Parse un catalogue depuis un texte JSON. Refuse un JSON mal formé ou un
    /// identifiant en double (fail-safe).
    pub fn from_json(json: &str) -> Result<Self, CatalogError> {
        let file: CatalogFile =
            serde_json::from_str(json).map_err(|e| CatalogError::Parse(e.to_string()))?;
        let mut by_id = BTreeMap::new();
        for info in file.techniques {
            let id = info.id.clone();
            if by_id.insert(id.clone(), info).is_some() {
                return Err(CatalogError::Duplicate(id));
            }
        }
        Ok(Self {
            version: file.version,
            by_id,
        })
    }

    /// Libellé de version du référentiel chargé.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Métadonnées d'une technique par identifiant, ou `None` si inconnue.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&TechniqueInfo> {
        self.by_id.get(id)
    }

    /// Vrai si l'identifiant figure au catalogue.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    /// Nombre de techniques au catalogue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Vrai si le catalogue est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Identifiants ATT&CK connus, dans l'ordre lexicographique (déterministe).
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.by_id.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_embarque_se_charge_et_est_non_vide() {
        let catalog = TechniqueCatalog::embedded().unwrap();
        assert!(!catalog.is_empty());
        assert!(catalog.len() >= 5);
        assert!(!catalog.version().is_empty());
    }

    #[test]
    fn lookup_rend_les_metadonnees_attendues() {
        let catalog = TechniqueCatalog::embedded().unwrap();
        let info = catalog.get("T1021").expect("T1021 au catalogue");
        assert_eq!(info.name, "Remote Services");
        assert_eq!(info.tactic, "Lateral Movement");
        assert!(catalog.contains("T1046"));
        assert!(!catalog.contains("T9999"));
        assert!(catalog.get("T9999").is_none());
    }

    #[test]
    fn identifiants_tries_lexicographiquement() {
        let catalog = TechniqueCatalog::embedded().unwrap();
        let ids: Vec<&str> = catalog.ids().collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "les identifiants doivent être triés");
    }

    #[test]
    fn json_malforme_refuse() {
        let err = TechniqueCatalog::from_json("ceci n'est pas du json").unwrap_err();
        assert!(matches!(err, CatalogError::Parse(_)), "{err}");
    }

    #[test]
    fn identifiant_en_double_refuse() {
        let json = r#"{
            "version": "test",
            "techniques": [
                { "id": "T1021", "name": "A", "tactic": "X" },
                { "id": "T1021", "name": "B", "tactic": "Y" }
            ]
        }"#;
        let err = TechniqueCatalog::from_json(json).unwrap_err();
        assert_eq!(err, CatalogError::Duplicate("T1021".to_string()));
    }

    #[test]
    fn description_absente_tolere_defaut_vide() {
        let json = r#"{
            "version": "test",
            "techniques": [
                { "id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery" }
            ]
        }"#;
        let catalog = TechniqueCatalog::from_json(json).unwrap();
        let info = catalog.get("T1046").unwrap();
        assert_eq!(info.description, "");
    }
}
