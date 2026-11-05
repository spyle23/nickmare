//! Erreurs de la crate `cve` (issue #14).
//!
//! Volontairement **sans secret** : aucun message ne reproduit la clé API NVD ni
//! une donnée sensible (§12). Les erreurs réseau ne portent qu'un libellé
//! d'opération, jamais l'en-tête d'authentification.

use std::fmt;

/// Erreur d'une opération de la crate `cve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CveError {
    /// Lecture/écriture du cache local impossible.
    Io(String),
    /// Donnée (cache local ou flux) illisible.
    Parse(String),
    /// Échec de récupération en ligne (repli hors ligne attendu).
    Network(String),
}

impl fmt::Display for CveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CveError::Io(msg) => write!(f, "cache CVE inaccessible : {msg}"),
            CveError::Parse(msg) => write!(f, "donnée CVE illisible : {msg}"),
            CveError::Network(msg) => write!(f, "récupération NVD en ligne échouée : {msg}"),
        }
    }
}

impl std::error::Error for CveError {}

/// Résultat d'une opération de la crate `cve`.
pub type CveResult<T> = Result<T, CveError>;
