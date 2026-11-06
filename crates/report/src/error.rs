//! Erreurs du crate `report`.
//!
//! Aucun chemin de génération ne panique (lints de sûreté #27) : toute défaillance
//! — lecture de l'état d'engagement, (dé)sérialisation JSON, rendu de template —
//! remonte via ce type, converti depuis les erreurs sous-jacentes par `From`.

use std::fmt;

use nickmare_core::engagement::StoreError;

/// Erreur de génération d'un rapport.
#[derive(Debug)]
pub enum ReportError {
    /// Lecture de l'état d'engagement (store SQLite / mock) en échec.
    Store(StoreError),
    /// (Dé)sérialisation JSON du modèle de rapport en échec (US-H2).
    Json(serde_json::Error),
    /// Rendu d'un template HTML en échec (US-H1).
    Render(askama::Error),
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportError::Store(err) => write!(f, "lecture de l'engagement : {err}"),
            ReportError::Json(err) => write!(f, "export JSON : {err}"),
            ReportError::Render(err) => write!(f, "rendu HTML : {err}"),
        }
    }
}

impl std::error::Error for ReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReportError::Store(err) => Some(err),
            ReportError::Json(err) => Some(err),
            ReportError::Render(err) => Some(err),
        }
    }
}

impl From<StoreError> for ReportError {
    fn from(err: StoreError) -> Self {
        ReportError::Store(err)
    }
}

impl From<serde_json::Error> for ReportError {
    fn from(err: serde_json::Error) -> Self {
        ReportError::Json(err)
    }
}

impl From<askama::Error> for ReportError {
    fn from(err: askama::Error) -> Self {
        ReportError::Render(err)
    }
}
