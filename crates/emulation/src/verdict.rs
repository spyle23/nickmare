//! Collecte des **verdicts de détection** (blue team), calcul du **MTTD** et
//! **matrice de couverture ATT&CK** croisée avec le profil (N4, issue #22, cf.
//! `docs/ARCHITECTURE.md` §9 Phase 8, §11.3, US-G2/G3).
//!
//! # Du verdict au MTTD
//!
//! Une [`AttackExecution`](nickmare_core::model::AttackExecution) est d'abord
//! tracée côté opérateur (horodatage `performed_at`, détection `Unknown`). La blue
//! team renseigne ensuite un [`DetectionReport`] (détecté / non / partiel +
//! horodatage d'alerte). [`apply_verdict`] reporte ce verdict sur l'exécution, et
//! [`mttd`] en déduit le **délai de détection** = `detected_at - performed_at`.
//!
//! # Matrice de couverture
//!
//! [`CoverageMatrix::build`] croise les exécutions avec le catalogue ATT&CK et le
//! profil : pour chaque technique, le verdict, le MTTD et la tactique. Elle
//! s'exporte en JSON ([`CoverageMatrix::to_json`]) et en représentation
//! structurée ([`CoverageMatrix::render_text`]), et permet de **comparer les taux
//! de détection entre profils** ([`CoverageMatrix::compare_profiles`], US-G3).

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use nickmare_core::model::{AdversaryProfile, AttackExecution, DetectionVerdict};

use crate::profile::profile_label;
use crate::techniques::TechniqueCatalog;

// --- Verdict de la blue team ------------------------------------------------

/// Verdict de détection renseigné par la blue team pour une technique émise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionReport {
    /// Détecté / non détecté / partiel / inconnu.
    pub verdict: DetectionVerdict,
    /// Horodatage de l'alerte côté défense (→ MTTD). `None` si non détecté.
    pub detected_at: Option<DateTime<Utc>>,
    /// Contrôle/outil ayant alerté (ex. `"Suricata"`, `"EDR"`).
    pub detected_by: Option<String>,
    /// Note libre de la blue team.
    pub notes: Option<String>,
}

impl DetectionReport {
    /// Verdict « non détecté » (aucune alerte).
    #[must_use]
    pub fn not_detected() -> Self {
        Self {
            verdict: DetectionVerdict::NotDetected,
            detected_at: None,
            detected_by: None,
            notes: None,
        }
    }

    /// Verdict « détecté » à `at` par `by`.
    #[must_use]
    pub fn detected(at: DateTime<Utc>, by: impl Into<String>) -> Self {
        Self {
            verdict: DetectionVerdict::Detected,
            detected_at: Some(at),
            detected_by: Some(by.into()),
            notes: None,
        }
    }

    /// Verdict « partiellement détecté » à `at` par `by`.
    #[must_use]
    pub fn partial(at: DateTime<Utc>, by: impl Into<String>) -> Self {
        Self {
            verdict: DetectionVerdict::Partial,
            detected_at: Some(at),
            detected_by: Some(by.into()),
            notes: None,
        }
    }

    /// Attache une note de la blue team (chaînage de construction).
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// Reporte un verdict de la blue team sur une exécution déjà tracée. Ne touche
/// **pas** à l'horodatage opérateur (`performed_at`, en clair) : on n'ajoute que
/// l'information de détection.
pub fn apply_verdict(execution: &mut AttackExecution, report: &DetectionReport) {
    execution.detection = report.verdict;
    execution.detected_at = report.detected_at;
    execution.detected_by = report.detected_by.clone();
    if let Some(notes) = &report.notes {
        execution.notes = Some(notes.clone());
    }
}

/// **MTTD** d'une exécution : délai entre l'horodatage opérateur (`performed_at`)
/// et l'alerte blue team (`detected_at`).
///
/// Renvoie `None` si la technique n'a pas été détectée, s'il manque l'horodatage
/// d'alerte, ou si l'alerte précède l'action (incohérent → `None`, fail-safe).
#[must_use]
pub fn mttd(execution: &AttackExecution) -> Option<TimeDelta> {
    let detected_at = execution.detected_at?;
    match execution.detection {
        DetectionVerdict::Detected | DetectionVerdict::Partial => {
            if detected_at < execution.performed_at {
                None
            } else {
                Some(detected_at - execution.performed_at)
            }
        }
        DetectionVerdict::NotDetected | DetectionVerdict::Unknown => None,
    }
}

// --- Matrice de couverture ATT&CK -------------------------------------------

/// Vrai si un verdict compte comme (au moins partiellement) détecté.
fn is_detected(verdict: DetectionVerdict) -> bool {
    verdict == DetectionVerdict::Detected || verdict == DetectionVerdict::Partial
}

/// Libellé stable d'un verdict de détection, pour l'affichage.
fn verdict_label(verdict: DetectionVerdict) -> &'static str {
    match verdict {
        DetectionVerdict::Detected => "detected",
        DetectionVerdict::NotDetected => "not-detected",
        DetectionVerdict::Partial => "partial",
        DetectionVerdict::Unknown => "unknown",
    }
}

/// Une cellule de la matrice : une technique émise, son profil et son verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageCell {
    /// Identifiant ATT&CK émis.
    pub technique_id: String,
    /// Nom de la technique (du catalogue, ou libellé « inconnue »).
    pub technique_name: String,
    /// Tactique ATT&CK.
    pub tactic: String,
    /// Profil d'adversaire rejoué.
    pub profile: AdversaryProfile,
    /// Verdict de détection de la blue team.
    pub detection: DetectionVerdict,
    /// MTTD en secondes (si détecté et calculable).
    pub mttd_seconds: Option<i64>,
    /// Contrôle/outil ayant alerté.
    pub detected_by: Option<String>,
}

/// Matrice de couverture ATT&CK : une cellule par exécution. Exportable en JSON
/// (US-G2) et comparable entre profils (US-G3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageMatrix {
    pub cells: Vec<CoverageCell>,
}

/// Statistiques de détection pour un profil : décompte des verdicts, taux de
/// détection et MTTD moyen. Permet la **comparaison entre profils** (US-G3).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DetectionStats {
    pub profile: AdversaryProfile,
    pub total: usize,
    pub detected: usize,
    pub partial: usize,
    pub not_detected: usize,
    pub unknown: usize,
    /// Part des techniques au moins partiellement détectées (0.0..=1.0).
    pub detection_rate: f64,
    /// MTTD moyen (secondes) sur les techniques détectées, si au moins une l'est.
    pub mean_mttd_seconds: Option<i64>,
}

impl CoverageMatrix {
    /// Construit la matrice en croisant les exécutions avec le catalogue ATT&CK.
    /// Une technique absente du catalogue reste présente (transparence), avec un
    /// libellé « inconnue ».
    #[must_use]
    pub fn build(executions: &[AttackExecution], catalog: &TechniqueCatalog) -> Self {
        let mut cells = Vec::with_capacity(executions.len());
        for exec in executions {
            let name = match catalog.get(&exec.technique_id) {
                Some(info) => info.name.clone(),
                None => "(inconnue du catalogue)".to_string(),
            };
            let tactic = match catalog.get(&exec.technique_id) {
                Some(info) => info.tactic.clone(),
                None => "(inconnu)".to_string(),
            };
            cells.push(CoverageCell {
                technique_id: exec.technique_id.clone(),
                technique_name: name,
                tactic,
                profile: exec.profile,
                detection: exec.detection,
                mttd_seconds: mttd(exec).map(|d| d.num_seconds()),
                detected_by: exec.detected_by.clone(),
            });
        }
        Self { cells }
    }

    /// Nombre de cellules (exécutions).
    #[must_use]
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// Vrai si la matrice est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Export JSON indenté et déterministe (US-G2).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Taux de détection **global** (toutes cellules, détecté + partiel comptés).
    #[must_use]
    pub fn detection_rate(&self) -> f64 {
        let total = self.cells.len();
        if total == 0 {
            return 0.0;
        }
        let mut detected = 0usize;
        for cell in &self.cells {
            if is_detected(cell.detection) {
                detected += 1;
            }
        }
        detected as f64 / total as f64
    }

    /// Statistiques de détection pour un profil donné (une passe).
    #[must_use]
    pub fn stats_for(&self, profile: AdversaryProfile) -> DetectionStats {
        let mut total = 0usize;
        let mut detected = 0usize;
        let mut partial = 0usize;
        let mut not_detected = 0usize;
        let mut unknown = 0usize;
        let mut mttd_sum = 0i64;
        let mut mttd_count = 0usize;
        for cell in self.cells.iter().filter(|c| c.profile == profile) {
            total += 1;
            match cell.detection {
                DetectionVerdict::Detected => detected += 1,
                DetectionVerdict::Partial => partial += 1,
                DetectionVerdict::NotDetected => not_detected += 1,
                DetectionVerdict::Unknown => unknown += 1,
            }
            if let Some(seconds) = cell.mttd_seconds {
                mttd_sum += seconds;
                mttd_count += 1;
            }
        }
        let detection_rate = if total == 0 {
            0.0
        } else {
            (detected + partial) as f64 / total as f64
        };
        let mean_mttd_seconds = if mttd_count == 0 {
            None
        } else {
            Some(mttd_sum / mttd_count as i64)
        };
        DetectionStats {
            profile,
            total,
            detected,
            partial,
            not_detected,
            unknown,
            detection_rate,
            mean_mttd_seconds,
        }
    }

    /// Comparaison des taux de détection **entre profils** présents dans la
    /// matrice, dans l'ordre `noisy → balanced → stealth` (US-G3).
    #[must_use]
    pub fn compare_profiles(&self) -> Vec<DetectionStats> {
        const PROFILES: [AdversaryProfile; 3] = [
            AdversaryProfile::Noisy,
            AdversaryProfile::Balanced,
            AdversaryProfile::Stealth,
        ];
        let mut out = Vec::new();
        for profile in PROFILES {
            let stats = self.stats_for(profile);
            if stats.total > 0 {
                out.push(stats);
            }
        }
        out
    }

    /// Représentation **structurée** (une ligne par technique) pour le rapport.
    #[must_use]
    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        // Écrire dans une `String` est infaillible ; le `Result` est ignoré à
        // dessein (même idiome que `core::scope::to_hex`).
        let _ = writeln!(
            out,
            "Matrice de couverture ATT&CK ({} technique(s))",
            self.len()
        );
        for cell in &self.cells {
            let mttd_label = match cell.mttd_seconds {
                Some(seconds) => format!("{seconds}s"),
                None => "-".to_string(),
            };
            let by = cell.detected_by.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "{} {} [{}] profil={} détection={} MTTD={} par={}",
                cell.technique_id,
                cell.technique_name,
                cell.tactic,
                profile_label(cell.profile),
                verdict_label(cell.detection),
                mttd_label,
                by
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use chrono::TimeZone;

    fn ip() -> IpAddr {
        "192.168.10.25".parse().unwrap()
    }

    fn at(hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
        let dt = Utc.with_ymd_and_hms(2026, 6, 1, hour, minute, second);
        dt.unwrap()
    }

    fn execution(technique: &str, profile: AdversaryProfile) -> AttackExecution {
        AttackExecution {
            technique_id: technique.to_string(),
            host: ip(),
            profile,
            performed_at: at(12, 0, 0),
            detection: DetectionVerdict::Unknown,
            detected_at: None,
            detected_by: None,
            notes: None,
        }
    }

    #[test]
    fn mttd_calcule_le_delai_depuis_l_horodatage_d_alerte() {
        let mut exec = execution("T1021", AdversaryProfile::Stealth);
        let report = DetectionReport::detected(at(12, 1, 0), "Suricata");
        apply_verdict(&mut exec, &report);
        let delay = mttd(&exec).expect("détecté → MTTD calculable");
        assert_eq!(delay.num_seconds(), 60);
        assert_eq!(exec.detected_by.as_deref(), Some("Suricata"));
    }

    #[test]
    fn mttd_absent_si_non_detecte() {
        let mut exec = execution("T1021", AdversaryProfile::Stealth);
        apply_verdict(&mut exec, &DetectionReport::not_detected());
        assert!(mttd(&exec).is_none(), "non détecté → pas de MTTD");
        assert_eq!(exec.detection, DetectionVerdict::NotDetected);
    }

    #[test]
    fn mttd_absent_si_alerte_anterieure_a_l_action() {
        // Fail-safe : une alerte « avant » l'action est incohérente → pas de MTTD.
        let mut exec = execution("T1021", AdversaryProfile::Noisy);
        let report = DetectionReport::detected(at(11, 0, 0), "EDR");
        apply_verdict(&mut exec, &report);
        assert!(mttd(&exec).is_none());
    }

    #[test]
    fn mttd_partiel_est_calcule() {
        let mut exec = execution("T1046", AdversaryProfile::Balanced);
        let report = DetectionReport::partial(at(12, 0, 30), "SIEM");
        apply_verdict(&mut exec, &report);
        assert_eq!(mttd(&exec).map(|d| d.num_seconds()), Some(30));
    }

    #[test]
    fn matrice_croise_technique_profil_et_verdict() {
        let catalog = TechniqueCatalog::embedded().unwrap();
        let mut noisy = execution("T1021", AdversaryProfile::Noisy);
        let report = DetectionReport::detected(at(12, 0, 10), "EDR");
        apply_verdict(&mut noisy, &report);
        let stealth = execution("T1021", AdversaryProfile::Stealth); // Unknown

        let matrix = CoverageMatrix::build(&[noisy, stealth], &catalog);
        assert_eq!(matrix.len(), 2);
        assert!(!matrix.is_empty());

        let json = matrix.to_json().unwrap();
        assert!(json.contains("T1021"));
        assert!(json.contains("Remote Services"));
        assert!(json.contains("Lateral Movement"));

        // Représentation structurée lisible.
        let text = matrix.render_text();
        assert!(text.contains("T1021"));
        assert!(text.contains("profil=noisy"));
        assert!(text.contains("profil=stealth"));
    }

    #[test]
    fn technique_absente_du_catalogue_reste_tracee() {
        let catalog = TechniqueCatalog::embedded().unwrap();
        let exec = execution("T9999", AdversaryProfile::Stealth);
        let matrix = CoverageMatrix::build(&[exec], &catalog);
        assert_eq!(matrix.len(), 1);
        assert!(matrix.cells[0].technique_name.contains("inconnue"));
    }

    #[test]
    fn comparaison_des_taux_de_detection_entre_profils() {
        let catalog = TechniqueCatalog::embedded().unwrap();
        // Noisy : détecté. Stealth : non détecté. Le taux doit différer.
        let mut noisy = execution("T1021", AdversaryProfile::Noisy);
        let report = DetectionReport::detected(at(12, 0, 20), "EDR");
        apply_verdict(&mut noisy, &report);
        let mut stealth = execution("T1570", AdversaryProfile::Stealth);
        apply_verdict(&mut stealth, &DetectionReport::not_detected());

        let matrix = CoverageMatrix::build(&[noisy, stealth], &catalog);

        let noisy_stats = matrix.stats_for(AdversaryProfile::Noisy);
        assert_eq!(noisy_stats.detected, 1);
        assert!((noisy_stats.detection_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(noisy_stats.mean_mttd_seconds, Some(20));

        let stealth_stats = matrix.stats_for(AdversaryProfile::Stealth);
        assert_eq!(stealth_stats.not_detected, 1);
        assert!(stealth_stats.detection_rate.abs() < f64::EPSILON);

        // L'évasion stealth passe mieux : taux de détection strictement inférieur.
        assert!(stealth_stats.detection_rate < noisy_stats.detection_rate);

        let comparison = matrix.compare_profiles();
        assert_eq!(comparison.len(), 2);
        // Ordre stable : noisy avant stealth.
        assert_eq!(comparison[0].profile, AdversaryProfile::Noisy);
        assert_eq!(comparison[1].profile, AdversaryProfile::Stealth);
    }

    #[test]
    fn matrice_vide_a_un_taux_nul() {
        let matrix = CoverageMatrix { cells: Vec::new() };
        assert!(matrix.is_empty());
        assert!(matrix.detection_rate().abs() < f64::EPSILON);
        assert!(matrix.compare_profiles().is_empty());
    }
}
