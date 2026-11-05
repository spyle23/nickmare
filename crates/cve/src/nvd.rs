//! Lecture **défensive** du flux NVD (format API 2.0) vers la base locale
//! (issue #14, cf. `docs/ARCHITECTURE.md` §10.1 « parsing de réponses CVE », §12).
//!
//! Le flux NVD est une **donnée externe** : qu'il vienne de l'API en ligne ou
//! d'un miroir téléchargé, il est traité comme **hostile** (§12). Le parsing ne
//! fait donc **aucune** hypothèse de présence de champ : tout est optionnel et
//! `#[serde(default)]`, aucun `unwrap` sur la donnée, et un objet mal formé est
//! **ignoré** plutôt que de faire échouer tout le lot (dégradation propre).
//!
//! On en extrait une forme réduite ([`CveDatabase`]) : pour chaque vulnérabilité,
//! l'identifiant, une description, le meilleur score CVSS disponible (v3.1 → v3.0
//! → v2), et la liste des produits/versions affectés tirée des `cpeMatch`.

use serde::Deserialize;

use crate::model::{AffectedProduct, Cvss, CveDatabase, CveRecord};
use crate::version::VersionRange;

// --- Miroir *lâche* du JSON NVD (tout optionnel, rien d'obligatoire) --------

/// Enveloppe de la réponse NVD 2.0 : `{ "vulnerabilities": [ { "cve": … } ] }`.
#[derive(Debug, Default, Deserialize)]
struct NvdFeed {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdVulnerability {
    #[serde(default)]
    cve: Option<NvdCve>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdCve {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    configurations: Vec<NvdConfiguration>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdDescription {
    #[serde(default)]
    lang: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdMetrics {
    #[serde(default)]
    #[serde(rename = "cvssMetricV31")]
    v31: Vec<NvdMetric>,
    #[serde(default)]
    #[serde(rename = "cvssMetricV30")]
    v30: Vec<NvdMetric>,
    #[serde(default)]
    #[serde(rename = "cvssMetricV2")]
    v2: Vec<NvdMetric>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdMetric {
    #[serde(default)]
    #[serde(rename = "cvssData")]
    cvss_data: Option<NvdCvssData>,
    #[serde(default)]
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdCvssData {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    #[serde(rename = "vectorString")]
    vector_string: Option<String>,
    #[serde(default)]
    #[serde(rename = "baseScore")]
    base_score: Option<f64>,
    #[serde(default)]
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdConfiguration {
    #[serde(default)]
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdNode {
    #[serde(default)]
    #[serde(rename = "cpeMatch")]
    cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Default, Deserialize)]
struct NvdCpeMatch {
    #[serde(default)]
    vulnerable: Option<bool>,
    #[serde(default)]
    criteria: Option<String>,
    #[serde(default)]
    #[serde(rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(default)]
    #[serde(rename = "versionStartExcluding")]
    version_start_excluding: Option<String>,
    #[serde(default)]
    #[serde(rename = "versionEndIncluding")]
    version_end_including: Option<String>,
    #[serde(default)]
    #[serde(rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

// --- Conversion défensive vers la base locale -------------------------------

/// Analyse un flux NVD (JSON, format API 2.0) en une [`CveDatabase`].
///
/// - Un JSON invalide renvoie une base **vide** (jamais d'erreur propagée ni de
///   panique) : le repli hors ligne reste possible sur le cache déjà présent.
/// - Les vulnérabilités sans identifiant, ou dont aucun `cpeMatch` exploitable ne
///   ressort, sont **ignorées** (une CVE sans produit corrélable n'aide pas et
///   risque le faux positif).
#[must_use]
pub fn parse_feed(json: &str) -> CveDatabase {
    let feed: NvdFeed = serde_json::from_str(json).unwrap_or_default();
    let mut records = Vec::new();
    for vuln in feed.vulnerabilities {
        if let Some(record) = vuln.cve.and_then(to_record) {
            records.push(record);
        }
    }
    CveDatabase {
        refreshed_at: None,
        records,
    }
}

/// Convertit une CVE NVD en [`CveRecord`], ou `None` si elle est inexploitable
/// (pas d'identifiant, ou aucun produit affecté lisible).
fn to_record(cve: NvdCve) -> Option<CveRecord> {
    let id = cve.id.filter(|s| !s.trim().is_empty())?;
    let affected = collect_affected(&cve.configurations);
    if affected.is_empty() {
        return None;
    }
    Some(CveRecord {
        id,
        description: best_description(&cve.descriptions),
        cvss: best_cvss(&cve.metrics),
        affected,
        published: cve.published,
        last_modified: cve.last_modified,
    })
}

/// Description en anglais si disponible, sinon la première non vide, sinon `""`.
fn best_description(descriptions: &[NvdDescription]) -> String {
    let pick = descriptions
        .iter()
        .find(|d| d.lang.as_deref() == Some("en") && has_text(&d.value))
        .or_else(|| descriptions.iter().find(|d| has_text(&d.value)));
    pick.and_then(|d| d.value.clone()).unwrap_or_default()
}

/// Meilleur CVSS disponible : v3.1, puis v3.0, puis v2 (ordre de préférence NVD).
fn best_cvss(metrics: &NvdMetrics) -> Cvss {
    for group in [&metrics.v31, &metrics.v30, &metrics.v2] {
        if let Some(metric) = group.first() {
            return metric_to_cvss(metric);
        }
    }
    // Aucune métrique : score neutre (ne vaut pas 0 arbitrairement une gravité
    // élevée). `Info` par défaut via `Cvss::new(0.0)`.
    Cvss::new(0.0)
}

/// Convertit une métrique NVD en [`Cvss`] borné (score `[0, 10]`).
fn metric_to_cvss(metric: &NvdMetric) -> Cvss {
    let data = metric.cvss_data.as_ref();
    let base_score = data.and_then(|d| d.base_score).map_or(0.0, |s| s as f32);
    let mut cvss = Cvss::new(base_score);
    // La gravité peut figurer dans `cvssData` (v3) ou directement sur la métrique
    // (v2 historique) ; on prend la première renseignée.
    cvss.base_severity = data
        .and_then(|d| d.base_severity.clone())
        .or_else(|| metric.base_severity.clone())
        .filter(|s| !s.trim().is_empty());
    cvss.vector = data
        .and_then(|d| d.vector_string.clone())
        .filter(|s| !s.trim().is_empty());
    cvss.metric_version = data
        .and_then(|d| d.version.clone())
        .filter(|s| !s.trim().is_empty());
    cvss
}

/// Rassemble les produits affectés de toutes les configurations/noeuds.
fn collect_affected(configurations: &[NvdConfiguration]) -> Vec<AffectedProduct> {
    let mut out = Vec::new();
    for config in configurations {
        for node in &config.nodes {
            for cpe in &node.cpe_match {
                // Un `cpeMatch` explicitement non vulnérable est ignoré ; absent,
                // on le considère vulnérable (cas usuel d'un noeud de configuration).
                if cpe.vulnerable == Some(false) {
                    continue;
                }
                if let Some(affected) = cpe_to_affected(cpe) {
                    out.push(affected);
                }
            }
        }
    }
    out
}

/// Convertit un `cpeMatch` en [`AffectedProduct`], ou `None` si le CPE n'offre pas
/// de produit lisible **ou** aucune contrainte de version (anti-faux-positif : on
/// ne retient pas un produit sans la moindre borne).
fn cpe_to_affected(cpe: &NvdCpeMatch) -> Option<AffectedProduct> {
    let (vendor, product, cpe_version) = parse_cpe(cpe.criteria.as_deref()?)?;

    let mut range = VersionRange {
        start_including: non_wildcard(&cpe.version_start_including),
        start_excluding: non_wildcard(&cpe.version_start_excluding),
        end_including: non_wildcard(&cpe.version_end_including),
        end_excluding: non_wildcard(&cpe.version_end_excluding),
        ..VersionRange::default()
    };
    // Une version concrète dans le CPE lui-même (≠ `*`/`-`) et sans borne séparée
    // devient une correspondance exacte.
    if range.is_unbounded() {
        range.exact = cpe_version;
    }
    if range.is_unbounded() {
        return None;
    }

    Some(AffectedProduct {
        product,
        vendor: Some(vendor).filter(|v| !v.is_empty()),
        aliases: Vec::new(),
        range,
    })
}

/// Extrait `(vendor, product, version)` d'un CPE 2.3
/// (`cpe:2.3:a:vendor:product:version:…`), en minuscules. `None` si la chaîne
/// n'a pas la forme attendue ou si le produit est vide/générique (`*`).
fn parse_cpe(criteria: &str) -> Option<(String, String, Option<String>)> {
    let parts: Vec<&str> = criteria.split(':').collect();
    // cpe:2.3:part:vendor:product:version:… → au moins 6 segments.
    if parts.len() < 6 || parts[0] != "cpe" {
        return None;
    }
    let vendor = parts[3].trim().to_ascii_lowercase();
    let product = parts[4].trim().to_ascii_lowercase();
    if product.is_empty() || product == "*" || product == "-" {
        return None;
    }
    let version = parts
        .get(5)
        .map(|v| v.trim())
        .filter(|v| !v.is_empty() && *v != "*" && *v != "-")
        .map(str::to_string);
    Some((vendor, product, version))
}

/// Normalise une borne optionnelle : vide / `*` / `-` → `None`.
fn non_wildcard(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && *v != "*" && *v != "-")
        .map(str::to_string)
}

/// Vrai si une valeur optionnelle contient du texte non vide.
fn has_text(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../testdata/cve/nvd_feed_sample.json");

    #[test]
    fn parse_fixture_nvd_produit_une_base_exploitable() {
        let db = parse_feed(SAMPLE);
        assert!(!db.is_empty(), "la fixture NVD doit produire des CVE");
        let ssh = db
            .records
            .iter()
            .find(|r| r.id == "CVE-2023-38408")
            .expect("CVE OpenSSH présente");
        assert!((ssh.cvss.base_score - 9.8).abs() < 0.01);
        assert_eq!(ssh.cvss.base_severity.as_deref(), Some("CRITICAL"));
        let affected = ssh.affected.first().expect("un produit affecté");
        assert_eq!(affected.product, "openssh");
        assert_eq!(affected.range.end_excluding.as_deref(), Some("9.3p2"));
    }

    #[test]
    fn json_invalide_donne_une_base_vide_sans_paniquer() {
        assert!(parse_feed("").is_empty());
        assert!(parse_feed("ce n'est pas du json").is_empty());
        assert!(parse_feed("{").is_empty());
        assert!(parse_feed("null").is_empty());
        assert!(parse_feed("[]").is_empty());
        // Structure valide mais vide.
        assert!(parse_feed(r#"{"vulnerabilities": []}"#).is_empty());
    }

    #[test]
    fn cve_sans_id_ou_sans_produit_est_ignoree() {
        let json = r#"{
            "vulnerabilities": [
                { "cve": { "descriptions": [{"lang":"en","value":"pas d'id"}] } },
                { "cve": { "id": "CVE-0000-0001", "configurations": [] } },
                { "cve": { "id": "   " } }
            ]
        }"#;
        assert!(parse_feed(json).is_empty());
    }

    #[test]
    fn cpe_sans_version_ni_borne_est_ignore() {
        // Produit générique sans aucune borne : ne doit pas produire de match.
        let json = r#"{
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-0000-0002",
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [
                                {"vulnerable": true, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}
                            ]
                        }]
                    }]
                }
            }]
        }"#;
        assert!(parse_feed(json).is_empty());
    }

    #[test]
    fn cpe_non_vulnerable_est_exclu() {
        let json = r#"{
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-0000-0003",
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [
                                {"vulnerable": false, "criteria": "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"}
                            ]
                        }]
                    }]
                }
            }]
        }"#;
        assert!(parse_feed(json).is_empty());
    }

    #[test]
    fn version_concrete_dans_le_cpe_devient_exacte() {
        let json = r#"{
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-0000-0004",
                    "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]},
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [
                                {"vulnerable": true, "criteria": "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"}
                            ]
                        }]
                    }]
                }
            }]
        }"#;
        let db = parse_feed(json);
        let rec = db.records.first().expect("une CVE");
        let affected = rec.affected.first().unwrap();
        assert_eq!(affected.product, "vsftpd");
        assert_eq!(affected.range.exact.as_deref(), Some("2.3.4"));
        // La gravité portée au niveau de la métrique (v2) est bien reprise.
        assert_eq!(rec.cvss.base_severity.as_deref(), Some("HIGH"));
    }
}
