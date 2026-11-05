//! Comparaison de versions **défensive** (issue #14, cf. `docs/ARCHITECTURE.md`
//! §12 : entrées hostiles, pas d'`unwrap` ni de panique).
//!
//! Les numéros de version proviennent de deux sources tout aussi **peu fiables** :
//! les bannières réseau (via le `Service` identifié par #13, §12) et le flux NVD
//! (données externes). Ce module doit donc comparer `9.6p1`, `1.24.0`,
//! `2.3.4-ubuntu` ou `` sans jamais paniquer, et **sans surdéclarer** de
//! correspondance (le risque n°1 d'une corrélation CVE est le faux positif).
//!
//! # Modèle
//!
//! Une version est réduite à sa **suite de segments numériques** : on découpe sur
//! les séparateurs usuels (`.`, `-`, `_`, `+`, `~`, espace) puis, pour chaque
//! segment, on ne garde que le **nombre de tête** (`6p1` → `6`, `0ubuntu3` → `0`).
//! Un segment sans chiffre de tête (`p1`, `rc`) est ignoré. La comparaison se fait
//! segment par segment, les manquants valant `0` (`9.6` == `9.6.0`).
//!
//! Ce modèle est volontairement **prudent** : il ordonne correctement les versions
//! numériques usuelles des produits réseau et, face à une entrée illisible, se
//! dégrade vers « vide » (qui ne borne rien) plutôt que vers une correspondance
//! hasardeuse.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// Nombre maximal de segments conservés : une version hostile ne gonfle ni la
/// mémoire ni le temps de comparaison (§12). Au-delà, les segments sont ignorés.
const MAX_SEGMENTS: usize = 16;

/// Nombre maximal de chiffres lus par segment avant saturation : borne l'entrée
/// avant d'atteindre les limites de `u64` (jamais de dépassement, jamais de panique).
const MAX_DIGITS: usize = 18;

/// Une version comparable : une suite bornée de segments numériques.
///
/// Construite par [`Version::parse`], qui ne panique jamais. Deux versions se
/// comparent segment par segment ([`Ord`]), les segments manquants valant `0`.
/// La forme est **canonique** (zéros de queue retirés) : l'égalité dérivée
/// ([`PartialEq`]) et l'ordre ([`Ord`]) sont donc cohérents (`9.6` == `9.6.0`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Version {
    segments: Vec<u64>,
}

impl Version {
    /// Analyse une chaîne de version de façon **défensive** : découpe sur les
    /// séparateurs usuels, ne retient que le nombre de tête de chaque segment,
    /// borne le nombre de segments et de chiffres. Ne panique jamais.
    ///
    /// Une entrée vide ou sans aucun chiffre donne une version **vide** : elle
    /// n'est égale qu'à une autre version vide et ne borne aucun intervalle (cf.
    /// [`matches_range`]), ce qui évite les faux positifs.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let mut segments = Vec::new();
        for part in raw.split(['.', '-', '_', '+', '~', ' ']) {
            if segments.len() >= MAX_SEGMENTS {
                break;
            }
            if let Some(value) = leading_number(part) {
                segments.push(value);
            }
        }
        // Les zéros de queue ne changent pas l'ordre (`9.6` == `9.6.0`) : on les
        // retire pour une forme canonique (deux versions égales ont la même).
        while segments.last() == Some(&0) {
            segments.pop();
        }
        Self { segments }
    }

    /// Vrai si la version est vide (aucun segment numérique exploitable).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

impl Ord for Version {
    /// Compare deux versions segment par segment, les segments manquants valant
    /// `0` (`9.6` == `9.6.0`). Total et sans panique (accès par `get`, jamais
    /// d'indexation).
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.segments.len().max(other.segments.len());
        for i in 0..len {
            let a = self.segments.get(i).copied().unwrap_or(0);
            let b = other.segments.get(i).copied().unwrap_or(0);
            let ord = a.cmp(&b);
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Extrait le nombre de tête d'un segment (`6p1` → `6`, `0ubuntu` → `0`),
/// saturé à [`MAX_DIGITS`] chiffres. `None` si le segment ne commence pas par un
/// chiffre (il est alors ignoré, jamais pris pour `0`).
fn leading_number(part: &str) -> Option<u64> {
    let mut value: u64 = 0;
    let mut digits = 0usize;
    for b in part.bytes() {
        if b.is_ascii_digit() {
            if digits >= MAX_DIGITS {
                // Entrée anormalement longue : on sature plutôt que de déborder.
                return Some(u64::MAX);
            }
            value = value * 10 + u64::from(b - b'0');
            digits += 1;
        } else {
            break;
        }
    }
    if digits == 0 {
        None
    } else {
        Some(value)
    }
}

/// Bornes de version d'un produit affecté, telles qu'exprimées par le flux NVD
/// (CPE match). Toutes optionnelles ; une borne absente ou illisible **ne borne
/// pas** (fail-safe vers un intervalle plus large seulement si une autre borne le
/// restreint — cf. [`matches_range`], qui exige au moins une contrainte).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    /// Version exacte affectée (CPE sans borne, version ≠ `*`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    /// `versionStartIncluding` — borne basse incluse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_including: Option<String>,
    /// `versionStartExcluding` — borne basse exclue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_excluding: Option<String>,
    /// `versionEndIncluding` — borne haute incluse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_including: Option<String>,
    /// `versionEndExcluding` — borne haute exclue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_excluding: Option<String>,
}

impl VersionRange {
    /// Intervalle borné uniquement en haut, exclusif (`< end`) — le cas le plus
    /// courant (« corrigé dans la version X »).
    #[must_use]
    pub fn end_excluding(version: impl Into<String>) -> Self {
        Self {
            end_excluding: Some(version.into()),
            ..Self::default()
        }
    }

    /// Correspondance à une version exacte.
    #[must_use]
    pub fn exact(version: impl Into<String>) -> Self {
        Self {
            exact: Some(version.into()),
            ..Self::default()
        }
    }

    /// Vrai si la plage n'exprime **aucune** contrainte exploitable (ni version
    /// exacte, ni borne). Un tel enregistrement ne corrèle jamais (fail-safe
    /// anti-faux-positif : on ne signale pas « toutes versions » sur un simple
    /// vide).
    #[must_use]
    pub fn is_unbounded(&self) -> bool {
        self.exact.is_none()
            && self.start_including.is_none()
            && self.start_excluding.is_none()
            && self.end_including.is_none()
            && self.end_excluding.is_none()
    }
}

/// Vrai si la version détectée `detected` tombe dans la plage `range`.
///
/// Règles **défensives** (§12), pensées pour **ne pas surdéclarer** :
///
/// - une `detected` vide (version illisible/absente) ne correspond **jamais** ;
/// - une plage sans aucune contrainte ([`VersionRange::is_unbounded`]) ne
///   correspond **jamais** (on ne signale pas une CVE sur la seule foi du produit) ;
/// - `exact` : correspondance ssi les versions comparées sont égales **et** la
///   borne exacte est elle-même lisible (une borne `*`/vide ne matche rien) ;
/// - bornes : `start_*` et `end_*` sont appliquées quand elles sont lisibles ;
///   une borne illisible est simplement **ignorée** (elle ne restreint ni
///   n'élargit), les autres bornes continuant de s'appliquer.
#[must_use]
pub fn matches_range(detected: &str, range: &VersionRange) -> bool {
    let detected = Version::parse(detected);
    if detected.is_empty() || range.is_unbounded() {
        return false;
    }

    // `exact` renseigné (même illisible) : seule une égalité **lisible** compte.
    // Une borne exacte présente mais illisible (`0`, `*`, `rc`…) ne matche RIEN —
    // on ne retombe jamais sur un « tout accepter » (anti-faux-positif, §12).
    if range.exact.is_some() {
        return match readable(&range.exact) {
            Some(exact) => detected.cmp(&exact) == Ordering::Equal,
            None => false,
        };
    }

    // Bornes : on exige qu'au moins **une** borne soit lisible (`applied`), et on
    // applique toutes celles qui le sont. Si toutes les bornes présentes sont
    // illisibles, la plage n'exprime aucune contrainte exploitable → pas de match.
    let mut applied = false;
    if let Some(lo) = readable(&range.start_including) {
        applied = true;
        if detected.cmp(&lo) == Ordering::Less {
            return false;
        }
    }
    if let Some(lo) = readable(&range.start_excluding) {
        applied = true;
        if detected.cmp(&lo) != Ordering::Greater {
            return false;
        }
    }
    if let Some(hi) = readable(&range.end_including) {
        applied = true;
        if detected.cmp(&hi) == Ordering::Greater {
            return false;
        }
    }
    if let Some(hi) = readable(&range.end_excluding) {
        applied = true;
        if detected.cmp(&hi) != Ordering::Less {
            return false;
        }
    }
    applied
}

/// Analyse une borne optionnelle en une [`Version`] **non vide**, ou `None` si la
/// borne est absente, vide, `*` ou illisible (elle est alors ignorée).
fn readable(bound: &Option<String>) -> Option<Version> {
    let raw = bound.as_deref()?;
    if raw.is_empty() || raw == "*" || raw == "-" {
        return None;
    }
    let version = Version::parse(raw);
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        Version::parse(a).cmp(&Version::parse(b))
    }

    #[test]
    fn ordre_des_versions_numeriques() {
        assert_eq!(cmp("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp("1.2.0", "1.2"), Ordering::Equal);
        assert_eq!(cmp("1.2", "1.10"), Ordering::Less);
        assert_eq!(cmp("2.0", "1.99"), Ordering::Greater);
        assert_eq!(cmp("1.24.0", "1.20.0"), Ordering::Greater);
    }

    #[test]
    fn suffixes_sont_reduits_au_nombre_de_tete() {
        // `9.6p1` et `9.6` réduisent au même `9.6`.
        assert_eq!(cmp("9.6p1", "9.6"), Ordering::Equal);
        assert_eq!(cmp("3.0.5", "2.3.4"), Ordering::Greater);
        // Un suffixe non numérique ne crée pas de segment fantôme.
        assert_eq!(cmp("2.4.58-ubuntu", "2.4.58"), Ordering::Equal);
    }

    #[test]
    fn versions_vides_ou_illisibles_sont_vides() {
        assert!(Version::parse("").is_empty());
        assert!(Version::parse("   ").is_empty());
        assert!(Version::parse("unknown").is_empty());
        assert!(Version::parse("*").is_empty());
        assert!(Version::parse("rc").is_empty());
        // Deux versions vides sont égales ; une vide n'est pas < une non vide ici
        // (mais `matches_range` refuse toute version détectée vide, cf. plus bas).
        assert_eq!(cmp("", ""), Ordering::Equal);
    }

    #[test]
    fn plage_end_excluding_borne_correctement() {
        let range = VersionRange::end_excluding("9.8");
        assert!(matches_range("9.6p1", &range)); // 9.6 < 9.8
        assert!(matches_range("9.7", &range));
        assert!(!matches_range("9.8", &range)); // exclu
        assert!(!matches_range("9.9", &range));
    }

    #[test]
    fn plage_intervalle_ferme_ouvert() {
        let range = VersionRange {
            start_including: Some("8.5".to_string()),
            end_excluding: Some("9.9".to_string()),
            ..VersionRange::default()
        };
        assert!(!matches_range("8.4", &range)); // sous la borne basse
        assert!(matches_range("8.5", &range)); // borne basse incluse
        assert!(matches_range("9.6p1", &range));
        assert!(!matches_range("9.9", &range)); // borne haute exclue
    }

    #[test]
    fn start_excluding_et_end_including() {
        let range = VersionRange {
            start_excluding: Some("1.0.0".to_string()),
            end_including: Some("1.2.0".to_string()),
            ..VersionRange::default()
        };
        assert!(!matches_range("1.0.0", &range)); // exclu
        assert!(matches_range("1.0.1", &range));
        assert!(matches_range("1.2.0", &range)); // inclus
        assert!(!matches_range("1.2.1", &range));
    }

    #[test]
    fn exact_ne_matche_que_la_version_exacte() {
        let range = VersionRange::exact("2.3.4");
        assert!(matches_range("2.3.4", &range));
        assert!(!matches_range("3.0.5", &range));
        assert!(!matches_range("2.3.5", &range));
    }

    #[test]
    fn version_detectee_vide_ne_matche_jamais() {
        // Même une plage large ne doit rien signaler sans version détectée.
        let range = VersionRange {
            start_including: Some("0.0.0".to_string()),
            end_excluding: Some("99.0".to_string()),
            ..VersionRange::default()
        };
        assert!(!matches_range("", &range));
        assert!(!matches_range("unknown", &range));
    }

    #[test]
    fn plage_sans_contrainte_ne_matche_jamais() {
        // Anti-faux-positif : pas de « toutes versions » sur un enregistrement vide.
        assert!(VersionRange::default().is_unbounded());
        assert!(!matches_range("1.2.3", &VersionRange::default()));
        // Une plage dont toutes les bornes sont illisibles est inoffensive.
        let junk = VersionRange {
            start_including: Some("*".to_string()),
            end_excluding: Some(String::new()),
            ..VersionRange::default()
        };
        assert!(!matches_range("1.2.3", &junk));
    }

    #[test]
    fn exact_illisible_ne_matche_rien() {
        // Régression anti-faux-positif : une borne exacte présente mais illisible
        // (`0`, `*`, `rc`, vide) ne doit JAMAIS retomber sur un « tout accepter ».
        for junk in ["0", "0.0", "*", "-", "", "rc", "latest"] {
            let range = VersionRange::exact(junk);
            assert!(
                !matches_range("1.5", &range),
                "exact illisible {junk:?} ne doit pas matcher"
            );
        }
    }

    #[test]
    fn bornes_toutes_illisibles_ne_matchent_rien() {
        // Toutes les bornes présentes mais illisibles → aucune contrainte → faux.
        let range = VersionRange {
            start_including: Some("rc".to_string()),
            end_excluding: Some("*".to_string()),
            ..VersionRange::default()
        };
        assert!(!matches_range("1.5", &range));
    }

    #[test]
    fn bornes_tres_longues_saturent_sans_paniquer() {
        let huge = "9".repeat(5000);
        let range = VersionRange::end_excluding(huge.clone());
        // Pas de panique ; la borne sature à u64::MAX, donc tout est en dessous.
        assert!(matches_range("1.0", &range));
        // Une version détectée tout aussi longue ne panique pas non plus.
        let _ = matches_range(&huge, &VersionRange::end_excluding("1.0"));
    }

    #[test]
    fn fuzz_leger_comparaison_ne_panique_jamais() {
        // Générateur congruentiel déterministe (sans dépendance externe), même
        // esprit que le fuzz léger de `net::service_id`.
        let mut state: u64 = 0xdead_beef_1234_5678;
        let alphabet = b"0123456789.-_+~ abcdefX*";
        for _ in 0..2000 {
            let len = (state % 24) as usize;
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let idx = (state >> 40) as usize % alphabet.len();
                s.push(alphabet[idx] as char);
            }
            // Ni le parsing, ni la comparaison, ni le matching ne paniquent.
            let _ = Version::parse(&s).cmp(&Version::parse("1.2.3"));
            let _ = matches_range(&s, &VersionRange::end_excluding("2.0"));
            let _ = matches_range("1.5", &VersionRange::exact(s));
        }
    }
}
