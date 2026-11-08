//! Évaluation de **politique de mots de passe** (issue #21, cf.
//! `docs/ARCHITECTURE.md` §7, §9 Phase 7, US-F2).
//!
//! # La valeur livrable : un verdict, pas des secrets
//!
//! À partir d'un [`CrackReport`](crate::engine::CrackReport) (hashes tentés +
//! comptes recouvrés, secrets **masqués**), on produit un
//! [`PolicyVerdict`](nickmare_core::model::PolicyVerdict) et la liste des **patterns
//! faibles** observés : mot de dictionnaire, mot du dico + année, longueur
//! insuffisante, réutilisation. L'analyse lit le clair **en interne au crate** (via
//! `MaskedSecret::expose`, `pub(crate)`) pour en tirer des patterns ; **aucun
//! clair** ne franchit la frontière du module — seuls des libellés de patterns et
//! des statistiques sortent (§1, §7).
//!
//! # Verdict
//!
//! - aucun hash tenté → `Unknown` (pas de donnée) ;
//! - rien de craqué → `Compliant` (robuste face à ce craquage) ;
//! - sinon `Weak`, ou `NonCompliant` si la réutilisation est avérée ou si au moins
//!   la moitié des hashes tombent (taux de craquage élevé).

use std::collections::{BTreeSet, HashMap, HashSet};

use nickmare_core::model::PolicyVerdict;

use crate::engine::CrackReport;

/// Libellé du pattern « mot de dictionnaire ».
const PAT_DICT: &str = "mot de dictionnaire";
/// Libellé du pattern « mot du dico + année ».
const PAT_DICT_YEAR: &str = "mot du dico + année";
/// Libellé du pattern « réutilisation de mot de passe ».
const PAT_REUSE: &str = "réutilisation de mot de passe";

/// Petit dictionnaire de bases courantes (minuscule, séparé par espaces). La
/// racine alphabétique d'un clair y est cherchée pour détecter un « mot de
/// dictionnaire ». Volontairement court : il illustre le pattern, il ne prétend
/// pas à l'exhaustivité (le craquage réel, lui, est délégué à hashcat/John).
const DICTIONARY: &str = "password motdepasse admin administrateur welcome bienvenue \
    summer ete printemps hiver automne winter spring autumn qwerty azerty soleil \
    london paris root love dragon monkey master letmein football baseball iloveyou \
    sunshine princess test demo changeme secret company";

/// Politique de mots de passe évaluée. Minimaliste : seul le seuil de longueur est
/// paramétré ici ; les autres patterns sont structurels (dico, année, réutilisation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Longueur minimale exigée : en deçà → pattern « longueur insuffisante ».
    pub min_length: usize,
}

impl PasswordPolicy {
    /// Politique avec un seuil de longueur explicite.
    #[must_use]
    pub fn new(min_length: usize) -> Self {
        Self { min_length }
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        // 12 caractères : seuil usuel d'une politique robuste.
        Self { min_length: 12 }
    }
}

/// Résultat d'une évaluation : verdict + patterns faibles (dédupliqués, ordre
/// déterministe). Jamais de clair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAssessment {
    /// Verdict de politique.
    pub verdict: PolicyVerdict,
    /// Patterns faibles observés (libellés, triés).
    pub weak_patterns: Vec<String>,
}

/// Évalue la politique à partir d'un rapport de craquage. Lit le clair **en
/// interne** pour en tirer des patterns ; ne restitue que des libellés + le verdict.
#[must_use]
pub fn evaluate(report: &CrackReport, policy: &PasswordPolicy) -> PolicyAssessment {
    let mut patterns: BTreeSet<String> = BTreeSet::new();

    // Réutilisation : un même clair recouvré sur ≥ 2 comptes distincts.
    let mut by_secret: HashMap<&str, HashSet<&str>> = HashMap::new();
    for rec in &report.recovered {
        by_secret
            .entry(rec.secret.expose())
            .or_default()
            .insert(rec.account.as_str());
    }
    let reuse = by_secret.values().any(|accounts| accounts.len() >= 2);
    if reuse {
        patterns.insert(PAT_REUSE.to_string());
    }

    // Patterns par clair recouvré (lecture interne, jamais exportée).
    for rec in &report.recovered {
        let clear = rec.secret.expose();
        if clear.chars().count() < policy.min_length {
            patterns.insert(format!(
                "longueur insuffisante (< {} caractères)",
                policy.min_length
            ));
        }
        if word_plus_year(clear) {
            patterns.insert(PAT_DICT_YEAR.to_string());
        } else if is_dictionary_word(&alpha_core(clear)) {
            patterns.insert(PAT_DICT.to_string());
        }
    }

    let verdict = verdict_for(report.attempted, report.cracked(), reuse);
    PolicyAssessment {
        verdict,
        weak_patterns: patterns.into_iter().collect(),
    }
}

/// Verdict à partir des compteurs + réutilisation (cf. règles du module).
fn verdict_for(attempted: u64, cracked: u64, reuse: bool) -> PolicyVerdict {
    if attempted == 0 {
        return PolicyVerdict::Unknown;
    }
    if cracked == 0 {
        return PolicyVerdict::Compliant;
    }
    let rate = cracked as f64 / attempted as f64;
    if reuse || rate >= 0.5 {
        PolicyVerdict::NonCompliant
    } else {
        PolicyVerdict::Weak
    }
}

/// Racine alphabétique d'un clair, en minuscules (les chiffres/symboles sont
/// retirés). `"Summer2023!"` → `"summer"`.
fn alpha_core(secret: &str) -> String {
    secret
        .chars()
        .filter(|c| c.is_alphabetic())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Vrai si la racine (non vide) figure dans le dictionnaire.
fn is_dictionary_word(core: &str) -> bool {
    !core.is_empty() && DICTIONARY.split_whitespace().any(|word| word == core)
}

/// Vrai si le clair contient une base alphabétique (≥ 3 lettres) suivie d'une
/// **année** (1900–2099) : le classique `"Printemps2024"`.
fn word_plus_year(secret: &str) -> bool {
    let chars: Vec<char> = secret.chars().collect();
    for (start, window) in chars.windows(4).enumerate() {
        if !is_year(window) {
            continue;
        }
        let letters_before = chars[..start]
            .iter()
            .rev()
            .take_while(|c| c.is_alphabetic())
            .count();
        if letters_before >= 3 {
            return true;
        }
    }
    false
}

/// Vrai si la fenêtre de 4 caractères est une année plausible (1900–2099).
fn is_year(window: &[char]) -> bool {
    if window.len() != 4 || !window.iter().all(char::is_ascii_digit) {
        return false;
    }
    let value: String = window.iter().collect();
    matches!(value.parse::<u32>(), Ok(year) if (1900..=2099).contains(&year))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{HashType, MaskedSecret, Recovered};

    /// Rapport construit à la main (hashes tentés + comptes recouvrés).
    fn report(attempted: u64, recovered: Vec<Recovered>) -> CrackReport {
        CrackReport {
            hash_type: HashType::Ntlm,
            source: "lab".to_string(),
            attempted,
            recovered,
        }
    }

    /// Un recouvrement (compte, clair).
    fn rec(account: &str, clear: &str) -> Recovered {
        Recovered::new(account, MaskedSecret::new(clear))
    }

    fn has(assessment: &PolicyAssessment, needle: &str) -> bool {
        assessment.weak_patterns.iter().any(|p| p.contains(needle))
    }

    #[test]
    fn aucun_hash_tente_est_inconnu() {
        let assessment = evaluate(&report(0, vec![]), &PasswordPolicy::default());
        assert_eq!(assessment.verdict, PolicyVerdict::Unknown);
        assert!(assessment.weak_patterns.is_empty());
    }

    #[test]
    fn rien_de_craque_est_conforme() {
        let assessment = evaluate(&report(100, vec![]), &PasswordPolicy::default());
        assert_eq!(assessment.verdict, PolicyVerdict::Compliant);
    }

    #[test]
    fn mot_du_dico_plus_annee_est_detecte() {
        let recovered = vec![rec("alice", "Printemps2024")];
        let assessment = evaluate(&report(50, recovered), &PasswordPolicy::default());
        assert!(has(&assessment, "année"), "{:?}", assessment.weak_patterns);
        assert_eq!(assessment.verdict, PolicyVerdict::Weak);
    }

    #[test]
    fn mot_de_dictionnaire_simple_est_detecte() {
        let recovered = vec![rec("bob", "Password!!")];
        let assessment = evaluate(&report(50, recovered), &PasswordPolicy::default());
        assert!(has(&assessment, "dictionnaire"));
    }

    #[test]
    fn longueur_insuffisante_est_detectee() {
        let recovered = vec![rec("carol", "aB3$")];
        let policy = PasswordPolicy::new(12);
        let assessment = evaluate(&report(10, recovered), &policy);
        assert!(has(&assessment, "longueur insuffisante"));
    }

    #[test]
    fn reutilisation_rend_non_conforme() {
        // Deux comptes distincts partagent le même clair → réutilisation.
        let recovered = vec![
            rec("alice", "Zx9!qWerT2@kP"),
            rec("bob", "Zx9!qWerT2@kP"),
        ];
        let assessment = evaluate(&report(4, recovered), &PasswordPolicy::default());
        assert!(has(&assessment, "réutilisation"));
        assert_eq!(assessment.verdict, PolicyVerdict::NonCompliant);
    }

    #[test]
    fn taux_de_craquage_eleve_rend_non_conforme() {
        // 3 craqués sur 4 tentés (> 50 %) → NonCompliant, même sans réutilisation.
        let recovered = vec![
            rec("a", "LongPhraseAleatoireX1"),
            rec("b", "LongPhraseAleatoireY2"),
            rec("c", "LongPhraseAleatoireZ3"),
        ];
        let assessment = evaluate(&report(4, recovered), &PasswordPolicy::default());
        assert_eq!(assessment.verdict, PolicyVerdict::NonCompliant);
    }

    #[test]
    fn patterns_sont_tries_et_dedupliques() {
        let recovered = vec![rec("alice", "Summer2023"), rec("bob", "Summer2024")];
        let assessment = evaluate(&report(10, recovered), &PasswordPolicy::default());
        // « mot du dico + année » n'apparaît qu'une fois malgré deux occurrences.
        let count = assessment
            .weak_patterns
            .iter()
            .filter(|p| p.contains("année"))
            .count();
        assert_eq!(count, 1);
        let mut sorted = assessment.weak_patterns.clone();
        sorted.sort();
        assert_eq!(assessment.weak_patterns, sorted, "ordre déterministe");
    }

    #[test]
    fn annee_hors_plage_n_est_pas_un_pattern_annee() {
        // 1800 n'est pas dans 1900–2099 → pas de pattern « année ».
        let recovered = vec![rec("x", "Chateau1800!")];
        let assessment = evaluate(&report(5, recovered), &PasswordPolicy::default());
        assert!(!has(&assessment, "année"));
    }
}
