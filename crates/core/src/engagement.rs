//! Fiabilité & reprise — état d'engagement persistant (issue #26, cf.
//! `docs/ARCHITECTURE.md` §11.2).
//!
//! Un run doit survivre à un plantage ou à une coupure : chaque résultat est
//! écrit **au fil de l'eau**, et `nickmare resume <engagement>` **repart du
//! dernier état cohérent** sans tout refaire — ni re-solliciter inutilement la
//! cible. Deux invariants tiennent la robustesse :
//!
//! - **Idempotence** : relancer une étape déjà faite ne double ni l'action
//!   réseau ni l'entrée d'audit. Chaque opération porte une **clé déterministe**
//!   ([`EngagementStore::begin`] renvoie [`BeginOutcome::AlreadyCompleted`] si la
//!   clé est déjà terminée → l'appelant **saute** l'action et sa journalisation).
//! - **Jamais « réussie » en silence** : une action en vol au moment de la
//!   coupure est, à la reprise, marquée [`OpStatus::Incomplete`] — jamais `Done`.
//!
//! Le stockage est abstrait par le trait [`EngagementStore`], ce qui le rend
//! **testable par mocks** ([`InMemoryStore`]) sans aucune I/O. L'implémentation
//! persistante SQLite (décision 4) vit dans la crate `nickmare-store` et
//! implémente le **même** trait.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};

/// Identifiant d'un engagement (une base de persistance par engagement).
///
/// Normalisé en caractères sûrs pour servir aussi de nom de fichier de base.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EngagementId(String);

impl EngagementId {
    /// Construit un identifiant en ne gardant que les caractères sûrs
    /// (alphanumériques, `-`, `_`, `.`) ; les autres deviennent `_`.
    #[must_use]
    pub fn new(raw: impl AsRef<str>) -> Self {
        let sanitized: String = raw
            .as_ref()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let value = if sanitized.is_empty() {
            "engagement".to_string()
        } else {
            sanitized
        };
        Self(value)
    }

    /// Forme textuelle normalisée.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EngagementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Statut d'une opération dans le journal d'état.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpStatus {
    /// Démarrée, pas encore terminée (en vol).
    Pending,
    /// Interrompue avant la fin : jamais considérée comme réussie.
    Incomplete,
    /// Terminée avec succès.
    Done,
}

impl OpStatus {
    /// Forme persistée (texte stable).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OpStatus::Pending => "pending",
            OpStatus::Incomplete => "incomplete",
            OpStatus::Done => "done",
        }
    }

    /// Reconstruit depuis la forme persistée.
    #[must_use]
    pub fn from_persisted(raw: &str) -> Option<Self> {
        match raw {
            "pending" => Some(OpStatus::Pending),
            "incomplete" => Some(OpStatus::Incomplete),
            "done" => Some(OpStatus::Done),
            _ => None,
        }
    }
}

/// Opération idempotente consignée dans l'état d'engagement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    /// Clé d'idempotence déterministe (ex. `scan:192.168.10.25:22,80`).
    pub key: String,
    /// Nature de l'opération (`scan`, `banner`, `exploit`…).
    pub kind: String,
    /// Cible de l'opération.
    pub target: String,
    /// Statut courant.
    pub status: OpStatus,
    /// Démarrage de la (dernière) tentative.
    pub started_at: DateTime<Utc>,
    /// Fin, renseignée uniquement si [`OpStatus::Done`].
    pub finished_at: Option<DateTime<Utc>>,
}

/// Issue d'un [`EngagementStore::begin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginOutcome {
    /// Opération inédite : à exécuter.
    Started,
    /// Opération déjà commencée (en vol ou interrompue) : à ré-exécuter.
    Resumed,
    /// Opération déjà terminée : **à sauter** (idempotence — ni action ni audit).
    AlreadyCompleted,
}

impl BeginOutcome {
    /// Vrai si l'appelant doit exécuter l'action (tout sauf `AlreadyCompleted`).
    #[must_use]
    pub fn should_execute(self) -> bool {
        !matches!(self, BeginOutcome::AlreadyCompleted)
    }
}

/// Consommation cumulée d'un engagement (pour les budgets globaux, §11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub actions: u64,
    pub bytes: u64,
}

/// Erreur d'accès au stockage d'état.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Erreur du backend de persistance (SQLite…).
    Backend(String),
    /// Opération référencée inconnue.
    UnknownOperation(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Backend(msg) => write!(f, "stockage d'état : {msg}"),
            StoreError::UnknownOperation(key) => {
                write!(f, "opération inconnue : {key}")
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// Stockage de l'état d'un engagement : opérations idempotentes, résultats écrits
/// au fil de l'eau, et consommation (budgets). Abstrait pour être testable par
/// mock ([`InMemoryStore`]) comme adossé à SQLite (`nickmare-store`).
///
/// Objet-sûr : [`resume`] opère sur `&mut dyn EngagementStore`.
pub trait EngagementStore {
    /// Déclare le **début** d'une opération identifiée par `key`. Idempotent :
    ///
    /// - clé terminée → [`BeginOutcome::AlreadyCompleted`] (l'appelant saute) ;
    /// - clé en vol/interrompue → [`BeginOutcome::Resumed`] (re-tentée) ;
    /// - clé inédite → [`BeginOutcome::Started`] (consignée `Pending`).
    fn begin(
        &mut self,
        key: &str,
        kind: &str,
        target: &str,
        now: DateTime<Utc>,
    ) -> Result<BeginOutcome, StoreError>;

    /// Marque l'opération `key` comme terminée avec succès.
    fn complete(&mut self, key: &str, now: DateTime<Utc>) -> Result<(), StoreError>;

    /// Écrit (ou remplace, idempotent) le résultat associé à `key`.
    fn put_result(&mut self, key: &str, payload: &str) -> Result<(), StoreError>;

    /// Lit le résultat associé à `key`, s'il existe.
    fn get_result(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Toutes les opérations consignées (ordre déterministe par clé).
    fn operations(&self) -> Result<Vec<Operation>, StoreError>;

    /// **Reprise** : toute opération restée `Pending` (en vol au moment de la
    /// coupure) devient `Incomplete` — jamais `Done`. Renvoie les clés touchées.
    fn recover_inflight(&mut self, now: DateTime<Utc>) -> Result<Vec<String>, StoreError>;

    /// Consommation cumulée (actions, octets).
    fn usage(&self) -> Result<Usage, StoreError>;

    /// Ajoute `actions` actions et `bytes` octets à la consommation.
    fn add_usage(&mut self, actions: u64, bytes: u64) -> Result<(), StoreError>;
}

/// Plan de reprise : ce qui est déjà fait (à sauter), ce qui a été récupéré comme
/// incomplet, et ce qui reste à faire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumePlan {
    /// Opérations terminées : **ne pas re-solliciter la cible** pour elles.
    pub completed: Vec<String>,
    /// Opérations en vol récupérées comme `Incomplete` lors de cette reprise.
    pub recovered: Vec<String>,
    /// Opérations restant à (re)faire (incomplètes comprises).
    pub pending: Vec<String>,
}

impl ResumePlan {
    /// Vrai si l'opération `key` est déjà terminée (donc à sauter).
    #[must_use]
    pub fn is_completed(&self, key: &str) -> bool {
        self.completed.iter().any(|k| k == key)
    }

    /// Rendu lisible du plan de reprise.
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines = vec![
            "Reprise de l'engagement — dernier état cohérent :".to_string(),
            format!(
                "  Terminées (sautées, cible non re-sollicitée) : {}",
                self.completed.len()
            ),
            format!(
                "  Récupérées incomplètes (jamais « réussies » en silence) : {}",
                self.recovered.len()
            ),
            format!("  À reprendre : {}", self.pending.len()),
        ];
        for key in &self.pending {
            lines.push(format!("    - {key}"));
        }
        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

/// Reprend un engagement depuis son dernier état cohérent (§11.2).
///
/// Récupère d'abord les opérations en vol (→ `Incomplete`), puis classe l'état :
/// les opérations terminées ne seront pas re-sollicitées, les autres restent à
/// faire. N'émet **aucune** action réseau : logique pure de reprise.
pub fn resume(
    store: &mut dyn EngagementStore,
    now: DateTime<Utc>,
) -> Result<ResumePlan, StoreError> {
    let recovered = store.recover_inflight(now)?;
    let ops = store.operations()?;
    let mut completed = Vec::new();
    let mut pending = Vec::new();
    for op in ops {
        match op.status {
            OpStatus::Done => completed.push(op.key),
            OpStatus::Pending | OpStatus::Incomplete => pending.push(op.key),
        }
    }
    Ok(ResumePlan {
        completed,
        recovered,
        pending,
    })
}

/// Store en mémoire : implémentation de référence pour les tests, sans I/O. Les
/// opérations sont ordonnées par clé (déterminisme).
#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    ops: BTreeMap<String, Operation>,
    results: BTreeMap<String, String>,
    usage: Usage,
}

impl InMemoryStore {
    /// Store vide.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl EngagementStore for InMemoryStore {
    fn begin(
        &mut self,
        key: &str,
        kind: &str,
        target: &str,
        now: DateTime<Utc>,
    ) -> Result<BeginOutcome, StoreError> {
        if let Some(op) = self.ops.get_mut(key) {
            if op.status == OpStatus::Done {
                return Ok(BeginOutcome::AlreadyCompleted);
            }
            // En vol ou interrompue : nouvelle tentative.
            op.status = OpStatus::Pending;
            op.started_at = now;
            op.finished_at = None;
            return Ok(BeginOutcome::Resumed);
        }
        self.ops.insert(
            key.to_string(),
            Operation {
                key: key.to_string(),
                kind: kind.to_string(),
                target: target.to_string(),
                status: OpStatus::Pending,
                started_at: now,
                finished_at: None,
            },
        );
        Ok(BeginOutcome::Started)
    }

    fn complete(&mut self, key: &str, now: DateTime<Utc>) -> Result<(), StoreError> {
        match self.ops.get_mut(key) {
            Some(op) => {
                op.status = OpStatus::Done;
                op.finished_at = Some(now);
                Ok(())
            }
            None => Err(StoreError::UnknownOperation(key.to_string())),
        }
    }

    fn put_result(&mut self, key: &str, payload: &str) -> Result<(), StoreError> {
        self.results.insert(key.to_string(), payload.to_string());
        Ok(())
    }

    fn get_result(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.results.get(key).cloned())
    }

    fn operations(&self) -> Result<Vec<Operation>, StoreError> {
        Ok(self.ops.values().cloned().collect())
    }

    fn recover_inflight(&mut self, _now: DateTime<Utc>) -> Result<Vec<String>, StoreError> {
        let mut recovered = Vec::new();
        for (key, op) in &mut self.ops {
            if op.status == OpStatus::Pending {
                op.status = OpStatus::Incomplete;
                recovered.push(key.clone());
            }
        }
        Ok(recovered)
    }

    fn usage(&self) -> Result<Usage, StoreError> {
        Ok(self.usage)
    }

    fn add_usage(&mut self, actions: u64, bytes: u64) -> Result<(), StoreError> {
        self.usage.actions = self.usage.actions.saturating_add(actions);
        self.usage.bytes = self.usage.bytes.saturating_add(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn engagement_id_normalise_pour_nom_de_fichier() {
        assert_eq!(EngagementId::new("ACME/2026 #14").as_str(), "ACME_2026__14");
        assert_eq!(EngagementId::new("").as_str(), "engagement");
        assert_eq!(EngagementId::new("pentest-14_v2.db").as_str(), "pentest-14_v2.db");
    }

    #[test]
    fn begin_puis_complete_marche_une_fois() {
        let mut store = InMemoryStore::new();
        let out = store.begin("scan:h:22", "scan", "h", t(1)).unwrap();
        assert_eq!(out, BeginOutcome::Started);
        store.complete("scan:h:22", t(2)).unwrap();
        let ops = store.operations().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].status, OpStatus::Done);
    }

    #[test]
    fn idempotence_une_cle_terminee_se_saute() {
        // Rejouer une étape déjà terminée : begin renvoie AlreadyCompleted →
        // l'appelant saute l'action ET sa journalisation (pas de doublon).
        let mut store = InMemoryStore::new();
        let first = store.begin("scan:h:22", "scan", "h", t(1)).unwrap();
        assert!(first.should_execute());
        store.complete("scan:h:22", t(2)).unwrap();

        let again = store.begin("scan:h:22", "scan", "h", t(3)).unwrap();
        assert_eq!(again, BeginOutcome::AlreadyCompleted);
        assert!(!again.should_execute());
        // Toujours une seule opération, pas de doublon.
        assert_eq!(store.operations().unwrap().len(), 1);
    }

    #[test]
    fn put_result_est_idempotent_pas_de_doublon() {
        let mut store = InMemoryStore::new();
        store.put_result("scan:h:22", "ouvert").unwrap();
        store.put_result("scan:h:22", "ouvert").unwrap(); // rejeu
        assert_eq!(store.get_result("scan:h:22").unwrap().as_deref(), Some("ouvert"));
    }

    #[test]
    fn reprise_marque_en_vol_comme_incomplete_jamais_reussie() {
        // Une action en vol au moment de la coupure ne doit jamais devenir Done.
        let mut store = InMemoryStore::new();
        store.begin("scan:a", "scan", "a", t(1)).unwrap();
        store.complete("scan:a", t(2)).unwrap();
        store.begin("exploit:b", "exploit", "b", t(3)).unwrap(); // en vol → coupure

        let plan = resume(&mut store, t(10)).unwrap();
        assert_eq!(plan.completed, vec!["scan:a".to_string()]);
        assert_eq!(plan.recovered, vec!["exploit:b".to_string()]);
        assert_eq!(plan.pending, vec!["exploit:b".to_string()]);

        // L'opération interrompue est Incomplete, surtout pas Done.
        let ops = store.operations().unwrap();
        let exploit = ops.iter().find(|o| o.key == "exploit:b").unwrap();
        assert_eq!(exploit.status, OpStatus::Incomplete);
        assert!(exploit.finished_at.is_none());
    }

    #[test]
    fn reprise_ne_ressollicite_pas_les_operations_terminees() {
        let mut store = InMemoryStore::new();
        store.begin("scan:a", "scan", "a", t(1)).unwrap();
        store.complete("scan:a", t(2)).unwrap();

        let plan = resume(&mut store, t(5)).unwrap();
        assert!(plan.is_completed("scan:a"));

        // Après reprise, rejouer l'étape terminée la saute (pas de re-sollicitation).
        let out = store.begin("scan:a", "scan", "a", t(6)).unwrap();
        assert_eq!(out, BeginOutcome::AlreadyCompleted);
    }

    #[test]
    fn reprise_d_une_incomplete_la_relance() {
        let mut store = InMemoryStore::new();
        store.begin("exploit:b", "exploit", "b", t(1)).unwrap();
        resume(&mut store, t(2)).unwrap(); // en vol → incomplete

        // On relance : l'incomplète redevient à exécuter (Resumed), pas sautée.
        let out = store.begin("exploit:b", "exploit", "b", t(3)).unwrap();
        assert_eq!(out, BeginOutcome::Resumed);
        assert!(out.should_execute());
    }

    #[test]
    fn usage_s_accumule_pour_les_budgets() {
        let mut store = InMemoryStore::new();
        store.add_usage(3, 512).unwrap();
        store.add_usage(2, 488).unwrap();
        let usage = store.usage().unwrap();
        assert_eq!(usage.actions, 5);
        assert_eq!(usage.bytes, 1000);
    }

    #[test]
    fn completer_une_operation_inconnue_echoue() {
        let mut store = InMemoryStore::new();
        let err = store.complete("inconnue", t(1)).unwrap_err();
        assert_eq!(err, StoreError::UnknownOperation("inconnue".to_string()));
    }

    #[test]
    fn plan_de_reprise_s_affiche() {
        let mut store = InMemoryStore::new();
        store.begin("scan:a", "scan", "a", t(1)).unwrap();
        store.complete("scan:a", t(2)).unwrap();
        store.begin("exploit:b", "exploit", "b", t(3)).unwrap();
        let plan = resume(&mut store, t(10)).unwrap();
        let out = plan.render();
        assert!(out.contains("dernier état cohérent"));
        assert!(out.contains("exploit:b"));
    }
}
