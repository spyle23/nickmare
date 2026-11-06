//! Crate `store` de Nickmare — état d'engagement persistant sur **SQLite**
//! (issue #26, décision 4, cf. `docs/ARCHITECTURE.md` §11.2).
//!
//! [`SqliteStore`] implémente le trait
//! [`EngagementStore`](nickmare_core::engagement::EngagementStore) défini dans
//! `core` : **une base par engagement**, écriture **au fil de l'eau** (chaque
//! appel est auto-commité, donc durable face à un plantage), opérations
//! **idempotentes** (clé primaire) et **reprise** d'un run interrompu.
//!
//! Le mode autocommit de SQLite garantit qu'une opération déclarée `begin`
//! (statut `pending`) est sur le disque **avant** l'action réseau : si le
//! processus meurt en plein vol, la réouverture retrouve cette opération en
//! `pending` et [`EngagementStore::recover_inflight`] la bascule en `incomplete`
//! — jamais « réussie » en silence (§11.2).
//!
//! La logique de reprise ([`resume`](nickmare_core::engagement::resume)) et le
//! mock en mémoire ([`InMemoryStore`](nickmare_core::engagement::InMemoryStore))
//! vivent dans `core` : ils partagent le **même** trait, donc les mêmes garanties
//! sont vérifiables sans I/O (mocks) comme sur disque (ici).

use std::fmt::Display;
use std::path::Path;

use chrono::{DateTime, Utc};
use nickmare_core::engagement::{
    BeginOutcome, EngagementStore, Operation, OpStatus, StoreError, Usage,
};
use rusqlite::{params, Connection, OptionalExtension};

/// Schéma de la base d'un engagement. `CREATE ... IF NOT EXISTS` : rouvrir une
/// base existante est sans effet (reprise). La ligne `usage` unique est semée.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS operations (
    key         TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS results (
    key     TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage (
    id      INTEGER PRIMARY KEY CHECK (id = 0),
    actions INTEGER NOT NULL,
    bytes   INTEGER NOT NULL
);
INSERT OR IGNORE INTO usage (id, actions, bytes) VALUES (0, 0, 0);
";

const SQL_OP_STATUS: &str = "SELECT status FROM operations WHERE key = ?1";
const SQL_OP_REOPEN: &str =
    "UPDATE operations SET status = 'pending', started_at = ?2, finished_at = NULL WHERE key = ?1";
const SQL_OP_INSERT: &str =
    "INSERT INTO operations (key, kind, target, status, started_at) VALUES (?1, ?2, ?3, 'pending', ?4)";
const SQL_OP_COMPLETE: &str =
    "UPDATE operations SET status = 'done', finished_at = ?2 WHERE key = ?1";
const SQL_OP_LIST: &str =
    "SELECT key, kind, target, status, started_at, finished_at FROM operations ORDER BY key";
const SQL_OP_PENDING: &str = "SELECT key FROM operations WHERE status = 'pending' ORDER BY key";
const SQL_OP_RECOVER: &str = "UPDATE operations SET status = 'incomplete' WHERE status = 'pending'";
const SQL_RESULT_UPSERT: &str = "INSERT OR REPLACE INTO results (key, payload) VALUES (?1, ?2)";
const SQL_RESULT_GET: &str = "SELECT payload FROM results WHERE key = ?1";
const SQL_USAGE_GET: &str = "SELECT actions, bytes FROM usage WHERE id = 0";
const SQL_USAGE_ADD: &str =
    "UPDATE usage SET actions = actions + ?1, bytes = bytes + ?2 WHERE id = 0";

/// Store d'engagement adossé à une base SQLite (une base par engagement).
#[derive(Debug)]
pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Ouvre (ou crée) la base de l'engagement au chemin donné et garantit le
    /// schéma. Réouvrir une base existante **reprend** l'état en place.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(backend)?;
        conn.execute_batch(SCHEMA).map_err(backend)?;
        Ok(Self { conn })
    }

    /// Ouvre une base **en mémoire** (tests) : même schéma, aucune I/O disque.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(backend)?;
        conn.execute_batch(SCHEMA).map_err(backend)?;
        Ok(Self { conn })
    }

    /// Exécute une instruction paramétrée et renvoie le nombre de lignes touchées.
    fn exec(&self, sql: &str, params: impl rusqlite::Params) -> Result<usize, StoreError> {
        self.conn.execute(sql, params).map_err(backend)
    }
}

impl EngagementStore for SqliteStore {
    fn begin(
        &mut self,
        key: &str,
        kind: &str,
        target: &str,
        now: DateTime<Utc>,
    ) -> Result<BeginOutcome, StoreError> {
        let found = self.conn.query_row(SQL_OP_STATUS, [key], |row| row.get(0));
        let status: Option<String> = found.optional().map_err(backend)?;
        match status.as_deref() {
            Some("done") => Ok(BeginOutcome::AlreadyCompleted),
            Some(_) => {
                self.exec(SQL_OP_REOPEN, params![key, now.to_rfc3339()])?;
                Ok(BeginOutcome::Resumed)
            }
            None => {
                self.exec(SQL_OP_INSERT, params![key, kind, target, now.to_rfc3339()])?;
                Ok(BeginOutcome::Started)
            }
        }
    }

    fn complete(&mut self, key: &str, now: DateTime<Utc>) -> Result<(), StoreError> {
        let affected = self.exec(SQL_OP_COMPLETE, params![key, now.to_rfc3339()])?;
        if affected == 0 {
            return Err(StoreError::UnknownOperation(key.to_string()));
        }
        Ok(())
    }

    fn put_result(&mut self, key: &str, payload: &str) -> Result<(), StoreError> {
        self.exec(SQL_RESULT_UPSERT, params![key, payload])?;
        Ok(())
    }

    fn get_result(&self, key: &str) -> Result<Option<String>, StoreError> {
        let found = self.conn.query_row(SQL_RESULT_GET, [key], |row| row.get(0));
        found.optional().map_err(backend)
    }

    fn operations(&self) -> Result<Vec<Operation>, StoreError> {
        let mut stmt = self.conn.prepare(SQL_OP_LIST).map_err(backend)?;
        let rows = stmt.query_map([], |row| {
            Ok(RawOperation {
                key: row.get(0)?,
                kind: row.get(1)?,
                target: row.get(2)?,
                status: row.get(3)?,
                started_at: row.get(4)?,
                finished_at: row.get(5)?,
            })
        });
        let rows = rows.map_err(backend)?;
        let mut operations = Vec::new();
        for row in rows {
            operations.push(row.map_err(backend)?.into_operation()?);
        }
        Ok(operations)
    }

    fn recover_inflight(&mut self, _now: DateTime<Utc>) -> Result<Vec<String>, StoreError> {
        let keys = {
            let mut stmt = self.conn.prepare(SQL_OP_PENDING).map_err(backend)?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0));
            let rows = rows.map_err(backend)?;
            let mut keys = Vec::new();
            for row in rows {
                keys.push(row.map_err(backend)?);
            }
            keys
        };
        self.conn.execute(SQL_OP_RECOVER, []).map_err(backend)?;
        Ok(keys)
    }

    fn usage(&self) -> Result<Usage, StoreError> {
        let row = self.conn.query_row(SQL_USAGE_GET, [], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        });
        let (actions, bytes): (i64, i64) = row.map_err(backend)?;
        Ok(Usage {
            actions: actions.max(0) as u64,
            bytes: bytes.max(0) as u64,
        })
    }

    fn add_usage(&mut self, actions: u64, bytes: u64) -> Result<(), StoreError> {
        let actions = actions as i64;
        let bytes = bytes as i64;
        self.exec(SQL_USAGE_ADD, params![actions, bytes])?;
        Ok(())
    }
}

/// Ligne brute d'`operations`, avant interprétation du statut et des horodatages.
struct RawOperation {
    key: String,
    kind: String,
    target: String,
    status: String,
    started_at: String,
    finished_at: Option<String>,
}

impl RawOperation {
    fn into_operation(self) -> Result<Operation, StoreError> {
        let status = OpStatus::from_persisted(&self.status).ok_or_else(|| {
            StoreError::Backend(format!("statut d'opération inconnu : {}", self.status))
        })?;
        let started_at = parse_ts(&self.started_at)?;
        let finished_at = match self.finished_at {
            Some(ref raw) => Some(parse_ts(raw)?),
            None => None,
        };
        Ok(Operation {
            key: self.key,
            kind: self.kind,
            target: self.target,
            status,
            started_at,
            finished_at,
        })
    }
}

/// Convertit une erreur du backend en [`StoreError::Backend`].
fn backend(err: impl Display) -> StoreError {
    StoreError::Backend(err.to_string())
}

/// Parse un horodatage RFC3339 persisté en `DateTime<Utc>`.
fn parse_ts(raw: &str) -> Result<DateTime<Utc>, StoreError> {
    let parsed = DateTime::parse_from_rfc3339(raw).map_err(backend)?;
    Ok(parsed.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nickmare_core::engagement::resume;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn begin_complete_et_lecture_en_memoire() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let started = store.begin("scan:h:22", "scan", "h", t(1)).unwrap();
        assert_eq!(started, BeginOutcome::Started);
        store.put_result("scan:h:22", "ouvert").unwrap();
        store.complete("scan:h:22", t(2)).unwrap();

        let ops = store.operations().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].status, OpStatus::Done);
        assert_eq!(ops[0].finished_at, Some(t(2)));
        let result = store.get_result("scan:h:22").unwrap();
        assert_eq!(result.as_deref(), Some("ouvert"));
    }

    #[test]
    fn idempotence_une_cle_terminee_se_saute() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        store.begin("scan:h:22", "scan", "h", t(1)).unwrap();
        store.complete("scan:h:22", t(2)).unwrap();
        let again = store.begin("scan:h:22", "scan", "h", t(3)).unwrap();
        assert_eq!(again, BeginOutcome::AlreadyCompleted);
        // Pas de doublon : toujours une seule ligne d'opération.
        assert_eq!(store.operations().unwrap().len(), 1);
        // Et rejouer put_result ne duplique pas non plus.
        store.put_result("scan:h:22", "ouvert").unwrap();
        store.put_result("scan:h:22", "ouvert").unwrap();
        assert_eq!(store.operations().unwrap().len(), 1);
    }

    /// Chemin de base jetable, isolé par tag et par PID.
    fn tmp_db(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nm-store-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engagement.db");
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn coupure_puis_reouverture_reprend_sans_perte_ni_doublon() {
        let path = tmp_db("resume");

        // Run 1 : une opération terminée (résultat persisté), une en vol au moment
        // de la « coupure » (on referme la connexion sans la terminer).
        {
            let mut store = SqliteStore::open(&path).unwrap();
            store.begin("scan:a", "scan", "a", t(1)).unwrap();
            store.put_result("scan:a", "ports: 22").unwrap();
            store.complete("scan:a", t(2)).unwrap();
            // Opération en vol : déclarée, jamais terminée (la « coupure »).
            store.begin("exploit:b", "exploit", "b", t(3)).unwrap();
            // `store` Drop ici → connexion fermée, process « tué ».
        }

        // Run 2 : réouverture de la MÊME base → reprise.
        let mut store = SqliteStore::open(&path).unwrap();
        let plan = resume(&mut store, t(100)).unwrap();

        // Rien perdu : l'opération terminée et son résultat sont là.
        assert_eq!(plan.completed, vec!["scan:a".to_string()]);
        let result = store.get_result("scan:a").unwrap();
        assert_eq!(result.as_deref(), Some("ports: 22"));

        // L'action en vol est Incomplete, jamais « réussie » en silence.
        assert_eq!(plan.recovered, vec!["exploit:b".to_string()]);
        let ops = store.operations().unwrap();
        let b = ops.iter().find(|o| o.key == "exploit:b").unwrap();
        assert_eq!(b.status, OpStatus::Incomplete);

        // Pas de doublon : re-déclarer l'opération terminée la saute.
        let replay = store.begin("scan:a", "scan", "a", t(101)).unwrap();
        assert_eq!(replay, BeginOutcome::AlreadyCompleted);
        // L'incomplète, elle, se relance.
        let relance = store.begin("exploit:b", "exploit", "b", t(102)).unwrap();
        assert_eq!(relance, BeginOutcome::Resumed);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn usage_persiste_pour_les_budgets() {
        let path = tmp_db("usage");
        {
            let mut store = SqliteStore::open(&path).unwrap();
            store.add_usage(3, 512).unwrap();
        }
        // Réouverture : la consommation déjà faite est reprise.
        let mut store = SqliteStore::open(&path).unwrap();
        store.add_usage(2, 488).unwrap();
        let usage = store.usage().unwrap();
        assert_eq!(usage.actions, 5);
        assert_eq!(usage.bytes, 1000);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn completer_une_operation_inconnue_echoue() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let err = store.complete("inconnue", t(1)).unwrap_err();
        assert_eq!(err, StoreError::UnknownOperation("inconnue".to_string()));
    }
}
