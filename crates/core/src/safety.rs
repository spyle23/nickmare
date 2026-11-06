//! Sûreté opérationnelle — *primum non nocere* (issue #26, cf.
//! `docs/ARCHITECTURE.md` §11.1).
//!
//! Regroupe les garde-fous qui empêchent l'outil de **casser la cible**, tous
//! **purs et testables par mocks** (aucun accès réseau ni privilège requis) :
//!
//! - [`fragile`] — détection de services fragiles (SCADA/ICS, imprimantes,
//!   équipements médicaux, vieux SNMP) → interaction bridée/refusée, journalisée.
//! - [`backoff`] — back-off adaptatif : le débit chute sous `max_rate_pps` dès
//!   que la cible montre des signes de stress, puis remonte prudemment.
//! - [`breaker`] — circuit-breaker par cible : au-delà d'un seuil d'anomalies,
//!   les actions sont suspendues et l'opérateur alerté.
//! - [`dryrun`] — mode `--dry-run` : montre ce qui serait émis, n'envoie rien.
//! - [`teardown`] — teardown garanti (RAII/`Drop`, drapeau d'arrêt coopératif) :
//!   sessions, sockets et fichiers temporaires toujours libérés.
//! - [`budget`] — budgets globaux (durée/volume par engagement → arrêt propre).

pub mod backoff;
pub mod breaker;
pub mod budget;
pub mod dryrun;
pub mod fragile;
pub mod teardown;
