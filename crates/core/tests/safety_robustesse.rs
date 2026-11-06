//! Tests de robustesse §11.4 (issue #26, cf. `docs/ARCHITECTURE.md` §11.1/§11.4,
//! `docs/TESTING.md` §3 « Intégration (mocks) »).
//!
//! Une cible mock qui **ralentit, coupe (RST/timeout) et renvoie des données
//! malformées** doit déclencher, de bout en bout et **sans réseau réel** :
//!
//! - le **back-off adaptatif** : le débit chute sous `max_rate_pps` ;
//! - le **circuit-breaker** : au-delà du seuil d'anomalies, la cible est
//!   suspendue et l'opérateur alerté ;
//! - le **teardown garanti** : les ressources ouvertes sont libérées à la sortie.
//!
//! Aucune donnée externe n'est `unwrap`ée aveuglément : le parsing de bannière
//! est défensif (une trame malformée rend une erreur, jamais une panique, §12).

use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};
use nickmare_core::safety::backoff::{AdaptiveBackoff, StressSignal};
use nickmare_core::safety::breaker::{BreakerDecision, CircuitBreaker, Phase};
use nickmare_core::safety::teardown::{ResourceKind, TeardownGuard};

/// Issue d'une sonde contre la cible mock.
#[derive(Debug, Clone, Copy)]
enum ProbeOutcome {
    /// Réponse normale et rapide.
    Healthy,
    /// Réponse anormalement lente (cible qui peine).
    Slow,
    /// Pas de réponse dans le délai.
    Timeout,
    /// Connexion coupée par la cible (RST).
    Reset,
    /// Octets reçus mais illisibles (données malformées).
    Malformed(&'static [u8]),
}

/// Cible mock rejouant un script d'issues déterministe, sans aucune socket.
struct FlakyTarget {
    script: Vec<ProbeOutcome>,
    cursor: usize,
}

impl FlakyTarget {
    fn new(script: Vec<ProbeOutcome>) -> Self {
        Self { script, cursor: 0 }
    }

    /// Rejoue la prochaine issue (la dernière se répète si on dépasse).
    fn probe(&mut self) -> ProbeOutcome {
        let outcome = self.script[self.cursor.min(self.script.len() - 1)];
        self.cursor += 1;
        outcome
    }
}

/// Parsing **défensif** d'une bannière : rend une erreur sur données malformées,
/// ne panique jamais (les entrées réseau sont hostiles, §12).
fn parse_banner(raw: &[u8]) -> Result<String, &'static str> {
    let text = std::str::from_utf8(raw).map_err(|_| "bannière non-UTF-8")?;
    if text.trim().is_empty() {
        return Err("bannière vide");
    }
    Ok(text.to_string())
}

fn ip() -> IpAddr {
    "192.168.10.25".parse().unwrap()
}

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

#[test]
fn cible_instable_declenche_backoff_breaker_et_teardown() {
    // Script : une réponse saine, puis une dégringolade (lenteur, timeout, RST,
    // trame malformée) — 4 anomalies, de quoi franchir le seuil (4) pile sur la
    // dernière, tout en ayant traité la trame malformée.
    let mut target = FlakyTarget::new(vec![
        ProbeOutcome::Healthy,
        ProbeOutcome::Slow,
        ProbeOutcome::Timeout,
        ProbeOutcome::Reset,
        ProbeOutcome::Malformed(b"\xff\xfe\x00"),
    ]);

    let mut backoff = AdaptiveBackoff::new(200);
    let mut breaker = CircuitBreaker::new(4, TimeDelta::seconds(30));
    let target_ip = ip();

    // Garde RAII : socket + fichier temporaire de hashes à libérer quoi qu'il
    // arrive. On observe la libération après sa sortie de portée.
    let ledger = {
        let mut guard = TeardownGuard::new();
        guard.register("tcp:192.168.10.25:502", ResourceKind::Socket);
        guard.register("/tmp/run-hashes", ResourceKind::TempFile);
        let handle = guard.ledger();

        let mut malformed_seen = false;
        for _ in 0..5 {
            // Le circuit-breaker commande en amont : si la cible est suspendue,
            // on n'émet plus rien (on ne la sollicite pas à l'aveugle).
            if breaker.allow(target_ip, t0()) == BreakerDecision::Suspended {
                break;
            }
            match target.probe() {
                ProbeOutcome::Healthy => {
                    backoff.observe(StressSignal::Healthy);
                    breaker.record_success(target_ip);
                }
                ProbeOutcome::Slow => {
                    backoff.observe(StressSignal::SlowResponse);
                    breaker.record_anomaly(target_ip, t0());
                }
                ProbeOutcome::Timeout => {
                    backoff.observe(StressSignal::Timeout);
                    breaker.record_anomaly(target_ip, t0());
                }
                ProbeOutcome::Reset => {
                    backoff.observe(StressSignal::Reset);
                    breaker.record_anomaly(target_ip, t0());
                }
                ProbeOutcome::Malformed(raw) => {
                    // Donnée malformée : parsing défensif → anomalie, pas de panique.
                    assert!(parse_banner(raw).is_err());
                    malformed_seen = true;
                    backoff.observe(StressSignal::SlowResponse);
                    breaker.record_anomaly(target_ip, t0());
                }
            }
        }
        assert!(malformed_seen, "la trame malformée a bien été traitée");
        handle
        // `guard` Drop ici → teardown garanti.
    };

    // Back-off : le débit a chuté bien en-dessous du plafond.
    assert!(backoff.is_throttled(), "le débit doit être bridé");
    assert!(backoff.effective_pps() < 200);
    assert!(backoff.effective_pps() >= 1, "jamais totalement figé");

    // Circuit-breaker : la cible instable est suspendue (seuil franchi).
    assert_eq!(breaker.phase(target_ip), Phase::Open);
    assert_eq!(breaker.allow(target_ip, t0()), BreakerDecision::Suspended);

    // Teardown : toutes les ressources ont été libérées, en ordre inverse (LIFO).
    let released = ledger.lock().unwrap();
    assert_eq!(released.len(), 2);
    assert_eq!(released[0], "libéré fichier-temp /tmp/run-hashes");
    assert_eq!(released[1], "libéré socket tcp:192.168.10.25:502");
}

#[test]
fn cible_qui_se_retablit_referme_le_circuit() {
    // Après suspension puis refroidissement, une sonde saine referme le circuit :
    // on reprend prudemment, on ne reste pas bloqué pour toujours.
    let mut breaker = CircuitBreaker::new(2, TimeDelta::seconds(30));
    let target_ip = ip();
    breaker.record_anomaly(target_ip, t0());
    breaker.record_anomaly(target_ip, t0());
    assert_eq!(breaker.allow(target_ip, t0()), BreakerDecision::Suspended);

    let apres = t0() + TimeDelta::seconds(31);
    assert_eq!(breaker.allow(target_ip, apres), BreakerDecision::Proceed);
    breaker.record_success(target_ip);
    assert_eq!(breaker.phase(target_ip), Phase::Closed);
}
