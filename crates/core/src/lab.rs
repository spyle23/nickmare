//! Voie C — mode laboratoire / apprentissage (issue #11, cf.
//! `docs/ARCHITECTURE.md` §3.0 décision 5, §3.2 note, US-A5).
//!
//! `nickmare lab start <cidr> [<cidr>...]` établit un périmètre de session à
//! partir d'**un ou plusieurs sous-réseaux reliés** (ex. DMZ + LAN) sur une
//! **attestation unique** : pas de fichier signé ni de confirmation par cible.
//! Cette attestation débloque d'emblée la chaîne complète N1–N4 **sur tout le
//! périmètre déclaré**, en marquant chaque action comme émise en
//! [`AuditMode::Lab`] (`mode = "lab"` dans le journal et le rapport).
//!
//! # Ce que le mode labo change — et ce qu'il ne change pas
//!
//! Le labo réduit la **cérémonie**, jamais la **sûreté**. Concrètement il n'agit
//! que sur les étapes 3 (capacités ouvertes d'office, sous-filtres levés) et 5
//! (confirmation par cible levée) du gate, plus l'exigence de fichier signé.
//! **Tout le reste du mur reste debout** (§3.2 note) :
//!
//! - **confinement au périmètre** (étape 2) : un sous-réseau **non déclaré** —
//!   même joignable depuis un hôte compromis — reste hors d'atteinte ;
//! - **pré-conditions** (étape 4), **anti-destruction** (étape 6) et **plafonds**
//!   (étape 7) : inchangés ;
//! - **attestation** (étape 8) : toujours exigée — l'attestation de lab *est* ce
//!   consentement, elle ne le contourne pas.
//!
//! Ce module **ne réimplémente pas** le gate : il construit un [`Scope`] de
//! session (via [`Scope::from_toml`], qui valide les CIDR et calcule l'empreinte
//! SHA-256) et l'[`Attestation`] correspondante, puis les remet au gate en mode
//! [`AuditMode::Lab`]. Il porte en propre le **garde-fou de cohérence** : un
//! sous-réseau qui ne ressemble pas à un réseau privé/isolé déclenche un
//! avertissement et exige une confirmation renforcée (fail-safe §1).

use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, SecondsFormat, Utc};

use crate::audit::{AuditMode, AuditRecord, CapabilityLevel};
use crate::gate::{Attestation, Gate};
use crate::scope::{Scope, ScopeError};

// --- Erreurs ----------------------------------------------------------------

/// Raison pour laquelle un démarrage de lab est refusé (fail-safe §1 : en cas de
/// doute, on refuse plutôt que d'établir un périmètre douteux).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabError {
    /// Aucun sous-réseau déclaré : un lab exige au moins un CIDR.
    NoNetwork,
    /// Le scope de lab généré est invalide (CIDR mal formé, fenêtre incohérente…).
    /// Porte l'erreur sous-jacente de validation du scope.
    Scope(ScopeError),
}

impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabError::NoNetwork => {
                write!(f, "aucun sous-réseau déclaré (au moins un CIDR requis)")
            }
            LabError::Scope(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for LabError {}

// --- Session de lab ---------------------------------------------------------

/// Périmètre de lab établi (voie C) : le [`Scope`] de session, l'[`Attestation`]
/// unique qui le couvre, les sous-réseaux déclarés et ceux qui n'ont **pas**
/// l'air privés/isolés (garde-fou de cohérence).
///
/// On l'obtient par [`LabSession::start`]. Le gate s'en sert via
/// [`LabSession::gate`], qui le met en [`AuditMode::Lab`].
#[derive(Debug, Clone)]
pub struct LabSession {
    scope: Scope,
    attestation: Attestation,
    networks: Vec<String>,
    non_isolated: Vec<String>,
}

impl LabSession {
    /// Établit un périmètre de lab à partir des `networks` (CIDR), de
    /// l'`operator` qui atteste, et de la fenêtre `[valid_from, valid_until]`.
    ///
    /// Construit un [`Scope`] de session (capacités N1–N4 activées, défauts
    /// **sûrs** : `destructive_checks = false`, pas de plafond artificiel) en le
    /// faisant passer par [`Scope::from_toml`] — ce qui **valide** les CIDR et la
    /// fenêtre et **calcule l'empreinte SHA-256**. L'attestation unique est liée
    /// à cette empreinte exacte et à l'opérateur (étape 8 du gate).
    ///
    /// Refuse (fail-safe) si aucun réseau n'est déclaré, si un CIDR est mal formé
    /// ou si la fenêtre est incohérente (`valid_until` avant `valid_from`).
    pub fn start(
        networks: Vec<String>,
        operator: impl Into<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, LabError> {
        if networks.is_empty() {
            return Err(LabError::NoNetwork);
        }
        let operator = operator.into();
        let toml = build_lab_toml(&networks, &operator, valid_from, valid_until);
        let scope = Scope::from_toml(&toml).map_err(LabError::Scope)?;
        let perimeter = networks.join(", ");
        let attestation = Attestation::for_scope(&scope, operator, perimeter);
        let non_isolated = networks
            .iter()
            .filter(|cidr| !is_isolated_cidr(cidr.as_str()))
            .cloned()
            .collect();
        Ok(Self {
            scope,
            attestation,
            networks,
            non_isolated,
        })
    }

    /// Le scope de session construit pour ce lab.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// L'attestation unique couvrant ce périmètre (étape 8 du gate).
    #[must_use]
    pub fn attestation(&self) -> &Attestation {
        &self.attestation
    }

    /// Les sous-réseaux déclarés, dans l'ordre fourni.
    #[must_use]
    pub fn networks(&self) -> &[String] {
        &self.networks
    }

    /// Les sous-réseaux déclarés qui n'ont **pas** l'air privés/isolés (plage
    /// routable, hors RFC1918/ULA/link-local/loopback). Vide = périmètre sain.
    #[must_use]
    pub fn non_isolated_networks(&self) -> &[String] {
        &self.non_isolated
    }

    /// Vrai si au moins un sous-réseau déclaré n'a pas l'air privé/isolé : une
    /// **confirmation renforcée** est alors exigée avant de démarrer le lab
    /// (garde-fou de cohérence, pour éviter qu'un « lab » soit en réalité un
    /// réseau de production ou public).
    #[must_use]
    pub fn requires_reinforced_confirmation(&self) -> bool {
        !self.non_isolated.is_empty()
    }

    /// Un [`Gate`] adossé à ce périmètre, **en mode laboratoire**
    /// ([`AuditMode::Lab`]). Le scope est cloné : la session reste réutilisable.
    #[must_use]
    pub fn gate(&self) -> Gate {
        Gate::with_scope(self.scope.clone(), AuditMode::Lab)
    }

    /// Enregistrement d'audit du démarrage de lab (`lab.start`), marqué
    /// `mode = "lab"` : l'établissement du périmètre est lui-même journalisé
    /// (N1, comme l'attestation de cible). L'appelant l'écrit dans le journal
    /// chaîné.
    #[must_use]
    pub fn start_record(&self) -> AuditRecord {
        AuditRecord::new(
            self.scope.engagement.operator.clone(),
            self.networks.join(", "),
            "lab.start",
            "ok",
            CapabilityLevel::Recon,
        )
        .in_lab()
    }
}

// --- Construction du scope de lab -------------------------------------------

/// Génère le TOML canonique d'un scope de lab : capacités N1–N4 activées,
/// défauts sûrs (`manual`, `destructive_checks = false`, aucun plafond
/// artificiel), fenêtre fournie. Passé ensuite à [`Scope::from_toml`] qui valide
/// et empreinte. Les chaînes injectées sont échappées pour rester des chaînes
/// TOML valides (pas d'injection de structure).
fn build_lab_toml(
    networks: &[String],
    operator: &str,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> String {
    let nets = networks
        .iter()
        .map(|cidr| format!("\"{}\"", toml_escape(cidr)))
        .collect::<Vec<_>>()
        .join(", ");
    let operator = toml_escape(operator);
    let from = valid_from.to_rfc3339_opts(SecondsFormat::Secs, true);
    let until = valid_until.to_rfc3339_opts(SecondsFormat::Secs, true);
    format!(
        "[engagement]\n\
         client = \"Laboratoire (mode apprentissage)\"\n\
         reference = \"LAB\"\n\
         authorized_by = \"attestation de lab unique (voie C)\"\n\
         operator = \"{operator}\"\n\
         valid_from = \"{from}\"\n\
         valid_until = \"{until}\"\n\
         \n\
         [targets]\n\
         networks = [{nets}]\n\
         \n\
         [capabilities]\n\
         recon = true\n\
         \n\
         [capabilities.exploitation]\n\
         enabled = true\n\
         mode = \"manual\"\n\
         destructive_checks = false\n\
         \n\
         [capabilities.cracking]\n\
         enabled = true\n\
         online_spray = false\n\
         \n\
         [capabilities.emulation]\n\
         enabled = true\n"
    )
}

/// Échappe une chaîne pour une **chaîne de base** TOML : seuls `\` et `"`
/// peuvent briser le littéral et sont neutralisés. Un éventuel caractère de
/// contrôle restant fera échouer le parseur TOML (→ refus, fail-safe) plutôt que
/// d'ouvrir une injection.
fn toml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out
}

// --- Garde-fou de cohérence : réseau privé / isolé --------------------------

/// Blocs d'adresses considérés « privés / isolés » (lab-like) : RFC1918,
/// loopback et link-local (v4/v6), ULA v6. Volontairement **strict** : tout ce
/// qui n'est pas clairement dans l'un de ces blocs est jugé routable/public et
/// déclenche l'avertissement (fail-safe — on préfère sur-avertir).
const PRIVATE_BLOCKS: &[(&str, u8)] = &[
    ("10.0.0.0", 8),     // RFC1918
    ("172.16.0.0", 12),  // RFC1918
    ("192.168.0.0", 16), // RFC1918
    ("169.254.0.0", 16), // link-local v4 (RFC3927)
    ("127.0.0.0", 8),    // loopback v4
    ("fc00::", 7),       // ULA v6 (RFC4193)
    ("fe80::", 10),      // link-local v6
    ("::1", 128),        // loopback v6
];

/// Vrai si le CIDR déclaré est **entièrement** contenu dans un bloc privé/isolé.
/// Un CIDR mal formé renvoie `false` (fail-safe : traité comme non isolé →
/// avertissement). Les CIDR du scope sont de toute façon déjà validés en amont.
fn is_isolated_cidr(cidr: &str) -> bool {
    let Some(child) = parse_cidr(cidr) else {
        return false;
    };
    for (base, prefix) in PRIVATE_BLOCKS {
        if let Ok(ip) = base.parse::<IpAddr>() {
            if cidr_is_subnet(child, (ip, *prefix)) {
                return true;
            }
        }
    }
    false
}

/// Analyse un CIDR « adresse/longueur » en `(IpAddr, préfixe)`. `None` si mal
/// formé ou si le préfixe dépasse la taille de la famille.
fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = cidr.split_once('/')?;
    let ip = addr.parse::<IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return None;
    }
    Some((ip, prefix))
}

/// Vrai si `child` (CIDR) est un sous-réseau de `parent` (CIDR) : préfixe au
/// moins aussi long **et** base de `child` incluse dans `parent`. Familles
/// croisées (v4 vs v6) → jamais inclus.
fn cidr_is_subnet(child: (IpAddr, u8), parent: (IpAddr, u8)) -> bool {
    let (child_ip, child_prefix) = child;
    let (parent_ip, parent_prefix) = parent;
    if child_prefix < parent_prefix {
        return false;
    }
    match (child_ip, parent_ip) {
        (IpAddr::V4(c), IpAddr::V4(p)) => {
            let mask = if parent_prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(parent_prefix))
            };
            (u32::from(c) & mask) == (u32::from(p) & mask)
        }
        (IpAddr::V6(c), IpAddr::V6(p)) => {
            let mask = if parent_prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(parent_prefix))
            };
            (u128::from(c) & mask) == (u128::from(p) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    use crate::gate::{Action, Decision, DenyReason, Progress, Request};
    use crate::model::ExploitMode;
    use crate::scope::Capability;

    /// Opérateur de lab de référence (atteste et agit sous la même identité).
    const OP: &str = "apprenant@labo.local";

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    /// Session de lab de référence sur les CIDR donnés, fenêtre large.
    fn session(networks: &[&str]) -> LabSession {
        LabSession::start(
            networks.iter().map(|s| s.to_string()).collect(),
            OP,
            at(2026, 1, 1, 0),
            at(2027, 1, 1, 0),
        )
        .unwrap()
    }

    /// Instant nominal (dans la fenêtre de la session de référence).
    fn now() -> DateTime<Utc> {
        at(2026, 6, 1, 12)
    }

    // --- Établissement du périmètre -----------------------------------------

    #[test]
    fn lab_start_construit_un_scope_et_une_attestation_lies() {
        let s = session(&["10.10.1.0/24", "10.10.2.0/24"]);
        // Le périmètre couvre exactement les sous-réseaux déclarés.
        assert_eq!(
            s.networks().to_vec(),
            vec!["10.10.1.0/24".to_string(), "10.10.2.0/24".to_string()]
        );
        assert_eq!(s.scope().targets.networks, s.networks().to_vec());
        // L'attestation est liée à l'empreinte exacte du scope et à l'opérateur.
        assert_eq!(s.attestation().scope_fingerprint, s.scope().fingerprint());
        assert_eq!(s.attestation().operator, OP);
        // Capacités N1–N4 activées d'office.
        let caps = &s.scope().capabilities;
        assert!(caps.allows(Capability::Recon));
        assert!(caps.allows(Capability::Exploitation));
        assert!(caps.allows(Capability::Cracking));
        assert!(caps.allows(Capability::Emulation));
        // Défaut sûr conservé : pas de charge destructrice.
        assert!(!caps.exploitation.destructive_checks);
    }

    #[test]
    fn lab_start_sans_reseau_refuse() {
        let err = LabSession::start(vec![], OP, at(2026, 1, 1, 0), at(2027, 1, 1, 0)).unwrap_err();
        assert_eq!(err, LabError::NoNetwork);
    }

    #[test]
    fn lab_start_cidr_malforme_refuse() {
        let err = LabSession::start(
            vec!["10.10.1.0/99".to_string()],
            OP,
            at(2026, 1, 1, 0),
            at(2027, 1, 1, 0),
        )
        .unwrap_err();
        assert!(matches!(err, LabError::Scope(ScopeError::Network(_))), "{err}");
    }

    #[test]
    fn lab_start_fenetre_incoherente_refuse() {
        // valid_until avant valid_from → refus (fenêtre incohérente).
        let err = LabSession::start(
            vec!["10.10.1.0/24".to_string()],
            OP,
            at(2027, 1, 1, 0),
            at(2026, 1, 1, 0),
        )
        .unwrap_err();
        assert!(matches!(err, LabError::Scope(ScopeError::Window(_))), "{err}");
    }

    #[test]
    fn empreinte_reproductible_et_sensible_au_perimetre() {
        let a = session(&["10.10.1.0/24"]);
        let b = session(&["10.10.1.0/24"]);
        assert_eq!(a.scope().fingerprint(), b.scope().fingerprint());
        let c = session(&["10.10.2.0/24"]);
        assert_ne!(a.scope().fingerprint(), c.scope().fingerprint());
    }

    #[test]
    fn audit_du_lab_start_est_en_mode_lab() {
        let s = session(&["10.10.1.0/24", "10.10.2.0/24"]);
        let rec = s.start_record();
        assert_eq!(rec.action, "lab.start");
        assert_eq!(rec.result, "ok");
        assert_eq!(rec.mode, AuditMode::Lab);
        assert_eq!(rec.level, CapabilityLevel::Recon);
        assert_eq!(rec.operator, OP);
        assert_eq!(rec.target, "10.10.1.0/24, 10.10.2.0/24");
    }

    // --- Déblocage N1–N4 sur le périmètre (DoD, US-A5) ----------------------

    #[test]
    fn lab_debloque_n1_a_n4_dans_le_perimetre_sans_friction() {
        let s = session(&["10.10.1.0/24", "10.10.2.0/24"]);
        let att = s.attestation().clone();
        let mut gate = s.gate();
        assert_eq!(gate.mode(), AuditMode::Lab);

        let t1 = ip("10.10.1.5");
        let t2 = ip("10.10.2.9");

        // N1 — recon active : libre, aucune pré-condition.
        let req = Request::new(now(), OP).with_attestation(&att);
        let recon = Action::Recon { target: t1 };
        assert_eq!(gate.check(&recon, &req), Decision::Allow);

        // Pré-conditions N≥2 : recon aboutie enregistrée sur chaque cible
        // (étape 4 inchangée, même en labo).
        let mut prog = Progress::new();
        prog.record(t1, Capability::Recon);
        prog.record(t2, Capability::Recon);
        // Volontairement SANS .confirmed() : le labo lève la confirmation (étape 5).
        let req = Request::new(now(), OP)
            .with_attestation(&att)
            .with_progress(&prog);

        // N2 — exploitation (Validate) alors que `allowed_hosts` est vide et
        // sans confirmation : le sous-filtre de l'étape 3 et l'étape 5 sont levés.
        let exploit = Action::Exploit {
            target: t1,
            mode: ExploitMode::Validate,
        };
        assert_eq!(gate.check(&exploit, &req), Decision::Allow);

        // N4 — émulation d'une technique non listée (sous-filtre technique levé).
        let emulate = Action::Emulate {
            target: t2,
            technique: "T9999".to_string(),
        };
        assert_eq!(gate.check(&emulate, &req), Decision::Allow);

        // N3 — spray en ligne sans opt-in `online_spray` ni confirmation.
        let crack = Action::Crack {
            target: t2,
            online: true,
            account: Some("admin".to_string()),
        };
        assert_eq!(gate.check(&crack, &req), Decision::Allow);
    }

    // --- Garde-fou de cohérence : réseau non isolé --------------------------

    #[test]
    fn detecte_un_reseau_non_prive_et_exige_confirmation_renforcee() {
        // Un sous-réseau privé + un sous-réseau publiquement routable.
        let s = session(&["10.10.1.0/24", "8.8.8.0/24"]);
        assert!(s.requires_reinforced_confirmation());
        assert_eq!(s.non_isolated_networks().to_vec(), vec!["8.8.8.0/24".to_string()]);
    }

    #[test]
    fn reseaux_prives_rfc1918_ne_declenchent_aucun_avertissement() {
        let s = session(&["10.0.0.0/24", "172.16.5.0/24", "192.168.56.0/24"]);
        assert!(!s.requires_reinforced_confirmation());
        assert!(s.non_isolated_networks().is_empty());
    }

    #[test]
    fn classification_reseau_prive_ou_routable() {
        // Privés / isolés.
        assert!(is_isolated_cidr("10.10.1.0/24"));
        assert!(is_isolated_cidr("172.16.0.0/12"));
        assert!(is_isolated_cidr("172.31.255.0/24"));
        assert!(is_isolated_cidr("192.168.56.0/24"));
        assert!(is_isolated_cidr("169.254.0.0/16"));
        assert!(is_isolated_cidr("127.0.0.0/8"));
        assert!(is_isolated_cidr("fd00::/8")); // ULA ⊂ fc00::/7
        assert!(is_isolated_cidr("fe80::/64"));
        assert!(is_isolated_cidr("::1/128"));

        // Routables / publics / hors blocs privés → non isolés.
        assert!(!is_isolated_cidr("8.8.8.0/24"));
        assert!(!is_isolated_cidr("1.1.1.1/32"));
        assert!(!is_isolated_cidr("172.32.0.0/16")); // hors du /12
        assert!(!is_isolated_cidr("100.64.0.0/10")); // CGNAT : prudence → avertit
        assert!(!is_isolated_cidr("2001:db8::/32")); // global unicast
        // Trop large pour être contenu dans un bloc privé → non isolé (fail-safe).
        assert!(!is_isolated_cidr("10.0.0.0/4"));
        // Mal formé → non isolé (fail-safe).
        assert!(!is_isolated_cidr("pas-un-cidr"));
    }

    // --- Tests négatifs de sécurité §10.4 : la sûreté ne baisse jamais ------

    #[test]
    fn negatif_lab_reste_confine_au_perimetre_declare() {
        // Confinement (étape 2) : un sous-réseau NON déclaré reste hors
        // d'atteinte, même en labo, et le refus est journalisé en mode lab.
        let s = session(&["10.10.1.0/24", "10.10.2.0/24"]);
        let att = s.attestation().clone();
        let mut gate = s.gate();

        let undeclared = ip("10.10.9.4"); // 10.10.9.0/24 non déclaré
        let mut prog = Progress::new();
        prog.record(undeclared, Capability::Recon);
        let req = Request::new(now(), OP)
            .with_attestation(&att)
            .with_progress(&prog)
            .confirmed();

        let action = Action::Exploit {
            target: undeclared,
            mode: ExploitMode::Validate,
        };
        let decision = gate.check(&action, &req);
        assert_eq!(decision, Decision::Deny(DenyReason::OutOfScope));

        // Journalisé : action bloquée hors-scope (code stable `target`), mode lab.
        let rec = crate::gate::audit_record(&action, decision, OP, AuditMode::Lab);
        assert_eq!(rec.action, "blocked_target");
        assert_eq!(rec.result, "blocked");
        assert_eq!(rec.mode, AuditMode::Lab);
    }

    #[test]
    fn negatif_lab_recon_active_hors_perimetre_refusee() {
        // Même la recon ACTIVE sur un hôte hors périmètre est droppée (§3.2) ;
        // seule l'observation passive échappe au gate (et ne passe pas par ici).
        let s = session(&["10.10.1.0/24"]);
        let att = s.attestation().clone();
        let mut gate = s.gate();
        let req = Request::new(now(), OP).with_attestation(&att);
        let action = Action::Recon {
            target: ip("192.168.99.1"),
        };
        assert_eq!(gate.check(&action, &req), Decision::Deny(DenyReason::OutOfScope));
    }

    #[test]
    fn negatif_lab_n_outrepasse_jamais_l_attestation() {
        // L'attestation (étape 8) reste exigée : sans elle, tout est refusé même
        // dans le périmètre de lab.
        let s = session(&["10.10.1.0/24"]);
        let mut gate = s.gate();
        let t = ip("10.10.1.5");
        let mut prog = Progress::new();
        prog.record(t, Capability::Recon);
        let req = Request::new(now(), OP).with_progress(&prog); // sans attestation
        let action = Action::Exploit {
            target: t,
            mode: ExploitMode::Validate,
        };
        let out = gate.check(&action, &req);
        assert_eq!(out, Decision::Deny(DenyReason::AttestationMissing));
    }

    #[test]
    fn negatif_lab_conserve_l_anti_destruction() {
        // destructive_checks = false (défaut sûr du lab) ⇒ charge destructrice
        // refusée en labo comme ailleurs (étape 6 inchangée).
        let s = session(&["10.10.1.0/24"]);
        let att = s.attestation().clone();
        let mut gate = s.gate();
        let t = ip("10.10.1.5");
        let mut prog = Progress::new();
        prog.record(t, Capability::Recon);
        let req = Request::new(now(), OP)
            .with_attestation(&att)
            .with_progress(&prog)
            .confirmed();
        let action = Action::Exploit {
            target: t,
            mode: ExploitMode::Exploit, // charge destructrice
        };
        assert_eq!(gate.check(&action, &req), Decision::Deny(DenyReason::Destructive));
    }

    #[test]
    fn negatif_lab_conserve_les_plafonds() {
        // Le labo ne contourne pas l'étape 7 : un lab qui fixe un plafond le voit
        // appliqué. Scope de lab (mode lab) avec max_rate_pps = 1 : deux recon au
        // même instant épuisent le seau.
        let toml = "\
[engagement]
client = \"Lab\"
reference = \"LAB\"
authorized_by = \"attestation de lab\"
operator = \"apprenant@labo.local\"
valid_from = \"2026-01-01T00:00:00Z\"
valid_until = \"2027-01-01T00:00:00Z\"

[targets]
networks = [\"10.10.1.0/24\"]

[constraints]
max_rate_pps = 1

[capabilities]
recon = true
";
        let scope = Scope::from_toml(toml).unwrap();
        let att = Attestation::for_scope(&scope, OP, "10.10.1.0/24");
        let mut gate = Gate::with_scope(scope, AuditMode::Lab);
        let action = Action::Recon {
            target: ip("10.10.1.5"),
        };
        let req = Request::new(now(), OP).with_attestation(&att);
        assert_eq!(gate.check(&action, &req), Decision::Allow);
        assert_eq!(gate.check(&action, &req), Decision::Deny(DenyReason::RateExceeded));
    }
}
