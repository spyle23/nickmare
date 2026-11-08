# Revue des garde-fous avant N2–N4 (jalon bloquant)

> Jalon de revue obligatoire — `docs/ARCHITECTURE.md` §9 (entre Phase 5 et Phase 6),
> issue [#17](https://github.com/spyle23/nickmare/issues/17). Les niveaux 2–4
> (intrusif/offensif) ne démarrent **qu'après** le franchissement de ce jalon.

- **Date** : 2026-11-08
- **Revue par** : agent `dev-ticket` (run `20261108T175711Z-44ca`, autorisation humaine groupée accordée)
- **Nature** : revue formelle de sûreté — **aucune nouvelle fonctionnalité**. On vérifie,
  preuve à l'appui (fichier:ligne, nom de test, job CI), que le filet de confinement et
  d'anti-destruction est en place **avant** d'ouvrir l'implémentation offensive N2–N4.
- **Base revue** : `origin/main` à `d0ef8de` (prérequis mergés : Phase 0, #26 robustesse,
  #27 durcissement, #28 tests négatifs transverses).

## Méthode

Chaque item de la *Definition of Done* est confronté au **code réel** et à la **config CI**.
Un item n'est coché **OK** que si une preuve vérifiable l'atteste ; tout manque serait
signalé comme **bloquant** (rôle d'un jalon bloquant, fail-safe §1). L'exécution locale de
`cargo` n'est pas disponible dans cet environnement : **l'autorité d'exécution est la CI**
(jobs du dépôt). La revue cite donc les jobs et les tests concernés ; le verdict vert
définitif est celui de la CI sur la PR. Les suites `#28` citées sont déjà mergées sur `main`
(commit `8766608`), donc déjà passées en CI.

---

## Checklist de revue

### 1. `gate` — les 8 étapes implémentées, couvertes par tests positifs ET négatifs

**Statut : OK.**

Les étapes 0→8 (§3.2) sont implémentées dans `Gate::check` — `crates/core/src/gate.rs:473-575` :

| Étape | Contrôle | Implémentation | Test positif | Test négatif |
|------|----------|----------------|--------------|--------------|
| 0 | Périmètre établi | `gate.rs:475-477` | (implicite via les autres) | `etape0_sans_perimetre_tout_est_refuse` (`gate.rs:900`) |
| 1 | Validation temporelle (`valid_from/until`, `allowed_hours`) | `gate.rs:481-487` | `etape1_recon_dans_la_fenetre_autorisee` (`gate.rs:911`) | `etape1_hors_fenetre_temporelle_refuse` (`gate.rs:921`), `etape1_hors_fenetre_horaire_refuse` (`gate.rs:935`) |
| 2 | Filtre de cible (scope + exclusions) | `gate.rs:490-496`, `target_in_scope`/`target_excluded` `gate.rs:581-591` | `etape2_cible_dans_le_perimetre_autorisee` (`gate.rs:949`) | `etape2_cible_hors_perimetre_refuse` (`gate.rs:961`), `etape2_cible_exclue_refusee_malgre_le_reseau` (`gate.rs:972`), `etape2_exclusion_par_sous_reseau` (`gate.rs:984`) |
| 3 | Filtre de capacité (`allowed_hosts`, technique, `online_spray`) | `gate.rs:498-501`, `capability_denial` `gate.rs:597-633` | `etape3_exploitation_sur_hote_autorise` (`gate.rs:998`), `etape3_emulation_technique_listee_autorisee` (`gate.rs:1056`), `etape3_crack_hors_ligne_autorise_sans_confirmation` (`gate.rs:1082`) | `negatif_exploitation_hors_allowed_hosts_refuse` (`gate.rs:1008`), `negatif_capacite_desactivee_rend_inatteignable` (`gate.rs:1023`), `negatif_technique_attack_non_listee_refuse` (`gate.rs:1041`), `negatif_spray_en_ligne_sans_optin_refuse` (`gate.rs:1069`) |
| 4 | Pré-conditions (résultat N inférieur requis) | `gate.rs:503-512`, `Progress::has_lower_than` `gate.rs:342-348` | `etape4_recon_ne_demande_aucune_precondition` (`gate.rs:1126`) | `negatif_exploitation_sans_precondition_refuse` (`gate.rs:1098`), `etape4_precondition_sur_une_autre_cible_ne_compte_pas` (`gate.rs:1111`) |
| 5 | Confirmation humaine (mode `manual`, spray en ligne) | `gate.rs:514-517`, `confirmation_required` `gate.rs:636-647` | `etape5_mode_auto_ne_demande_pas_de_confirmation` (`gate.rs:1153`) | `negatif_exploitation_manual_sans_confirmation_refuse` (`gate.rs:1139`) |
| 6 | Garde anti-destruction (`destructive_checks`) | `gate.rs:519-525` | `etape6_exploit_reel_autorise_si_destructive_checks_true` (`gate.rs:1183`) | `negatif_charge_destructrice_refusee` (`gate.rs:1169`) |
| 7 | Plafonds (`max_rate_pps`, `max_actions`, `max_attempts_per_account`) | `gate.rs:527-544` (+ consommation différée `gate.rs:559-572`) | inclus dans les cas `Allow` ci-dessus | `negatif_max_actions_depasse_refuse` (`gate.rs:1195`), `negatif_max_attempts_par_compte_depasse_refuse` (`gate.rs:1210`), `negatif_max_rate_pps_depasse_puis_recharge` (`gate.rs:1230`), `etape7_refus_amont_ne_consomme_pas_le_debit` (`gate.rs:1250`) |
| 8 | Attestation / consentement (empreinte + opérateur) | `gate.rs:546-557` | tous les cas `Allow` (requête attestée) | `negatif_sans_attestation_refuse` (`gate.rs:1271`), `negatif_attestation_pour_un_autre_scope_refuse` (`gate.rs:1282`), `negatif_attestation_autre_operateur_refuse` (`gate.rs:1295`) |

Points de sûreté vérifiés en complément :
- Le gate est l'**unique chemin** vers l'exécution (doc de module `gate.rs:1-17`) ; seule la
  recon **passive** n'y passe pas (documenté).
- **Ordre des étapes** : le premier échec prime (`ordre_des_etapes_le_premier_echec_prime`
  `gate.rs:1310`).
- **Fail-safe** : défauts sûrs de `Request` (ni attestation, ni confirmation, ni progression)
  → refus par défaut (`gate.rs:366-376`) ; les plafonds ne sont **consommés** qu'en cas
  d'`Allow` (`gate.rs:559-572`), prouvé par `etape7_refus_amont_ne_consomme_pas_le_debit`.
- Journalisation des décisions en `blocked_<code>` (`audit_record` `gate.rs:733-754`,
  `audit_chaque_raison_a_un_code_blocked_distinct` `gate.rs:1408`).

> Nuance de nommage (non bloquante) : §3.2 parle des « huit étapes » tout en numérotant de 0
> à 8 (l'étape 0 « périmètre établi ? » est la porte d'entrée). Les 9 contrôles numérotés sont
> tous implémentés et testés ; l'écart est purement terminologique.

### 2. Tests négatifs du gate **verts en CI** (§10.4, crate `nickmare-sectests`, job `negatif`)

**Statut : OK.**

Le job CI **`negatif`** (`.github/workflows/ci.yml:83-92`) exécute
`cargo test -p nickmare-sectests --all-features`. Il est **précondition de merge** : le job
`auto-merge` le liste dans `needs` et exige `needs.negatif.result == 'success'`
(`ci.yml:205-215`). Il ne peut donc pas être dilué dans le job `test` global.

La suite transverse `crates/sectests/tests/confinement_negatif.rs` couvre chaque cas exigé —
**refus + audit chaîné `blocked_*`** via le helper `refuse_et_journalise` (`confinement_negatif.rs:184-189`)
qui relit le journal et vérifie l'intégrité (`journalise` `confinement_negatif.rs:152-181`) :

- **Hors `allowed_hosts`** : `exploitation_hors_allowed_hosts_refuse_et_journalise`
  (`confinement_negatif.rs:238`) → `blocked_allowed_hosts`.
- **Capacité désactivée inatteignable** : `exploitation_desactivee_rend_inatteignable`
  (`:260`), `cracking_desactive_rend_inatteignable` (`:281`),
  `emulation_desactivee_rend_inatteignable` (`:301`) → `blocked_capability`, même avec
  recon aboutie et confirmation (l'étape 3 tranche en amont).
- **Technique ATT&CK non listée** : `technique_attack_non_listee_refuse` (`:320`) →
  `blocked_technique`.
- **Dépassement de plafond** : `plafond_debit_depasse_refuse_et_journalise` (`:193`) →
  `blocked_rate`.
- **Hors scope / exclusion** : `cible_hors_scope_refuse_et_journalise` (`:209`),
  `cible_exclue_refuse_malgre_le_reseau` (`:219`).
- **Mode `manual` sans confirmation** + **module destructeur** : le mock ne tourne que sur
  `Allow` (`run_via_gate` `:346-357`) ; `mode_manual_bloque_sans_confirmation_et_le_module_ne_tourne_pas`
  (`:359`), `module_destructeur_refuse_quand_destructive_checks_false` (`:379`).
- **Confinement du scan** : `scan_hors_scope_refuse_sans_lire_de_banniere` (`:424`) — refus
  **avant** toute lecture de bannière (provider mock vide).
- **Règle d'or §10.4** (le filet ne bloque pas le légitime) : `le_filet_ne_bloque_pas_dans_le_perimetre` (`:399`).

> Honnêteté sur le « vert » : `cargo` n'est pas exécutable dans l'environnement de revue ;
> la preuve de verdict est le **job CI `negatif`**. La suite #28 est déjà mergée sur `main`
> (commit `8766608`) — donc déjà passée en CI — et la présente PR n'ajoute que du Markdown
> (aucun changement de comportement Rust). Nuance de vocabulaire : le dépôt est privé **sans
> protection de branche** (`ci.yml:9-12`) ; « bloquant » signifie ici *précondition du job
> `auto-merge`*, qui **est** le mécanisme de fusion du projet — fonctionnellement une porte
> de merge.

### 3. `audit` — chaînage vérifié, altération détectée, append-only, permissions restreintes

**Statut : OK.** `crates/core/src/audit.rs`.

- **Chaînage** : chaque entrée porte `prev_hash` → `hash` SHA-256 couvrant tous les champs
  (`AuditEntry` `audit.rs:78-105`, `compute_hash` `:278-284`) ; `verify_entries`
  (`:317-330`) revalide hash **et** lien. Test `chaine_de_hash_valide_et_relue` (`:436`).
- **Altération détectée** : ligne **modifiée** → `HashMismatch`
  (`negatif_ligne_modifiee_detectee` `:510`) ; **supprimée** → `BrokenChain`
  (`negatif_ligne_supprimee_detectee` `:525`) ; **insérée** (hash cohérent mais lien rompu)
  → `BrokenChain` (`negatif_ligne_inseree_detectee` `:539`) ; **corrompue** →
  `MalformedLine` (`negatif_fichier_corrompu_detecte` `:575`).
- **Append-only** : `open_append` ouvre en `append(true).create(true)` (`:345-354`) ;
  reprise idempotente du chaînage (`:206-216`, `reouverture_reprend_la_chaine` `:608`) ;
  `append_ne_reecrit_pas_en_place` (`:588`) prouve que le préfixe reste intact et que le
  fichier ne fait que croître.
- **Permissions restreintes** : `mode(0o600)` sur Unix (`:348-352`) ; test
  `fichier_a_permissions_restreintes_sur_unix` vérifie `mode & 0o077 == 0` (`:642-654`).
- **Traçabilité §11.3** : furtif pour la cible, en clair pour l'opérateur — une technique N4
  masquée est tout de même journalisée (`action_emulee_masquee_tracee_en_clair_meme_en_stealth` `:472`).

> Limite de conception, documentée et acceptée (non bloquante) : un journal chaîné **non
> signé/non ancré** n'empêche pas à lui seul la réécriture *complète* du suffixe par un
> attaquant disposant d'un accès en écriture — c'est le rôle des permissions `0600` + de
> l'append-only OS (doc de module `audit.rs:20-25`). Les permissions restreintes couvrent ce
> vecteur sur Unix ; sur Windows, l'ACL par défaut du profil s'applique (`audit.rs:342-344`).

### 4. `scope` — capacités désactivées par défaut ; intégrité SHA-256 ; refus de signature invalide

**Statut : OK.** `crates/core/src/scope.rs`.

- **Désactivées par défaut** : `Capabilities` dérive `Default` avec `enabled = false` partout
  (`:193-206`, sous-blocs `:234-284`) ; `Capabilities::allows` ne renvoie `true` que pour la
  recon (`:214-221`). Tests : `capacites_desactivees_par_defaut` (`:690`),
  `sans_capacite_seule_la_recon_est_autorisee` (`:704`),
  `capacites_absentes_du_toml_restent_desactivees` (`:713`). Défense en profondeur :
  `deny_unknown_fields` (`champ_inconnu_refuse` `:753`), plafond négatif rejeté (`:779`).
- **Intégrité SHA-256** : `fingerprint` calculée après parse (`from_toml` `:359-368`,
  `sha256_hex` `:511-516`). Tests : `empreinte_64_hex_minuscules` (`:677`),
  `empreinte_reproductible_et_sensible` (`:824`), `sha256_vecteurs_connus` (vecteurs NIST,
  `:835`).
- **Refus de signature invalide** : `verify_signature` (ed25519 `verify_strict`,
  `:421-449`) refuse signature altérée, mauvaise clé, clé/signature mal formées ; `load`
  **exige** une clé de confiance dès que `[integrity]` est présent (`:375-385`). Tests :
  `signature_alteree_refusee` (`:880`), `signature_mauvaise_cle_refusee` (`:891`),
  `integrity_presente_sans_cle_refuse_le_chargement` (`:899`), plus le cas positif
  `signature_valide_acceptee` (`:873`).

### 5. Mode labo — n'allège QUE les étapes 3/5 + fichier signé ; confinement/anti-destruction/plafonds intacts

**Statut : OK.** `crates/core/src/gate.rs` + `crates/core/src/lab.rs`.

- **Portée du labo strictement limitée aux étapes 3 et 5** : la variable `lab` n'est lue que
  par `capability_denial` (étape 3, renvoie `None` → `gate.rs:597-600`) et
  `confirmation_required` (étape 5, renvoie `false` → `gate.rs:636-639`). Les étapes 0, 1,
  2, 4, 6, 7, 8 n'en dépendent pas (`Gate::check` `:473-575`). Conforme à `ARCHITECTURE.md`
  §3.2 (ligne 222) : labo ⇒ étapes 3, 5 et exigence de **fichier signé** levées uniquement.
- **Fichier signé levé** : la voie C génère un scope de session **sans** bloc `[integrity]`
  (`build_lab_toml` `lab.rs:187-228`) à partir d'une attestation unique — pas de fichier
  signé requis — tout en calculant l'empreinte SHA-256 (via `Scope::from_toml`).
- **Confinement intact (étape 2)** : `labo_garde_le_confinement_au_perimetre` (`gate.rs:1344`),
  `negatif_lab_reste_confine_au_perimetre_declare` (`lab.rs:537`),
  `negatif_lab_recon_active_hors_perimetre_refusee` (`lab.rs:567`).
- **Anti-destruction intacte (étape 6)** : `labo_garde_l_anti_destruction_et_les_plafonds`
  (`gate.rs:1358`), `negatif_lab_conserve_l_anti_destruction` (`lab.rs:602`) — défaut sûr
  `destructive_checks = false` conservé dans le scope de lab (`lab.rs:219`).
- **Plafonds intacts (étape 7)** : `negatif_lab_conserve_les_plafonds` (`lab.rs:626`).
- **Attestation toujours exigée (étape 8)** : `labo_exige_toujours_une_attestation`
  (`gate.rs:1372`), `negatif_lab_n_outrepasse_jamais_l_attestation` (`lab.rs:584`).
- **Garde-fou de cohérence propre au labo** : un sous-réseau non privé/isolé exige une
  confirmation renforcée (`requires_reinforced_confirmation` `lab.rs:152-154`,
  `detecte_un_reseau_non_prive_et_exige_confirmation_renforcee` `lab.rs:494`).

### 6. Revue documentée et validée

**Statut : OK.** Le présent document (`docs/REVIEW_GATE_N2.md`) constitue le compte-rendu
versionné ; il est référencé depuis l'index de documentation (`README.md`). La validation
formelle relève de l'agent QA (verdict `PASS`) et de la CI verte sur la PR liée à #17.

---

## Conclusion

**Jalon franchi.** Les six items de la *Definition of Done* sont satisfaits, preuves à
l'appui : les 8 (0→8) étapes du gate sont implémentées et couvertes par des tests positifs et
négatifs ; la suite négative transverse (§10.4) est câblée dans le job CI **`negatif`**, lui-même
précondition du merge ; le journal d'audit est chaîné, détecte toute altération, est
append-only et à permissions restreintes ; le scope désactive les capacités intrusives par
défaut, calcule une empreinte SHA-256 et refuse toute signature invalide ; le mode labo
n'allège que les étapes 3/5 et l'exigence de fichier signé, en laissant debout confinement,
anti-destruction, plafonds et attestation.

**Aucun garde-fou manquant n'a été identifié.** Les deux limites relevées (réécriture complète
du suffixe d'un journal non ancré, contrée par permissions + append-only OS ; « bloquant » =
précondition du job `auto-merge` faute de protection de branche sur un dépôt privé) sont des
caractéristiques **documentées et assumées** de la conception, pas des régressions — elles ne
remettent pas en cause le franchissement du jalon.

Sous réserve du verdict `PASS` de la QA et de la CI verte sur la PR, **l'implémentation N2–N4
(Phases 6/7/8) peut démarrer**.
