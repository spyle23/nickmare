# Nickmare — Stratégie de tests

> Ce document pose **d'abord** la définition de réussite du produit, puis les tests qui la vérifient.
> Il complète `ARCHITECTURE.md` §10 et les tickets #17, #19, #20, #28.

---

## 1. Définition de réussite (principale)

> **Le logiciel choisit un réseau et s'y infiltre, puis choisit une cible et s'y infiltre.**
> → **RÉUSSI.**
>
> **S'il n'y arrive pas → NON RÉUSSI.**

C'est l'objectif du produit. Tous les tests fonctionnels mesurent **ça** : la chaîne
d'intrusion simulée aboutit, de bout en bout, sur des cibles **autorisées** (labo isolé ou
périmètre attesté, §10.3).

```
recon  → choisir un réseau  → s'y infiltrer   (accès obtenu)   ✅
       → choisir un hôte     → s'y infiltrer   (accès obtenu)   ✅
       → pivot vers la machine suivante         (accès obtenu)   ✅

Chaîne complète aboutie   = RÉUSSI
Accès non obtenu           = NON RÉUSSI
```

### Critères concrets de « réussi » (par étape)

| Étape | Réussi si… | Non réussi si… |
|-------|-----------|----------------|
| Choix du réseau | un réseau est sélectionné et le périmètre est actif | aucun périmètre établi |
| Infiltration du réseau | un hôte du réseau est atteint / une entrée obtenue | aucun accès obtenu |
| Choix de la cible | un hôte précis est désigné dans la carte | pas d'hôte désignable |
| Infiltration de l'hôte | **accès/preuve d'exploitabilité obtenu** (`ExploitOutcome = Success`) | `Failed` / pas d'accès |
| Pivot | rebond réussi vers une autre machine du périmètre (`PivotLink` créé) | pivot impossible |

> Ces tests tournent en **labo isolé** (§10.3) contre des cibles volontairement vulnérables
> (Metasploitable, DVWA, VulnHub). C'est là — et seulement là — qu'on mesure une infiltration réelle.

---

## 2. Filet de sécurité (secondaire)

En plus de l'objectif ci-dessus, une seconde famille de tests vérifie que l'outil **reste dans
la zone autorisée** : il doit bloquer et tracer toute action qui sortirait du périmètre attesté.

**Ce filet ne change pas la définition de réussite du produit.** Il ne doit jamais empêcher
l'infiltration **dans** la zone autorisée ; il empêche seulement d'agir **en dehors**.

- Réussi : action **dans** le périmètre → elle aboutit (voir §1).
- Filet OK : action **hors** périmètre → bloquée + journalisée (sinon, c'est un bug de confinement).

---

## 3. Comment les tests tournent

| Famille | Outil | Quand | Ce que ça prouve |
|---|---|---|---|
| Unitaires | `cargo test` | chaque commit | logique (gate, scope, audit, parsers) |
| Intégration (mocks) | `cargo test` + `tests/` | CI | chaîne recon→report sans réseau réel |
| **Infiltration réelle** | **labo isolé** | **manuel** | **la définition de réussite §1** |
| Filet de sécurité | `cargo test` | CI (bloquante) | confinement au périmètre |
| Fuzzing | `cargo-fuzz` | périodique | parsers ne paniquent pas |
| Qualité | `clippy`, `fmt`, `cargo audit/deny` | CI | tenue du code |

- **Local / CI** : logique + mocks, sans privilèges, sans réseau — on ne s'infiltre nulle part
  en CI (pas de cible réelle disponible, et par sûreté).
- **Labo isolé (§10.3)** : la vraie mesure de la réussite. VMs sans route vers l'extérieur,
  kill-switch réseau documenté dans `OPERATOR_GUIDE.md`.
