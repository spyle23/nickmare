# Nickmare

> Outil d'audit de sécurité réseau multiplateforme (Windows / Linux), écrit en Rust.

Destiné **exclusivement** à des engagements de test d'intrusion **autorisés par écrit**, à
l'audit de réseaux dont l'utilisateur est propriétaire ou gestionnaire, et à l'apprentissage
de la sécurité réseau en **laboratoire contrôlé et isolé**.

- **Statut** : fondations (v0.2) — workspace Cargo et CI multiplateforme en place (Phase 0).
- **Spécification** : voir [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture & spécifications.
- [`docs/LEGAL.md`](docs/LEGAL.md) — cadre d'usage, modèle d'autorisation écrite, mentions légales.
- [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) — guide opérateur, flux d'intrusion
  simulée, modèle de scope, et [kill-switch réseau du lab](docs/OPERATOR_GUIDE.md#kill-switch-réseau-du-lab).
- [`docs/TESTING.md`](docs/TESTING.md) — stratégie de tests.
- [`docs/REVIEW_GATE_N2.md`](docs/REVIEW_GATE_N2.md) — revue des garde-fous avant N2–N4
  (jalon bloquant, §9).

## Prérequis système

Nickmare est multiplateforme (Windows / Linux). La capture de paquets et le scan SYN
nécessitent une bibliothèque de capture native :

- **Linux** : `libpcap` (paquet de la distribution, p. ex. `libpcap-dev` / `libpcap-devel`).
  Le SYN scan et la capture brute requièrent la capability `CAP_NET_RAW` (ou `root`).
- **Windows** : [**Npcap**](https://npcap.com/) requis pour la capture et le SYN scan.
  Sa présence est détectée au démarrage ; à défaut, un message clair est affiché.

Le mode `tcp_connect_only` fonctionne sans privilèges élevés ni bibliothèque de capture.

## Compiler & tester

```sh
cargo build --workspace      # compile toutes les crates
cargo test  --workspace      # lance les tests
cargo fmt --all -- --check   # vérifie le formatage
cargo clippy --all-targets --all-features -- -D warnings
```

La toolchain est épinglée par [`rust-toolchain.toml`](rust-toolchain.toml) ; la CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) rejoue build, test, `fmt` et
`clippy` sur Windows **et** Linux.

## Principes directeurs

1. **Recon libre, action ciblée** — la reconnaissance passive ne demande aucune autorisation ;
   toute action active exige un périmètre établi et attesté.
2. **Traçabilité totale, même en mode furtif** — chaque action est journalisée de façon
   inaltérable côté opérateur, quel que soit le mode.
3. **Human-in-the-loop pour l'intrusif** — l'exploitation et le craquage exigent une
   confirmation explicite (sauf mode labo, qui lève la confirmation par cible mais jamais la traçabilité).
4. **Non destructif par défaut** — aucune charge destructrice sans drapeau explicite.
5. **Fail-safe** — en cas de doute, l'outil s'arrête plutôt que d'agir.

## Roadmap

L'implémentation suit 10 phases incrémentales (Phase 0 → Phase 9), chacune produisant un
incrément utilisable et testé. Voir les *milestones* et *issues* du dépôt, et
[`docs/ARCHITECTURE.md` §9](docs/ARCHITECTURE.md).

## Licence

Nickmare est distribué sous licence **Apache-2.0** — voir [`LICENSE`](LICENSE). Cette
licence régit les droits sur le *logiciel* ; elle ne confère **aucun** droit d'auditer
des systèmes tiers. L'usage de l'outil est réservé aux engagements autorisés (voir
[`docs/LEGAL.md`](docs/LEGAL.md)).
