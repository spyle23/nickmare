<!-- Le label `auto-merge` déclenche la fusion squash automatique dès que la CI est verte. -->

## Ticket lié

Closes #<!-- numéro -->

## Ce que fait cette PR

<!-- Résumé orienté résultat. -->

## Invariants de sécurité (docs/ARCHITECTURE.md §3, §11)

- [ ] Non destructif par défaut — aucune action intrusive sans drapeau explicite
- [ ] Toute action active reste bornée au périmètre attesté (recon libre / action ciblée)
- [ ] Journal d'audit inaltérable préservé (aucune action ne contourne la traçabilité)
- [ ] Fail-safe : en cas de doute, l'outil s'arrête plutôt que d'agir

## Définition de réussite (docs/TESTING.md)

- [ ] Critères d'acceptation du ticket satisfaits
- [ ] Tests ajoutés/à jour (unitaires, intégration, **tests négatifs de sécurité** si pertinent)
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo test` verts localement (si code Rust)
