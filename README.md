# Nickmare

> Outil d'audit de sécurité réseau multiplateforme (Windows / Linux), écrit en Rust.

Destiné **exclusivement** à des engagements de test d'intrusion **autorisés par écrit**, à
l'audit de réseaux dont l'utilisateur est propriétaire ou gestionnaire, et à l'apprentissage
de la sécurité réseau en **laboratoire contrôlé et isolé**.

- **Statut** : conception (v0.2) — aucune ligne de code encore écrite.
- **Spécification** : voir [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

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

Voir [`LICENSE`](LICENSE) (à définir).
