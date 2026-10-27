# Tests d'intégration end-to-end

Tests d'intégration transverses au workspace, exécutés **avec le `NetworkProvider`
mock** (aucun trafic réseau réel), conformément à [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §6
et à [`docs/TESTING.md`](../docs/TESTING.md).

Vide au départ (Phase 0) : les scénarios bout-en-bout arrivent avec les crates
qu'ils exercent (recon → scan → identification → rapport), à partir de la Phase 1.
