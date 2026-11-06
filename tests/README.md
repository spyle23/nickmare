# Tests d'intégration end-to-end

Tests d'intégration transverses au workspace, exécutés **avec le `NetworkProvider`
mock** (aucun trafic réseau réel), conformément à [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §6
et à [`docs/TESTING.md`](../docs/TESTING.md).

> **Où vivent concrètement ces tests ?** Le `Cargo.toml` racine est un workspace
> **virtuel** (sans `[package]`) : un fichier `tests/*.rs` déposé ici ne serait
> **pas** compilé ni exécuté par `cargo test --workspace`. Les tests
> d'intégration transverses sont donc hébergés par un **crate dédié**,
> [`crates/sectests`](../crates/sectests) (`nickmare-sectests`), qui peut
> dev-dépendre de plusieurs crates et tourne bien en CI :
>
> - **suite négative de sécurité** (§10.4, issue #28) : confinement au périmètre,
>   refus + journalisation, « désactiver une capacité la rend inatteignable » ;
> - **scénario mock** recon → scan → identification → corrélation CVE → constats ;
> - **robustesse « type fuzz »** déterministe des parsers (bannières, TOML, pcap).
>
> Le fuzzing `cargo-fuzz` (nightly) vit à part dans [`fuzz/`](../fuzz) (hors
> workspace), exercé par un job CI non bloquant.

Les scénarios bout-en-bout s'enrichissent avec les crates qu'ils exercent
(recon → scan → identification → rapport, puis exploit → crack → émulation à
partir des Phases 6/7/8).
