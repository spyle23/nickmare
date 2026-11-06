# Fuzzing des parsers (`cargo-fuzz`) — issue #28, §10.4

Cibles [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) des **parsers de
données externes hostiles** de Nickmare. Elles prouvent, en explorant l'espace
des entrées, que ces parsers ne **paniquent jamais** (§12) :

| Cible | Parser | Crate |
|-------|--------|-------|
| `banner`     | bannières de services (`identify_service` / `clean_banner`) | `net::service_id` (#13) |
| `scope_toml` | fichier de scope TOML (`Scope::from_toml` / `Scope::load`) | `core::scope` (#3) |
| `wifi_pcap`  | captures pcap WiFi (`inventory_from_pcap` / `PcapCapture::parse`) | `net::wifi` (#15) |

## Pourquoi hors du workspace

`cargo-fuzz` exige le toolchain **nightly** et libFuzzer, **incompatibles** avec
le pin MSRV 1.83 stable du workspace (et l'absence de `Cargo.lock`). Ce crate est
donc **exclu** du workspace principal (`exclude = ["fuzz"]` dans le `Cargo.toml`
racine) et constitue son propre workspace : aucun `cargo *--workspace`, ni
`cargo generate-lockfile` (→ `audit`/`deny`), ne le résout. Il **ne peut pas**
casser la CI de PR bloquante.

## Le filet bloquant est ailleurs

Le contrat de CI **bloquant** pour le fuzzing repose sur des tests de robustesse
« type fuzz » **déterministes sur stable**, dans
[`crates/sectests/tests/fuzz_parsers.rs`](../crates/sectests/tests/fuzz_parsers.rs) :
ils exercent les **mêmes** parsers (corpus réels + mutations + aléatoire à graine
fixe) dans le job `test` normal, sans nightly, sans réseau et sans instabilité.
Ces cibles `cargo-fuzz` les **complètent** par une exploration plus large,
exécutée **périodiquement** par un job nightly **non bloquant**
([`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml)).

## Lancer en local (nightly requis)

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# Run court d'une cible (depuis la racine du dépôt) :
cargo +nightly fuzz run banner     --fuzz-dir fuzz -- -max_total_time=30
cargo +nightly fuzz run scope_toml --fuzz-dir fuzz -- -max_total_time=30
cargo +nightly fuzz run wifi_pcap  --fuzz-dir fuzz -- -max_total_time=30
```

Un reproducteur trouvé est déposé sous `fuzz/artifacts/<cible>/` ; on le rejoue
avec `cargo +nightly fuzz run <cible> --fuzz-dir fuzz <artefact>`, puis on ajoute
le cas au corpus déterministe de `fuzz_parsers.rs` pour verrouiller la
non-régression.

## Extensibilité (Phases 6/7/8)

Les parsers des capacités N2–N4 (sorties **hashcat/John**, **Metasploit RPC**,
flux d'émulation) — derrière le jalon de revue #17, **non franchi** — n'existent
pas encore. Leurs cibles de fuzz s'ajouteront ici (un fichier par cible +
l'entrée `[[bin]]` correspondante), sans changer la structure.
