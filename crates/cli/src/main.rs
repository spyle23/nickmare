//! Binaire `nickmare` — point d'entrée de l'outil (placeholder Phase 0, issue #1).
//!
//! L'orchestration réelle (parsing clap, chargement du scope, exécution des
//! niveaux) arrive dans les phases suivantes (cf. `docs/ARCHITECTURE.md` §4).

/// Bannière de version, dérivée des métadonnées du paquet.
fn banniere() -> String {
    format!(
        "nickmare {} — placeholder Phase 0",
        env!("CARGO_PKG_VERSION")
    )
}

fn main() {
    println!("{}", banniere());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_workspace() {
        assert!(banniere().starts_with("nickmare "));
    }
}
