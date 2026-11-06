//! Cible cargo-fuzz : parser de bannières (net::service_id #13).
//!
//! Invariant : identifier un service à partir d'octets réseau **hostiles** ne
//! panique jamais (§12). Pendant nightly uniquement (voir ../README.md).
#![no_main]

use libfuzzer_sys::fuzz_target;
use nickmare_net::service_id::{clean_banner, identify_service};

fuzz_target!(|data: &[u8]| {
    // Un port dérivé des données varie la table « well-known » / le repli.
    let port = if data.len() >= 2 {
        u16::from_le_bytes([data[0], data[1]])
    } else {
        0
    };
    let service = identify_service(port, Some(data));
    assert!(!service.name.is_empty());
    let _ = clean_banner(data);
});
