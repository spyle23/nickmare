//! Cible cargo-fuzz : parser de capture pcap WiFi (net::wifi #15).
//!
//! Invariant : rejouer une capture tronquée/corrompue dégrade proprement
//! (`Result`), jamais une panique (§12). Pendant nightly uniquement.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nickmare_net::wifi::{self, PcapCapture};

fuzz_target!(|data: &[u8]| {
    let _ = wifi::inventory_from_pcap(data);
    let _ = PcapCapture::parse(data);
});
