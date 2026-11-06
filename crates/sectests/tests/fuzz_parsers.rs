//! Robustesse « type fuzz » **déterministe** des parsers existants (issue #28,
//! §10.4 ; `docs/ARCHITECTURE.md` §12 « parsing défensif »).
//!
//! Invariant prouvé : **aucune entrée hostile ne fait paniquer l'outil**. Une
//! bannière, un fichier de scope TOML ou une capture pcap malformés/tronqués/
//! aléatoires doivent **dégrader proprement** (`Result`/valeur par défaut sûre),
//! jamais paniquer — c'est la condition pour qu'une donnée réseau adverse ne
//! puisse jamais détourner l'outil.
//!
//! # Pourquoi « type fuzz » sur **stable**, et pas `cargo-fuzz` ici
//!
//! `cargo-fuzz` exige le toolchain **nightly** + libFuzzer, incompatibles avec
//! le pin MSRV 1.83 stable du workspace (et l'absence de Cargo.lock). Ces tests
//! rejouent donc un **générateur déterministe** (LCG sans dépendance externe,
//! graine fixe) couplé à des **corpus réels** (bannières usuelles, scopes et
//! captures de `testdata/`) et à leurs mutations. Ils tournent dans le job
//! `test` normal (Windows + Linux), **bloquant**, sans réseau, sans nightly et
//! sans la moindre instabilité. Les **mêmes** parsers sont aussi câblés à de
//! vraies cibles `cargo-fuzz` dans `fuzz/` (hors workspace), exercées par un job
//! nightly dédié et non bloquant (voir `fuzz/README.md`).

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'appliquent pas ici — un `unwrap` qui échoue EST le signal d'échec attendu,
// et les helpers hors #[test] échappent au allow-in-tests de clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use nickmare_core::scope::Scope;
use nickmare_net::service_id::{clean_banner, identify_service};
use nickmare_net::wifi::{self, PcapCapture};

/// Bornage interne d'une bannière nettoyée (cf. `BANNER_TEXT_CAP` de #13).
const BANNER_CAP: usize = 256;

/// Corpus de bannières **réelles** (graines des mutations ciblées).
const BANNERS: &[&[u8]] = &[
    b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1\r\n",
    b"SSH-2.0-dropbear_2022.83",
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n",
    b"HTTP/1.1 404 Not Found\r\nServer: Apache/2.4.58 (Ubuntu)\r\n\r\n",
    b"220 (vsFTPd 3.0.5)\r\n",
    b"220 mail.example.com ESMTP Postfix\r\n",
    b"+OK Dovecot ready.\r\n",
    b"* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n",
    b"\xff\xfe\x00\x01binaire\x7f",
];

/// Corpus de scopes TOML **réels** (fixtures de `testdata/scope/`).
const SCOPE_CORPUS: &[&str] = &[
    include_str!("../../../testdata/scope/valid.toml"),
    include_str!("../../../testdata/scope/expired.toml"),
    include_str!("../../../testdata/scope/integrity.toml"),
];

/// Corpus de captures pcap **réelles** (fixtures de `testdata/wifi/`).
const PCAPS: &[&[u8]] = &[
    include_bytes!("../../../testdata/wifi/wifi_beacons.pcap"),
    include_bytes!("../../../testdata/wifi/wifi_raw_80211.pcap"),
    include_bytes!("../../../testdata/wifi/wifi_truncated.pcap"),
];

/// Générateur congruentiel linéaire déterministe (sans dépendance externe) :
/// même graine ⇒ même suite d'octets ⇒ test reproductible, jamais flaky.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mul = self.0.wrapping_mul(6_364_136_223_846_793_005);
        self.0 = mul.wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// Entier dans `0..n` (0 si `n == 0`).
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// Applique 1 à 6 mutations d'octets à une graine : flip, insertion, suppression
/// et troncature — de quoi casser en-têtes, longueurs et frontières de champs.
fn mutate(rng: &mut Lcg, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    let ops = 1 + rng.below(6);
    for _ in 0..ops {
        if v.is_empty() {
            v.push(rng.byte());
            continue;
        }
        let i = rng.below(v.len());
        match rng.below(4) {
            0 => v[i] = rng.byte(),
            1 => v.insert(i, rng.byte()),
            2 => {
                v.remove(i);
            }
            _ => v.truncate(i),
        }
    }
    v
}

// --- Parser de bannières (service_id #13) -----------------------------------

#[test]
fn fuzz_bannieres_ne_paniquent_jamais() {
    let mut rng = Lcg::new(0x5EED_0028_BEEF_1234);

    // a) Corpus réel muté.
    for &seed in BANNERS {
        for _ in 0..64 {
            let data = mutate(&mut rng, seed);
            let port = rng.next_u64() as u16;
            let svc = identify_service(port, Some(data.as_slice()));
            assert!(!svc.name.is_empty(), "nom de service jamais vide");
            if let Some(banner) = svc.banner.as_deref() {
                assert!(banner.chars().count() <= BANNER_CAP, "bannière bornée");
            }
            let _ = clean_banner(&data);
        }
    }

    // b) Pur aléatoire de longueurs variées (dont 0 et grandes).
    for _ in 0..4096 {
        let len = rng.below(400);
        let data = rng.bytes(len);
        let port = rng.next_u64() as u16;
        let svc = identify_service(port, Some(data.as_slice()));
        assert!(!svc.name.is_empty());
    }

    // c) Cas limites : absence / vide.
    assert!(!identify_service(0, None).name.is_empty());
    assert!(!identify_service(22, Some(b"")).name.is_empty());
    assert!(clean_banner(b"").is_none());
}

// --- Parser de scope TOML (scope #3) ----------------------------------------

#[test]
fn fuzz_scope_toml_ne_panique_jamais() {
    let mut rng = Lcg::new(0x5C0E_0028_1234_ABCD);

    for &seed in SCOPE_CORPUS {
        // La fixture telle quelle : parse sans paniquer (Ok OU Err selon le cas).
        let _ = Scope::from_toml(seed);
        let _ = Scope::load(seed, Some("00"));
        for _ in 0..96 {
            let data = mutate(&mut rng, seed.as_bytes());
            let text = String::from_utf8_lossy(&data);
            let _ = Scope::from_toml(&text);
            // `load` avec une clé malformée : si [integrity] apparaît, refus
            // propre (Err), jamais de panique.
            let _ = Scope::load(&text, Some("00"));
        }
    }

    // Pur aléatoire (souvent UTF-8 invalide → décodage lossy avant parse).
    for _ in 0..2048 {
        let len = rng.below(256);
        let data = rng.bytes(len);
        let text = String::from_utf8_lossy(&data);
        let _ = Scope::from_toml(&text);
    }
}

// --- Parser de capture pcap WiFi (wifi #15) ---------------------------------

#[test]
fn fuzz_wifi_pcap_ne_panique_jamais() {
    let mut rng = Lcg::new(0x11F1_0028_FACE_0001);

    for &seed in PCAPS {
        // a) Toutes les troncatures-préfixes (dégradation défensive, §12).
        let step = 1 + seed.len() / 128;
        let mut n = 0;
        while n <= seed.len() {
            let _ = wifi::inventory_from_pcap(&seed[..n]);
            let _ = PcapCapture::parse(&seed[..n]);
            n += step;
        }
        // b) Mutations d'octets (en-têtes/longueurs corrompus).
        for _ in 0..96 {
            let data = mutate(&mut rng, seed);
            let _ = wifi::inventory_from_pcap(&data);
            let _ = PcapCapture::parse(&data);
        }
    }

    // c) Pur aléatoire.
    for _ in 0..2048 {
        let len = rng.below(512);
        let data = rng.bytes(len);
        let _ = wifi::inventory_from_pcap(&data);
    }
}
