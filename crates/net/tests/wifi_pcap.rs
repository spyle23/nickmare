//! Test d'intégration — inventaire WiFi **passif** par rejeu de captures pcap
//! (issue #15 ; cf. `docs/ARCHITECTURE.md` §9 Phase 4, `docs/TESTING.md` §3).
//!
//! On rejoue des captures de référence déterministes (`testdata/wifi/`) via
//! l'API publique de `net::wifi` : aucun matériel WiFi, aucun privilège, aucune
//! trame émise (écoute pure). On prouve la chaîne « lire la capture → extraire
//! les points d'accès (SSID, BSSID, canal, chiffrement, puissance) », le repli
//! clair quand la capture en direct est indisponible, et l'absence de panique
//! sur des trames partielles.

// Fichier de tests d'intégration (100 % code de test) : les lints de sûreté du
// workspace (unwrap/expect/panic interdits sur les chemins d'exécution, #27) ne
// s'appliquent pas ici — un `unwrap` qui échoue EST le signal d'échec attendu.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use nickmare_net::wifi::{self, AccessPoint, Encryption, FrameSource, PcapReplaySource, WifiError};

const BEACONS: &[u8] = include_bytes!("../../../testdata/wifi/wifi_beacons.pcap");
const RAW: &[u8] = include_bytes!("../../../testdata/wifi/wifi_raw_80211.pcap");
const TRUNCATED: &[u8] = include_bytes!("../../../testdata/wifi/wifi_truncated.pcap");

fn by_ssid<'a>(aps: &'a [AccessPoint], ssid: &str) -> &'a AccessPoint {
    aps.iter()
        .find(|ap| ap.ssid.as_deref() == Some(ssid))
        .unwrap_or_else(|| panic!("AP {ssid} absent"))
}

#[test]
fn inventaire_passif_extrait_ssid_bssid_canal_chiffrement_puissance() {
    let aps = wifi::inventory_from_pcap(BEACONS).unwrap();
    // 7 BSSID distincts (le beacon dupliqué est fusionné, la trame data ignorée).
    assert_eq!(aps.len(), 7);

    // Chaque niveau de chiffrement du ticket est couvert (US-D1).
    assert_eq!(by_ssid(&aps, "OpenCafe").encryption, Encryption::Open);
    assert_eq!(by_ssid(&aps, "OldWEP").encryption, Encryption::Wep);
    assert_eq!(by_ssid(&aps, "HomeWPA2").encryption, Encryption::Wpa2);
    assert_eq!(by_ssid(&aps, "SecureWPA3").encryption, Encryption::Wpa3);

    // SSID + BSSID + canal + puissance d'un AP concret.
    let wpa2 = by_ssid(&aps, "HomeWPA2");
    assert_eq!(wpa2.bssid.to_string(), "02:11:22:33:44:03");
    assert_eq!(wpa2.channel, Some(11));
    assert_eq!(wpa2.signal_dbm, Some(-48)); // signal le plus fort retenu
}

#[test]
fn rejeu_via_source_passive_equivaut_au_pcap() {
    // La source ne permet que de lire les trames (réception seule) : même
    // inventaire qu'en passant directement par le pcap.
    let mut source = PcapReplaySource::from_pcap(BEACONS).unwrap();
    let depuis_source = wifi::inventory_from_source(&mut source).unwrap();
    assert_eq!(depuis_source, wifi::inventory_from_pcap(BEACONS).unwrap());
}

#[test]
fn source_802_11_brut_sans_radiotap() {
    let mut source: Box<dyn FrameSource> = Box::new(PcapReplaySource::from_pcap(RAW).unwrap());
    let aps = wifi::inventory_from_source(&mut *source).unwrap();
    assert_eq!(aps.len(), 1);
    let ap = &aps[0];
    assert_eq!(ap.encryption, Encryption::Wpa2);
    assert_eq!(ap.channel, Some(3)); // DS Parameter Set
    assert_eq!(ap.signal_dbm, None); // aucune puissance sans en-tête radio
}

#[test]
fn trames_partielles_ne_paniquent_pas() {
    // Captures mêlant trames tronquées et enregistrement final coupé : l'écoute
    // dégrade proprement sans panique (§12) et retient les AP sains.
    let aps = wifi::inventory_from_pcap(TRUNCATED).unwrap();
    assert!(aps.iter().any(|ap| ap.ssid.as_deref() == Some("HealthyAP")));
    assert!(aps.iter().any(|ap| ap.encryption == Encryption::Unknown));
}

#[test]
fn capture_en_direct_indisponible_donne_un_repli_clair() {
    // DoD Phase 4 : repli clair si capture indisponible (pas de Npcap/monitor).
    assert!(matches!(
        wifi::open_live("wlan0"),
        Err(WifiError::CaptureUnavailable { .. })
    ));
}
