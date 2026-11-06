# Données de test

Jeux de données de référence pour les tests (cf. [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §6) :

- scopes de test (`*.toml`) — **autorisés par `.gitignore`** sous `testdata/` ;
- scénarios de recon mock (`mock/recon_simple.json`) rejoués par
  `MockNetworkProvider`, et carte réseau de démonstration
  (`mock/network_map.json`) rendue par `nickmare map` ;
- bannières de services (`mock/service_banners.json`) rejouées par
  `MockNetworkProvider` pour l'identification de services (`net::service_id`, Phase 3) ;
- captures pcap de référence pour le **WiFi passif** (`wifi/`, Phase 4,
  `net::wifi`), rejouées par `inventory_from_pcap` — **synthétiques** (SSID
  fictifs, BSSID en plage localement administrée `02:…`, reproductibles via
  `wifi/generate_fixtures.py`, marquées `binary` dans `.gitattributes`) :
  - `wifi/wifi_beacons.pcap` — beacons radiotap (DLT 127) : ouvert / WEP / WPA2 /
    WPA3, SSID masqué, probe-response, trame de données ignorée, beacon dupliqué ;
  - `wifi/wifi_raw_80211.pcap` — 802.11 brut (DLT 105), sans radiotap ;
  - `wifi/wifi_truncated.pcap` — trames partielles + dernier enregistrement coupé
    (robustesse défensive, §12) ;
- fixtures CVE / NVD pour la corrélation (`cve/`, Phase 3, crate `nickmare-cve`) :
  - `cve/nvd_feed_sample.json` — extrait **synthétique** du flux NVD (format API
    2.0), parsé défensivement par `cve::nvd::parse_feed` ;
  - `cve/cache_sample.json` — base/cache CVE **locale** (schéma `CveDatabase`),
    rejouée par `cve::correlate` pour le chemin **hors ligne**.
  Toutes les CVE y sont synthétiques (identifiants réalistes, données factices).

Vide au départ (Phase 0). Aucune donnée réelle d'engagement ne doit être déposée
ici : uniquement des fixtures synthétiques et non sensibles.
