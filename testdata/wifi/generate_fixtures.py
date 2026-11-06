#!/usr/bin/env python3
"""Générateur **déterministe** des captures pcap de référence du WiFi passif.

Issue #15 (cf. ``docs/ARCHITECTURE.md`` §9 Phase 4). Les octets d'un pcap sont
opaques en revue : ce script versionné les rend reproductibles et lisibles. Il
n'émet **aucune** trame — il écrit des fichiers rejoués par les tests de
``crates/net/src/wifi.rs``. Toutes les données sont **synthétiques** (SSID
fictifs, BSSID en plage localement administrée 02:…, aucune donnée réelle).

Usage (depuis la racine du dépôt) ::

    python testdata/wifi/generate_fixtures.py

Réécrit :
  - ``wifi_beacons.pcap``     — radiotap (DLT 127) : Open / WEP / WPA2 / WPA3,
                                SSID masqué, probe-response, trame data ignorée,
                                et un beacon dupliqué (signal plus fort) ;
  - ``wifi_raw_80211.pcap``   — 802.11 brut (DLT 105), sans radiotap ;
  - ``wifi_truncated.pcap``   — trames partielles + dernier enregistrement coupé.
"""

import os
import struct

LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127

# Types d'AKM RSN (OUI 00-0F-AC) utiles ici.
AKM_DOT1X = 1
AKM_PSK = 2  # WPA2-Personal
AKM_SAE = 8  # WPA3-Personal


def pcap_global_header(linktype):
    # Magique micro-seconde little-endian (0xa1b2c3d4), version 2.4.
    return struct.pack(
        "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype
    )


def pcap_record(data, ts_sec=1_700_000_000, ts_usec=0, orig_len=None):
    if orig_len is None:
        orig_len = len(data)
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), orig_len) + data


def radiotap(signal_dbm, freq, chan_flags=0x00A0):
    """En-tête radiotap minimal : Flags, Rate, Channel, Antenna signal (dBm)."""
    present = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5)
    body = b""
    body += struct.pack("<B", 0x00)  # Flags
    body += struct.pack("<B", 0x02)  # Rate (unités de 500 kb/s → 1 Mb/s)
    body += struct.pack("<HH", freq, chan_flags)  # Channel : fréquence + flags
    body += struct.pack("<b", signal_dbm)  # Antenna signal, dBm (signé)
    it_len = 8 + len(body)
    header = struct.pack("<BBHI", 0, 0, it_len, present)
    return header + body


def rsn_ie(akm_types):
    """Information Element RSN (tag 48) : CCMP + liste d'AKM."""
    ie = struct.pack("<H", 1)  # version
    ie += bytes([0x00, 0x0F, 0xAC, 4])  # group cipher = CCMP
    ie += struct.pack("<H", 1) + bytes([0x00, 0x0F, 0xAC, 4])  # pairwise = CCMP
    ie += struct.pack("<H", len(akm_types))
    for akm in akm_types:
        ie += bytes([0x00, 0x0F, 0xAC, akm])
    ie += struct.pack("<H", 0x0000)  # RSN capabilities
    return bytes([48, len(ie)]) + ie


def wpa_vendor_ie():
    """IE vendeur Microsoft (tag 221, OUI 00:50:F2 type 1) = WPA1/TKIP."""
    data = bytes([0x00, 0x50, 0xF2, 0x01])
    data += struct.pack("<H", 1)  # version
    data += bytes([0x00, 0x50, 0xF2, 0x02])  # group = TKIP
    data += struct.pack("<H", 1) + bytes([0x00, 0x50, 0xF2, 0x02])  # pairwise
    data += struct.pack("<H", 1) + bytes([0x00, 0x50, 0xF2, 0x02])  # akm PSK
    return bytes([221, len(data)]) + data


def mgmt_frame(subtype, bssid, ssid, channel, privacy,
               rsn=None, wpa_vendor=False, with_ds=True):
    """Trame de gestion 802.11 (beacon=8, probe-response=5)."""
    fc0 = 0x00 | (0x00 << 2) | (subtype << 4)  # version 0, type 0 (gestion)
    frame = bytes([fc0, 0x00])  # Frame Control
    frame += b"\x00\x00"  # Duration
    frame += b"\xff\xff\xff\xff\xff\xff"  # Adresse 1 (destination)
    frame += bytes(bssid)  # Adresse 2 (source)
    frame += bytes(bssid)  # Adresse 3 (BSSID)
    frame += b"\x00\x00"  # Sequence Control

    # Paramètres fixes : timestamp(8) + beacon interval(2) + capability(2).
    frame += b"\x00" * 8
    frame += struct.pack("<H", 100)
    cap = 0x0001  # ESS
    if privacy:
        cap |= 0x0010  # Privacy
    frame += struct.pack("<H", cap)

    # Paramètres marqués (information elements).
    frame += bytes([0, len(ssid)]) + ssid  # SSID (tag 0)
    frame += bytes([1, 4, 0x82, 0x84, 0x8B, 0x96])  # Supported Rates (tag 1)
    if with_ds:
        frame += bytes([3, 1, channel])  # DS Parameter Set (tag 3) → canal
    if rsn is not None:
        frame += rsn_ie(rsn)
    if wpa_vendor:
        frame += wpa_vendor_ie()
    return frame


def data_frame(bssid):
    """Trame de données (type 2) — doit être ignorée par l'inventaire."""
    fc0 = 0x00 | (0x02 << 2) | (0x00 << 4)  # version 0, type 2 (data)
    frame = bytes([fc0, 0x00]) + b"\x00\x00"
    frame += b"\xff\xff\xff\xff\xff\xff"
    frame += bytes(bssid) + bytes(bssid) + b"\x00\x00"
    frame += b"charge utile ignoree"
    return frame


def write(path, linktype, records):
    blob = pcap_global_header(linktype)
    for rec in records:
        blob += rec
    with open(path, "wb") as handle:
        handle.write(blob)
    print(f"{path}: {len(blob)} octets, {len(records)} enregistrement(s)")


def bssid(last):
    return [0x02, 0x11, 0x22, 0x33, 0x44, last]


def build_beacons(path):
    records = []

    # 1. Réseau ouvert (pas de Privacy) — canal 1, -40 dBm.
    records.append(pcap_record(
        radiotap(-40, 2412)
        + mgmt_frame(8, bssid(0x01), b"OpenCafe", 1, privacy=False)))

    # 2. WEP (Privacy sans RSN ni WPA) — canal 6, -62 dBm.
    records.append(pcap_record(
        radiotap(-62, 2437)
        + mgmt_frame(8, bssid(0x02), b"OldWEP", 6, privacy=True)))

    # 3. WPA2-PSK (RSN AKM PSK) — canal 11, -55 dBm.
    records.append(pcap_record(
        radiotap(-55, 2462)
        + mgmt_frame(8, bssid(0x03), b"HomeWPA2", 11, privacy=True,
                     rsn=[AKM_PSK])))

    # 3bis. Même BSSID vu une 2e fois, signal plus fort (-48) → dédup + maj.
    records.append(pcap_record(
        radiotap(-48, 2462)
        + mgmt_frame(8, bssid(0x03), b"HomeWPA2", 11, privacy=True,
                     rsn=[AKM_PSK])))

    # 4. WPA3-SAE — canal 36 (5 GHz), -70 dBm.
    records.append(pcap_record(
        radiotap(-70, 5180)
        + mgmt_frame(8, bssid(0x04), b"SecureWPA3", 36, privacy=True,
                     rsn=[AKM_SAE])))

    # 5. SSID masqué + transition WPA2/WPA3 (PSK + SAE) → classé WPA3, -48 dBm.
    records.append(pcap_record(
        radiotap(-48, 2412)
        + mgmt_frame(8, bssid(0x05), b"", 1, privacy=True,
                     rsn=[AKM_PSK, AKM_SAE])))

    # 6. Probe-response (subtype 5) WPA2 — prouve le parsing probe-resp, -58 dBm.
    records.append(pcap_record(
        radiotap(-58, 2412)
        + mgmt_frame(5, bssid(0x06), b"GuestNet", 1, privacy=True,
                     rsn=[AKM_PSK])))

    # 7. WPA1 vendeur (TKIP) — canal 6, -66 dBm.
    records.append(pcap_record(
        radiotap(-66, 2437)
        + mgmt_frame(8, bssid(0x07), b"LegacyWPA", 6, privacy=True,
                     wpa_vendor=True)))

    # 8. Trame de données — ignorée par l'inventaire (ni beacon ni probe-resp).
    records.append(pcap_record(radiotap(-50, 2412) + data_frame(bssid(0x08))))

    write(path, LINKTYPE_IEEE802_11_RADIOTAP, records)


def build_raw(path):
    # 802.11 brut, sans radiotap : la puissance est inconnue, le canal vient du
    # DS Parameter Set.
    records = [pcap_record(
        mgmt_frame(8, bssid(0x20), b"RawAP", 3, privacy=True, rsn=[AKM_PSK]))]
    write(path, LINKTYPE_IEEE802_11, records)


def build_truncated(path):
    records = []

    # a. Beacon coupé au milieu des paramètres fixes : seul le BSSID est sûr,
    #    chiffrement indéterminé → trame partielle tolérée, sans panique.
    full = radiotap(-45, 2412) + mgmt_frame(
        8, bssid(0x30), b"PartialAP", 1, privacy=True, rsn=[AKM_PSK])
    radiotap_len = 8 + 2 + 4 + 1  # cf. radiotap() ci-dessus (15 octets)
    cut = radiotap_len + 24 + 6  # en-tête MAC complet + 6 octets fixes (< 12)
    records.append(pcap_record(full[:cut]))

    # b. Trame beaucoup trop courte (quelques octets) → rejetée proprement.
    records.append(pcap_record(radiotap(-50, 2412) + b"\x80\x00\x00"))

    # c. Radiotap annonçant une longueur supérieure aux octets présents → rejeté.
    broken_rt = struct.pack("<BBHI", 0, 0, 64, 0x2E)  # it_len=64 mais vide
    records.append(pcap_record(broken_rt + b"\x80\x00"))

    # d. Un beacon WPA2 complet et valide, pour prouver que les trames saines de
    #    la même capture restent inventoriées malgré les partielles.
    records.append(pcap_record(
        radiotap(-52, 2437)
        + mgmt_frame(8, bssid(0x31), b"HealthyAP", 6, privacy=True,
                     rsn=[AKM_PSK])))

    # e. Dernier enregistrement volontairement coupé : l'en-tête annonce plus
    #    d'octets que le fichier n'en contient → le lecteur pcap doit s'arrêter
    #    sans paniquer (fin de capture tronquée, cas réel d'arrêt brutal).
    good = radiotap(-60, 2462) + mgmt_frame(
        8, bssid(0x32), b"NeverSeen", 11, privacy=False)
    header = struct.pack(
        "<IIII", 1_700_000_000, 0, len(good) + 40, len(good) + 40)
    truncated_record = header + good[:10]  # données tronquées

    blob = pcap_global_header(LINKTYPE_IEEE802_11_RADIOTAP)
    for rec in records:
        blob += rec
    blob += truncated_record
    with open(path, "wb") as handle:
        handle.write(blob)
    print(f"{path}: {len(blob)} octets, {len(records)} + 1 (tronqué)")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    build_beacons(os.path.join(here, "wifi_beacons.pcap"))
    build_raw(os.path.join(here, "wifi_raw_80211.pcap"))
    build_truncated(os.path.join(here, "wifi_truncated.pcap"))


if __name__ == "__main__":
    main()
