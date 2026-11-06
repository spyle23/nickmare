//! WiFi passif — inventaire des points d'accès **strictement en écoute** (issue
//! #15, cf. `docs/ARCHITECTURE.md` §2 N1, §9 Phase 4, US-D1, §12).
//!
//! # Invariant non négociable : zéro émission
//!
//! Ce module **n'émet jamais** la moindre trame : il se contente d'**écouter**
//! l'air (beacons et probe-responses diffusés par les points d'accès) et d'en
//! dresser l'inventaire. L'invariant est garanti **par construction** : la seule
//! abstraction de capture ([`FrameSource`]) est en **réception seule**
//! (`next_frame`), sans aucune méthode d'émission ; aucune fonction du module
//! n'ouvre de socket d'envoi. Contrairement au scan de ports (#12, recon
//! *active* confinée au gate), l'écoute passive ne sollicite pas la cible et ne
//! traverse donc pas de gate — rien n'est transmis sur le réseau.
//!
//! # Un cœur **pur** et défensif
//!
//! Les octets capturés viennent de l'air : ils sont **hostiles par principe**
//! (§12). Tout le décodage est donc **pur** et défensif — [`PcapCapture::parse`]
//! (format pcap classique), le dépouillement radiotap et l'analyse des trames de
//! gestion 802.11 n'`unwrap`ent jamais une donnée externe, ne paniquent jamais
//! sur une trame tronquée ou malformée, et bornent chaque lecture. Une trame
//! partielle **dégrade proprement** (BSSID conservé, reste indéterminé) plutôt
//! que d'interrompre l'inventaire.
//!
//! On extrait, par point d'accès ([`AccessPoint`]) : SSID (masqué → `None`),
//! BSSID, canal, chiffrement ([`Encryption`] : ouvert / WEP / WPA / WPA2 / WPA3)
//! et puissance reçue (dBm, via radiotap). Les observations sont **dédupliquées
//! par BSSID** (le signal le plus fort et les champs les plus complets priment).
//!
//! # Rejeu de captures et capture en direct
//!
//! La source éprouvée et portable est le **rejeu** d'une capture pcap
//! ([`PcapReplaySource`], [`inventory_from_pcap`]) : c'est elle que rejouent les
//! tests, sans matériel WiFi ni privilèges, à partir de fixtures
//! (`testdata/wifi/`). La **capture passive en direct** (mode monitor Linux /
//! Npcap Windows) se branche derrière la même [`FrameSource`] via
//! [`open_live`] ; tant que le binding natif n'est pas livré — ou en l'absence
//! de pilote (pas de Npcap, interface hors mode monitor) — elle renvoie un
//! **repli clair** ([`WifiError::CaptureUnavailable`]), jamais une panique.

use std::collections::BTreeMap;
use std::fmt;

use nickmare_core::model::MacAddr;

/// Link-type pcap « IEEE 802.11 brut » (sans en-tête radiotap).
pub const LINKTYPE_IEEE802_11: u32 = 105;
/// Link-type pcap « IEEE 802.11 + radiotap » (en-tête radio en préfixe).
pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;

/// Type d'AKM RSN (OUI 00-0F-AC) « SAE » : marqueur de WPA3-Personal.
const AKM_SAE: u8 = 8;

const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;

// --- Types d'inventaire -----------------------------------------------------

/// Chiffrement annoncé par un point d'accès, du plus faible au plus robuste.
///
/// `Unknown` est réservé aux trames **partielles** dont on n'a pu lire que le
/// BSSID : on n'invente jamais un niveau de sécurité à partir de données
/// tronquées (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// Réseau ouvert (aucun chiffrement).
    Open,
    /// WEP (obsolète, cassé).
    Wep,
    /// WPA « original » (TKIP, IE vendeur Microsoft).
    Wpa,
    /// WPA2 (RSN, sans SAE).
    Wpa2,
    /// WPA3 (RSN avec AKM SAE ; inclut la transition WPA2/WPA3).
    Wpa3,
    /// Indéterminé (trame partielle : seul le BSSID a pu être lu).
    Unknown,
}

impl Encryption {
    /// Libellé court et stable, pour l'affichage et les rapports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Encryption::Open => "ouvert",
            Encryption::Wep => "WEP",
            Encryption::Wpa => "WPA",
            Encryption::Wpa2 => "WPA2",
            Encryption::Wpa3 => "WPA3",
            Encryption::Unknown => "indéterminé",
        }
    }

    /// Vrai si le chiffrement est **faible** (ouvert, WEP ou WPA d'origine) :
    /// base d'un constat de sécurité à venir (hors périmètre de ce ticket).
    #[must_use]
    pub fn is_weak(self) -> bool {
        matches!(self, Encryption::Open | Encryption::Wep | Encryption::Wpa)
    }
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Point d'accès observé passivement : ce que révèle un beacon ou une
/// probe-response, sans jamais rien émettre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPoint {
    /// SSID diffusé (`None` si masqué : longueur nulle ou octets nuls).
    pub ssid: Option<String>,
    /// BSSID (adresse MAC de l'AP).
    pub bssid: MacAddr,
    /// Canal annoncé (DS Parameter Set, ou déduit de la fréquence radiotap).
    pub channel: Option<u8>,
    /// Chiffrement annoncé.
    pub encryption: Encryption,
    /// Puissance reçue en dBm (via radiotap ; `None` sans en-tête radio).
    pub signal_dbm: Option<i8>,
}

impl AccessPoint {
    /// Point d'accès issu d'une trame **partielle** : seul le BSSID est sûr.
    fn partial(bssid: MacAddr) -> Self {
        Self {
            ssid: None,
            bssid,
            channel: None,
            encryption: Encryption::Unknown,
            signal_dbm: None,
        }
    }

    /// Fusionne une nouvelle observation du même BSSID : on complète les champs
    /// manquants et on garde le signal le plus fort (le plus proche de 0 dBm).
    fn merge(&mut self, other: AccessPoint) {
        if self.ssid.is_none() {
            self.ssid = other.ssid;
        }
        if self.channel.is_none() {
            self.channel = other.channel;
        }
        if self.encryption == Encryption::Unknown {
            self.encryption = other.encryption;
        }
        self.signal_dbm = strongest(self.signal_dbm, other.signal_dbm);
    }
}

/// Signal le plus fort de deux mesures (dBm négatifs : le maximum est le plus
/// proche de 0), en préférant une mesure présente à une absente.
fn strongest(a: Option<i8>, b: Option<i8>) -> Option<i8> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) => Some(x),
        (None, other) => other,
    }
}

// --- Erreurs ----------------------------------------------------------------

/// Erreur d'inventaire WiFi passif.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiError {
    /// Capture passive en direct indisponible (pas de Npcap, interface hors
    /// mode monitor, ou binding natif non livré) : **repli clair**, jamais une
    /// panique.
    CaptureUnavailable {
        /// Interface demandée.
        interface: String,
        /// Explication lisible du repli.
        detail: String,
    },
    /// Link-type pcap non géré (on ne traite que 802.11 brut / radiotap).
    UnsupportedLinkType(u32),
    /// Capture pcap malformée (en-tête tronqué, magique inconnue).
    MalformedCapture(String),
}

impl fmt::Display for WifiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WifiError::CaptureUnavailable { interface, detail } => {
                write!(f, "capture passive indisponible sur {interface} : {detail}")
            }
            WifiError::UnsupportedLinkType(lt) => {
                write!(f, "link-type pcap non géré : {lt} (attendu 105 ou 127)")
            }
            WifiError::MalformedCapture(msg) => {
                write!(f, "capture pcap malformée : {msg}")
            }
        }
    }
}

impl std::error::Error for WifiError {}

/// Résultat d'une opération d'inventaire WiFi.
pub type WifiResult<T> = Result<T, WifiError>;

// --- Source de trames en réception seule ------------------------------------

/// Source de trames capturées, **en réception seule**. L'absence de toute
/// méthode d'émission garantit l'invariant passif **par construction** : on ne
/// peut, via ce trait, qu'extraire la trame suivante.
pub trait FrameSource {
    /// Link-type pcap des trames fournies (105 ou 127).
    fn link_type(&self) -> u32;

    /// Trame capturée suivante, ou `None` en fin de flux. Ne bloque pas sur une
    /// source finie (rejeu) ; une source en direct renvoie la trame reçue.
    fn next_frame(&mut self) -> Option<Vec<u8>>;
}

/// Source par **rejeu** d'une capture pcap : la voie portable et testable, sans
/// matériel WiFi ni privilèges. Branchable partout où une [`FrameSource`] est
/// attendue, tout comme le sera la capture en direct.
pub struct PcapReplaySource {
    link_type: u32,
    frames: std::vec::IntoIter<Vec<u8>>,
}

impl PcapReplaySource {
    /// Construit la source depuis le contenu d'un fichier pcap.
    ///
    /// # Erreurs
    /// [`WifiError::MalformedCapture`] si l'en-tête pcap est invalide, ou
    /// [`WifiError::UnsupportedLinkType`] si le link-type n'est pas du 802.11.
    pub fn from_pcap(bytes: &[u8]) -> WifiResult<Self> {
        let capture = PcapCapture::parse(bytes)?;
        ensure_supported(capture.link_type)?;
        Ok(Self {
            link_type: capture.link_type,
            frames: capture.frames.into_iter(),
        })
    }
}

impl FrameSource for PcapReplaySource {
    fn link_type(&self) -> u32 {
        self.link_type
    }

    fn next_frame(&mut self) -> Option<Vec<u8>> {
        self.frames.next()
    }
}

/// Ouvre une **capture passive en direct** (mode monitor Linux / Npcap Windows)
/// derrière une [`FrameSource`] en réception seule.
///
/// Le binding natif (libpcap / Npcap) relève d'une itération ultérieure, comme
/// l'émission brute ARP/ICMP/SYN l'est pour la recon active : la logique
/// d'analyse — le cœur délicat — est ici, prouvée par rejeu. En attendant, et en
/// l'absence de pilote exploitable, cette fonction renvoie un **repli clair**
/// ([`WifiError::CaptureUnavailable`]) ; elle n'émet évidemment aucune trame.
///
/// # Erreurs
/// Toujours [`WifiError::CaptureUnavailable`] pour l'instant.
pub fn open_live(interface: &str) -> WifiResult<Box<dyn FrameSource>> {
    Err(WifiError::CaptureUnavailable {
        interface: interface.to_string(),
        detail: LIVE_UNAVAILABLE.to_string(),
    })
}

/// Message du repli quand la capture passive en direct n'est pas disponible.
const LIVE_UNAVAILABLE: &str =
    "capture en direct non disponible (mode monitor / Npcap requis) ; utiliser le rejeu d'une capture pcap";

// --- Inventaire -------------------------------------------------------------

/// Dresse l'inventaire des points d'accès depuis le contenu d'un fichier pcap.
///
/// # Erreurs
/// [`WifiError::MalformedCapture`] / [`WifiError::UnsupportedLinkType`] selon la
/// validité de la capture.
pub fn inventory_from_pcap(bytes: &[u8]) -> WifiResult<Vec<AccessPoint>> {
    let capture = PcapCapture::parse(bytes)?;
    inventory_from_capture(&capture)
}

/// Dresse l'inventaire depuis une capture déjà analysée.
///
/// # Erreurs
/// [`WifiError::UnsupportedLinkType`] si le link-type n'est pas du 802.11.
pub fn inventory_from_capture(capture: &PcapCapture) -> WifiResult<Vec<AccessPoint>> {
    ensure_supported(capture.link_type)?;
    let mut inventory = Inventory::default();
    for frame in &capture.frames {
        if let Some(ap) = parse_access_point(capture.link_type, frame) {
            inventory.observe(ap);
        }
    }
    Ok(inventory.into_sorted())
}

/// Dresse l'inventaire en consommant une [`FrameSource`] passive jusqu'à son
/// épuisement (fin du rejeu, ou arrêt de la capture en direct).
///
/// # Erreurs
/// [`WifiError::UnsupportedLinkType`] si le link-type n'est pas du 802.11.
pub fn inventory_from_source<S>(source: &mut S) -> WifiResult<Vec<AccessPoint>>
where
    S: FrameSource + ?Sized,
{
    let link_type = source.link_type();
    ensure_supported(link_type)?;
    let mut inventory = Inventory::default();
    while let Some(frame) = source.next_frame() {
        if let Some(ap) = parse_access_point(link_type, &frame) {
            inventory.observe(ap);
        }
    }
    Ok(inventory.into_sorted())
}

/// Rejette tout link-type hors 802.11 (brut ou radiotap).
fn ensure_supported(link_type: u32) -> WifiResult<()> {
    match link_type {
        LINKTYPE_IEEE802_11 | LINKTYPE_IEEE802_11_RADIOTAP => Ok(()),
        other => Err(WifiError::UnsupportedLinkType(other)),
    }
}

/// Collecteur d'inventaire : un point d'accès par BSSID, trié par BSSID.
#[derive(Default)]
struct Inventory {
    by_bssid: BTreeMap<[u8; 6], AccessPoint>,
}

impl Inventory {
    fn observe(&mut self, access_point: AccessPoint) {
        match self.by_bssid.get_mut(&access_point.bssid.0) {
            Some(existing) => existing.merge(access_point),
            None => {
                self.by_bssid.insert(access_point.bssid.0, access_point);
            }
        }
    }

    fn into_sorted(self) -> Vec<AccessPoint> {
        self.by_bssid.into_values().collect()
    }
}

// --- Format de fichier pcap (pur, défensif) ---------------------------------

/// Capture pcap analysée : link-type + trames brutes (radiotap + 802.11, ou
/// 802.11 seul selon le link-type).
pub struct PcapCapture {
    /// Link-type global de la capture.
    pub link_type: u32,
    /// Trames brutes, dans l'ordre de capture.
    pub frames: Vec<Vec<u8>>,
}

impl PcapCapture {
    /// Analyse le contenu d'un fichier pcap **classique** (magique
    /// `0xa1b2c3d4`, micro- ou nanoseconde, petit- ou gros-boutiste).
    ///
    /// Parsing **défensif** : un en-tête tronqué ou une magique inconnue
    /// renvoie une erreur ; un dernier enregistrement coupé (capture
    /// interrompue) est **ignoré** sans panique.
    ///
    /// # Erreurs
    /// [`WifiError::MalformedCapture`] si l'en-tête global est trop court ou la
    /// magique inconnue.
    pub fn parse(bytes: &[u8]) -> WifiResult<Self> {
        if bytes.len() < PCAP_GLOBAL_HEADER_LEN {
            return Err(WifiError::MalformedCapture(
                "en-tête global pcap tronqué".to_string(),
            ));
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let little_endian = match magic {
            0xa1b2_c3d4 | 0xa1b2_3c4d => true,
            0xd4c3_b2a1 | 0x4d3c_b2a1 => false,
            other => {
                return Err(WifiError::MalformedCapture(format!(
                    "magique pcap inconnue : {other:#010x}"
                )));
            }
        };
        let link_type = read_u32(&bytes[20..24], little_endian);

        let mut frames = Vec::new();
        let mut offset = PCAP_GLOBAL_HEADER_LEN;
        while offset + PCAP_RECORD_HEADER_LEN <= bytes.len() {
            let incl = read_u32(&bytes[offset + 8..offset + 12], little_endian) as usize;
            offset += PCAP_RECORD_HEADER_LEN;
            let Some(end) = offset.checked_add(incl) else {
                break;
            };
            if end > bytes.len() {
                // Dernier enregistrement tronqué (capture coupée) : on s'arrête.
                break;
            }
            if incl > 0 {
                frames.push(bytes[offset..end].to_vec());
            }
            offset = end;
        }
        Ok(Self { link_type, frames })
    }
}

/// Lit un u32 depuis 4 octets selon le boutisme de la capture.
fn read_u32(bytes: &[u8], little_endian: bool) -> u32 {
    let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if little_endian {
        u32::from_le_bytes(array)
    } else {
        u32::from_be_bytes(array)
    }
}

// --- Analyse d'une trame : radiotap + 802.11 --------------------------------

/// Analyse une trame brute (selon le link-type) en un point d'accès, ou `None`
/// si ce n'est pas un beacon / une probe-response exploitable. **Pure**.
fn parse_access_point(link_type: u32, frame: &[u8]) -> Option<AccessPoint> {
    let (signal, freq, body) = match link_type {
        LINKTYPE_IEEE802_11_RADIOTAP => {
            let radiotap = parse_radiotap(frame)?;
            let body = frame.get(radiotap.header_len..)?;
            (radiotap.signal_dbm, radiotap.channel_freq, body)
        }
        LINKTYPE_IEEE802_11 => (None, None, frame),
        _ => return None,
    };
    let mut access_point = parse_management(body)?;
    access_point.signal_dbm = signal;
    if access_point.channel.is_none() {
        access_point.channel = freq.and_then(freq_to_channel);
    }
    Some(access_point)
}

/// Champs utiles extraits d'un en-tête radiotap.
struct Radiotap {
    /// Longueur de l'en-tête radiotap (début de la trame 802.11).
    header_len: usize,
    /// Puissance reçue (dBm), si présente.
    signal_dbm: Option<i8>,
    /// Fréquence du canal (MHz), si présente.
    channel_freq: Option<u16>,
}

/// Analyse un en-tête radiotap **défensivement** : on en tire la longueur (donc
/// le début de la trame 802.11), et au mieux la puissance et la fréquence. Tout
/// en-tête incohérent renvoie `None`, jamais une panique (§12).
fn parse_radiotap(bytes: &[u8]) -> Option<Radiotap> {
    if bytes.len() < 8 {
        return None;
    }
    let it_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if it_len < 8 || it_len > bytes.len() {
        return None;
    }

    // Mots « present » chaînés (bit 31 = un mot d'extension suit). On repère le
    // premier (celui des champs standard) et on avance jusqu'au premier champ.
    let mut offset = 4;
    let mut first_present = 0u32;
    let mut have_first = false;
    loop {
        if offset + 4 > it_len {
            return None;
        }
        let word = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        if !have_first {
            first_present = word;
            have_first = true;
        }
        offset += 4;
        if word & (1u32 << 31) == 0 {
            break;
        }
    }

    // Champs du premier mot « present », alignés relativement au début de
    // l'en-tête. On ne décode que les champs standard connus ; au moindre bit
    // inconnu on s'arrête (la longueur, elle, reste fiable via `it_len`).
    let mut signal_dbm = None;
    let mut channel_freq = None;
    for bit in 0..32u32 {
        if first_present & (1u32 << bit) == 0 {
            continue;
        }
        let Some((align, size)) = radiotap_field_layout(bit) else {
            break;
        };
        offset = align_up(offset, align);
        if offset + size > it_len {
            break;
        }
        match bit {
            3 => {
                channel_freq = Some(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]));
            }
            5 => signal_dbm = Some(i8::from_le_bytes([bytes[offset]])),
            _ => {}
        }
        offset += size;
    }

    Some(Radiotap {
        header_len: it_len,
        signal_dbm,
        channel_freq,
    })
}

/// Alignement (octets) et taille (octets) d'un champ radiotap standard, par
/// numéro de bit `present` ; `None` au-delà des champs gérés.
fn radiotap_field_layout(bit: u32) -> Option<(usize, usize)> {
    // (alignement, taille) en octets par bit `present` radiotap standard.
    Some(match bit {
        0 => (8, 8), // TSFT
        1 => (1, 1), // Flags
        2 => (1, 1), // Rate
        3 => (2, 4), // Channel (fréquence + flags)
        4 => (2, 2), // FHSS
        5 => (1, 1), // Antenna signal (dBm)
        6 => (1, 1), // Antenna noise (dBm)
        7 => (2, 2), // Lock quality
        8 => (2, 2), // TX attenuation
        9 => (2, 2), // dB TX attenuation
        10 => (1, 1), // dBm TX power
        11 => (1, 1), // Antenna
        12 => (1, 1), // dB antenna signal
        13 => (1, 1), // dB antenna noise
        14 => (2, 2), // RX flags
        _ => return None,
    })
}

/// Arrondit `offset` au multiple supérieur de `align` (alignement radiotap).
fn align_up(offset: usize, align: usize) -> usize {
    offset.div_ceil(align) * align
}

/// Analyse une trame de gestion 802.11 (beacon / probe-response) en un point
/// d'accès. Renvoie `None` si ce n'en est pas une, ou un point d'accès
/// **partiel** si la trame est tronquée après le BSSID. **Pure**, ne panique
/// jamais (§12).
fn parse_management(body: &[u8]) -> Option<AccessPoint> {
    if body.len() < 24 {
        return None;
    }
    let frame_control = body[0];
    if frame_control & 0x03 != 0 {
        return None; // version de protocole inattendue
    }
    let frame_type = (frame_control >> 2) & 0x03;
    let subtype = (frame_control >> 4) & 0x0f;
    // Type 0 = gestion ; sous-type 8 = beacon, 5 = probe-response.
    if frame_type != 0 || (subtype != 8 && subtype != 5) {
        return None;
    }

    let mut raw = [0u8; 6];
    raw.copy_from_slice(&body[16..22]); // Adresse 3 = BSSID
    let bssid = MacAddr(raw);

    let fixed = &body[24..];
    if fixed.len() < 12 {
        // Trame partielle : seul le BSSID est sûr (défensif).
        return Some(AccessPoint::partial(bssid));
    }
    // Paramètres fixes : timestamp(8) + beacon interval(2) + capability(2).
    let capability = u16::from_le_bytes([fixed[10], fixed[11]]);
    let privacy = capability & 0x0010 != 0;

    let params = parse_tags(&fixed[12..]);
    let encryption = classify(privacy, params.rsn_present, params.rsn_sae, params.wpa_vendor);
    Some(AccessPoint {
        ssid: params.ssid,
        bssid,
        channel: params.channel,
        encryption,
        signal_dbm: None,
    })
}

/// Paramètres marqués (information elements) retenus d'un beacon.
#[derive(Default)]
struct TaggedParams {
    ssid: Option<String>,
    channel: Option<u8>,
    rsn_present: bool,
    rsn_sae: bool,
    wpa_vendor: bool,
}

/// Parcourt les information elements (tag, longueur, données) de façon
/// **défensive** : un tag annonçant plus d'octets qu'il n'en reste arrête le
/// parcours sans panique.
fn parse_tags(mut tags: &[u8]) -> TaggedParams {
    let mut params = TaggedParams::default();
    while tags.len() >= 2 {
        let tag = tags[0];
        let len = tags[1] as usize;
        let Some(data) = tags.get(2..2 + len) else {
            break; // tag tronqué
        };
        match tag {
            0 => params.ssid = parse_ssid(data),
            3 => params.channel = data.first().copied(),
            48 => {
                params.rsn_present = true;
                params.rsn_sae = rsn_has_sae(data);
            }
            221 => {
                if is_wpa_vendor(data) {
                    params.wpa_vendor = true;
                }
            }
            _ => {}
        }
        tags = &tags[2 + len..];
    }
    params
}

/// Décode un SSID (tag 0). Longueur nulle ou octets tous nuls → masqué
/// (`None`). Décodage *lossy*, octets de contrôle neutralisés (§12).
fn parse_ssid(data: &[u8]) -> Option<String> {
    if data.is_empty() || data.iter().all(|&b| b == 0) {
        return None;
    }
    let cleaned: String = String::from_utf8_lossy(data)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Vrai si l'IE RSN (tag 48) annonce un AKM SAE (→ WPA3). **Défensif** : toute
/// troncature interrompt l'analyse sans panique.
fn rsn_has_sae(data: &[u8]) -> bool {
    // version(2) + group cipher(4) + pairwise count(2).
    let mut offset = 2 + 4;
    let Some(count) = data.get(offset..offset + 2) else {
        return false;
    };
    let pairwise = u16::from_le_bytes([count[0], count[1]]) as usize;
    offset += 2 + pairwise.saturating_mul(4);
    let Some(count) = data.get(offset..offset + 2) else {
        return false;
    };
    let akm = u16::from_le_bytes([count[0], count[1]]) as usize;
    offset += 2;
    for _ in 0..akm {
        let Some(suite) = data.get(offset..offset + 4) else {
            return false;
        };
        if suite[0] == 0x00 && suite[1] == 0x0f && suite[2] == 0xac && suite[3] == AKM_SAE {
            return true;
        }
        offset += 4;
    }
    false
}

/// Vrai si l'IE vendeur (tag 221) est l'IE WPA de Microsoft (OUI 00:50:F2,
/// type 1) : marqueur de WPA « original ».
fn is_wpa_vendor(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xf2 && data[3] == 0x01
}

/// Classe le chiffrement à partir du bit Privacy et des IE observés.
fn classify(privacy: bool, rsn_present: bool, rsn_sae: bool, wpa_vendor: bool) -> Encryption {
    if rsn_present {
        return if rsn_sae {
            Encryption::Wpa3
        } else {
            Encryption::Wpa2
        };
    }
    if wpa_vendor {
        return Encryption::Wpa;
    }
    if privacy {
        Encryption::Wep
    } else {
        Encryption::Open
    }
}

/// Convertit une fréquence (MHz) en numéro de canal (2,4 GHz et 5 GHz), ou
/// `None` hors bandes connues.
fn freq_to_channel(freq: u16) -> Option<u8> {
    let channel = match freq {
        2412..=2472 => (freq - 2407) / 5,
        2484 => 14,
        5000..=5895 => (freq - 5000) / 5,
        _ => return None,
    };
    u8::try_from(channel).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEACONS: &[u8] = include_bytes!("../../../testdata/wifi/wifi_beacons.pcap");
    const RAW: &[u8] = include_bytes!("../../../testdata/wifi/wifi_raw_80211.pcap");
    const TRUNCATED: &[u8] = include_bytes!("../../../testdata/wifi/wifi_truncated.pcap");

    fn by_ssid<'a>(aps: &'a [AccessPoint], ssid: &str) -> &'a AccessPoint {
        aps.iter()
            .find(|ap| ap.ssid.as_deref() == Some(ssid))
            .unwrap_or_else(|| panic!("AP {ssid} absent de l'inventaire"))
    }

    fn by_bssid(aps: &[AccessPoint], last: u8) -> &AccessPoint {
        let expected = [0x02, 0x11, 0x22, 0x33, 0x44, last];
        aps.iter()
            .find(|ap| ap.bssid.0 == expected)
            .unwrap_or_else(|| panic!("BSSID ..{last:02x} absent"))
    }

    // --- Lecture pcap -------------------------------------------------------

    #[test]
    fn pcap_lit_le_linktype_et_les_trames() {
        let capture = PcapCapture::parse(BEACONS).unwrap();
        assert_eq!(capture.link_type, LINKTYPE_IEEE802_11_RADIOTAP);
        // 8 trames de gestion + 1 trame de données = 9 enregistrements.
        assert_eq!(capture.frames.len(), 9);
    }

    // --- Inventaire complet (beacons radiotap) ------------------------------

    #[test]
    fn inventaire_extrait_tous_les_points_d_acces() {
        let aps = inventory_from_pcap(BEACONS).unwrap();
        // 7 BSSID distincts (HomeWPA2 vu 2× dédupliqué ; trame data ignorée).
        assert_eq!(aps.len(), 7);
    }

    #[test]
    fn reseau_ouvert() {
        let aps = inventory_from_pcap(BEACONS).unwrap();
        let ap = by_ssid(&aps, "OpenCafe");
        assert_eq!(ap.encryption, Encryption::Open);
        assert_eq!(ap.channel, Some(1));
        assert_eq!(ap.signal_dbm, Some(-40));
    }

    #[test]
    fn wep_detecte_par_le_bit_privacy_sans_rsn() {
        let ap_set = inventory_from_pcap(BEACONS).unwrap();
        let ap = by_ssid(&ap_set, "OldWEP");
        assert_eq!(ap.encryption, Encryption::Wep);
        assert_eq!(ap.channel, Some(6));
        assert_eq!(ap.signal_dbm, Some(-62));
    }

    #[test]
    fn wpa2_rsn_psk() {
        let aps = inventory_from_pcap(BEACONS).unwrap();
        let ap = by_ssid(&aps, "HomeWPA2");
        assert_eq!(ap.encryption, Encryption::Wpa2);
        assert_eq!(ap.channel, Some(11));
        // Vu à -55 puis -48 : on garde le signal le plus fort.
        assert_eq!(ap.signal_dbm, Some(-48));
    }

    #[test]
    fn wpa3_rsn_sae() {
        let aps = inventory_from_pcap(BEACONS).unwrap();
        let ap = by_ssid(&aps, "SecureWPA3");
        assert_eq!(ap.encryption, Encryption::Wpa3);
        // Canal 36 (5 GHz) via le DS Parameter Set.
        assert_eq!(ap.channel, Some(36));
        assert_eq!(ap.signal_dbm, Some(-70));
    }

    #[test]
    fn ssid_masque_est_cache_mais_inventorie() {
        let aps = inventory_from_pcap(BEACONS).unwrap();
        // BSSID ..05 : SSID longueur nulle + transition WPA2/WPA3 (PSK + SAE).
        let ap = by_bssid(&aps, 0x05);
        assert!(ap.ssid.is_none(), "SSID masqué → None");
        assert_eq!(ap.encryption, Encryption::Wpa3, "SAE présent → WPA3");
    }

    #[test]
    fn probe_response_est_analysee() {
        let aps = inventory_from_pcap(BEACONS).unwrap();
        let ap = by_ssid(&aps, "GuestNet");
        assert_eq!(ap.encryption, Encryption::Wpa2);
        assert_eq!(ap.signal_dbm, Some(-58));
    }

    #[test]
    fn wpa1_vendeur_microsoft() {
        let aps = inventory_from_pcap(BEACONS).unwrap();
        let ap = by_ssid(&aps, "LegacyWPA");
        assert_eq!(ap.encryption, Encryption::Wpa);
        assert_eq!(ap.channel, Some(6));
    }

    // --- 802.11 brut (sans radiotap) ----------------------------------------

    #[test]
    fn raw_80211_sans_radiotap_puissance_inconnue() {
        let capture = PcapCapture::parse(RAW).unwrap();
        assert_eq!(capture.link_type, LINKTYPE_IEEE802_11);
        let aps = inventory_from_capture(&capture).unwrap();
        assert_eq!(aps.len(), 1);
        let ap = by_ssid(&aps, "RawAP");
        assert_eq!(ap.encryption, Encryption::Wpa2);
        // Canal via le DS Parameter Set ; aucune puissance sans radiotap.
        assert_eq!(ap.channel, Some(3));
        assert_eq!(ap.signal_dbm, None);
    }

    // --- Trames partielles / captures tronquées -----------------------------

    #[test]
    fn trames_partielles_ne_paniquent_pas() {
        // La capture mêle : une trame coupée au milieu des paramètres fixes, une
        // trame beaucoup trop courte, un radiotap incohérent, un beacon sain, et
        // un dernier enregistrement coupé. Rien ne doit paniquer.
        let aps = inventory_from_pcap(TRUNCATED).unwrap();

        // Le beacon sain reste inventorié malgré les trames partielles autour.
        let healthy = by_ssid(&aps, "HealthyAP");
        assert_eq!(healthy.encryption, Encryption::Wpa2);

        // La trame partielle garde son BSSID et son chiffrement reste
        // indéterminé (corps 802.11 tronqué), mais le radiotap complet fournit
        // encore canal et puissance.
        let partial = by_bssid(&aps, 0x30);
        assert!(partial.ssid.is_none());
        assert_eq!(partial.encryption, Encryption::Unknown);
        assert_eq!(partial.channel, Some(1));
        assert_eq!(partial.signal_dbm, Some(-45));

        // Le dernier enregistrement (tronqué) n'apparaît jamais.
        assert!(
            aps.iter().all(|ap| ap.ssid.as_deref() != Some("NeverSeen")),
            "enregistrement coupé ignoré"
        );
        // Deux AP seulement : la partielle et le beacon sain.
        assert_eq!(aps.len(), 2);
    }

    // --- Rejeu via FrameSource (réception seule) ----------------------------

    #[test]
    fn source_passive_rejoue_les_trames_en_reception_seule() {
        // La source n'expose que `next_frame` : lecture, jamais d'émission.
        let mut source = PcapReplaySource::from_pcap(BEACONS).unwrap();
        assert_eq!(source.link_type(), LINKTYPE_IEEE802_11_RADIOTAP);
        let mut lues = 0;
        while source.next_frame().is_some() {
            lues += 1;
        }
        assert_eq!(lues, 9);

        // L'inventaire via la source donne le même résultat que via le pcap.
        let mut source = PcapReplaySource::from_pcap(BEACONS).unwrap();
        let depuis_source = inventory_from_source(&mut source).unwrap();
        let depuis_pcap = inventory_from_pcap(BEACONS).unwrap();
        assert_eq!(depuis_source, depuis_pcap);
    }

    #[test]
    fn source_injectable_en_objet_de_trait() {
        let mut source: Box<dyn FrameSource> = Box::new(PcapReplaySource::from_pcap(RAW).unwrap());
        let aps = inventory_from_source(&mut *source).unwrap();
        assert_eq!(aps.len(), 1);
    }

    // --- Repli clair (capture indisponible) ---------------------------------

    #[test]
    fn capture_live_renvoie_un_repli_clair() {
        // §Phase 4 DoD : repli clair si capture indisponible (pas de Npcap /
        // monitor), jamais une panique, et évidemment aucune trame émise.
        let err = open_live("wlan0").unwrap_err();
        match err {
            WifiError::CaptureUnavailable { interface, detail } => {
                assert_eq!(interface, "wlan0");
                assert!(!detail.is_empty());
            }
            other => panic!("repli inattendu : {other:?}"),
        }
    }

    // --- Robustesse défensive (§12) -----------------------------------------

    #[test]
    fn pcap_malforme_renvoie_une_erreur_sans_paniquer() {
        assert!(matches!(
            PcapCapture::parse(&[]),
            Err(WifiError::MalformedCapture(_))
        ));
        assert!(matches!(
            PcapCapture::parse(b"trop court"),
            Err(WifiError::MalformedCapture(_))
        ));
        // Magique inconnue (24 octets de zéros).
        assert!(matches!(
            PcapCapture::parse(&[0u8; 24]),
            Err(WifiError::MalformedCapture(_))
        ));
    }

    #[test]
    fn linktype_non_supporte_est_rejete() {
        // En-tête global LE micro-seconde, link-type 1 (Ethernet), sans record.
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&[0u8; 8]); // thiszone + sigfigs
        pcap.extend_from_slice(&262_144u32.to_le_bytes()); // snaplen
        pcap.extend_from_slice(&1u32.to_le_bytes()); // link-type = Ethernet
        assert!(matches!(
            inventory_from_pcap(&pcap),
            Err(WifiError::UnsupportedLinkType(1))
        ));
        assert!(matches!(
            PcapReplaySource::from_pcap(&pcap),
            Err(WifiError::UnsupportedLinkType(1))
        ));
    }

    #[test]
    fn radiotap_defensif_sur_entrees_courtes() {
        assert!(parse_radiotap(&[]).is_none());
        assert!(parse_radiotap(&[0, 0, 4]).is_none()); // trop court
        // it_len annonçant plus que disponible.
        assert!(parse_radiotap(&[0, 0, 64, 0, 0x2e, 0, 0, 0]).is_none());
    }

    #[test]
    fn management_defensif_sur_entrees_courtes() {
        assert!(parse_management(&[]).is_none());
        assert!(parse_management(&[0x80, 0x00, 0x00]).is_none());
        // Trame data (type 2) : ignorée.
        let mut data = vec![0x08, 0x00];
        data.extend_from_slice(&[0u8; 30]);
        assert!(parse_management(&data).is_none());
    }

    #[test]
    fn fuzz_leger_ne_panique_jamais() {
        // Générateur congruentiel linéaire déterministe (sans dépendance externe).
        let mut state: u64 = 0x0f1e_2d3c_4b5a_6978;
        for _ in 0..512 {
            let len = (state % 400) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                bytes.push((state >> 33) as u8);
            }
            // Ni la lecture pcap ni l'analyse d'une trame ne doivent paniquer.
            let _ = inventory_from_pcap(&bytes);
            let _ = parse_access_point(LINKTYPE_IEEE802_11_RADIOTAP, &bytes);
            let _ = parse_access_point(LINKTYPE_IEEE802_11, &bytes);
        }
    }

    // --- Fonctions pures isolées --------------------------------------------

    #[test]
    fn classification_couvre_toutes_les_variantes() {
        assert_eq!(classify(false, false, false, false), Encryption::Open);
        assert_eq!(classify(true, false, false, false), Encryption::Wep);
        assert_eq!(classify(true, false, false, true), Encryption::Wpa);
        assert_eq!(classify(true, true, false, false), Encryption::Wpa2);
        assert_eq!(classify(true, true, true, false), Encryption::Wpa3);
        // RSN prime sur l'IE vendeur ; SAE prime et classe WPA3 (transition).
        assert_eq!(classify(true, true, true, true), Encryption::Wpa3);
    }

    #[test]
    fn frequence_vers_canal() {
        assert_eq!(freq_to_channel(2412), Some(1));
        assert_eq!(freq_to_channel(2437), Some(6));
        assert_eq!(freq_to_channel(2462), Some(11));
        assert_eq!(freq_to_channel(2484), Some(14));
        assert_eq!(freq_to_channel(5180), Some(36));
        assert_eq!(freq_to_channel(1234), None);
    }

    #[test]
    fn libelles_et_faiblesse_du_chiffrement() {
        assert_eq!(Encryption::Wpa3.label(), "WPA3");
        assert_eq!(Encryption::Open.to_string(), "ouvert");
        assert!(Encryption::Open.is_weak());
        assert!(Encryption::Wep.is_weak());
        assert!(Encryption::Wpa.is_weak());
        assert!(!Encryption::Wpa2.is_weak());
        assert!(!Encryption::Wpa3.is_weak());
    }
}
