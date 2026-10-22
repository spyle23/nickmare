# Nickmare — Architecture & Spécifications

> **Outil d'audit de sécurité réseau multiplateforme (Windows / Linux), écrit en Rust.**
> Destiné exclusivement à des engagements de test d'intrusion **autorisés par écrit**, à l'audit de réseaux dont l'utilisateur est propriétaire ou gestionnaire, et à l'**apprentissage de la sécurité réseau en laboratoire contrôlé**.

- **Version du document** : 0.2 (brouillon d'architecture)
- **Statut** : conception — aucune ligne de code encore écrite
- **Dernière mise à jour** : 2026-10-22
- **Nouveautés v0.2** : mode laboratoire/apprentissage (friction réduite, chaîne complète utilisable) ; cartographie du réseau + ciblage d'hôte et pivot intra-réseau ; émulation d'adversaire réaliste (évasion effective en périmètre autorisé, mesure de détection conservée).

---

## Table des matières

1. [Principes directeurs](#1-principes-directeurs)
2. [Portée fonctionnelle (scope)](#2-portée-fonctionnelle-scope)
3. [Cadre légal & garde-fous intégrés](#3-cadre-légal--garde-fous-intégrés)
4. [Architecture logicielle](#4-architecture-logicielle)
5. [Choix techniques (crates Rust)](#5-choix-techniques-crates-rust)
6. [Structure du dépôt](#6-structure-du-dépôt)
7. [Modèle de données](#7-modèle-de-données)
8. [User stories](#8-user-stories)
9. [Phases d'implémentation (roadmap)](#9-phases-dimplémentation-roadmap)
10. [Stratégie de tests](#10-stratégie-de-tests)
11. [Robustesse & sûreté opérationnelle](#11-robustesse--sûreté-opérationnelle)
12. [Sécurité du logiciel lui-même](#12-sécurité-du-logiciel-lui-même)
13. [Distribution & multiplateforme](#13-distribution--multiplateforme)
14. [Glossaire](#14-glossaire)

---

## 1. Principes directeurs

Ces principes conditionnent **toutes** les décisions techniques qui suivent.

| Principe | Conséquence concrète |
|----------|----------------------|
| **Recon libre, action ciblée** | La reconnaissance passive (lister les réseaux/hôtes à portée) ne demande aucune autorisation préalable : elle ne bloque jamais l'opérateur. En revanche, toute action **active ou offensive** exige une cible établie — soit choisie interactivement et **attestée** par l'opérateur (voie A), soit chargée depuis un fichier de scope (voie B). Pas de cible établie → pas d'action active. Plus une capacité est intrusive, plus son activation doit être explicite et granulaire. |
| **Traçabilité totale, même en mode furtif** | Chaque action émise est horodatée et journalisée de façon inaltérable (append-only) **côté opérateur**. Le mode d'émulation d'adversaire peut masquer l'activité vis-à-vis de la cible/blue team, mais **jamais** vis-à-vis du journal d'audit de l'opérateur. Un audit doit toujours pouvoir reconstituer exactement ce qui a été fait. |
| **Human-in-the-loop pour l'intrusif** | L'exploitation et le craquage ne se déclenchent pas « tout seuls ». Par défaut, chaque exploitation requiert une confirmation explicite par cible. L'automatisation complète est un mode opt-in, borné par le scope. |
| **Non destructif par défaut** | Lecture et reconnaissance par défaut. Toute action susceptible d'altérer une cible (exploitation) est derrière un drapeau explicite, dispose d'un *mode validation* (vérifie l'exploitabilité sans délivrer de charge destructrice) et est interdite hors des cibles explicitement marquées dans le scope. |
| **Évasion réaliste → la détection devient mesurable** | Pour qu'une mesure de détection ait un sens, l'évasion doit **réellement tenter de passer** : une intrusion simulée qui se fait repérer par construction n'apprend rien. Les techniques d'évasion (N4) sont donc **effectives** dans le périmètre autorisé — c'est ce qui rend le verdict « détecté / non détecté » crédible et le délai de détection (MTTD) significatif. Chaque technique reste rattachée à un identifiant ATT&CK. L'invariant n'est pas « ne pas déjouer la cible » mais « **ne jamais déjouer son propre journal d'audit** » (voir ligne suivante). |
| **Furtif vis-à-vis de la cible, jamais vis-à-vis de l'opérateur** | Une technique d'évasion peut masquer l'activité pour la cible, le SIEM ou la blue team. Elle n'altère **jamais** le journal d'audit côté opérateur, qui enregistre tout, en clair et horodaté. C'est cette asymétrie — furtif dehors, transparent dedans — qui distingue un outil d'engagement/apprentissage d'un malware. |
| **Friction proportionnée au contexte** | Sur ses propres réseaux et en laboratoire d'apprentissage, l'outil **ne doit pas brider l'opérateur** : une attestation unique débloque la chaîne complète (recon → intrusion → émulation). La cérémonie lourde (scope signé, confirmation par cible) est réservée aux engagements tiers formels. La traçabilité, elle, ne baisse jamais, quel que soit le mode. |
| **Fail-safe** | En cas de doute (scope ambigu, cible hors périmètre, fenêtre expirée), l'outil s'arrête plutôt que d'agir. |

> **Note de conception** : l'outil couvre la chaîne complète d'une intrusion simulée autorisée — reconnaissance → cartographie du réseau → sélection d'un hôte → intrusion/pivot → émulation d'adversaire (évasion réaliste + mesure de détection) → restitution. Les garde-fous (scope, confirmation, journal inaltérable) **s'adaptent au contexte** (mode labo/apprentissage vs. engagement tiers) mais la **traçabilité côté opérateur reste absolue dans tous les modes**. C'est elle, et non une limitation de la furtivité vis-à-vis de la cible, qui distingue cet outil d'un malware : il est furtif dehors, parfaitement transparent dedans, et strictement confiné à un périmètre attesté.

---

## 2. Portée fonctionnelle (scope)

La portée est organisée en **niveaux de capacité**, du moins au plus intrusif. Chaque niveau doit être explicitement activé dans le fichier de scope (voir §3). Un niveau supérieur ne peut agir que sur des cibles où le niveau inférieur a déjà établi un résultat.

#### Niveau 1 — Reconnaissance & cartographie (non intrusif)
- **Découverte d'hôtes** sur un réseau autorisé (ARP sweep, ping ICMP).
- **Cartographie du réseau** : une fois l'accès au réseau établi, construction d'une **carte des machines connectées** (IP, MAC, hostname, OS présumé, ports/services ouverts, rôle présumé — passerelle, serveur, poste). Visualisable en TUI (`ratatui`) et exportée dans le rapport.
- **Scan de ports** TCP (connect & SYN) et UDP, débit limité.
- **Identification de services** : bannières, versions.
- **Fingerprinting OS** léger (indices TTL, fenêtre TCP).
- **Inventaire WiFi passif** : points d'accès, chiffrement (WEP/WPA2/WPA3), canal, puissance. Écoute passive uniquement.
- **Corrélation CVE** : versions détectées ↔ base NVD/CVE (hors ligne ou API).

> **Flux d'intrusion simulée (le parcours d'apprentissage central).**
> `recon networks` (voir les réseaux à portée, libre) → `target select` (choisir un réseau et attester → périmètre de session) → `discover` + `map` (cartographier les machines du réseau et les **visualiser**) → `target host <ip>` (désigner **l'hôte précis** à pénétrer parmi ceux de la carte) → N2 intrusion → éventuellement pivot vers d'autres hôtes du **périmètre attesté** (y compris d'autres sous-réseaux reliés si le périmètre en déclare plusieurs).

#### Niveau 2 — Intrusion & exploitation (intrusif, human-in-the-loop)
- **Sélection d'un hôte-cible dans la carte** : parmi les machines découvertes, l'opérateur désigne celle qu'il veut pénétrer. C'est le point de bascule « j'ai cartographié, je choisis où j'entre ».
- **Vérification d'exploitabilité** : pour une CVE corrélée sur l'hôte choisi, un *check* qui confirme si la cible est réellement vulnérable, **sans délivrer de charge destructrice** (mode validation par défaut).
- **Exploitation assistée** : lancement d'un exploit référencé contre l'hôte **explicitement choisi** dans le périmètre, après **confirmation humaine**. Objectif : obtenir un accès/preuve d'exploitabilité, pas la destruction.
- **Pivot / mouvement latéral** : depuis un hôte compromis, re-cartographier ce qui devient visible et rebondir vers d'autres machines **du périmètre attesté**. Ce périmètre peut couvrir **plusieurs sous-réseaux reliés** (ex. lab DMZ + LAN en voie C, ou plusieurs CIDR dans `targets.networks` en voie B) : le pivot peut alors franchir ces sous-réseaux. Il s'arrête net à la frontière du périmètre — un sous-réseau joignable mais non déclaré reste hors d'atteinte. Chaque saut est tracé (hôte source → hôte cible) et apparaît dans la carte comme un chemin de propagation.
- **Mode automatisé opt-in** : enchaînement auto des checks + exploits « safe », borné au périmètre, avec un plafond d'actions. Désactivé par défaut hors mode labo.
- **Intégration de moteurs externes** : plutôt que de réimplémenter des exploits, l'outil s'interface avec des moteurs établis (ex. Metasploit via RPC) quand c'est pertinent — l'outil orchestre et trace, il n'est pas une base d'exploits de plus.

#### Niveau 3 — Craquage de credentials (hors ligne par défaut)
- **Craquage de hashes capturés** (NTLM, Kerberos, hashes Unix, hashes WPA handshake) via dictionnaire / règles / masque, en s'appuyant sur des moteurs établis (hashcat / John) ou une implémentation native pour les cas simples.
- **Évaluation de politique de mots de passe** : rapport sur la force des credentials, taux de craquage, patterns faibles — c'est la *valeur livrable* côté client.
- **Spray / test en ligne** : test de credentials contre un service, **strictement borné** par le scope (débit, nombre de tentatives, listes fournies) pour éviter le verrouillage de comptes. Opt-in, human-confirmed.

#### Niveau 4 — Émulation d'adversaire réaliste & test de détection
- **Techniques d'évasion rattachées à MITRE ATT&CK** (catégories : timing/low-and-slow, fragmentation, obfuscation de trafic, vie-sur-le-terrain) appliquées de façon **effective** : elles tentent réellement de passer sous le radar de la défense, car c'est la seule manière de mesurer honnêtement ce que la blue team détecte et en combien de temps.
- **Profil d'adversaire** : l'opérateur choisit un profil (bruyant → furtif) pour rejouer un comportement réaliste et comparer les niveaux de détection selon l'agressivité.
- **Verdict de détection** par technique : l'opérateur (ou la blue team en collaboration) marque « détecté / non détecté / partiellement » et renseigne l'horodatage de l'alerte, produisant une matrice de couverture ATT&CK + un MTTD par technique.
- **Mouvement latéral / pivoting** à des fins de démonstration de propagation, borné au périmètre, tracé pas à pas.

> **Asymétrie fondamentale (principe §1)** : en mode émulation, l'activité peut être masquée **vis-à-vis de la cible, du SIEM et de la blue team** — c'est voulu, pour que la mesure soit crédible. Mais le journal d'audit **opérateur** enregistre tout en clair : chaque technique émise, son horodatage, son résultat. Le but affiché n'est jamais « garantir de ne pas être vu » mais « savoir précisément si et quand on est vu ». Hors mode labo, ce niveau se coordonne avec la blue team (`blue_team_contact`).

### Hors périmètre (exclu par conception)

- ❌ **Déni de service** (flood, exhaustion de ressources) — jamais, c'est destructeur et sans valeur d'audit.
- ❌ **Ciblage de masse** / scan d'Internet / toute cible active hors de la cible établie (sélectionnée+attestée ou chargée).
- ❌ **Charges destructrices** (wipe, ransomware, corruption de données) — l'exploitation vise la preuve, pas la destruction.
- ❌ **Persistance furtive non tracée** / backdoors qui survivraient à l'engagement sans être au journal.
- ❌ **Toute action hors scope**, quelle que soit la capacité.

Ces exclusions sont **architecturales**. Le `gate` (§3) les fait respecter quelle que soit la commande.

---

## 3. Cadre légal & garde-fous intégrés

### 3.0 Comment le périmètre est établi

Le `gate` consomme toujours un objet **`Scope`** interne. Il existe **deux façons** de le peupler ; les deux produisent le même objet, donc l'architecture du gate ne change pas.

**Reconnaissance d'abord, libre et non intrusive.** Lister/reconnaître ce qui est à portée (réseaux WiFi visibles, sous-réseaux filaires joignables, hôtes actifs) **ne demande aucun scope préalable** : c'est de l'observation passive, ça ne bloque pas l'opérateur. C'est le point de départ normal quand on travaille sur ses propres réseaux.

```
nickmare recon networks      # liste les réseaux à portée — aucune autorisation requise
```

**Voie A — Sélection interactive (travail sur ses propres réseaux).**
L'opérateur choisit un **réseau** dans la liste reconnue, puis **atteste** une fois qu'il est autorisé dessus. Cette sélection + attestation **génèrent le scope de session** en mémoire. Pas de fichier à écrire. Il **cartographie** ensuite les machines du réseau et désigne, parmi elles, l'**hôte** qu'il veut pénétrer.

```
nickmare target select       # choisir un réseau parmi les résultats de recon
                             # → attestation d'autorisation (case explicite, loguée)
                             # → le scope de session est verrouillé sur ce réseau
nickmare discover            # découvrir les machines du réseau établi
nickmare map                 # visualiser la carte des hôtes (TUI)
nickmare target host <ip>    # désigner l'hôte précis à pénétrer (dans le périmètre)
```

- Dès l'attestation, **toute action active/offensive est confinée au réseau choisi**. Les autres réseaux vus pendant la recon (ex. le WiFi du voisin) ne sont **pas** dans le scope et restent hors d'atteinte. Le pivot ne peut rebondir qu'entre hôtes de **ce** réseau.
- L'attestation enregistre : le réseau exact (BSSID/SSID ou CIDR), l'empreinte SHA-256 du scope généré, l'identité opérateur, l'horodatage. Elle apparaît dans le rapport comme preuve du périmètre réellement utilisé.
- `target host` ne fait qu'affiner la cible active à l'intérieur du périmètre déjà attesté ; il n'élargit jamais le scope.

**Voie C — Mode laboratoire / apprentissage (friction minimale).**
Destinée à l'apprentissage sur **ses propres machines** ou un **lab isolé** (voir §10.3). L'opérateur déclare une fois le périmètre de lab — **un ou plusieurs sous-réseaux reliés** (ex. DMZ + LAN) — et atteste qu'il lui appartient / est dédié à l'entraînement ; cette attestation unique **active d'emblée la chaîne complète N1–N4** sur tout ce périmètre, sans confirmation par cible ni fichier signé.

```
nickmare lab start 192.168.56.0/24                      # lab mono-sous-réseau
nickmare lab start 10.10.1.0/24 10.10.2.0/24 10.10.9.0/24  # lab multi-sous-réseaux (DMZ + LAN…)
                                      # → N1–N4 débloqués sur TOUS les sous-réseaux déclarés
                                      # → le pivot peut traverser ces sous-réseaux (voir §2, US-E4)
```

- La recon reste libre ; au-delà, tout reste **confiné aux sous-réseaux de lab déclarés**. Un sous-réseau non déclaré — même joignable depuis un hôte compromis — reste hors périmètre.
- Les plafonds de sûreté (back-off, circuit-breaker, anti-destruction §11) **restent actifs** : le mode labo réduit la *cérémonie*, pas la *sûreté*.
- La **traçabilité est identique** aux autres modes : journal chaîné complet. Le mode labo est marqué comme tel dans l'audit et le rapport (`mode = "lab"`).
- Garde-fou de cohérence : si **l'un** des sous-réseaux déclarés ne ressemble pas à un réseau privé/isolé (plage routable publiquement, passerelle vers Internet active), l'outil **avertit** et demande une confirmation renforcée — pour éviter qu'un « lab » soit en réalité un réseau de production ou public.

**Voie B — Fichier de scope (engagements formels).**
Pour un mandat client avec périmètre négocié et signature, l'opérateur charge un **fichier TOML** (ci-dessous). Recommandé dès qu'un tiers (client) définit le périmètre, car il supporte la signature `ed25519` (décision 3) et fige les contraintes à l'avance.

> **Principe inchangé** : la recon ne bloque jamais ; tout ce qui va **au-delà** de l'observation passive exige un périmètre établi — sélection + attestation (voie A), attestation de lab unique (voie C), ou fichier chargé (voie B). Impossible d'agir activement sans périmètre établi — mais l'établir est l'affaire d'une sélection + une case (ou d'une commande `lab start`), pas d'un fichier obligatoire. Le choix de la voie règle seulement la **friction** ; le confinement au périmètre et la traçabilité, eux, sont constants.

### 3.1 Le fichier de scope (voie B, optionnel)

Pour un engagement formel, l'opérateur charge un **fichier de scope** (format TOML). Exemple :

```toml
[engagement]
client        = "ACME Corp"
reference     = "PENTEST-2026-014"
authorized_by = "DSI ACME — contrat signé 2026-10-01"
operator      = "sampingyen.lee@gmail.com"
valid_from    = "2026-10-20T00:00:00Z"
valid_until   = "2026-10-31T23:59:59Z"

[targets]
# CIDR et hôtes explicitement autorisés
networks = ["192.168.10.0/24", "10.20.0.0/16"]
hosts    = ["192.168.50.5"]

[targets.exclusions]
# Jamais touchés, même s'ils tombent dans un CIDR autorisé
hosts = ["192.168.10.1", "10.20.0.254"]  # passerelles critiques

[constraints]
max_rate_pps    = 200          # paquets/seconde max
allowed_hours   = "08:00-18:00" # fenêtre d'intervention
tcp_connect_only = false        # true = pas de SYN scan brut

# Activation granulaire des niveaux de capacité (tout désactivé par défaut)
[capabilities]
recon        = true            # Niveau 1 — toujours requis
exploitation = true            # Niveau 2
cracking     = true            # Niveau 3
emulation    = true            # Niveau 4

[capabilities.exploitation]
mode               = "manual"  # "manual" (confirmation par cible) | "auto"
destructive_checks = false     # false = mode validation uniquement, jamais de charge destructrice
# Seules ces cibles peuvent être exploitées, même si d'autres sont dans `targets`
allowed_hosts      = ["192.168.10.25", "192.168.10.30"]
max_actions        = 50        # plafond de sécurité en mode auto

[capabilities.cracking]
online_spray   = false         # true = autorise le test en ligne (risque de lockout)
max_attempts_per_account = 3   # borne anti-verrouillage
# Le craquage hors ligne de hashes capturés reste autorisé si cracking = true

[capabilities.emulation]
attack_techniques = ["T1046", "T1021", "T1570"]  # IDs ATT&CK autorisés
profile           = "stealth"                    # "noisy" | "balanced" | "stealth" — agressivité rejouée
blue_team_contact = "soc@acme.example"           # coordination purple team
# Note : le mode labo (voie C, CLI `lab start`) active toutes les capacités
# sur le réseau de lab sans fichier ; ce bloc concerne les engagements formels (voie B).

# Optionnel — preuve d'autorisation forte (décision 3, mode hybride).
# Absent → mode v1 (vérification visuelle du SHA-256).
# Présent → signature ed25519 obligatoire et vérifiée, sinon refus de chargement.
[integrity]
signature = "RWQf6...<signature ed25519 du scope par le donneur d'ordre>"
```

### 3.2 Contrôles appliqués par le moteur

La reconnaissance passive (listing des réseaux/hôtes à portée) **ne traverse pas** les contrôles de cible : elle est autorisée sans scope. Toute **autre** action, quelle qu'en soit la capacité, traverse le `gate` qui applique dans l'ordre :

0. **Périmètre établi ?** : refus de toute action active si aucun scope de session n'a été établi (ni sélection+attestation voie A, ni attestation de lab voie C, ni fichier voie B).
1. **Validation temporelle** : refus si la date courante est hors de `valid_from`/`valid_until` ou hors `allowed_hours` (le cas échéant).
2. **Filtre de cible** : toute cible est vérifiée contre le scope établi (réseau sélectionné+attesté, ou `networks`/`hosts`) **et** les `exclusions`. Hors scope → action droppée + journalisée comme violation évitée. Les réseaux simplement *vus* pendant la recon mais non sélectionnés ne sont **pas** dans le scope.
3. **Filtre de capacité** : l'action porte un *niveau* (recon/exploitation/cracking/emulation). Si la capacité n'est pas activée dans le scope → refus. L'exploitation vérifie en plus l'appartenance à `exploitation.allowed_hosts`.
4. **Pré-conditions** : une action de niveau N≥2 exige un résultat de niveau inférieur sur la cible (p. ex. pas d'exploitation sans port ouvert + CVE corrélée identifiés au préalable).
5. **Confirmation humaine** : en mode `manual`, toute exploitation/spray en ligne exige une confirmation interactive explicite (loguée avec l'identité opérateur). En **mode labo** (voie C), cette confirmation par cible est levée — l'attestation de lab unique en tient lieu — mais l'action reste intégralement journalisée.
6. **Garde anti-destruction** : si `destructive_checks = false`, tout exploit tentant une charge destructrice est refusé ; seul le mode validation passe.
7. **Plafonds** : `max_rate_pps` (token bucket), `max_actions`, `max_attempts_per_account` — dépassement → arrêt.
8. **Attestation / consentement** : à l'établissement du périmètre (sélection voie A, attestation de lab voie C, ou chargement voie B), l'opérateur confirme qu'il dispose de l'autorisation sur ce périmètre précis (case explicite, loguée avec la cible, l'empreinte SHA-256 du scope et l'identité opérateur), avec rappel des capacités activées.

> **Mode labo et gate** : le mode labo (voie C) agit uniquement sur les étapes 3 (toutes les capacités N1–N4 sont activées d'office sur le réseau de lab), 5 (confirmation par cible levée) et sur l'exigence de fichier signé. Les étapes 0, 1, 2 (confinement au périmètre), 4 (pré-conditions), 6 (anti-destruction) et 7 (plafonds) **s'appliquent exactement comme dans les autres modes**. Le mode labo élargit ce qu'on a le droit de faire *dans* le périmètre, jamais le périmètre lui-même.

### 3.3 Journal d'audit

- Format **JSON Lines**, un événement par ligne, append-only.
- Chaque ligne contient : horodatage UTC, opérateur, cible, action, résultat.
- Chaînage d'intégrité : chaque entrée inclut le hash de la précédente (style journal chaîné) pour détecter toute altération a posteriori.

---

## 4. Architecture logicielle

Architecture en **cœur + couches**, pensée pour que la logique réseau soit testable sans privilèges.

```
┌─────────────────────────────────────────────────────────┐
│                        CLI / TUI                          │
│         (parsing args, affichage, progression)            │
└───────────────────────────┬───────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────┐
│                    ORCHESTRATEUR                           │
│   charge le scope · ordonnance les tâches · agrège         │
│   les résultats · demande les confirmations humaines       │
└───────────────────────────┬───────────────────────────────┘
                            │  (tout passe par le GATE)
┌───────────────────────────▼───────────────────────────────┐
│   GATE  ·  temps · cible · capacité · pré-conditions ·     │
│           confirmation · anti-destruction · plafonds       │
└──┬────────┬────────┬────────┬────────┬────────┬────────────┘
   │        │        │        │        │        │
┌──▼──┐ ┌───▼──┐ ┌───▼──┐ ┌───▼───┐ ┌──▼────┐ ┌─▼──────┐
│Disco│ │Port  │ │Svc ID│ │Exploit│ │Crack  │ │Emulation│
│very │ │Scan  │ │ +CVE │ │(N2)   │ │(N3)   │ │ (N4)    │
│(N1) │ │(N1)  │ │(N1)  │ │       │ │       │ │ ATT&CK  │
└──┬──┘ └───┬──┘ └───┬──┘ └───┬───┘ └──┬────┘ └─┬──────┘
   │        │        │        │        │        │
   │        │        │     ┌──▼────────▼──┐  ┌──▼─────────┐
   │        │        │     │ moteurs ext. │  │ ATT&CK map │
   │        │        │     │ (Metasploit  │  │ + verdict  │
   │        │        │     │  RPC, hashcat│  │ détection  │
   │        │        │     │  /John)      │  └────────────┘
   │        │        │     └──────────────┘
┌──▼────────▼────────▼────────▼───────────────────────────┐
│          COUCHE RÉSEAU / EXÉCUTION (abstraction)         │
│   traits NetworkProvider / ExploitEngine / CrackEngine   │
│      → impl réelles (sockets/pcap/RPC)                   │
│      → impl mock (tests déterministes)                   │
└───────────────────────────┬───────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────┐
│          AUDIT LOG (append-only, chaîné)  +  STORE         │
└───────────────────────────┬───────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────┐
│          REPORTING (HTML / JSON + matrice ATT&CK)          │
└─────────────────────────────────────────────────────────┘
```

**Points clés :**

- Le **`gate`** est le seul chemin vers l'exécution : *aucun* module (y compris exploitation/cracking/emulation) n'atteint le réseau ou un moteur externe sans le traverser. C'est l'invariant de sécurité central.
- Les **traits d'abstraction** (`NetworkProvider`, `ExploitEngine`, `CrackEngine`) permettent des implémentations *mock* complètes → tests déterministes sans réseau, sans privilèges, et **sans exploiter ni craquer quoi que ce soit de réel** en CI.
- Les capacités intrusives **délèguent à des moteurs établis** (Metasploit via RPC, hashcat/John) via ces traits : l'outil orchestre, cadre et trace ; il ne réimplémente pas une base d'exploits ni un moteur de craquage.
- Chaque module est **indépendant**, communiquant par messages (channels `tokio`).
- La **carte du réseau** (`NetworkMap`) est construite par les modules N1 (Discovery/PortScan/SvcID), enrichie par le pivot N2 (liens de propagation), consommée par la **TUI** (visualisation interactive des hôtes) et le **reporting** (carte annotée). C'est l'objet qui matérialise « je vois les machines, je choisis où j'entre ».

---

## 5. Choix techniques (crates Rust)

| Besoin | Crate | Pourquoi |
|--------|-------|----------|
| Runtime async | `tokio` | Concurrence massive pour scans parallèles. |
| Paquets bas niveau | `pnet` | Construction/lecture de paquets ARP, TCP SYN, ICMP. |
| Capture | `pcap` | Sniffing WiFi passif et capture ARP. |
| CLI | `clap` (derive) | Parsing d'arguments robuste et ergonomique. |
| TUI (optionnel) | `ratatui` | Affichage temps réel de la progression. |
| Config / scope | `serde` + `toml` | Désérialisation du fichier de scope. |
| Journalisation | `tracing` + `tracing-subscriber` | Logs structurés. |
| Hash (chaînage audit + empreinte scope) | `sha2` | Intégrité du journal et du fichier de scope. |
| Signature scope (option) | `ed25519-dalek` | Vérification de la signature du scope (décision 3, mode hybride). |
| Stockage résultats | `rusqlite` (SQLite) | Une base par engagement ; export JSON conservé. |
| Rapports HTML | `askama` | Templates compilés, typés. |
| Sérialisation résultats | `serde_json` | Export JSON. |
| Base CVE | `reqwest` (API NVD) + cache local | Corrélation vulnérabilités. |
| Moteur d'exploitation | Metasploit via **RPC** (`msgrpc`) — client JSON/MessagePack maison | Orchestrer un moteur éprouvé plutôt que réimplémenter des exploits. |
| Moteur de craquage | **hashcat / John** invoqués en sous-processus + parsing de sortie | Craquage hors ligne performant (GPU) sans réinventer. |
| Émulation ATT&CK | Mapping statique (JSON) des techniques + collecteur de verdicts | Produire la matrice de couverture de détection. |
| Erreurs | `thiserror` + `anyhow` | Gestion d'erreurs idiomatique. |

> **Note privilèges** : le SYN scan et la capture brute nécessitent `CAP_NET_RAW` (Linux) ou Npcap (Windows). Le mode `tcp_connect_only` fonctionne sans privilèges élevés.
>
> **Note dépendances externes** : Metasploit et hashcat/John ne sont **pas** embarqués. L'outil détecte leur présence au démarrage et désactive proprement les niveaux concernés s'ils sont absents (avec message clair). Cela garde le binaire Nickmare léger, et maintient la responsabilité de l'exploitation dans des outils audités par la communauté.

---

## 6. Structure du dépôt

Organisation en **workspace Cargo** multi-crates pour séparer nettement les responsabilités (et faciliter les tests).

```
nickmare/
├── Cargo.toml                 # workspace
├── README.md
├── LICENSE
├── docs/
│   ├── ARCHITECTURE.md        # ce document
│   ├── LEGAL.md               # modèle d'autorisation, mentions
│   └── OPERATOR_GUIDE.md      # guide d'utilisation opérateur
├── crates/
│   ├── core/                  # logique métier, pur, testable
│   │   ├── src/
│   │   │   ├── scope.rs        # chargement + validation du scope + capabilities
│   │   │   ├── gate.rs         # garde-fous (le "mur" obligatoire, tous niveaux)
│   │   │   ├── audit.rs        # journal chaîné
│   │   │   ├── model.rs        # types (Host, Port, Service, Finding, Exploit...)
│   │   │   └── traits.rs       # NetworkProvider / ExploitEngine / CrackEngine
│   │   └── Cargo.toml
│   ├── net/                   # implémentations réseau (N1)
│   │   ├── src/
│   │   │   ├── discovery.rs
│   │   │   ├── portscan.rs
│   │   │   ├── service_id.rs
│   │   │   ├── map.rs          # construction/mise à jour de la NetworkMap
│   │   │   └── wifi.rs
│   │   └── Cargo.toml
│   ├── cve/                   # corrélation CVE / NVD
│   ├── exploit/              # N2 — client Metasploit RPC + validation + pivot
│   │   └── src/{engine.rs, msf_rpc.rs, validate.rs, pivot.rs}
│   ├── crack/               # N3 — orchestration hashcat/John, parsing
│   │   └── src/{engine.rs, hashcat.rs, policy.rs}
│   ├── emulation/           # N4 — techniques ATT&CK + profils + verdicts de détection
│   │   └── src/{attack.rs, techniques.rs, profile.rs, verdict.rs}
│   ├── report/               # génération HTML / JSON + matrice ATT&CK
│   └── cli/                   # binaire final (clap, orchestration)
│       └── src/main.rs
├── tests/                     # tests d'intégration end-to-end (avec mock)
├── testdata/                  # scopes de test, captures pcap de référence
└── .github/workflows/ci.yml   # CI multiplateforme
```

---

## 7. Modèle de données

Types centraux (dans `crates/core/src/model.rs`), simplifiés :

```rust
pub struct Host {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub hostname: Option<String>,
    pub os_guess: Option<OsGuess>,
    pub ports: Vec<Port>,
    pub role: HostRole,        // Gateway | Server | Workstation | Unknown (pour la carte)
    pub compromised: bool,     // marqué true après une intrusion réussie (N2)
    pub first_seen: DateTime<Utc>,
}

// --- Carte du réseau (visualisation + support du pivot) ---
pub struct NetworkMap {
    pub scope_network: String,     // réseau attesté (CIDR/SSID)
    pub hosts: Vec<Host>,
    pub pivots: Vec<PivotLink>,    // chemins de propagation établis
}

pub struct PivotLink {
    pub from: IpAddr,              // hôte source (déjà compromis)
    pub to: IpAddr,                // hôte atteint via le pivot
    pub via: String,              // technique/relais (ex. "ssh", "smb"), tracé
    pub at: DateTime<Utc>,
}

pub struct Port {
    pub number: u16,
    pub proto: Proto,          // Tcp | Udp
    pub state: PortState,      // Open | Closed | Filtered
    pub service: Option<Service>,
}

pub struct Service {
    pub name: String,          // "ssh", "http"...
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

pub struct Finding {
    pub host: IpAddr,
    pub port: Option<u16>,
    pub severity: Severity,    // Info | Low | Medium | High | Critical
    pub cve: Option<String>,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

// --- Niveau 2 : exploitation ---
pub struct ExploitAttempt {
    pub host: IpAddr,
    pub cve: Option<String>,
    pub module: String,            // réf. du module (ex. Metasploit)
    pub mode: ExploitMode,         // Validate (preuve non destructrice) | Exploit
    pub confirmed_by: String,      // opérateur ayant validé (human-in-the-loop)
    pub outcome: ExploitOutcome,   // Vulnerable | NotVulnerable | Success | Failed
    pub evidence: Option<String>,  // preuve d'exploitabilité (jamais de charge destructrice)
}

// --- Niveau 3 : craquage ---
pub struct CrackResult {
    pub source: String,            // origine du hash (capture, dump autorisé)
    pub hash_type: String,         // NTLM, krb5, WPA, sha512crypt...
    pub attempted: u64,
    pub cracked: u64,              // on rapporte des statistiques, pas les secrets en clair par défaut
    pub weak_patterns: Vec<String>,// ex. "mot du dico + année"
    pub policy_verdict: PolicyVerdict,
}

// --- Niveau 4 : émulation d'adversaire ---
pub struct AttackExecution {
    pub technique_id: String,      // ID MITRE ATT&CK, ex. "T1021"
    pub host: IpAddr,
    pub profile: AdversaryProfile, // Noisy | Balanced | Stealth — agressivité rejouée
    pub performed_at: DateTime<Utc>,   // horodatage côté opérateur (toujours en clair)
    pub detection: DetectionVerdict,   // Detected | NotDetected | Partial | Unknown
    pub detected_at: Option<DateTime<Utc>>, // horodatage de l'alerte blue team (→ MTTD)
    pub detected_by: Option<String>,   // contrôle/outil de la blue team ayant alerté
    pub notes: Option<String>,
}

// Profil d'adversaire : règle l'agressivité/furtivité d'une émulation réaliste.
// La furtivité joue vis-à-vis de la CIBLE ; l'exécution reste toujours
// horodatée en clair dans le journal d'audit opérateur (invariant §1).
pub enum AdversaryProfile { Noisy, Balanced, Stealth }
```

> **Choix de conception (credentials)** : `CrackResult` rapporte par défaut des **statistiques** (taux de craquage, patterns faibles) et non les mots de passe en clair. L'affichage des secrets eux-mêmes est derrière un drapeau explicite, et ils ne sont jamais écrits dans le rapport livré au client sans décision explicite.

Le **rapport** est une agrégation : `Engagement → NetworkMap (Vec<Host> + Vec<PivotLink>) → {Findings, ExploitAttempts, CrackResults, AttackExecutions}` → carte du réseau annotée (hôtes compromis, chemins de pivot) + matrice de couverture ATT&CK + MTTD par technique.

---

## 8. User stories

Format : *En tant que … je veux … afin de …* + critères d'acceptation.

### Epic A — Cadrage & sécurité

**US-A0** — En tant qu'**opérateur**, je veux **lister les réseaux à portée sans aucune autorisation préalable** afin de voir sur quoi je peux travailler.
- ✅ `nickmare recon networks` → liste des réseaux WiFi visibles + sous-réseaux joignables, sans scope requis.
- ✅ Opération strictement passive ; aucune action active déclenchée.

**US-A1** — En tant qu'**opérateur**, je veux **choisir une cible dans la liste et attester mon autorisation** afin d'établir le périmètre de session sans écrire de fichier.
- ✅ `nickmare target select` → je choisis un réseau/hôte reconnu, je confirme l'autorisation (case explicite).
- ✅ La sélection + attestation génèrent un scope de session verrouillé sur cette cible ; empreinte SHA-256 + identité + horodatage logués.
- ✅ Les réseaux vus mais non sélectionnés (ex. WiFi voisin) restent hors scope.

**US-A2** — En tant qu'**opérateur** sur un engagement formel, je veux **charger un fichier de scope (optionnellement signé)** afin de figer un périmètre négocié avec un client.
- ✅ Scope TOML valide → résumé affiché ; bloc `[integrity]` présent → signature `ed25519` vérifiée sinon refus.
- ✅ Scope expiré ou mal formé → refus clair, aucune action active.

**US-A3** — En tant qu'**opérateur**, je veux que **toute action active hors de la cible établie soit automatiquement bloquée** afin de ne jamais toucher un réseau non autorisé par erreur.
- ✅ Cible hors scope (y compris un réseau simplement vu en recon) → action droppée + audit « blocked_out_of_scope ».
- ✅ Cible dans une `exclusion` → jamais contactée.

**US-A4** — En tant qu'**auditeur/client**, je veux **un journal inaltérable de toutes les actions** afin de vérifier a posteriori ce qui a été fait.
- ✅ Chaque action émise → une ligne d'audit horodatée (y compris l'attestation de cible).
- ✅ Toute altération du journal est détectable (hash chaîné rompu).

**US-A5** — En tant qu'**apprenant**, je veux **un mode laboratoire qui débloque la chaîne complète sans friction** afin d'apprendre sur mes propres machines / mon lab sans la cérémonie d'un engagement client.
- ✅ `nickmare lab start <cidr>` → attestation unique → N1–N4 utilisables sur ce réseau, sans confirmation par cible ni fichier signé.
- ✅ Tout reste confiné au réseau de lab déclaré ; sûreté (§11) et journal chaîné inchangés ; `mode = "lab"` marqué dans l'audit et le rapport.
- ✅ Si le réseau déclaré n'a pas l'air privé/isolé (routable, passerelle Internet active) → avertissement + confirmation renforcée.

### Epic B — Découverte

**US-B1** — En tant qu'opérateur, je veux **découvrir les hôtes actifs** d'un sous-réseau afin d'établir l'inventaire.
- ✅ ARP sweep sur `/24` < 10 s → liste IP + MAC.
- ✅ Respect de `max_rate_pps`.

**US-B2** — En tant qu'opérateur, je veux **scanner les ports** d'un hôte afin d'identifier les services exposés.
- ✅ Scan des 1000 ports courants avec états Open/Closed/Filtered.
- ✅ Mode `tcp_connect_only` fonctionne sans privilèges root/admin.

**US-B3** — En tant qu'opérateur, je veux **visualiser les machines connectées au réseau** afin de comprendre ce qui est présent avant de choisir une cible.
- ✅ `nickmare map` → carte des hôtes (IP, MAC, hostname, OS présumé, rôle, services ouverts) en TUI.
- ✅ La carte se met à jour au fil de la découverte ; les hôtes compromis et les chemins de pivot y apparaissent distinctement.
- ✅ Exportée dans le rapport HTML.

**US-B4** — En tant qu'opérateur, je veux **désigner un hôte précis de la carte comme cible d'intrusion** afin de concentrer les actions actives sur lui.
- ✅ `nickmare target host <ip>` → l'hôte doit appartenir au réseau attesté ; sinon refus + audit.
- ✅ N'élargit jamais le périmètre ; ne fait qu'affiner la cible active à l'intérieur.

### Epic C — Identification & analyse

**US-C1** — En tant qu'opérateur, je veux **identifier le service et sa version** afin d'évaluer les risques.
- ✅ Lecture de bannière → nom + version quand disponible.

**US-C2** — En tant qu'opérateur, je veux **corréler les versions avec les CVE connues** afin de prioriser.
- ✅ Service versionné → liste de CVE avec score CVSS.
- ✅ Fonctionne hors ligne avec une base CVE locale.

### Epic D — WiFi (passif)

**US-D1** — En tant qu'opérateur, je veux **lister les points d'accès visibles et leur chiffrement** afin d'identifier les configurations faibles (ex. WEP, WPA2 avec WPS).
- ✅ Écoute passive → SSID, BSSID, canal, chiffrement, puissance.
- ✅ Aucune émission de trame (strictement passif).

### Epic E — Exploitation (Niveau 2)

**US-E1** — En tant qu'opérateur, je veux **vérifier si une cible est réellement vulnérable à une CVE corrélée**, sans rien casser, afin de confirmer un finding avant de le rapporter.
- ✅ Mode validation par défaut → verdict Vulnerable/NotVulnerable, aucune charge destructrice envoyée.
- ✅ Refus si la capacité `exploitation` est désactivée ou si l'hôte n'est pas dans `allowed_hosts`.

**US-E2** — En tant qu'opérateur, je veux **lancer un exploit référencé après confirmation explicite**, afin d'obtenir une preuve d'exploitabilité pour le rapport.
- ✅ Mode `manual` → confirmation interactive obligatoire par cible, loguée avec mon identité.
- ✅ Déléguée à Metasploit via RPC ; chaque tentative produit une entrée `ExploitAttempt` tracée.
- ✅ Impossible si `destructive_checks = false` et que l'exploit tente une charge destructrice.

**US-E3** — En tant que **responsable de l'engagement**, je veux **un plafond d'actions en mode auto** afin que l'automatisation ne dérape jamais.
- ✅ `max_actions` atteint → arrêt propre + log.

**US-E4** — En tant qu'opérateur, je veux **rebondir depuis un hôte compromis vers d'autres machines du périmètre, y compris d'autres sous-réseaux reliés**, afin de simuler la propagation d'un attaquant (ex. de la DMZ vers le LAN).
- ✅ Depuis un hôte `compromised`, re-découverte de ce qui devient visible, puis pivot borné au **périmètre attesté** — qui peut couvrir plusieurs sous-réseaux (lab multi-CIDR voie C, ou `targets.networks` voie B).
- ✅ Chaque saut crée un `PivotLink` (source → cible, relais, horodatage) tracé et visible dans la carte.
- ✅ Tentative de pivot vers un sous-réseau **non déclaré** dans le périmètre, même joignable → refus + audit « blocked_out_of_scope ».

### Epic F — Craquage de credentials (Niveau 3)

**US-F1** — En tant qu'opérateur, je veux **craquer hors ligne des hashes capturés** afin d'évaluer la robustesse des mots de passe.
- ✅ Délégué à hashcat/John ; support NTLM, Kerberos, hashes Unix, WPA handshake.
- ✅ Rapport = statistiques (taux de craquage, patterns faibles), secrets en clair masqués par défaut.

**US-F2** — En tant que **client**, je veux **un verdict sur ma politique de mots de passe** afin de savoir quoi corriger.
- ✅ Patterns faibles identifiés (dico+année, réutilisation, longueur).

**US-F3** — En tant qu'opérateur, je veux que **le test de credentials en ligne soit borné** afin de ne pas verrouiller les comptes du client.
- ✅ Désactivé par défaut (`online_spray = false`).
- ✅ `max_attempts_per_account` respecté ; dépassement → arrêt.

### Epic G — Émulation d'adversaire & détection (Niveau 4)

**US-G1** — En tant qu'opérateur **purple team**, je veux **exécuter des techniques ATT&CK autorisées** afin de mesurer la capacité de détection de la défense.
- ✅ Seules les techniques listées dans `emulation.attack_techniques` sont exécutables.
- ✅ Chaque exécution produit une entrée `AttackExecution` et reste **entièrement tracée côté opérateur**, même si masquée pour la cible.

**US-G2** — En tant que **blue team**, je veux **un verdict détecté / non détecté par technique** afin de produire une matrice de couverture ATT&CK.
- ✅ Verdict renseignable par technique ; rapport = matrice de couverture.
- ✅ Horodatage de l'alerte renseignable → calcul du MTTD par technique.
- ✅ Contact SOC (`blue_team_contact`) rappelé au démarrage du mode émulation (hors mode labo).

**US-G3** — En tant qu'opérateur, je veux **choisir un profil d'adversaire (bruyant → furtif) dont l'évasion tente réellement de passer** afin que la mesure de détection soit crédible.
- ✅ Profil `noisy | balanced | stealth` ; en `stealth`, les techniques appliquent effectivement leur évasion vis-à-vis de la cible.
- ✅ Quel que soit le profil, l'exécution est horodatée **en clair** au journal d'audit opérateur (jamais masquée côté opérateur).
- ✅ Comparaison des taux de détection entre profils exploitable dans le rapport (apprentissage : « à partir de quel niveau de furtivité ma défense décroche ? »).

### Epic H — Restitution

**US-H1** — En tant que **client**, je veux **un rapport HTML lisible** avec résumé exécutif et détail technique.
- ✅ Résumé : hôtes, findings par sévérité, exploits confirmés, taux de craquage, couverture de détection.
- ✅ Détail : par hôte, par finding, avec recommandations.

**US-H2** — En tant qu'opérateur, je veux **un export JSON** afin d'intégrer les résultats dans d'autres outils.

---

## 9. Phases d'implémentation (roadmap)

Chaque phase produit un incrément **utilisable et testé**.

### Phase 0 — Fondations (socle non négociable)
- Workspace Cargo, CI multiplateforme (Windows + Linux), lint (`clippy`), format (`rustfmt`).
- `core::model`, `core::scope`, `core::gate`, `core::audit`.
- Trait `NetworkProvider` + implémentation **mock**.
- **Livrable** : `nickmare scope validate <fichier>` + tests du gate (dont les tests négatifs). *Pas encore de réseau réel.*

### Phase 1 — Reconnaissance, cartographie & établissement de cible
- `discovery.rs` (ARP + ICMP + listing des réseaux à portée), token bucket de débit.
- Implémentation réelle du `NetworkProvider` (Linux d'abord).
- `NetworkMap` + vue **carte** (d'abord textuelle, TUI enrichie en Phase 9).
- **Voie A** : sélection interactive d'un réseau + attestation → scope de session ; `target host` pour désigner l'hôte dans le périmètre.
- **Voie C** : `lab start` (attestation de lab unique, N1–N4 débloqués sur le réseau de lab).
- **Voie B** : chargement du fichier de scope.
- **Livrable** : `nickmare recon networks` (sans autorisation) ; `nickmare target select` / `lab start` ; `nickmare discover` + `nickmare map` ; `nickmare target host <ip>`.

### Phase 2 — Scan de ports
- `portscan.rs` : TCP connect, puis SYN. UDP basique.
- **Livrable** : `nickmare scan ports` (borné à la cible établie).

### Phase 3 — Identification de services + CVE
- `service_id.rs`, crate `cve` (cache NVD local).
- **Livrable** : findings avec versions et CVE.

### Phase 4 — WiFi passif
- `wifi.rs` via `pcap`, mode monitor (Linux) / Npcap (Windows).
- **Livrable** : inventaire WiFi.

### Phase 5 — Rapports (socle)
- Crate `report` : templates HTML (`askama`) + JSON.
- **Livrable** : `nickmare report --format html` pour les niveaux 1.

> **Jalon de revue** : avant d'implémenter les niveaux 2–4, revue explicite des garde-fous (gate capabilities, confirmation humaine, anti-destruction, journal). Ces niveaux ne démarrent qu'une fois les tests négatifs du gate verts.

### Phase 6 — Intrusion & exploitation (Niveau 2)
- Trait `ExploitEngine` + mock ; crate `exploit` : client Metasploit RPC, **mode validation d'abord**.
- Confirmation human-in-the-loop (levée en mode labo), garde anti-destruction, plafond `max_actions`.
- **Pivot** : `PivotLink`, re-découverte depuis un hôte compromis, **franchissement des sous-réseaux reliés déclarés** dans le périmètre (lab multi-CIDR / `targets.networks`), confinement strict à la frontière du périmètre, mise à jour de la carte.
- **Livrable** : `nickmare exploit validate` puis `nickmare exploit run` ; `nickmare pivot <ip>` ; carte annotée des hôtes compromis + chemins.

### Phase 7 — Craquage (Niveau 3)
- Trait `CrackEngine` + mock ; crate `crack` : orchestration hashcat/John, parsing, évaluation de politique.
- Masquage des secrets par défaut.
- **Livrable** : `nickmare crack --hashes <f>` → statistiques + verdict de politique.

### Phase 8 — Émulation d'adversaire réaliste (Niveau 4)
- Crate `emulation` : techniques ATT&CK autorisées, **profils d'adversaire** (noisy/balanced/stealth), collecte de verdicts + horodatages → MTTD, matrice de couverture.
- Invariant : exécution toujours en clair au journal opérateur, furtivité appliquée uniquement vis-à-vis de la cible.
- **Livrable** : `nickmare emulate --technique T1021 --profile stealth` + matrice ATT&CK + MTTD dans le rapport.

### Phase 9 — Rapports complets & finitions
- Rapport consolidé (exploits, craquage, matrice ATT&CK), TUI (`ratatui`), empaquetage, `OPERATOR_GUIDE.md`.

---

## 10. Stratégie de tests

Approche en pyramide, avec un fort accent sur le fait de **tester sans réseau réel** grâce au `NetworkProvider` mock.

### 10.1 Tests unitaires
- **Scope & gate** (priorité maximale) : validation temporelle, filtrage CIDR, exclusions, fenêtre horaire, **filtrage par capacité**, `allowed_hosts` exploitation, plafonds (`max_actions`, `max_attempts_per_account`). On teste explicitement les cas « doit bloquer ».
- **Audit** : chaînage de hash, détection d'altération, traçage des actions en mode émulation (masquées pour la cible mais présentes au journal).
- **Parsing** : bannières, réponses CVE, sortie hashcat/John, réponses Metasploit RPC.

### 10.2 Tests d'intégration (avec mocks)
- Scénario complet recon → exploitation → craquage → émulation → report contre des **mocks** (`NetworkProvider`, `ExploitEngine`, `CrackEngine`) rejouant des réponses prédéfinies. **Aucun exploit/craquage réel n'est exécuté en CI.**
- Vérification que le mode `manual` **bloque** en l'absence de confirmation, et que `destructive_checks = false` rejette un module destructeur (mock).
- Rejeu de captures pcap réelles (`testdata/`) pour le parsing WiFi/ARP.

### 10.3 Tests en laboratoire contrôlé (isolé)
- Environnement **totalement isolé** (VMs/conteneurs sans route vers l'extérieur : routeur virtuel + cibles volontairement vulnérables type Metasploitable, DVWA, VulnHub).
- Jamais sur un réseau de production ou public. Un *kill-switch* réseau du lab est documenté dans `OPERATOR_GUIDE.md`.
- Vérifie de bout en bout : découverte, exploitation en mode validation puis réel contre les cibles de lab, craquage de hashes de test connus, exécution de techniques ATT&CK et relevé de détection.

### 10.4 Tests de non-régression de sécurité (le filet le plus important)
- **Tests « négatifs » dédiés**, étendus à chaque capacité : tenter d'exploiter un hôte hors `allowed_hosts`, craquer sans capacité activée, exécuter une technique ATT&CK non listée, dépasser un plafond → l'outil doit **refuser et journaliser** à chaque fois. Contrat de CI.
- Test que **désactiver une capacité dans le scope la rend réellement inatteignable**, quelle que soit la commande CLI.
- Fuzzing des parsers (bannières, TOML, pcap, sorties d'outils externes) avec `cargo-fuzz`.

### 10.5 Qualité continue (CI)
- `cargo test` (Windows + Linux), `cargo clippy -- -D warnings`, `cargo fmt --check`.
- Audit des dépendances : `cargo audit` + `cargo deny`.
- Couverture suivie (objectif indicatif : > 80 % sur `core`).

---

## 11. Robustesse & sûreté opérationnelle

Cette section renforce la **fiabilité de l'outil** et sa **sûreté vis-à-vis des cibles** — c'est-à-dire ne jamais provoquer de panne, ne jamais corrompre de données, et toujours pouvoir reconstituer ce qui a été fait.

> **Ce que cette section n'est PAS** : elle ne traite pas de la furtivité vis-à-vis de la cible. Cette furtivité existe bien — au niveau N4 (émulation d'adversaire), l'évasion tente **réellement** de passer, car sans cela la mesure de détection n'aurait aucune valeur (§1). Ce que la traçabilité totale garantit, c'est autre chose : l'outil n'échappe **jamais à son propre journal d'audit opérateur**. Furtif vis-à-vis de la cible/SIEM, intégralement transparent vis-à-vis de l'opérateur. Voir §11.3.

### 11.1 Sûreté opérationnelle (ne pas casser la cible)

Primum non nocere : un audit ne doit jamais dégrader le système audité.

- **Détection de services fragiles** : avant toute interaction active soutenue, sonde légère ; marquage des services réputés sensibles (SCADA/ICS, imprimantes, équipements médicaux, vieux SNMP) → interaction minimale ou refus, journalisé.
- **Back-off adaptatif** : si la cible montre des signes de stress (latence qui grimpe, RST en rafale, timeouts), le débit diminue automatiquement, en-deçà même de `max_rate_pps`.
- **Circuit-breaker** : au-delà d'un seuil d'anomalies sur une cible (ex. un service qui cesse de répondre après nos requêtes), les actions actives sur cette cible sont **suspendues** et l'opérateur alerté, plutôt que de poursuivre à l'aveugle.
- **Mode `--dry-run`** : affiche exactement ce qui serait émis (cibles, actions, volumétrie) **sans rien envoyer**. Obligatoire-recommandé avant un run offensif.
- **Teardown garanti** : toute ressource ouverte (sessions, sockets, sessions Metasploit, fichiers temporaires avec hashes) est libérée via RAII/`Drop`, même en cas de panique ou d'interruption (`Ctrl-C` capté → arrêt propre).
- **Non-destructif par construction** : rappel du principe §1 — pas de charge destructrice sans `destructive_checks = true`, jamais de wipe/ransomware/corruption.

### 11.2 Fiabilité & reprise

- **État persistant dans SQLite** (décision 4) : chaque résultat (hôte, port, finding, tentative) est écrit au fil de l'eau. Un plantage ou une coupure n'efface pas le travail déjà fait.
- **Reprise d'un run interrompu** : `nickmare resume <engagement>` repart du dernier état cohérent plutôt que de tout refaire (et sans re-solliciter inutilement la cible).
- **Opérations idempotentes** : relancer une étape déjà faite ne double pas les actions réseau ni les entrées d'audit.
- **Gestion de la perte de lien** : reconnexion avec back-off ; une action en vol interrompue est marquée `incomplete` dans l'audit, jamais silencieusement « réussie ».
- **Budgets globaux** : plafond de durée et de volume par engagement (au-delà → arrêt propre), pour éviter un run qui s'emballe.

### 11.3 Mesure de détection (N4) — évasion réaliste, audit transparent

Le niveau émulation sert à **quantifier** la capacité de détection de la défense. Pour que cette mesure soit honnête, l'évasion doit vraiment tenter de passer (une intrusion qui se signale par construction ne teste rien) — c'est l'objet des **profils d'adversaire**. Hors mode labo, cela se fait en coordination avec la blue team (`blue_team_contact`). Points de conception :

- **Évasion effective, par profil** : `noisy | balanced | stealth` rejouent des niveaux d'agressivité réalistes ; comparer les taux de détection entre profils révèle à partir de quel seuil la défense décroche. C'est le cœur de l'apprentissage « une intrusion n'en est une que si elle n'est pas détectée ».
- **Latence de détection (MTTD)** : pour chaque technique ATT&CK exécutée, on horodate l'action côté opérateur ; la blue team renseigne l'horodatage de l'alerte → délai de détection par technique.
- **Corrélation horodatée** : l'export inclut une timeline précise permettant de rapprocher chaque action d'un éventuel événement SIEM.
- **Matrice de couverture ATT&CK** exportable (JSON + visuel dans le rapport) : détecté / non-détecté / partiel par technique, croisé avec le profil.
- **Rien n'est masqué côté opérateur** : même quand une technique passe effectivement inaperçue *du SIEM*, elle reste intégralement, en clair, au journal d'audit opérateur. La non-détection par la cible est un **résultat mesuré et assumé** du test ; l'opacité vis-à-vis de l'opérateur, elle, est **impossible par conception**. C'est cette ligne — furtivité dehors autorisée et cadrée, transparence dedans garantie — qui tient l'outil du bon côté.

### 11.4 Qualité du code au service de la robustesse

- **Pas de `panic!`/`unwrap`/`expect` sur des chemins d'exécution** : erreurs remontées via `Result` (`thiserror`/`anyhow`), paniques réservées aux invariants internes.
- **Timeouts partout** : aucune opération réseau sans timeout borné ; pas de blocage indéfini.
- **Tests de robustesse dédiés** (complète §10) : simulation de cible qui ralentit/coupe/renvoie des données malformées (via les mocks), vérification du back-off, du circuit-breaker et du teardown ; tests de reprise après coupure.

---

## 12. Sécurité du logiciel lui-même

- **Minimiser les privilèges** : fonctionner sans root/admin autant que possible ; n'escalader que pour SYN/capture, et le documenter.
- **Dépendances** : `cargo audit` + `cargo deny` en CI ; épingler les versions.
- **Pas de secrets en clair** : clé API NVD via variable d'environnement, jamais commitée.
- **Entrées non fiables** : tout ce qui vient du réseau (bannières, trames) est traité comme hostile → parsing défensif, pas d'`unwrap` sur des données externes.
- **Protection du journal d'audit** : fichier en append-only, permissions restreintes.

---

## 13. Distribution & multiplateforme

- **Cibles** : `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu` (+ `aarch64-unknown-linux-gnu`).
- **Binaire unique** par plateforme (force de Rust/Cargo).
- **Dépendances système** :
  - Linux : `libpcap` (paquet distro).
  - Windows : **Npcap** requis pour capture/SYN ; détection au démarrage + message clair si absent.
- **Releases** via GitHub Actions : build croisé, artefacts signés, checksums.

---

## 14. Glossaire

| Terme | Définition |
|-------|-----------|
| **Scope** | Périmètre autorisé de l'engagement (réseaux, hôtes, fenêtre temporelle). |
| **ROE** (Rules of Engagement) | Règles contractuelles de l'intervention. |
| **Gate** | Composant obligatoire qui valide chaque action contre le scope. |
| **ARP sweep** | Découverte d'hôtes via requêtes ARP sur un réseau local. |
| **SYN scan** | Scan de ports semi-ouvert (envoie SYN, analyse SYN/ACK). |
| **CVE / CVSS** | Identifiant de vulnérabilité publique / son score de gravité. |
| **Fingerprinting** | Déduction de l'OS/service à partir d'indices réseau. |
| **Mode monitor** | Mode d'une carte WiFi permettant l'écoute passive de toutes les trames. |
| **MTTD** (Mean Time To Detect) | Délai entre une action offensive et l'alerte de détection correspondante côté défense. |
| **Circuit-breaker** | Mécanisme qui suspend automatiquement les actions sur une cible devenue instable. |
| **ATT&CK** | Référentiel MITRE des tactiques/techniques d'adversaires, utilisé pour la matrice de couverture de détection. |
| **Carte du réseau** (`NetworkMap`) | Inventaire visualisable des machines du périmètre (hôtes, rôles, services, hôtes compromis, chemins de pivot). Support de « je vois les machines, je choisis où j'entre ». |
| **Pivot / mouvement latéral** | Rebond depuis un hôte compromis vers d'autres machines du **même** réseau autorisé, chaque saut étant tracé (`PivotLink`). |
| **Profil d'adversaire** | Niveau d'agressivité/furtivité rejoué en émulation (noisy/balanced/stealth) ; règle l'évasion vis-à-vis de la cible, jamais la traçabilité opérateur. |
| **Mode laboratoire** | Mode d'apprentissage (voie C) : une attestation unique sur un réseau isolé/propre débloque la chaîne N1–N4 sans friction, sûreté et journal inchangés. |

---

## Annexe — Décisions

1. **Interface** → ✅ **CLI d'abord**, TUI (`ratatui`) ajoutée en Phase 9 (finitions). *(décidé 2026-10-22)*
2. **Base CVE** → ✅ **Les deux** : API NVD en ligne **+ cache/miroir local**, le local servant de repli hors ligne. *(décidé 2026-10-22)*
3. **Intégrité du fichier de scope** → ✅ **Hybride** : empreinte SHA-256 affichée et vérifiée dès la v1, architecture prête pour une signature `ed25519` activable par engagement. *(décidé 2026-10-22)* (détail ci-dessous)
4. **Stockage des résultats** → ✅ **SQLite** via `rusqlite` (une base par engagement), à la place de fichiers JSON épars. L'export JSON reste disponible pour l'interopérabilité. *(décidé 2026-10-22)*
5. **Mode laboratoire / apprentissage** → ✅ **Voie C** : attestation unique sur un réseau isolé/propre, déblocage N1–N4 sans friction par cible, sûreté et traçabilité inchangées, garde-fou de cohérence « réseau non isolé → avertissement ». Choisi pour ne pas brider l'apprentissage, le confinement au périmètre restant l'invariant. *(décidé 2026-10-22, v0.2)*
6. **Ciblage à deux niveaux + visualisation + pivot multi-sous-réseaux** → ✅ Périmètre **réseau** attesté d'abord (un ou **plusieurs sous-réseaux reliés** possibles), puis sélection d'un **hôte** dans la `NetworkMap` visualisable, puis pivot pouvant **franchir les sous-réseaux déclarés** mais jamais la frontière du périmètre. Matérialise le parcours « cartographier → choisir où entrer → pénétrer → se propager dans le lab (DMZ→LAN) ». *(décidé 2026-10-22, v0.2)*
7. **Philosophie de l'évasion (révision v0.2)** → ✅ L'évasion N4 est désormais **effective** (profils d'adversaire) et non plus purement symbolique, car une mesure de détection n'est crédible que si l'évasion tente réellement de passer. L'invariant déplacé de « ne pas déjouer la cible » vers « **ne jamais déjouer le journal d'audit opérateur** » : furtif dehors, transparent dedans, confiné au périmètre attesté. *(décidé 2026-10-22, v0.2)*

### Reste à trancher — décision 3 : intégrité du fichier de scope

Le scope autorise désormais des actions offensives (exploitation, craquage). Garantir qu'il n'a pas été altéré est donc un point de sécurité réel. Trois options :

- **(a) Hash + confiance opérateur** : l'outil affiche l'empreinte SHA-256 du scope au chargement, l'opérateur vérifie visuellement. Simple, zéro infrastructure, mais ne prouve pas *qui* a produit le scope.
- **(b) Signature cryptographique du client** : le scope est signé (ex. `minisign`/`ed25519`) par le donneur d'ordre ; l'outil refuse tout scope dont la signature ne vérifie pas contre une clé de confiance. Preuve forte d'autorisation, mais exige une gestion de clés.
- **(c) Hybride** : (a) maintenant, architecture prête pour (b) en option activable par engagement.

**Décision : (c) hybride.** Mise en œuvre :

- **v1** : au chargement, l'outil calcule et affiche l'empreinte **SHA-256** du scope ; l'opérateur la confronte à celle communiquée par le donneur d'ordre. L'empreinte est inscrite dans le journal d'audit et le rapport (preuve du périmètre exact utilisé).
- **Extension** : un bloc `[integrity]` optionnel dans le scope porte une signature `ed25519`. Si présent, l'outil **exige** une signature valide contre une clé de confiance configurée, sinon il refuse de charger. Les engagements sans ce bloc retombent sur le mode v1.

Cela ne ferme aucune porte : les clients qui exigent une preuve d'autorisation forte l'activent, les autres démarrent sans gestion de clés.
