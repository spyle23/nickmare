# Nickmare — Guide opérateur

> Guide d'utilisation de l'outil `nickmare`. Il décrit le **flux d'intrusion
> simulée** et les commandes concrètes. Il se complète au fil des phases
> (finalisation en Phase 9, cf. [`ARCHITECTURE.md`](ARCHITECTURE.md) §9) : les
> étapes non encore implémentées sont présentées comme **flux cible** et
> clairement signalées.
>
> **Avant tout** : lisez [`LEGAL.md`](LEGAL.md). Nickmare s'utilise **uniquement**
> sur un périmètre autorisé par écrit, vos propres réseaux, ou un laboratoire
> contrôlé et isolé. Pas de périmètre établi → aucune action active (fail-safe).

---

## 1. Prérequis & installation

Voir le [`README.md`](../README.md) (section « Prérequis système » et « Compiler
& tester »). En résumé :

- **Linux** : `libpcap` ; la capture brute / SYN scan exige la capability
  `CAP_NET_RAW`. Sans ce privilège, l'outil bascule sur `tcp_connect_only`.
- **Windows** : [Npcap](https://npcap.com/) pour la capture et le SYN scan.
- Le binaire s'appelle `nickmare` (`cargo build --workspace`, puis
  `target/debug/nickmare`). `nickmare --help` affiche l'aide intégrée, et
  `nickmare --version` la version.

---

## 2. Le flux d'intrusion simulée (vue d'ensemble)

Le parcours central de l'outil — « je choisis un réseau et je m'y infiltre, puis
je choisis une cible et je m'y infiltre » (cf. [`TESTING.md`](TESTING.md) §1) :

```
recon ──▶ map ──▶ target ──▶ N2 intrusion ──▶ pivot ──▶ émulation ──▶ report
(libre)  (carte) (hôte)     (exploitation)   (latéral)  (ATT&CK)     (restitution)
```

Chaque action active traverse le **gate** (§3.2) : périmètre établi, fenêtre
temporelle, cible dans le scope, capacité activée, pré-conditions, confirmation,
anti-destruction, plafonds. Une action hors périmètre est **refusée et
journalisée**, jamais émise.

### Disponibilité par étape (état actuel de l'implémentation)

| Étape du flux | Commande | État |
|---|---|---|
| Établir le périmètre (voie A) | `target select` | **Disponible** |
| Établir le périmètre (voie C, labo) | `lab start` | **Disponible** |
| Charger un scope (voie B) | `scope validate` | **Disponible** |
| Visualiser la carte | `map` | **Disponible** (rend une carte JSON) |
| Scan de ports (recon active N1) | `scan ports` | **Disponible** |
| Identification de services (N1) | `service id` | **Disponible** |
| Désigner l'hôte cible | `target host` | **Disponible** |
| Reprendre un engagement interrompu | `resume` | **Disponible** |
| Lister les réseaux à portée (recon passive) | `recon networks` | *À venir (Phase 1)* |
| Construire la carte en direct | `discover` | *À venir (Phase 1)* |
| Inventaire WiFi passif | — | *À venir (crate présente, pas de sous-commande CLI)* |
| Corrélation CVE | — | *À venir (crate présente, pas de sous-commande CLI)* |
| Restitution / rapport | `report` | *À venir (Phase 5)* |
| **N2 — exploitation** | `exploit validate` / `exploit run` | **Non encore disponible — gardé par le jalon de revue #17** |
| **N2 — pivot / mouvement latéral** | `pivot` | **Non encore disponible — gardé par le jalon de revue #17** |
| **N3 — craquage de credentials** | `crack` | **Non encore disponible — gardé par le jalon de revue #17** |
| **N4 — émulation d'adversaire** | `emulate` | **Non encore disponible — gardé par le jalon de revue #17** |

> **Jalon de revue #17.** Avant d'implémenter les niveaux 2 à 4 (intrusion,
> pivot, craquage, émulation), une **revue explicite des garde-fous** est exigée
> (gate capabilities, confirmation humaine, anti-destruction, journal ; cf.
> `ARCHITECTURE.md` §9, note après Phase 5). Tant que ce jalon n'est pas franchi,
> ces commandes **n'existent pas** dans l'outil. Les sections correspondantes
> ci-dessous décrivent le **comportement cible**, pas une fonctionnalité livrée.

---

## 3. Étape par étape

### 3.1 Reconnaissance (libre, non intrusive)

Lister ce qui est à portée ne demande aucune autorisation (observation passive,
§3.0). C'est le point de départ normal sur ses propres réseaux.

> *À venir (Phase 1).* La commande cible est `nickmare recon networks` (liste des
> réseaux WiFi visibles et sous-réseaux joignables). Elle **n'est pas encore
> disponible** dans le CLI. En attendant, identifiez vos réseaux par les outils
> système habituels.

### 3.2 Établir le périmètre

Trois voies produisent le même objet `Scope` interne ; elles ne diffèrent que par
la **friction** (cf. `ARCHITECTURE.md` §3.0).

**Voie A — sélection interactive (vos propres réseaux).** Vous choisissez un
réseau et **attestez** votre autorisation. L'attestation est obligatoire
(`--attest`) : sans elle, aucun périmètre n'est établi (fail-safe).

```sh
nickmare target select 192.168.10.0/24 --attest \
  --operator "operateur@example.test" --hours 12 --audit engagement.ndjson
```

Affiche l'opérateur, le réseau, la fenêtre, les capacités (recon N1), l'empreinte
SHA-256 du scope et l'attestation. Les réseaux vus mais non sélectionnés restent
hors d'atteinte.

**Voie C — mode laboratoire (friction minimale).** Une attestation unique sur un
ou plusieurs sous-réseaux **isolés** débloque la chaîne N1–N4 (mode `lab`).

```sh
nickmare lab start 192.168.56.0/24                         # lab mono-sous-réseau
nickmare lab start 10.10.1.0/24 10.10.2.0/24               # lab multi-sous-réseaux
```

Si un sous-réseau déclaré n'a pas l'air privé/isolé (plage routable), l'outil
**refuse** avec un avertissement ; relancez avec `--confirm-non-isolated`
seulement si c'est bien votre réseau d'entraînement. Le mode labo réduit la
*cérémonie*, jamais la *sûreté* (plafonds et journal inchangés).

**Voie B — fichier de scope (engagements formels).** Chargez un fichier TOML
décrivant le périmètre négocié (voir [§5](#5-modèle-de-fichier-de-scope)).

```sh
nickmare scope validate engagement.toml
# Scope signé (bloc [integrity]) : fournir la clé de confiance
nickmare scope validate engagement.toml --trusted-key-file cle_publique.hex
```

Affiche un résumé + l'empreinte SHA-256, ou un **refus clair** (code de sortie
≠ 0) si le scope est expiré, mal formé, ou signé sans clé fournie.

### 3.3 Cartographier & visualiser

```sh
nickmare map testdata/mock/network_map.json
```

Rend en texte la carte réseau (`NetworkMap`) : hôtes, rôles, services, hôtes
compromis et chemins de pivot (US-B3).

> **Note.** Aujourd'hui `map` **rend une carte déjà produite** (fichier JSON). La
> construction de la carte **en direct** à partir d'une découverte réseau
> (`nickmare discover`) et la TUI `ratatui` sont *à venir* (Phase 1 pour la
> découverte, Phase 9 pour la TUI).

### 3.4 Recon active : scan de ports & identification de services

Ces actions sont de la **recon active (N1)** : elles traversent le gate et sont
confinées au réseau attesté. L'attestation (`--attest`) est requise.

```sh
# Scan de ports (TCP connect sans privilège par défaut ; --udp pour l'UDP)
nickmare scan ports 192.168.10.25 --network 192.168.10.0/24 --attest \
  --ports 22,80,443 --rate 100 --timeout-ms 1000 --audit engagement.ndjson

# Identification de services sur les ports ouverts (bannières → nom/produit/version)
nickmare service id 192.168.10.25 --network 192.168.10.0/24 --attest \
  --ports 22,80,443 --audit engagement.ndjson
```

Une cible hors du réseau attesté est **refusée et journalisée** (jamais
contactée). `--rate` plafonne le débit (paquets/seconde) ; `--ports` omis = ports
courants.

### 3.5 Désigner l'hôte cible

```sh
nickmare target host 192.168.10.25 --network 192.168.10.0/24 --attest \
  --audit engagement.ndjson
```

Désigne l'hôte précis à pénétrer **dans le réseau attesté**. Refus + audit si
l'hôte est hors périmètre. N'élargit **jamais** le scope : affine seulement la
cible active.

### 3.6 Intrusion & exploitation (Niveau 2) — flux cible

> **Non encore disponible — gardé par le jalon de revue #17.** La description
> ci-dessous est le **comportement cible** (Phase 6), pas une fonctionnalité
> livrée.

Une fois un hôte désigné et une CVE corrélée, le flux cible prévoit :
`nickmare exploit validate` (vérifie l'exploitabilité **sans charge
destructrice**, mode validation par défaut), puis `nickmare exploit run` (après
**confirmation humaine** explicite, levée seulement en mode labo). L'exploitation
est bornée à `exploitation.allowed_hosts` et refusée si `destructive_checks =
false` tente une charge destructrice.

### 3.7 Pivot / mouvement latéral — flux cible

> **Non encore disponible — gardé par le jalon de revue #17** (Phase 6).

Depuis un hôte compromis, le flux cible re-cartographie ce qui devient visible et
rebondit (`nickmare pivot <ip>`) vers d'autres machines **du périmètre attesté**
(éventuellement d'autres sous-réseaux déclarés). Chaque saut est tracé
(`PivotLink`) et s'arrête net à la frontière du périmètre.

### 3.8 Craquage de credentials (Niveau 3) — flux cible

> **Non encore disponible — gardé par le jalon de revue #17** (Phase 7).

Le flux cible (`nickmare crack --hashes <f>`) craque **hors ligne** des hashes
capturés et rapporte des **statistiques** (taux de craquage, patterns faibles),
secrets masqués par défaut.

### 3.9 Émulation d'adversaire (Niveau 4) — flux cible

> **Non encore disponible — gardé par le jalon de revue #17** (Phase 8).

Le flux cible (`nickmare emulate --technique T1021 --profile stealth`) exécute des
techniques ATT&CK **autorisées** et mesure la détection (matrice de couverture +
MTTD). Invariant : l'exécution reste **toujours** journalisée en clair côté
opérateur, même quand elle passe inaperçue de la cible.

### 3.10 Restitution / rapport — flux cible

> **À venir (Phase 5).** `nickmare report --format html|json` consolidera la
> carte annotée, les findings, les exploits confirmés, le craquage et la matrice
> ATT&CK. Pas encore disponible dans le CLI.

### 3.11 Reprendre un engagement interrompu

```sh
nickmare resume engagement.db
```

Repart du dernier état cohérent d'un engagement depuis sa base SQLite persistante
(une base par engagement, §11.2) sans re-solliciter la cible. Une base absente
n'est **pas** créée à la volée (refus clair, pour ne pas masquer une erreur de
chemin). Les actions en vol interrompues sont marquées « incomplète ».

---

## 4. Journal d'audit

L'option `--audit <chemin>` (disponible sur `target select`, `target host`,
`lab start`, `scan ports`, `service id`) écrit chaque action dans un journal
**chaîné** au format JSON Lines, append-only (§3.3). Chaque ligne porte
l'horodatage UTC, l'opérateur, la cible, l'action et le résultat ; le chaînage par
hash rend toute altération détectable. **Y compris les refus** (actions hors
périmètre) sont journalisés : c'est la preuve a posteriori de ce qui a été fait.

Conservez le journal : il atteste du périmètre réellement utilisé (empreinte
SHA-256 du scope) et constitue le livrable de traçabilité de l'engagement.

---

## 5. Modèle de fichier de scope

Un fichier de scope (voie B) déclare le périmètre autorisé. Le modèle complet et
commenté est fourni dans
[`testdata/scope/template.toml`](../testdata/scope/template.toml) ; des exemples
de validation existent aussi (`testdata/scope/valid.toml`,
`expired.toml`, `integrity.toml`). Extrait :

```toml
[engagement]
client        = "Example Org"
reference     = "PENTEST-2026-000"
authorized_by = "Direction SI — mandat signé 2026-01-01"
operator      = "operateur@example.test"
valid_from    = "2026-01-01T00:00:00Z"   # fenêtre d'engagement (UTC)
valid_until   = "2026-12-31T23:59:59Z"

[targets]
networks = ["192.168.10.0/24", "10.20.0.0/16"]  # CIDR autorisés
hosts    = ["192.168.50.5"]

[targets.exclusions]
hosts = ["192.168.10.1", "10.20.0.254"]          # jamais touchés

[constraints]
max_rate_pps     = 200            # débit max (paquets/seconde)
allowed_hours    = "08:00-18:00"  # fenêtre horaire (UTC)
tcp_connect_only = false          # true = pas de SYN scan brut

[capabilities]
recon = true                      # Niveau 1 — toujours

# Tout le reste est DÉSACTIVÉ par défaut : il faut `enabled = true` explicitement.
[capabilities.exploitation]
enabled            = false        # Niveau 2 — mettre true pour autoriser
mode               = "manual"     # "manual" | "auto"
destructive_checks = false        # jamais de charge destructrice si false
allowed_hosts      = ["192.168.10.25"]
```

Points de vigilance :

- Les **champs inconnus sont refusés** (parseur strict) : attention aux fautes de
  frappe.
- `valid_from`/`valid_until` sont en **UTC** (ISO 8601) ; hors fenêtre → refus.
- Pour un engagement formel, faites **signer** le scope (bloc `[integrity]`,
  ed25519) et validez-le avec `--trusted-key-file`.
- **Aucune donnée réelle dans le dépôt** : les valeurs ci-dessus sont fictives
  (plages RFC1918, domaine `.test`). Conservez un scope d'engagement réel hors du
  dépôt.

---

## Kill-switch réseau du lab

> Référence `ARCHITECTURE.md` §10.3 et [`TESTING.md`](TESTING.md) §3. S'applique
> **au laboratoire d'apprentissage uniquement**. Un lab doit être **totalement
> isolé** (aucune route vers l'extérieur) : VMs/conteneurs reliés à un
> **routeur virtuel**, cibles volontairement vulnérables (Metasploitable, DVWA,
> VulnHub). **Jamais** sur un réseau de production ou public.

Le kill-switch sert à **couper instantanément et totalement** la connectivité du
lab — soit pour garantir l'isolation avant un run offensif, soit en urgence si un
doute surgit (une cible semble sortir du lab, un flux inattendu apparaît). Il y a
deux niveaux : l'**isolation par construction** (prévention) et le **kill-switch
d'urgence** (réaction). Exécutez ces commandes **sur l'hôte du lab**, avec les
droits d'administration, **jamais** sur une machine de production.

### A. Isolation par construction (prévention)

1. **Réseau interne uniquement.** Dans l'hyperviseur, raccordez les VMs à un
   réseau *Internal / Host-Only* (VirtualBox « Internal Network », VMware
   « Host-only », ou un bridge Linux **sans interface physique rattachée**).
   Retirez toute carte « NAT » ou « Bridged » qui donnerait un accès Internet.
2. **Pas de passerelle vers l'extérieur.** Le routeur virtuel du lab ne doit
   avoir **aucune** route par défaut vers le réseau de l'hôte ou Internet. Le DHCP
   du lab, s'il existe, distribue une passerelle **interne au lab** seulement.
3. **Vérifiez AVANT de commencer** (voir §C) : depuis une VM du lab, aucun accès
   Internet ne doit être possible.

### B. Kill-switch d'urgence (réaction) — pas à pas

L'objectif : couper tout trafic entre le lab et le reste du monde en une poignée
de commandes. Adaptez les noms d'interface (`LAB_IF`, `UPLINK_IF`) à votre hôte.

**Linux (hôte du lab)** — repérez puis coupez :

```sh
# 1) Repérer les interfaces : LAB_IF = bridge du lab, UPLINK_IF = lien externe
ip -brief link

# 2) Couper le routage/NAT (le cœur du kill-switch)
sudo sysctl -w net.ipv4.ip_forward=0          # plus aucun routage entre interfaces
sudo sysctl -w net.ipv6.conf.all.forwarding=0

# 3) Barrière pare-feu : tout ce qui est routé est jeté (nftables)
sudo nft add table inet killswitch
sudo nft add chain inet killswitch forward '{ type filter hook forward priority 0; policy drop; }'
#   (équivalent iptables : sudo iptables -P FORWARD DROP && sudo iptables -F FORWARD)

# 4) Isoler physiquement le lien externe du lab
sudo ip link set UPLINK_IF down               # on débranche l'uplink du lab
```

**Windows (hôte du lab, PowerShell administrateur)** :

```powershell
# 1) Repérer les cartes
Get-NetAdapter
# 2) Désactiver la carte qui donne accès à l'extérieur (nom exact via Get-NetAdapter)
Disable-NetAdapter -Name "<UPLINK_IF>" -Confirm:$false
# 3) Couper le partage/routage éventuel
Set-NetIPInterface -Forwarding Disabled
```

> **Note.** Si votre routeur de lab est lui-même une VM, l'arrêter (`Stop-VM` /
> `poweroff`) coupe aussi tout transit. Le pare-feu « policy drop » reste la
> garantie la plus fiable tant que le lab tourne.

### C. Vérifier l'isolation (indispensable)

Depuis **une VM du lab** (jamais depuis l'hôte), confirmez l'absence de sortie :

```sh
ping -c 2 1.1.1.1        # doit ÉCHOUER (aucune route vers Internet)
getent hosts example.com # la résolution DNS externe doit ÉCHOUER
ip route                 # aucune route par défaut (0.0.0.0/0) vers l'extérieur
```

Si **l'un** de ces tests réussit, le lab **n'est pas isolé** : ne lancez aucune
action offensive et corrigez l'isolation (revenez en §A / §B). En cas de doute :
**ne rien lancer** (fail-safe).

### D. Réarmer (fin de session)

Ne réactivez l'uplink que lorsque c'est volontaire et nécessaire :

```sh
# Linux
sudo nft delete table inet killswitch         # retire la barrière
sudo ip link set UPLINK_IF up                 # si un accès contrôlé est requis
```

```powershell
# Windows
Enable-NetAdapter -Name "<UPLINK_IF>" -Confirm:$false
```

---

## 6. Référence des commandes (état actuel)

Seules les commandes ci-dessous existent dans le binaire ; `nickmare --help`
affiche l'aide intégrée à jour.

```
nickmare scope validate <fichier> [--trusted-key <hex> | --trusted-key-file <chemin>]
nickmare target select <cidr> --attest [--operator <id>] [--hours <n>] [--audit <chemin>]
nickmare target host <ip> --network <cidr> --attest [--operator <id>] [--hours <n>] [--audit <chemin>]
nickmare lab start <cidr> [<cidr>...] [--operator <id>] [--hours <n>] [--confirm-non-isolated] [--audit <chemin>]
nickmare scan ports <ip> --network <cidr> --attest [--ports <p,p,...>] [--udp] [--rate <pps>] [--operator <id>] [--hours <n>] [--timeout-ms <n>] [--audit <chemin>]
nickmare service id <ip> --network <cidr> --attest [--ports <p,p,...>] [--rate <pps>] [--operator <id>] [--hours <n>] [--timeout-ms <n>] [--audit <chemin>]
nickmare resume <engagement.db>
nickmare map <carte.json>
nickmare --version | --help
```

Les commandes `recon`, `discover`, `report`, `exploit`, `pivot`, `crack`,
`emulate` apparaissent dans le flux cible (§2) mais **ne sont pas encore
disponibles** (voir le tableau de disponibilité et le jalon de revue #17).
