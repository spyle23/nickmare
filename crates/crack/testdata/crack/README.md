# Fixtures de craquage — crate `nickmare-crack` (issue #21)

Sorties **hashcat / John** (mode `--show`) reconstituées, servant à éprouver le
**parsing** et l'orchestration **sans hashcat, sans John, sans sous-processus**
(cf. `docs/ARCHITECTURE.md` §10.2, `docs/TESTING.md` §10.4). Elles sont rejouées
par le `ScriptedRunner` (clé = programme) et parsées par les tests.

| Fixture | Outil / mode | Rôle |
|---------|--------------|------|
| `hashcat_ntlm_show.txt` | `hashcat -m 1000 --show` | NTLM : deux comptes recouvrés. |
| `hashcat_wpa_show.txt` | `hashcat -m 22000 --show` | Handshake WPA : un clair recouvré. |
| `john_sha512_show.txt` | `john --format=sha512crypt --show` | Hashes Unix + ligne de résumé John. |
| `john_krb5_show.txt` | `john --format=krb5tgs --show` | Kerberos (TGS-REP). |
| `hashcat_version.txt` | `hashcat --version` | Détection de présence (§5). |

**Pas de secret réel** : les « mots de passe » recouvrés sont des exemples
**volontairement faibles** (mot de dico + année, longueur insuffisante) destinés à
exercer l'évaluation de politique. Le parsing relie chaque clair à un compte, puis
le **masque** immédiatement (`MaskedSecret`) : aucun clair ne sort dans le rapport.

## Procédure manuelle de laboratoire (§10.3 — HORS CI)

Le test « craquage de **hashes de test connus** » (DoD US-F1) **n'est jamais joué
en CI** (aucun craquage réel). Il se déroule **à la main**, dans un **laboratoire
isolé** (§10.3), avec un vrai hashcat/John :

1. Hashes de **comptes de lab** uniquement (NTLM/Kerberos/Unix/WPA), jamais de
   credentials réels.
2. `hashcat -m <mode> <hashes> <wordlist>` (ou `john --format=<fmt>`), puis
   `--show` pour relever les clairs recouvrés.
3. Vérifier les **statistiques** (taux de craquage) et le **verdict de politique**
   (`PolicyVerdict`), secrets **masqués par défaut** dans le rapport.
4. L'affichage des clairs reste derrière une **décision explicite**
   (`SecretDisclosure`), jamais dans le rapport client par défaut.

Ce scénario est documenté ici comme **mode opératoire**, pas exécuté
automatiquement.
