# Nickmare — Cadre légal & modèle d'autorisation

> Ce document complète [`ARCHITECTURE.md`](ARCHITECTURE.md) (§1, §2, §3) et
> [`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md). Il n'a pas valeur d'avis juridique :
> il fournit un cadre d'usage et un **modèle** d'autorisation à faire valider par
> un conseil compétent et par le donneur d'ordre avant tout engagement.

---

## 1. Usage autorisé uniquement

**Nickmare est un outil d'audit de sécurité réseau destiné EXCLUSIVEMENT à un
usage autorisé.** Il n'existe aucun usage légitime de cet outil en dehors des
trois cadres ci-dessous :

1. **Engagement de test d'intrusion autorisé par écrit** — un mandat signé par
   une personne habilitée à engager l'organisation propriétaire des systèmes
   visés (voie B, fichier de scope signé ; §3.1 de l'architecture).
2. **Réseaux et systèmes dont vous êtes propriétaire ou gestionnaire** — vos
   propres machines, votre propre infrastructure (voie A, sélection + attestation ;
   §3.0).
3. **Laboratoire d'apprentissage contrôlé et totalement isolé** — VMs/conteneurs
   sans route vers l'extérieur, cibles volontairement vulnérables (voie C, mode
   labo ; §10.3 et le [kill-switch du lab](OPERATOR_GUIDE.md#kill-switch-réseau-du-lab)).

Toute autre utilisation — scan, intrusion, exploitation, craquage ou émulation
contre un système sans autorisation explicite et préalable du propriétaire — est
**interdite**. Selon les juridictions, elle peut constituer une infraction pénale
(en France, atteinte aux systèmes de traitement automatisé de données, art.
323-1 et suivants du Code pénal ; ailleurs, Computer Fraud and Abuse Act,
Computer Misuse Act, et équivalents). **La responsabilité de disposer d'une
autorisation valide incombe entièrement à l'opérateur.**

### Ce que l'outil garantit par conception

Les garde-fous ne sont pas de simples recommandations : ils sont **intégrés au
moteur** (le `gate`, §3.2) et vérifiés par des tests négatifs de sécurité
(`ARCHITECTURE.md` §10.4, contrat de CI bloquant).

- **Recon libre, action ciblée** : la reconnaissance passive ne demande aucune
  autorisation ; **toute** action active exige un périmètre établi et attesté.
  Pas de périmètre → pas d'action active (fail-safe).
- **Confinement strict** : une action visant une cible hors du périmètre attesté
  est refusée et journalisée (« blocked_out_of_scope ») — jamais émise.
- **Traçabilité absolue** : chaque action est horodatée dans un journal
  inaltérable (chaîné par hash), **même en mode furtif**. L'outil peut être
  furtif vis-à-vis de la cible ; il ne l'est **jamais** vis-à-vis de son propre
  journal d'audit. C'est cette asymétrie qui distingue un outil d'engagement d'un
  logiciel malveillant.
- **Non destructif par défaut** : aucune charge destructrice sans drapeau
  explicite ; pas de déni de service, pas de wipe/ransomware (exclusions
  architecturales, §2).
- **Fail-safe** : en cas de doute (scope ambigu, fenêtre expirée, cible hors
  périmètre), l'outil s'arrête plutôt que d'agir.

### Ce que l'outil NE remplace PAS

Les garde-fous techniques ne remplacent pas l'autorisation **juridique**. Un
périmètre accepté par l'outil n'est légal que si l'autorisation sous-jacente
l'est. Le modèle ci-dessous sert à établir cette autorisation **avant** d'ouvrir
l'outil.

---

## 2. Modèle d'autorisation écrite (engagement)

> **À remplir et faire signer avant tout engagement tiers.** Les champs entre
> crochets `[…]` sont des emplacements à compléter : **n'y placez aucune donnée
> réelle tant que le document n'est pas l'exemplaire officiel signé** (ce dépôt ne
> doit contenir aucune identité, IP ou référence client réelle). Conservez
> l'exemplaire signé hors du dépôt.

```text
AUTORISATION DE TEST D'INTRUSION / AUDIT DE SÉCURITÉ

1. Parties
   Donneur d'ordre (propriétaire des systèmes) : [raison sociale]
   Représenté par (habilité à engager l'entité) : [nom, fonction]
   Prestataire / opérateur                      : [nom de l'opérateur ou société]
   Référence de l'engagement                    : [réf. contrat / bon de commande]

2. Objet
   Le donneur d'ordre AUTORISE le prestataire à réaliser un test d'intrusion /
   audit de sécurité sur le périmètre défini ci-dessous, aux seules fins
   d'évaluer la sécurité de ses systèmes, et atteste être propriétaire ou
   gestionnaire habilité de ce périmètre.

3. Périmètre autorisé (reporté dans le fichier de scope, cf. OPERATOR_GUIDE.md)
   Réseaux (CIDR)       : [ex. 10.x.0.0/16, 192.168.x.0/24]
   Hôtes explicites     : [ex. 192.168.x.x]
   Exclusions (jamais touchés) : [passerelles critiques, équipements sensibles]

4. Fenêtre d'intervention
   Du : [AAAA-MM-JJTHH:MM:SSZ]   Au : [AAAA-MM-JJTHH:MM:SSZ]
   Heures autorisées (le cas échéant) : [ex. 08:00-18:00 UTC]

5. Capacités autorisées (cocher ; alignées sur le fichier de scope)
   [x] Reconnaissance & cartographie (Niveau 1 — toujours)
   [ ] Exploitation (Niveau 2)      — mode : [validation | manuel | auto]
                                      hôtes exploitables : [liste restreinte]
                                      charges destructrices : NON (par défaut)
   [ ] Craquage de credentials (Niveau 3) — en ligne : [non par défaut]
   [ ] Émulation d'adversaire (Niveau 4)  — techniques ATT&CK : [T####, …]

6. Contraintes de sûreté
   Débit maximal              : [ex. 200 paquets/seconde]
   Contact technique / escalade : [nom, téléphone, e-mail]
   Contact blue team / SOC (si émulation N4) : [adresse de coordination]

7. Conditions
   - Le prestataire respecte strictement le périmètre et la fenêtre ci-dessus ;
     toute action hors périmètre est interdite et, par conception, bloquée et
     journalisée par l'outil.
   - Les actions sont non destructives sauf mention explicite et écrite au point 5.
   - Un journal d'audit horodaté et inaltérable est tenu et remis sur demande.
   - Les données collectées (y compris d'éventuels credentials) sont traitées de
     façon confidentielle et détruites à l'issue de l'engagement, sauf obligation
     légale contraire.

8. Signatures
   Donneur d'ordre : [nom] ______________________  Date : [AAAA-MM-JJ]
   Prestataire     : [nom] ______________________  Date : [AAAA-MM-JJ]
```

> **Lien outil ↔ autorisation.** Le périmètre des points 3 à 6 se reporte dans un
> **fichier de scope** TOML (voie B) que l'outil charge et dont il affiche
> l'empreinte SHA-256 — preuve technique du périmètre exact utilisé. Pour un
> engagement formel, faites **signer** le scope (bloc `[integrity]`, signature
> ed25519) : l'outil refuse alors de charger un scope signé dont la signature ne
> correspond pas. Voir le modèle de scope commenté dans
> [`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md#5-modèle-de-fichier-de-scope) et
> [`testdata/scope/template.toml`](../testdata/scope/template.toml).

---

## 3. Mentions légales & responsabilité

- **Licence.** Nickmare est distribué sous licence **Apache-2.0** (voir
  [`LICENSE`](../LICENSE)). La licence régit les droits sur le **logiciel** ; elle
  ne confère **aucun** droit d'auditer des systèmes tiers.
- **Absence de garantie.** Le logiciel est fourni « EN L'ÉTAT » (AS IS), sans
  garantie d'aucune sorte (cf. `LICENSE` §7). L'opérateur est seul responsable de
  l'appréciation de l'opportunité de son usage et des risques associés.
- **Limitation de responsabilité.** Dans les limites permises par la loi, les
  auteurs et contributeurs ne sauraient être tenus responsables d'un quelconque
  dommage résultant de l'usage ou de l'impossibilité d'usage du logiciel (cf.
  `LICENSE` §8). **L'usage illégal ou hors périmètre relève de la seule
  responsabilité de l'opérateur.**
- **Données personnelles & confidentialité.** Un engagement peut faire manipuler
  des données sensibles (configurations, identifiants, éventuels hashes). Elles
  doivent être traitées conformément au cadre applicable (p. ex. RGPD en UE),
  minimisées, et détruites à l'issue de l'engagement, sauf obligation contraire.
  Par conception, l'outil ne rapporte par défaut que des **statistiques** de
  craquage, jamais les secrets en clair (`ARCHITECTURE.md` §7).
- **Pas d'avis juridique.** Ce document est informatif. Faites valider engagement
  et autorisation par un conseil compétent dans la juridiction concernée.

---

## 4. Avant de lancer l'outil — points de contrôle

1. Une autorisation écrite et signée couvre-t-elle **ce** périmètre et **cette**
   fenêtre ? (sinon : ne rien lancer.)
2. Le périmètre est-il reporté fidèlement dans le scope / l'attestation ?
3. Les exclusions (équipements critiques) sont-elles déclarées ?
4. Le contact d'escalade est-il joignable pendant la fenêtre ?
5. En labo : le [kill-switch réseau](OPERATOR_GUIDE.md#kill-switch-réseau-du-lab)
   est-il en place et testé, le lab est-il réellement isolé ?

En cas de doute sur l'un de ces points : **ne pas agir** (principe fail-safe, §1).
