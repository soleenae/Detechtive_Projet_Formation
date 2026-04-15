# Active Directory 

Documentation de la mise en place de l'Active Directory. 
Domaine : `detechtive.local` 
Contrôleur de domaine : `SRV-AD01`

---

## Table des matières

Réseau & Adressage IP
Installation & Promotion du DC
DNS
Structure des Unités d'Organisation (OUs)
Groupes & Utilisateurs
Jonction des machines au domaine
Politique de mots de passe (FGPP)
GPO — Politiques appliquées
Validation & Tests finaux

## Réseau & Adressage IP

**Objectif :** Attribuer une adresse IP statique à `SRV-AD01` sur le VLAN 40, garantissant une disponibilité constante du contrôleur de domaine et du service DNS.

| Paramètre | Valeur |
|---|---|
| Hostname | `SRV-AD01` |
| VLAN | 40 |
| Réseau | `192.168.10.32/29` |
| Adresse IP | `192.168.10.34` |
| Passerelle | `192.168.10.33` (pfSense) |
| DNS primaire | `192.168.10.34` (lui-même, après promotion) |

**Impact :** Une IP statique garantit que les clients du domaine et les autres serveurs trouvent toujours le DC/DNS à la même adresse. Après la promotion, le serveur se désigne lui-même comme DNS primaire car il devient l'autorité de résolution pour `detechtive.local`.


## Installation & Promotion du DC

**Objectif :** Installer le rôle AD DS et promouvoir `SRV-AD01` en tant que premier contrôleur de domaine d'une nouvelle forêt `detechtive.local`.

*Étapes réalisées :*
1. Installation du rôle *Active Directory Domain Services* via le Gestionnaire de serveur
2. Lancement de l'assistant de promotion depuis la notification post-installation
3. Création d'une *nouvelle forêt* avec le nom de domaine `detechtive.local`
4. Installation automatique du rôle *DNS* conjointement au DC
5. Redémarrage automatique du serveur à l'issue de la promotion

**Impact :**
- Le serveur devient l'unique autorité d'authentification Kerberos et LDAP du domaine
- Le service DNS est intégré à AD (zone DNS intégrée à l'AD) pour une réplication automatique et une meilleure résilience
- Toutes les futures machines du projet peuvent rejoindre `detechtive.local` et bénéficier des GPO, de l'authentification centralisée et des politiques de sécurité

## DNS

**Objectif :** Créer les enregistrements DNS A et PTR pour chaque serveur du projet afin d'assurer la résolution de noms dans les deux sens.

**Configuration réalisée via le Gestionnaire DNS :**

| Type | Rôle | Enregistrement |
|---|---|---|
| A | Nom → IP | Créé manuellement dans la zone directe `detechtive.local` |
| PTR | IP → Nom | Créé manuellement dans la zone de recherche inversée |

Cas particulier — Postes clients (VLAN 30) :
Les workstations sont en DHCP (`192.168.10.130` → `.200`). Elles s'enregistrent automatiquement dans le DNS AD à la connexion — aucune entrée manuelle n'est nécessaire.

**Impact :**
- La résolution directe permet aux clients de trouver les serveurs par leur nom (`ping SRV-FILE01.detechtive.local`)
- La résolution inverse est indispensable pour Kerberos, Wazuh et certains outils de supervision
- Un DNS mal configuré est la première cause d'échec lors de la jonction au domaine


## Structure des Unités d'Organisation (OUs)

**Objectif :** Organiser les objets AD dans une hiérarchie d'OUs pour permettre une application ciblée des GPO et une administration claire.
Configuration réalisée via la console ADUC (Utilisateurs et ordinateurs Active Directory) avec l'affichage des fonctionnalités avancées activé.

**Hiérarchie mise en place :**

```
detechtive.local
└── DET (OU racine)
    ├── DET-Utilisateurs      → comptes utilisateurs du domaine
    ├── DET-Groupes           → groupes de sécurité
    ├── DET-Ordinateurs
    │   ├── Workstations      → postes clients (cibles GPO utilisateur)
    │   └── Servers           → serveurs membres du domaine
    └── DET-Admins            → comptes d'administration
```

*Attention :* Ne pas nommer les OUs `Users` ou `Computers` — ces conteneurs système existent déjà dans AD et provoqueraient une erreur de création.

**Impact :**
- La structure conditionne directement l'application des GPO : une GPO liée à `Workstations` s'applique uniquement aux postes, pas aux serveurs
- Regrouper les objets par type permet une délégation d'administration fine (ex : le helpdesk peut gérer les OUs utilisateurs sans toucher aux OUs serveurs)
- Les comptes ordinateurs doivent être déplacés manuellement dans la bonne OU après jonction au domaine (ils arrivent par défaut dans `CN=Computers`)

## Groupes & Utilisateurs

**Objectif :** Créer les groupes de sécurité et les comptes utilisateurs pour permettre un ciblage précis des GPO, des partages réseau et des politiques FGPP.

Organisation :
- Les *groupes de sécurité* sont créés dans l'OU `DET-Groupes`
- Les *comptes utilisateurs* sont créés dans l'OU `DET-Utilisateurs`, puis ajoutés aux groupes appropriés

Groupes créés :

| Groupe | Membres | Usage |
|---|---|---|
| `GRP-Admins` | Administrateurs du domaine | Accès total, cible FGPP renforcée |
| `GRP-Utilisateurs` | Employés standard | Accès aux partages, GPO workstations |
| `GRP-IT` | Équipe technique | Droits délégués sur certaines OUs |

**Impact :**
- Les GPO peuvent être filtrées par groupe de sécurité (filtrage WMI ou Security Filtering dans GPMC)
- Les partages réseau sur `SRV-FILE01` sont contrôlés par appartenance aux groupes
- Les FGPP (politiques de mots de passe) sont appliquées directement sur les groupes, permettant d'avoir des exigences différentes pour les admins et les utilisateurs standard


## Jonction des machines au domaine

**Objectif :** Intégrer chaque machine du projet dans le domaine `detechtive.local` pour bénéficier de la gestion centralisée (GPO, authentification, DNS).

**Prérequis indispensable :** Le DNS de chaque machine doit pointer vers `SRV-AD01` (`192.168.10.34`) **avant** la jonction. Sans cela, la machine ne peut pas résoudre `detechtive.local` et la jonction échoue.

Procédure :
1. Configurer le DNS de la machine → `192.168.10.34`
2. Joindre le domaine `detechtive.local` depuis les propriétés système
3. Redémarrer la machine
4. Déplacer le compte ordinateur de `CN=Computers` vers l'OU cible (`Workstations` ou `Servers`)

**Impact :**
- Sans la jonction au domaine, les GPO, l'authentification centralisée et la supervision Wazuh ne fonctionnent pas
- Le déplacement dans la bonne OU est critique : tant que le compte est dans `CN=Computers`, aucune GPO du projet ne s'applique
- L'authentification Kerberos remplace les comptes locaux — un seul identifiant donne accès à toutes les ressources du domaine

## Politique de mots de passe (FGPP)

**Objectif :** Appliquer des politiques de mots de passe différenciées selon les profils utilisateurs, en conformité avec le CIS Benchmark.

Configuration réalisée via le Centre d'administration Active Directory (ADAC), dans le conteneur `Password Settings Container (PSC)`.

Paramètres appliqués (CIS Benchmark) :

| Paramètre | Valeur |
|---|---|
| Longueur minimale | 14 caractères |
| Complexité | Activée (maj, min, chiffres, caractères spéciaux) |
| Historique | 24 mots de passe |
| Verrouillage du compte | 5 tentatives échouées |
| Durée de verrouillage | 30 minutes |

Application :
- Une FGPP renforcée est appliquée au groupe `GRP-Admins` (exigences plus strictes)
- Une FGPP standard est appliquée au groupe `GRP-Utilisateurs`

**Impact :**
- Les FGPP permettent de dépasser la limite d'une seule politique de mot de passe par domaine (Default Domain Policy)
- Le verrouillage à 5 tentatives couplé aux règles Wazuh 100401/100700 permet une détection et un blocage automatique des attaques brute force
- La conformité CIS Benchmark renforce la posture de sécurité globale du domaine


## GPO — Politiques appliquées

**Vue d'ensemble**

| GPO | Cible (OU) | Type de config | Objectif |
|---|---|---|---|
| GPO-Wallpaper | Workstations | Configuration utilisateur | Fond d'écran imposé |
| GPO-ScreenLock | Workstations | Configuration utilisateur | Verrouillage automatique |
| GPO-USB-Block | Workstations | Configuration ordinateur | Blocage des périphériques USB |
| GPO-Firewall | Workstations & Servers | Configuration ordinateur | Pare-feu Windows + règles Wazuh |
| GPO-Drivemap | Workstations | Configuration utilisateur | Mappage lecteur réseau |
| GPO-Audit | Servers (AD) | Configuration ordinateur | Audit des événements AD |

**1. Fond d'écran imposé**

Cible : OU `Workstations`
Type : Configuration utilisateur

Le fond d'écran est stocké dans `SYSVOL\netlogon`, accessible à tous les postes via chemin UNC (`\\detechtive.local\netlogon\`). L'option *"Empêcher la modification"* est activée pour verrouiller le choix de l'utilisateur.

**Impact :** Uniformise l'identité visuelle et empêche les utilisateurs de personnaliser l'environnement de travail — utile aussi pour afficher des avertissements légaux.

**2. Verrouillage automatique & Économiseur d'écran**

Cible : OU `Workstations`
Type : Configuration utilisateur

| Paramètre | Valeur |
|---|---|
| Délai d'inactivité | 5 minutes |
| Verrouillage par mot de passe | Activé |

**Impact :** Réduit la surface d'attaque physique — un poste laissé sans surveillance se verrouille automatiquement. Complément indispensable à la politique de mots de passe.

**3. Blocage des périphériques USB**

Cible : OU `Workstations`
Type : Configuration ordinateur

Le blocage s'applique en *Configuration ordinateur* (et non utilisateur) pour couvrir tous les comptes qui se connectent sur les postes, y compris les administrateurs locaux qui pourraient contourner une règle utilisateur.

**Impact :**
- Prévient l'exfiltration de données via supports amovibles
- Bloque l'introduction de malwares ou ransomwares par clé USB
- Couverture totale : aucun compte ne peut contourner la restriction sur les postes ciblés

**4. Pare-feu Windows & Mappage lecteur réseau**

Cible : Workstations & Servers
Type : Configuration ordinateur (pare-feu) + Configuration utilisateur (mappage)

**Deux GPO complémentaires :**

GPO Pare-feu :
- Autorise les communications de l'agent Wazuh (ports entrants nécessaires)
- Autorise le trafic SMB pour les partages réseau sur le domaine
- Bloque le reste par défaut

GPO Mappage lecteur :
- Mappe automatiquement un lecteur réseau vers `SRV-FILE01` à chaque connexion d'un utilisateur du domaine

**Impact :**
- Sans la règle Wazuh dans le pare-feu, les agents ne remontent pas les logs au SIEM (`192.168.10.42`, VLAN 50 MGMT)
- Sans le mappage, les utilisateurs n'ont pas accès aux partages de fichiers
- L'automatisation par GPO supprime toute configuration manuelle sur les postes


**5. Audit des événements AD**

Cible : `SRV-AD01`
Type : Configuration ordinateur

Événements audités :
- Connexions et déconnexions (succès & échecs)
- Modifications d'objets AD (création, suppression, modification d'utilisateurs, groupes)
- Échecs d'authentification Kerberos

*Flux de collecte*

```
SRV-AD01 (Windows Event Log)
    │
    └── Agent Wazuh (installé sur SRV-AD01)
            │
            └── Wazuh Manager (192.168.10.42 — VLAN 50 MGMT)
                    │
                    └── Corrélation & Alerting temps réel
```

**Impact :**
- Les logs AD alimentent directement les règles Wazuh `100100`, `100101`, `100102` (modifications de groupes privilégiés, DCSync)
- La centralisation sur le SIEM permet une corrélation croisée entre les événements AD, réseau (pfSense) et système (LSASS)
- Conformité aux exigences d'audit des référentiels de sécurité (CIS, ISO 27001)



**Validation & Tests finaux**

**Méthodologie :** Valider de bas en haut — réseau → DNS → authentification → GPO → partages.

| Étape | Vérification | Outil |
|---|---|---|
| Réseau | Connectivité entre VLANs | `ping` / règles pfSense |
| DNS | Résolution directe et inverse | `nslookup` |
| Authentification | Connexion avec compte de domaine | Ouverture de session |
| GPO | Application des politiques | `gpupdate /force` + `rsop.msc` |
| Partages | Accès aux lecteurs réseau mappés | Explorateur de fichiers |
| Wazuh | Remontée des logs AD | Interface Wazuh / Kibana |

**Diagnostics courants :**

| Symptôme | Cause probable | Action |
|---|---|---|
| Jonction au domaine échoue | DNS mal configuré sur le poste | Pointer le DNS vers `192.168.10.34` |
| GPO non appliquée | Compte ordinateur dans `CN=Computers` | Déplacer dans l'OU cible |
| GPO non appliquée | Cache GPO obsolète | `gpupdate /force` |
| GPO partiellement appliquée | Filtrage de sécurité manquant | Vérifier Security Filtering dans GPMC |
| Logs Wazuh absents | Pare-feu bloque l'agent | Vérifier GPO-Firewall |



**Références**

| Composant | Standard / Outil |
|---|---|
| Politique de mots de passe | CIS Benchmark for Windows Server |
| Audit AD | CIS Controls v8 — Control 8 (Audit Log Management) |
| Structure OUs | Microsoft Best Practices for AD Design |
| SIEM | Wazuh — intégration Windows Event Logs |
