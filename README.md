
## Présentation
Ce projet est un **Honeypot (pot de miel)** de haute interaction développé entièrement en langage **C**. Il simule un serveur Debian vulnérable pour attirer les attaquants, enregistrer leurs adresses IP et capturer l'intégralité des commandes saisies dans un système de fichiers virtuel.

Ce programme sert de "pense-bête" interactif pour les administrateurs souhaitant observer les opérations quotidiennes de manipulation et de surveillance effectuées par des tiers. Contrairement à un simple écouteur de port, il implémente une structure d'arborescence dynamique permettant une navigation réaliste (qui n'est absolument pas fini).



---

## Fonctionnalités
* **Système de Fichiers Virtuel (Tree Structure)** : Navigation réelle entre les répertoires grâce à une structure de données en arbre.
* **Multi-Client** : Gestion de plusieurs connexions simultanées via l'utilisation de `fork()`.
* **Audit & Logging** : Enregistrement systématique de l'adresse IP et de chaque commande envoyée dans un fichier `honeypot.log`.
* **Émulation de Commandes** : Support des commandes essentielles basées sur un guide de 83 commandes Linux à connaître (si j'ai le temps j'en rajouterai)[cite: 3].

---

## Commandes Supportées (Extraites du Guide)
Le Honeypot utilise les définitions standard pour simuler un environnement crédible :

### Navigation et Système
* **`ls`** : Liste les fichiers et les répertoires du répertoire de travail en cours.
* **`cd`** : Modifie le répertoire courant et permet de basculer entre les répertoires.
* **`pwd`** : Affiche le nom du répertoire de travail en cours.
* **`whoami`** : Affiche le nom de l'utilisateur en cours.
* **`uname`** : Affiche le nom du système d'exploitation actuel et des informations système.

### Manipulation de Fichiers et Dossiers
* **`cat`** : Lit et affiche le contenu des fichiers texte.
* **`mkdir`** : Crée un nouveau répertoire.
* **`touch`** : Permet de créer un fichier vide.
* **`chmod`** : Simule la modification des permissions d'un fichier.
* **`cp`** : Copie les fichiers et les répertoires.

### Surveillance et Utilitaires
* **`df`** : Affiche la quantité d'espace disponible sur le système de fichiers.
* **`apt-get`** : Simule l'outil de mise à jour automatique et d'installation de packages Debian.
* **`alias`** : Moyen d'exécuter une commande via un nom plus court.

---

## Installation et Compilation

### Prérequis
* Un compilateur C (`gcc`).
* Un environnement Linux/Unix.
* L'utilitaire `telnet` ou `nc` (netcat) pour les tests.

### Compilation
Ouvre un terminal dans le dossier du projet et compile le code :
```bash gcc honeypot.c -o honeypot```


## Lancement
Pour démarrer le serveur sur le port par défaut (2323) :

```./honeypot```

## Utilisation
Se connecter au Honeypot
Depuis un autre terminal, connectez-vous comme un attaquant :

```telnet 127.0.0.1 2323```

### Analyse des Logss
L'activité est enregistrée en temps réel dans honeypot.log : 
`[Tue Jan 6 21:10:12 2026] [IP:127.0.0.1] COMMANDE RECUE: cd etc 
[Tue Jan 6 21:10:15 2026] [IP:127.0.0.1]`


## Sécurité util d'apprentissage et de recherche.

Isolation : Ne faites jamais tourner ce programme avec les droits root réels.

Exposition : Utilisez une machine virtuelle (VM) ou un conteneur isolé pour éviter qu'un attaquant ne puisse atteindre votre hôte physique en cas de faille dans le code C.



(ce projet est purement en cours de dévellopement et non complet, si vous avez des questions sur des méthodes utilisées ou tout simplement sur mes projets, vous pouvez me contacter sur discord @fiakx)
