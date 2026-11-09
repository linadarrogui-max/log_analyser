# Mon projet : pipeline d’analyse des logs d’authentification

## Présentation

Dans ce projet, j’analyse des journaux SSH d’authentification pour repérer les
connexions acceptées, les échecs et les tentatives avec un utilisateur
invalide. Mon pipeline lit les fichiers `auth.log*` au format texte ou gzip,
extrait les événements, les enregistre dans PostgreSQL et affiche un dashboard
avec Matplotlib.

Le dashboard présente les trois indicateurs demandés :

1. le nombre de connexions échouées par pays ;
2. le nombre de connexions réussies par utilisateur ;
3. les connexions échouées avec un nom d’utilisateur invalide.

Les entrées syslog « message repeated N times » sont comptées comme N tentatives.
Les réimportations mettent à jour l’événement d’origine au lieu de créer des
doublons.

J’ai limité les dépendances Python déclarées à Matplotlib. `re` et les autres
modules utilisés (lecture des fichiers, gzip, réseau, PostgreSQL, journalisation)
font partie de la bibliothèque standard de Python ; je n’utilise aucun driver
PostgreSQL Python.

## Pipeline

```text
data/auth.log*
    -> ingestion/raw.py (uniquement les fichiers auth.log*)
    -> process/extract_transforme.py
    -> storage/postgres.py
    -> PostgreSQL
    -> requêtes d’agrégation
    -> serving/dashboard.py (Matplotlib)
```

Les erreurs sont enregistrées dans `logs/`, dans un fichier distinct par
module. Elles sont ensuite relancées afin que le programme ne masque pas un
échec.

## Prérequis

- Python 3.9 ou supérieur
- PostgreSQL installé et en cours d’exécution
- Le client PostgreSQL `psql`
- Matplotlib
- Une connexion Internet pour attribuer les pays des IP publiques, ou un fichier
  local de plages IP/pays

Le projet n’utilise aucun driver Python PostgreSQL. Il communique avec
PostgreSQL en invoquant `psql` via `subprocess`. Les autres imports utilisés
proviennent de la bibliothèque standard Python, notamment `re`, `gzip`, `csv`,
`ipaddress`, `logging` et `subprocess`.

## Installation

Depuis le dossier du projet `Log_analyser` (celui qui contient `main.py`) :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Le fichier `requirements.txt` contient uniquement Matplotlib. Matplotlib
installe ses propres dépendances.

Vérifier que PostgreSQL et `psql` sont accessibles :

```powershell
Get-Service *postgres*
psql --version
```

Si `psql` n’est pas dans le `PATH`, définir son chemin pour le terminal courant
(adapter le numéro de version si nécessaire) :

```powershell
$env:PSQL_PATH = "C:\Program Files\PostgreSQL\18\bin\psql.exe"
```

## Préparer PostgreSQL

### 1. Créer la base (si le compte ne peut pas la créer automatiquement)

Au premier lancement, le programme crée automatiquement la base `log_analyser`
si elle n’existe pas et si l’utilisateur PostgreSQL a le droit `CREATEDB`.
Sinon, la créer depuis pgAdmin ou depuis le client `psql` connecté à la base
système `postgres` :

```sql
CREATE DATABASE log_analyser;
```

### 2. Configurer les identifiants

Le programme utilise par défaut `localhost`, le port `5432`, l’utilisateur
`postgres` et la base `log_analyser`. Ces paramètres peuvent être remplacés par
les variables d’environnement `PGHOST`, `PGPORT`, `PGUSER` et `PGDATABASE`.

Pour éviter d’écrire un mot de passe dans le code ou dans le dépôt, configurer
le fichier de mots de passe PostgreSQL de l’utilisateur Windows :

```text
%APPDATA%\postgresql\pgpass.conf
```

Ajouter une ligne selon ce format, en remplaçant les valeurs par celles du
compte PostgreSQL :

```text
localhost:5432:log_analyser:postgres:VOTRE_MOT_DE_PASSE
```

Ne pas commiter ce fichier. `psql` lit les identifiants avec le mécanisme
standard libpq. Le programme désactive l’invite interactive afin qu’une
connexion mal configurée échoue explicitement au lieu de bloquer le pipeline.
Si `psql` indique qu’aucun mot de passe n’a été fourni, l’application demande
le mot de passe dans le terminal avec une saisie masquée. Il est transmis
uniquement au processus `psql`, conservé en mémoire pendant cette exécution et
n’est pas écrit dans les fichiers de log. Pour une exécution sans interaction,
configurer `pgpass.conf`.

### 3. Tables créées par l’application

Au démarrage, le programme exécute `storage/schema.sql`. Le schéma contient :

- `authentication_events` : les événements d’authentification, leur fichier et
  leur ligne d’origine, le nom d’utilisateur, l’IP, le résultat, le nombre de
  tentatives et le pays ;
- `ip_country_ranges` : les plages CIDR et leur pays ;
- des index pour accélérer les filtres par résultat, utilisateur, pays et IP.

L’année n’est pas présente dans les logs fournis ; le mois, le jour et l’heure
sont conservés séparément plutôt que d’inventer une date complète.

## Associer les IP aux pays

Par défaut, le pipeline utilise l’API sans clé ipwho.is pour résoudre les
adresses IP publiques. Cela envoie ces IP au service externe sur HTTPS. Les
adresses privées ou réservées ne sont pas envoyées. Aucun jeton ni compte n’est
nécessaire.
La documentation de l’API est disponible sur
[ipwho.is](https://ipwhois.io/documentation).

Le service gratuit limite l’utilisation à 1 000 requêtes par jour et par
adresse IP cliente. Le pipeline respecte un maximum local de 1 000 nouvelles
adresses par jour, met les résultats en cache dans
`data/ip_country_cache.json` et reprend les adresses restantes un autre jour.
Cette limite est partagée avec les autres usages du service provenant de la
même adresse IP publique ; elle n’est donc pas une garantie de disponibilité.
Les échecs temporaires ne sont pas gardés dans le cache afin de pouvoir les
réessayer ultérieurement.

Pour ne pas transmettre les IP à un service externe, utiliser à la place une
base locale autorisée dans `data/ip_country.csv` :

```csv
network,country
203.0.113.0/24,XX
2001:db8::/32,XX
```

Le fichier CSV est importé dans `ip_country_ranges` et ses plages sont utilisées
en priorité. Les IP non résolues par l’API ou la base locale apparaissent sous
« Inconnu ». La géolocalisation d’une IP reste approximative.

## Lancer le pipeline

Depuis le dossier `Log_analyser` :

```powershell
python main.py
```

Le programme :

1. initialise le schéma PostgreSQL ;
2. importe le CSV des pays s’il existe ;
3. cherche les fichiers `data/auth.log*` (texte ou gzip) et arrête clairement
   l’exécution si aucun journal d’entrée n’est présent ;
4. extrait les connexions réussies et échouées ;
5. enregistre les événements dans PostgreSQL de manière idempotente ;
6. calcule les trois agrégations depuis PostgreSQL ;
7. ouvre le dashboard Matplotlib et enregistre une copie dans `dashboard.png`.

Fermer la fenêtre Matplotlib pour terminer l’exécution.

## Requêtes de vérification

Échecs par pays :

```sql
SELECT country, SUM(attempt_count) AS attempts
FROM authentication_events
WHERE status = 'failed'
GROUP BY country
ORDER BY attempts DESC, country;
```

Réussites par utilisateur :

```sql
SELECT username, SUM(attempt_count) AS attempts
FROM authentication_events
WHERE status = 'successful'
GROUP BY username
ORDER BY attempts DESC, username;
```

Échecs avec utilisateur invalide :

```sql
SELECT username, SUM(attempt_count) AS attempts
FROM authentication_events
WHERE status = 'failed' AND invalid_user = TRUE
GROUP BY username
ORDER BY attempts DESC, username;
```

## Structure du projet

```text
Log_analyser/
├── data/                       # Logs d’entrée et CSV local des pays
├── ingestion/raw.py            # Lecture texte/gzip avec provenance des lignes
├── process/
│   ├── extract_transforme.py   # Extraction et classification des événements
│   └── geolocation.py          # Validation IP et pays de repli
├── storage/
│   ├── postgres.py             # Initialisation, import et requêtes PostgreSQL
│   └── schema.sql              # Tables et index
├── serving/dashboard.py        # Graphiques Matplotlib
├── logs/                       # Journaux d’exécution par module
├── app_logging.py              # Configuration des journaux
├── main.py                     # Point d’entrée du pipeline
└── requirements.txt
```

## Confidentialité et fichiers générés

Les journaux d’authentification peuvent contenir des IP et des noms
d’utilisateurs. Ils ne sont pas inclus dans Git. Les identifiants PostgreSQL,
les journaux d’exécution et `dashboard.png` sont également exclus du dépôt.
Ne pas ajouter de mot de passe ou de données personnelles au code source.

## Vérification

Compiler les modules :

```powershell
python -m compileall .
```

Exécuter les tests automatisés, sans installer de paquet de test :

```powershell
python -m unittest discover -s tests -v
```

Contrôler PostgreSQL avec les requêtes de vérification ci-dessus après une
exécution réussie du pipeline.
