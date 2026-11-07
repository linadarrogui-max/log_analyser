# Pipeline d’analyse des logs d’authentification

## Présentation

Ce projet analyse des journaux SSH d’authentification. Le pipeline lit les
fichiers texte et gzip, extrait les événements de connexion, les enregistre
dans PostgreSQL et affiche un dashboard graphique avec Matplotlib.

Le dashboard présente :

1. le nombre de connexions échouées par pays ;
2. le nombre de connexions réussies par utilisateur ;
3. les connexions échouées avec un nom d’utilisateur invalide.

Les entrées syslog « message repeated N times » sont comptées comme N tentatives.
Les réimportations mettent à jour l’événement d’origine au lieu de créer des
doublons.

## Pipeline

```text
data/auth.log*
    -> ingestion/raw.py
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
- Une base de plages IP/pays, si le dashboard doit attribuer un pays aux IP

Le projet n’utilise aucun driver Python PostgreSQL. Il communique avec
PostgreSQL en invoquant `psql` via `subprocess`. Les autres imports utilisés
proviennent de la bibliothèque standard Python, notamment `re`, `gzip`, `csv`,
`ipaddress`, `logging` et `subprocess`.

## Installation

Depuis le dossier `Log_analyser` :

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

Le pays n’est pas déductible des lignes SSH seules. Pour éviter d’envoyer les IP
à un service externe, fournir une base locale dans `data/ip_country.csv`, au
format suivant :

```csv
network,country
203.0.113.0/24,XX
2001:db8::/32,XX
```

Utiliser une source de géolocalisation dont la licence autorise cet usage.
Au lancement, les plages sont importées ou mises à jour dans
`ip_country_ranges`. Pour une IP correspondant à plusieurs plages, le réseau
le plus précis est utilisé. Les plages inconnues sont affichées comme
« Inconnu » ; les adresses privées ou réservées sont classées séparément.

Le CSV est facultatif. Sans ce fichier, le pipeline et le dashboard fonctionnent,
mais les IP publiques apparaissent sous « Inconnu ».

## Lancer le pipeline

Depuis le dossier `Log_analyser` :

```powershell
python main.py
```

Le programme :

1. initialise le schéma PostgreSQL ;
2. importe le CSV des pays s’il existe ;
3. lit chaque journal texte ou gzip dans `data/` ;
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

Contrôler PostgreSQL avec les requêtes de vérification ci-dessus après une
exécution réussie du pipeline.
