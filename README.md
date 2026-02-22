# Sanitizer

![Sanitizer Logo](assets/sanitize-logo.svg)

Sanitizer caviarde automatiquement les donnees sensibles d'un fichier de configuration
avant partage (support, audit, ticketing, documentation).

Objectif: partager vite un fichier exploitable, sans exposer de secrets.

## Pitch

Tu selectionnes un fichier.
Sanitizer genere un fichier `*_sanitized` dans le meme dossier.
Tu gardes la structure lisible, mais les secrets sont remplaces.

## Ce que l'application fait

- Caviarde les champs sensibles: `password`, `passphrase`, `secret`, `token`, `api_key`, etc.
- Caviarde les variantes de cles (`dbPassword`, `MY_PASSWORD`, `db.password`, etc.).
- Caviarde les e-mails.
- Caviarde les valeurs sensibles detectees par motif (JWT, bearer token, URL avec credentials, longues chaines de secret).
- Caviarde les blocs de cles privees (PEM et PGP private key block).
- Caviarde les certificats et cles SSH publiques (options activables/desactivables).
- Caviarde les domaines que tu choisis (pas de domaine hardcode).
- Conserve autant que possible le format original (espaces, indentation, commentaires).
- Affiche un log de remplacement masque (avant/apres) dans le CLI et la GUI.

## Formats pris en charge

- Lignes YAML style `key: value`
- Lignes type variable d'environnement `KEY=VALUE` (avec ou sans `export`)
- Paires JSON inline sur une ligne (`{"password":"..."}`)
- Texte libre (pour certains motifs sensibles comme e-mail, cle privee, etc.)

## Limites a connaitre

- Ce n'est pas une preuve formelle d'absence de secret.
- Il peut exister des faux positifs/faux negatifs selon tes conventions internes.
- Les fichiers binaires sont ignores (skipped).
- Toujours relire la sortie avant diffusion externe.

## Installation

```bash
python -m pip install .
```

Commandes installees:

- `sanitizer-cli`
- `sanitizer-gui`

Tu peux aussi lancer directement:

- `python sanitize.py`
- `python sanitize_gui.py`

## Utilisation rapide (GUI)

```bash
python sanitize_gui.py
```

1. Choisir le fichier source.
2. Laisser/ajuster les domaines a caviarder (optionnel).
3. Lancer.
4. Lire les onglets de journal/remplacements.
5. Recuperer le fichier `*_sanitized` dans le meme dossier que la source.

## Utilisation rapide (CLI)

Exemple minimal:

```bash
python sanitize.py /chemin/vers/config.yaml
```

Avec domaines:

```bash
python sanitize.py /chemin/vers/config.yaml \
  --domain example.com \
  --domain internal.local
```

Version compacte:

```bash
python sanitize.py /chemin/vers/config.yaml --domains "example.com,internal.local"
```

Options utiles:

- `--dry-run`: analyse sans ecriture de fichier
- `--no-redact-certs`: ne pas caviarder les certificats
- `--no-redact-public-keys`: ne pas caviarder les cles SSH publiques
- `--force-overwrite`: ecraser `*_sanitized` sans confirmation
- `--verbose`: afficher l'etat detaille
- `--self-test`: lancer les auto-tests integres

Nom de sortie:

- entree: `config.yaml`
- sortie: `config_sanitized.yaml`

## Exemple de resultat

Entree:

```yaml
dbPassword: supersecret
owner_email: user@example.com
api_url: https://api.example.com/v1
```

Sortie:

```yaml
dbPassword: <REDACTED>
owner_email: <REDACTED>
api_url: https://<REDACTED>/v1
```

## Tests

Tests unitaires:

```bash
python -m unittest -v tests/test_sanitizer.py
```

Self-test rapide:

```bash
python sanitize.py --self-test
```

## Build executables desktop

Installer les dependances packaging:

```bash
python -m pip install .[packaging]
```

Generer les executables pour l'OS courant:

```bash
python scripts/build_executable.py
```

Sorties:

- binaire/app: `dist/`
- archive distribuable: `release/`

Artefacts attendus:

- Windows: `ConfigSanitizer.exe` dans un `.zip`
- macOS: `ConfigSanitizer.app` dans un `.tar.gz`
- Linux: `ConfigSanitizer` dans un `.tar.gz`

## Build automatique GitHub Actions

Workflow:

- `.github/workflows/build-executables.yml`

Declenchement:

- manuel (`workflow_dispatch`)
- sur tag (`v*`, par exemple `v0.1.0`)

## Bonnes pratiques avant partage

1. Faire un `--dry-run` si le fichier est critique.
2. Ouvrir le fichier de sortie et verifier les sections sensibles.
3. Verifier le log de remplacements (contexte masque).
4. Ne jamais publier un extrait non relu.

