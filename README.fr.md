# dotation

Trouve les oublis de sécurité de base avant la mise en production : secrets en dur, `.env` versionné, CORS ouvert, Supabase sans RLS, Firebase ouvert, injections, dépendances vulnérables, code caché dans un « starter » piégé. Sans jargon. **Le scan tourne entièrement sur ta machine : `dotation scan` n'envoie jamais rien.** Le service en ligne (historique, packs Pro, assistant IA) est facultatif et ne sert que si tu le demandes.

Le CLI s'affiche en anglais ; le rapport peut être en français : `--lang fr`, ou `DOTATION_LANG=fr`, ou `lang: fr` dans `.dotation.yml`.

## Installation

Une commande, depuis les releases GitHub (Node.js 22.12 ou plus) :

```bash
npm install -g https://github.com/Sami-BUTRT/dotation-cli/releases/latest/download/dotation.tgz
```

Le paquet contient ses dépendances exactes, celles qui ont été testées : rien d'autre n'est résolu sur le registre npm et rien ne s'exécute à l'installation. La même commande met à jour. Une version précise : `…/releases/download/cli-v0.1.0/dotation-0.1.0.tgz` ; sommes de contrôle dans `SHA256SUMS` sur chaque release.

Sans installer : `npx --yes --package=https://github.com/Sami-BUTRT/dotation-cli/releases/latest/download/dotation.tgz dotation scan`

Pour aller plus loin (facultatif) : `brew install gitleaks semgrep osv-scanner`, puis `dotation update-db`.

## Utilisation

```bash
dotation scan [chemin]                 # projet entier (défaut : dossier courant)
dotation scan --staged                 # seulement les fichiers indexés (git add)
dotation scan --format sarif > d.sarif # pretty (défaut) | json | sarif
dotation scan --fail-on critical       # code retour 1 à partir de ce niveau (défaut : high)
dotation scan --all --lang fr          # tous les constats ; rapport en en (défaut) | fr | es | zh
dotation init                          # .dotation.yml + hook pre-commit + action GitHub (Code scanning)
dotation agent                         # skill + serveur MCP pour les assistants de code (voir plus bas)
dotation update-db                     # base de vulnérabilités OSV (téléchargement seul : rien n'est envoyé)
dotation mcp                           # serveur MCP (stdio)
```

Codes retour : `0` rien de bloquant, `1` au moins un problème au niveau `--fail-on`, `2` erreur d'utilisation.

Assumer un constat volontaire : commentaire `// dotation-ignore` (tout) ou `// dotation-ignore: DOT-CODE-001` sur la ligne ou la ligne du dessus. Désactiver une règle partout : `disable: [DOT-CODE-001]` dans `.dotation.yml`.

## Assistants de code (Claude Code, Cursor, VS Code, Codex…)

```bash
dotation agent                   # dans ton projet : skill Claude Code + .mcp.json, et .agents/skills
dotation agent --target all      # en plus .cursor/mcp.json et .vscode/mcp.json
dotation agent --global          # skills dans ton dossier personnel, pour tous tes projets
```

- **Skill** (`SKILL.md`) : dit à l'assistant quand scanner (après avoir touché aux secrets, à l'authentification, à la base de données, au CORS ou à la configuration ; avant un commit ; avant une mise en production) et comment traiter les constats (les critiques d'abord, ne jamais afficher un secret, dire quand une clé doit être révoquée, ne jamais faire taire un constat sans demander).
- **Serveur MCP** (`dotation mcp`), outils en lecture seule et hors ligne : `scan_project`, `scan_staged`, `scan_files` (les fichiers que l'assistant vient de modifier), `explain_rule`, `list_rules`. Les extraits renvoyés sont déjà masqués.

Les fichiers existants ne sont pas touchés (`--force` pour les remplacer) ; les configurations MCP sont complétées sans toucher aux autres serveurs. À la main, pour Claude Code : `claude mcp add --scope user dotation -- dotation mcp`.

## Service en ligne (facultatif)

```bash
dotation login                         # affiche un code ; tu le valides sur https://www.dotation.app/device
dotation whoami                        # compte et offre de la clé enregistrée
dotation scan --upload [--project nom] # envoie le rapport à ton historique (offre Pro)
dotation scan --upload --hash-paths    # idem, chemins remplacés par leur empreinte
dotation rules update                  # packs de règles signés (ouverts ; Pro selon ton offre)
dotation explain src/lib/db.ts:12      # explication par l'assistant IA (offre Pro) ; --fix pour un correctif
dotation logout                        # oublie la clé de cette machine (révocation : page Mon compte)
```

Ce qui part, et seulement avec ces commandes :

| Commande | Envoyé | Jamais envoyé |
|---|---|---|
| `scan` (sans `--upload`) | rien (vérifié par un test `strace`) | — |
| `scan --upload` | identifiant de règle, sévérité, catégorie, chemin relatif (ou son empreinte), ligne, empreinte du constat | code, extrait, titre, valeur d'un secret |
| `rules update` | ta clé d'accès (pour les packs Pro) | rien sur ton projet |
| `explain` | la règle et 13 lignes autour du constat, **secrets masqués sur ta machine** puis une seconde fois par le serveur | le reste du fichier |

La clé est enregistrée dans `~/.config/dotation/credentials.json` (lisible par toi seul) ; en CI, utilise la variable `DOTATION_TOKEN` (clé créée sur la page Mon compte). `DOTATION_API_URL` change l'adresse de l'API (HTTPS obligatoire, sauf `localhost`). Les packs sont vérifiés (signature ed25519, empreinte de chaque fichier) avant d'être installés dans `~/.cache/dotation/rulepacks`, puis lus hors ligne par `scan`.

## Moteurs

| Moteur | Rôle | Absent ? |
|---|---|---|
| Règles dotation (`rules/*.yaml`) | 16 règles : secrets, fichiers sensibles, CORS, Supabase, Firebase, TLS, debug, code caché | toujours là |
| Gitleaks | des centaines de formats de secrets | message d'installation, le scan continue |
| Semgrep | injections SQL / commandes, `eval`, XSS, désérialisation (règles locales de `engines/semgrep/`) | idem |
| OSV-Scanner | dépendances vulnérables, **hors ligne** (base téléchargée par `update-db`) | idem |

Confidentialité : Semgrep tourne sans métriques, sans vérification de version et sans le registre en ligne ; OSV-Scanner en mode hors ligne. Un test (`strace`) vérifie qu'un scan complet n'ouvre aucune connexion réseau. Les secrets sont masqués (`sk_live_****abcd`) dans toutes les sorties.

Score d'hygiène : 100 moins des pénalités (critique 25, élevé 10, moyen 4, faible 1) ; les dépendances comptent au plus pour 25 points.

## Développement

```bash
bash scripts/dev-tools.sh      # Node, Gitleaks, Semgrep, OSV-Scanner dans ~/.local (sans sudo, sommes vérifiées)
npm install && npm run check   # types, lint (biome), tests (vitest)
npm run pack:release           # release/dotation-X.Y.Z.tgz, tel que publié sur les releases GitHub
```

Publier une version : changer `version` dans `package.json`, puis pousser une étiquette `cli-vX.Y.Z` ; `.github/workflows/release.yml` lance les vérifications, construit le paquet, vérifie qu'il s'installe sans le registre npm et publie la release.

Règles maison : voir `rules/README.md`. Fixtures : `fixtures/` (faux secrets uniquement).

## Licence

Apache License 2.0 (`LICENSE`).
