# Écrire une règle dotation

Une règle est une entrée YAML. Les règles livrées sont dans ce dossier ; celles d'un projet dans `.dotation/rules/*.yaml` (une règle du projet remplace une règle livrée de même `id`). Chaque fichier est validé au chargement : une erreur arrête le scan avec un message précis.

```yaml
- id: ACME-SEC-001            # PREFIXE-FAMILLE-NUMÉRO, en majuscules
  severity: high              # low | medium | high | critical
  category: secret            # secret | config | code | dependency | access (sert au dédoublonnage)
  detector:
    type: regex               # voir les détecteurs ci-dessous
    files: ["**/*.{js,ts}"]   # globs : **, *, ?, {a,b} ; sans « / », s'applique au nom du fichier
    exclude: ["**/*.test.ts"]
    pattern: 'internalToken\s*=\s*"(?<secret>[^"]+)"'
    secretGroup: secret       # groupe nommé masqué dans l'extrait
    ignoreIf: ['process\.env'] # une ligne qui contient l'un de ces motifs est ignorée
  text:                       # au moins fr ou en ; es / zh facultatifs (repli anglais)
    fr: { title: Jeton interne en dur, explanation: Une phrase sur le risque., fix: Comment corriger, en une à trois lignes. }
    en: { title: Hardcoded internal token, explanation: One sentence on the risk., fix: How to fix it, one to three lines. }
```

## Détecteurs

| `type` | Signale | Options |
|---|---|---|
| `regex` | un motif, ligne par ligne (lignes de plus de 2 000 caractères ignorées) | `files`, `exclude`, `pattern`, `flags` (`""` ou `"i"`), `ignoreIf`, `secretGroup`, `fileMustMatch` (le fichier doit contenir ce motif, ex. `"use client"`), `skipUntrackedEnv` |
| `tracked-file` | un fichier sensible suivi par git | `files`, `exclude`, `publicEnvSeverity` (sévérité d'un `.env` qui ne contient que des variables publiques) |
| `not-gitignored` | un chemin que git n'ignore pas (projet entier seulement) | `path`, `when` (la règle ne s'applique que si l'un de ces fichiers existe) |
| `supabase-rls` | table du schéma `public` créée sans `enable row level security` dans aucune migration | `files` |
| `hidden-code` | code placé après une longue suite d'espaces (dépôts piégés) | `files`, `exclude`, `minSpaces` (défaut 150) |

## Ton des textes

Tutoiement, direct, jamais culpabilisant. `explanation` : pourquoi c'est risqué, en une phrase concrète. `fix` : quoi faire, une à trois lignes, avec un exemple si utile. Pas de jargon sans explication.

## Tester une règle

Ajoute le cas à `fixtures/vulnerable-app` (faux secrets uniquement) et, si besoin, le cas propre à `fixtures/clean-app`. Le test « chaque règle livrée se déclenche » échoue tant que la fixture ne déclenche pas la nouvelle règle.
