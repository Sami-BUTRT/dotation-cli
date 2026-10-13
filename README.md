# dotation

Finds basic security slip-ups before you ship: hardcoded secrets, committed `.env` files, open CORS, Supabase tables without RLS, open Firebase rules, injections, vulnerable dependencies, hidden code in a booby-trapped starter. No jargon. **Scans run entirely on your machine: `dotation scan` never sends anything.** The online service (history, Pro rule packs, AI assistant) is optional and only used when you ask for it.

French version: [README.fr.md](README.fr.md).

## Install

One command, from the GitHub releases (Node.js 22.12 or newer):

```bash
npm install -g https://github.com/Sami-BUTRT/dotation-cli/releases/latest/download/dotation.tgz
```

The package carries its exact, tested dependencies: nothing else is resolved from the npm registry and nothing runs at install time. Run the same command to update. A specific version: `…/releases/download/cli-v0.1.0/dotation-0.1.0.tgz`; checksums in `SHA256SUMS` on each release.

Without installing: `npx --yes --package=https://github.com/Sami-BUTRT/dotation-cli/releases/latest/download/dotation.tgz dotation scan`

Optional, for deeper checks: `brew install gitleaks semgrep osv-scanner`, then `dotation update-db`.

## Usage

```bash
dotation scan [path]                   # whole project (default: current folder)
dotation scan --staged                 # only the staged files (git add)
dotation scan --format sarif > d.sarif # pretty (default) | json | sarif
dotation scan --fail-on critical       # exit code 1 from this severity up (default: high)
dotation scan --all --lang fr          # every finding; report in en (default) | fr | es | zh
dotation init                          # .dotation.yml + pre-commit hook + GitHub Action (Code scanning)
dotation agent                         # skill + MCP server for AI coding agents (see below)
dotation update-db                     # OSV vulnerability database (download only: nothing is sent)
dotation mcp                           # MCP server (stdio)
```

Exit codes: `0` nothing blocking, `1` at least one problem at `--fail-on` level, `2` usage error.

Accept a deliberate finding: a `// dotation-ignore` comment (everything) or `// dotation-ignore: DOT-CODE-001` on the line or the line above. Turn a rule off everywhere: `disable: [DOT-CODE-001]` in `.dotation.yml`. Report language: `--lang`, `DOTATION_LANG` or `lang:` in `.dotation.yml`.

## AI coding agents (Claude Code, Cursor, VS Code, Codex…)

```bash
dotation agent                   # in your project: Claude Code skill + .mcp.json, and .agents/skills
dotation agent --target all      # also .cursor/mcp.json and .vscode/mcp.json
dotation agent --global          # skills in your home folder, for every project
```

- **Skill** (`SKILL.md`): tells the agent when to scan (after touching secrets, auth, database access, CORS or config; before a commit; before a deploy) and how to act on findings (fix critical first, never print a secret, say when a key must be revoked, never silence a finding without asking).
- **MCP server** (`dotation mcp`), all tools read-only and offline: `scan_project`, `scan_staged`, `scan_files` (the files the agent just changed), `explain_rule`, `list_rules`. Snippets in results are already redacted.

Existing files are left untouched (`--force` to overwrite); MCP config files are merged without touching other servers. By hand, for Claude Code: `claude mcp add --scope user dotation -- dotation mcp`.

## Online service (optional)

```bash
dotation login                         # shows a code; confirm it at https://www.dotation.app/device
dotation whoami                        # account and plan of the saved key
dotation scan --upload [--project name] # send the report to your history (Pro plan)
dotation scan --upload --hash-paths    # same, file paths replaced by their hash
dotation rules update                  # signed rule packs (open ones; Pro ones with your plan)
dotation explain src/lib/db.ts:12      # explanation by the AI assistant (Pro plan); --fix for a fix
dotation logout                        # forget this machine's key (revoke it on the Account page)
```

What leaves your machine, and only with these commands:

| Command | Sent | Never sent |
|---|---|---|
| `scan` (without `--upload`) | nothing (checked by an `strace` test) | — |
| `scan --upload` | rule id, severity, category, relative path (or its hash), line, finding fingerprint | code, snippet, title, secret value |
| `rules update` | your access key (for Pro packs) | nothing about your project |
| `explain` | the rule and 13 lines around the finding, **secrets redacted on your machine**, then again by the server | the rest of the file |

The key is saved in `~/.config/dotation/credentials.json` (readable by you only); in CI, use the `DOTATION_TOKEN` variable (key created on the Account page). `DOTATION_API_URL` changes the API address (HTTPS required, except `localhost`). Packs are verified (ed25519 signature, hash of every file) before being installed in `~/.cache/dotation/rulepacks`, then read offline by `scan`.

## Engines

| Engine | Role | Missing? |
|---|---|---|
| dotation rules (`rules/*.yaml`) | 16 rules: secrets, sensitive files, CORS, Supabase, Firebase, TLS, debug, hidden code | always there |
| Gitleaks | hundreds of secret formats | install hint, the scan goes on |
| Semgrep | SQL / command injection, `eval`, XSS, deserialization (local rules in `engines/semgrep/`) | same |
| OSV-Scanner | vulnerable dependencies, **offline** (database downloaded by `update-db`) | same |

Privacy: Semgrep runs without metrics, version check or online registry; OSV-Scanner in offline mode. A test (`strace`) checks that a full scan opens no network connection. Secrets are redacted (`sk_live_****abcd`) in every output.

Hygiene score: 100 minus penalties (critical 25, high 10, medium 4, low 1); dependencies count for 25 points at most.

## Development

```bash
bash scripts/dev-tools.sh      # Node, Gitleaks, Semgrep, OSV-Scanner in ~/.local (no sudo, checksums verified)
npm install && npm run check   # types, lint (biome), tests (vitest)
npm run pack:release           # release/dotation-X.Y.Z.tgz, as published on GitHub releases
```

Release: bump `version` in `package.json`, then push a `cli-vX.Y.Z` tag; `.github/workflows/release.yml` runs the checks, builds the package, checks that it installs without the npm registry and publishes the release.

House rules: see `rules/README.md`. Fixtures: `fixtures/` (fake secrets only).

## License

Apache License 2.0 (`LICENSE`).
