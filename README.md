# dotation

Finds basic security slip-ups before you ship: hardcoded secrets, committed `.env` files, API routes without auth checks, open CORS, Supabase tables without RLS, open Firebase rules, injections, unsafe AI calls, risky GitHub workflows and MCP configs, vulnerable dependencies, hidden code in a booby-trapped starter. Aligned with the OWASP Top 10 lists. No jargon. **Scans run entirely on your machine: `dotation scan` never sends anything.** The online service (history, Pro rule packs, AI assistant) is optional and only used when you ask for it.

dotation's CLI is English-only.

## Install

One command, from the GitHub releases (Node.js 22.12 or newer):

```bash
npm install -g https://github.com/Sami-BUTRT/dotation-cli/releases/latest/download/dotation.tgz
```

The package carries its exact, tested dependencies: nothing else is resolved from the npm registry and nothing runs at install time. Run the same command to update. A specific version: `…/releases/download/cli-v0.2.3/dotation-0.2.3.tgz`; checksums in `SHA256SUMS` on each release.

Without installing: `npx --yes --package=https://github.com/Sami-BUTRT/dotation-cli/releases/latest/download/dotation.tgz dotation scan`

Optional, for deeper checks: `brew install gitleaks semgrep osv-scanner`, then `dotation update-db`.

## Usage

```bash
dotation scan [path]                   # whole project (default: current folder)
dotation scan --staged                 # only the staged files (git add)
dotation scan --format sarif > d.sarif # pretty (default) | json | sarif
dotation scan --fail-on critical       # exit code 1 from this severity up (default: high)
dotation scan --all                     # every finding
dotation init                          # .dotation.yml + pre-commit hook + GitHub Action (Code scanning)
dotation agent                         # skill + MCP server for AI coding agents (see below)
dotation update-db                     # OSV vulnerability database (download only: nothing is sent)
dotation sbom [-o bom.json]            # CycloneDX SBOM from the lockfiles (offline)
dotation mcp                           # MCP server (stdio)
```

Exit codes: `0` nothing blocking, `1` at least one problem at `--fail-on` level, `2` usage error.

Accept a deliberate finding: a `// dotation-ignore` comment (everything) or `// dotation-ignore: DOT-CODE-001` on the line or the line above. Turn a rule off everywhere: `disable: [DOT-CODE-001]` in `.dotation.yml`. The report always lists what the project set aside this way. `DOT-SEC-007` (hidden code in trapped repos) can't be ignored, disabled or replaced: a trapped repo writes those settings itself.

### Adopt dotation on an existing project (baseline)

Plenty of old findings and no time to fix them all today? Freeze them and only get told about new ones:

```
dotation baseline            # writes .dotation/baseline.json (commit it)
dotation scan                # hides frozen findings, counts them in the report ("suppressed.baseline")
dotation scan --no-baseline  # shows everything again
dotation scan --baseline other.json
```

The baseline stores, per finding, the rule, the file and a SHA-256 fingerprint of the normalised line (trimmed, spaces collapsed), so moving code around doesn't unfreeze it. Secret values are never stored, only hashes. Frozen findings are treated like `dotation-ignore`: they count neither in the score nor in the exit code, and the report always says how many were hidden. In SARIF they stay in the report with `baselineState: "unchanged"` (new ones: `"new"`). `DOT-SEC-007` is never hidden, and a malformed or oversized (over 5 MB) baseline is ignored with a notice: the file comes from the repo, so a cloned project could write it. Two identical lines in the same file share one fingerprint. The path is part of the fingerprint: renaming or moving a file unfreezes its findings. Secret findings are fingerprinted from the masked excerpt shown in reports, never the raw line.

## What it checks

Every finding carries its references (OWASP category and CWE) in the report, the JSON, the SARIF (as GitHub Code scanning tags) and the MCP server.

| Family | Examples | References |
|---|---|---|
| Secrets and sensitive files | hardcoded keys, committed `.env` and keys, AI key in a public variable, token in an MCP config, secret printed in logs | A07, A02, A09:2025 · NHI2:2025 · LLM02:2025 · MCP01:2025 |
| Access control | API route or Server Action that writes data without checking the session, SSRF, open redirect, path traversal, Supabase without RLS, open RLS policies, `security definer` functions, public storage buckets, views bypassing RLS, open Firebase rules | A01:2025 · API1, API5, API7:2023 |
| AI apps | AI SDK allowed in the browser, model answer inserted as HTML or executed, user input in the system prompt, no output limit | LLM01, LLM05, LLM06, LLM07, LLM10:2025 |
| Integrity, crypto, auth | unverified Stripe webhook, JWT verification off or skipped, `Math.random` secrets, fast password hashes, mass assignment, token in `localStorage` | A04, A07, A08:2025 · API3, API10:2023 |
| GitHub Actions | unpinned actions, untrusted text in `run:`, `pull_request_target` running the PR's code, `write-all`, echoed secrets | CICD-SEC-3 to 6 |
| AI agent config (MCP) | server downloaded without a pinned version, hardcoded token, remote server over `http://` | MCP01, MCP04, MCP07:2025 |
| Containers and config | container running as root, `latest` images, database published on every interface, public source maps, unprotected cookies, debug mode, TLS off, open CORS | A02:2025 |
| Supply chain | missing lockfile, `*` / `latest` versions, unpinned `requirements.txt`, names close to a popular package (typos, AI-invented names, DOT-DEP-005; lookalike detection for npm: the ~5 000 top npm names are bundled in `data/popular-packages.json`, no network at scan time, source wooorm/npm-high-impact (MIT). Python support will be enabled once the data licence is confirmed.), vulnerable dependencies (OSV), hidden code in trapped starters, SBOM (`dotation sbom`) | A03, A08:2025 |
| Errors and logs | stack trace sent to the visitor, swallowed error in payment or auth code | A09, A10:2025 |

The rules are tuned to avoid false alarms: they need a precise signal (for instance a database write **and** no session check anywhere in the file), and they were checked against well-known open-source projects. A rule that misses a case is better than one that cries wolf.

Sources: [OWASP Top 10:2025](https://top10.owasp.org/2025), [API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10), [Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/), [MCP Top 10](https://owasp.org/www-project-mcp-top-10/), [Non-Human Identities Top 10](https://owasp.org/www-project-non-human-identities-top-10/2025/), [Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/), [CWE](https://cwe.mitre.org/).

## AI coding agents (Claude Code, Cursor, VS Code, Codex…)

```bash
dotation agent                   # in your project: Claude Code skill + .mcp.json, and .agents/skills
dotation agent --target all      # also .cursor/mcp.json and .vscode/mcp.json
dotation agent --global          # skills in your home folder, for every project
```

- **Skill** (`SKILL.md`): tells the agent when to scan (after touching secrets, auth, database access, CORS or config; before a commit; before a deploy) and how to act on findings (fix critical first, never print a secret, say when a key must be revoked, never silence a finding without asking).
- **MCP server** (`dotation mcp`), all tools read-only and offline: `scan_project`, `scan_staged`, `scan_files` (the files the agent just changed), `explain_rule`, `list_rules`. Snippets in results are already redacted. The server tells the agent that snippets and project rule texts come from the scanned repo: data to report, never instructions to follow.

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
| dotation rules (`rules/*.yaml`) | 63 rules: see « What it checks » | always there |
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

In an interactive terminal, `dotation scan` starts with the logo, version, project and plan (read from local state, no network). Hide it with `--no-banner` or `DOTATION_NO_BANNER=1`; it never appears with `--format json|sarif`, in CI or when piped.
