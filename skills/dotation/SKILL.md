---
name: dotation
description: Check code for basic security slip-ups (hardcoded API keys, committed .env files, open CORS, Supabase tables without RLS, open Firebase rules, SQL/command injection, vulnerable dependencies, hidden code in starter templates) with the local dotation scanner. Use after writing code that touches secrets, auth, database access, CORS or config, before proposing a commit, and before a deploy or release.
---

# dotation: security hygiene check

dotation scans the project on this machine. A scan sends nothing over the network.

## When to run it

- You wrote or edited code that touches secrets, environment variables, auth, database queries, CORS, file uploads, Supabase or Firebase: scan the files you changed.
- Before proposing a commit: scan the staged changes.
- Before a deploy, a release or "is this ready for production?": scan the whole project.

## How to run it

Prefer the MCP tools when the `dotation` MCP server is connected:

| Need | MCP tool | Command line |
|---|---|---|
| Files you just changed | `scan_files` with absolute paths | `dotation scan path/to/file.ts --format json` |
| Staged changes | `scan_staged` | `dotation scan --staged --format json` |
| Whole project | `scan_project` | `dotation scan --format json` |
| What a rule means | `explain_rule` | the `explanation` and `fix` fields of the finding |

Exit codes of `dotation scan`: `0` nothing blocking, `1` at least one finding at `--fail-on` level (default `high`), `2` usage error. Exit code 1 is a result, not a crash: read the JSON.

If the command is missing, tell the user it can be installed with
`npm install -g https://github.com/Sami-BUTRT/dotation-cli/releases/latest/download/dotation.tgz` (Node.js 22.12 or newer). Do not install it without asking.

## How to act on findings

1. Fix `critical` and `high` findings first, then `medium`. Mention `low` ones briefly.
2. For each fix, tell the user in one or two plain sentences what was wrong and what you changed. No jargon, no blame.
3. Leaked secret (category `secret`): move the value out of the code (environment variable, untracked `.env`), **and** tell the user to revoke the key and create a new one at the provider. A key that reached git history stays exposed even after it is removed from the code.
4. Supabase table without RLS: enable row level security and add policies that match the app's access rules; ask the user when the intended access is unclear.
5. Vulnerable dependency (category `dependency`): upgrade to the fixed version shown in the finding, then run the project's tests.
6. Scan again to confirm the findings are gone.

## Rules

- Never print, copy, log or move a secret value. Snippets in the report are already redacted; keep them redacted in your answers.
- Do not silence a finding (`// dotation-ignore` comment or `disable:` in `.dotation.yml`) unless the user confirms it is intended, and say which finding you silenced.
- Do not run `dotation scan --upload`, `dotation login` or `dotation explain` unless the user asks: those commands use the dotation.app online service.
