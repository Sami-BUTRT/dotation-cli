# Fixtures

- `vulnerable-app/` : application volontairement mal écrite (Next.js + Supabase + Express + FastAPI + Firebase) pour les tests. **Tous les secrets sont faux** : ils ont seulement le format des vrais (préfixes `sk_live_`, `AKIA`, `ghp_`…) et contiennent `FAKE` ou `DOTATION`. Aucun ne donne accès à quoi que ce soit.
- `clean-app/` : la même application, corrigée. Doit obtenir 100/100 et le code retour 0.

Ne pas « corriger » `vulnerable-app` : chaque problème y est attendu par un test (`src/fixtures.test.ts`).
Le `.env` de `vulnerable-app` est versionné exprès (voir `cli/.gitignore`), pour tester la règle DOT-CFG-001.
