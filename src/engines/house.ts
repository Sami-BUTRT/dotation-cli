import { detect } from "../rules/detectors.js";
import { loadRules } from "../rules/loader.js";
import { type Engine, result } from "./engine.js";

/** Règles maison (YAML) : toujours disponibles, aucun outil externe. */
export const houseEngine: Engine = {
  id: "house",
  async scan(ctx) {
    const rules = await loadRules(ctx.extraRuleDirs);
    const cache = new Map<string, Promise<string | null>>();
    const byPath = new Map(ctx.fileSet.files.map((f) => [f.path, f]));
    const content = (path: string) => {
      let p = cache.get(path);
      if (!p) {
        p = byPath.get(path)?.read() ?? Promise.resolve(null);
        cache.set(path, p);
      }
      return p;
    };
    const findings = (
      await Promise.all(
        rules.map((r) =>
          detect(r, { fileSet: ctx.fileSet, scope: ctx.staged ? "file" : ctx.scope, lang: ctx.lang, content }),
        ),
      )
    ).flat();
    return result("house", "ok", findings);
  },
};
