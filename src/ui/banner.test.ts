import { existsSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { saveCredentials } from "../cloud/config.js";
import { messages } from "../i18n/index.js";
import { packagePath } from "../paths.js";
import { tempDir } from "../test/helpers.js";
import { type BannerInfo, localPlan, renderBanner, renderLogo, repoInfo, shouldShowBanner } from "./banner.js";
import { SYMBOL } from "./symbol.js";

const m = messages();
const base: BannerInfo = {
  version: "1.2.3",
  repo: "mon-projet",
  branch: "main",
  plan: "free",
  columns: 80,
  color: "truecolor",
};
// biome-ignore lint/suspicious/noControlCharactersInRegex: on cherche les séquences d'échappement
const ESC = /\u001b/;
const strip = (s: string) => s.replace(new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g"), "");

describe("banner", () => {
  it("le logo tient en 60 colonnes et 12 lignes, aux couleurs de la charte, avec le mot dotation", () => {
    const lines = renderLogo("truecolor");
    expect(lines.length).toBeLessThanOrEqual(12);
    for (const l of lines) expect([...strip(l)].length).toBeLessThanOrEqual(60);
    expect(lines.join("")).toContain("38;2;141;207;245"); // ciel
    expect(lines.join("")).toContain("38;2;255;154;98"); // abricot
    expect(lines.map(strip).join("\n")).toContain("dotation");
    expect(lines.join("")).not.toContain("38;2;232;50;14"); // ancien rouge du logo pixel
  });
  it("NO_COLOR : aucun code d'échappement", () => {
    expect(renderBanner({ ...base, color: "none" }, m)).not.toMatch(ESC);
  });
  it("affiche version, projet, branche et abonnement", () => {
    const out = renderBanner(base, m);
    expect(out).toContain("dotation v1.2.3");
    expect(out).toContain("Project: mon-projet (main)");
    expect(out).toContain("Plan: Free");
  });
  it("terminal étroit : une seule ligne", () => {
    const out = renderBanner({ ...base, columns: 40 }, m);
    expect(out.trim().split("\n")).toHaveLength(1);
  });
  it("la branche est neutralisée", () => {
    const out = renderBanner({ ...base, color: "none", branch: "x\u001b[2Jy" }, m);
    expect(out).not.toMatch(ESC);
    expect(out).toContain("\\x1b");
  });
  it("pas d'en-tête hors TTY, en CI, avec --no-banner, en json/sarif ou --quiet", () => {
    const ok = { isTTY: true, env: {} };
    expect(shouldShowBanner(ok)).toBe(true);
    expect(shouldShowBanner({ ...ok, isTTY: false })).toBe(false);
    expect(shouldShowBanner({ ...ok, env: { CI: "true" } })).toBe(false);
    expect(shouldShowBanner({ ...ok, env: { DOTATION_NO_BANNER: "1" } })).toBe(false);
    expect(shouldShowBanner({ ...ok, noBanner: true })).toBe(false);
    expect(shouldShowBanner({ ...ok, quiet: true })).toBe(false);
    expect(shouldShowBanner({ ...ok, format: "json" })).toBe(false);
    expect(shouldShowBanner({ ...ok, format: "sarif" })).toBe(false);
  });
  it("plan : Free sans état local, Pro si en cache, Pro ? sans cache", async () => {
    const dir = await tempDir();
    const env = { XDG_CONFIG_HOME: dir };
    expect(await localPlan(env)).toBe("free");
    const cred = {
      apiUrl: "https://api.dotation.app",
      token: `dot_pat_abcdefghij_${"A".repeat(43)}`,
      scopes: [],
      createdAt: "",
    };
    await saveCredentials(cred, env);
    expect(await localPlan(env)).toBe("pro?");
    await saveCredentials({ ...cred, plan: "pro" }, env);
    expect(await localPlan(env)).toBe("pro");
  });
  it("repoInfo : nom du dossier et branche, sans chemin", async () => {
    const dir = await tempDir("banner-repo-");
    await mkdir(join(dir, ".git"));
    await writeFile(join(dir, ".git", "HEAD"), "ref: refs/heads/feat/x\n");
    const r = await repoInfo(dir);
    expect(r.branch).toBe("feat/x");
    expect(r.repo).not.toContain("/");
    expect((await repoInfo(await tempDir("banner-nogit-"))).branch).toBeUndefined();
  });
  it.skipIf(!existsSync(packagePath("../web/public/symbol.svg")))(
    "le symbole a la même géométrie que celui du site (ignoré hors monorepo)",
    () => {
      const svg = readFileSync(packagePath("../web/public/symbol.svg"), "utf8");
      expect(svg).toContain(`viewBox="${SYMBOL.viewBox.join(" ")}"`);
      expect(svg).toContain(`<circle cx="${SYMBOL.disc.cx}" cy="${SYMBOL.disc.cy}" r="${SYMBOL.disc.r}"`);
      expect(svg).toContain(`<circle cx="${SYMBOL.dot.cx}" cy="${SYMBOL.dot.cy}" r="${SYMBOL.dot.r}"`);
      expect(svg).toContain(`a${SYMBOL.arc.r} ${SYMBOL.arc.r} 0 0 1 ${SYMBOL.arc.r * 2} 0`);
      expect(svg).toContain(`stroke-width="${SYMBOL.arc.width}"`);
    },
  );
});
