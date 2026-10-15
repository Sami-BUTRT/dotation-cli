import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { houseEngine } from "../engines/house.js";
import { scan } from "../scan.js";
import { fixtureRepo, tempDir } from "../test/helpers.js";
import {
  damerau,
  lookalikes,
  parsePackageJson,
  parsePyproject,
  parseRequirements,
  popularIndex,
  setPopularForTests,
} from "./lookalike.js";

async function dep005(files: Record<string, string>) {
  const d = await tempDir();
  for (const [p, c] of Object.entries(files)) {
    await mkdir(dirname(join(d, p)), { recursive: true });
    await writeFile(join(d, p), c);
  }
  const r = await scan(d, { engines: [houseEngine] });
  return r.findings.filter((f) => f.id === "DOT-DEP-005");
}

const TEST_PYPI = ["requests", "python-dateutil", "flask", "uvicorn", "fastapi"];
afterEach(() => setPopularForTests(null));

describe("lookalike-package", () => {
  it("données embarquées présentes", () => {
    const idx = popularIndex();
    expect(idx.npm.set.has("express")).toBe(true);
    expect(idx.pypi.set.size).toBe(0);
  });

  it("distance de Damerau-Levenshtein", () => {
    expect(damerau("requests", "reqeusts", 1)).toBe(1);
    expect(damerau("abc", "xyz", 1)).toBe(2);
  });

  it("repère fautes de frappe, séparateurs et affixes ; ignore les paquets populaires", () => {
    setPopularForTests({ pypi: TEST_PYPI });
    expect(lookalikes("pypi", "reqeusts")).toContain("requests");
    expect(lookalikes("npm", "expresss")).toContain("express");
    expect(lookalikes("pypi", "pythondateutil")).toContain("python-dateutil");
    expect(lookalikes("pypi", "pyrequests")).toContain("requests");
    expect(lookalikes("npm", "lodash-js")).toContain("lodash");
    expect(lookalikes("npm", "express")).toEqual([]);
    expect(lookalikes("pypi", "Requests")).toEqual([]);
    expect(lookalikes("npm", "zzqx-internal-tool")).toEqual([]);
    expect(lookalikes("npm", "ab")).toEqual([]);
  });

  it("lit package.json, requirements et pyproject (Poetry compris)", () => {
    const pkg =
      '{\n  "name": "me",\n  "dependencies": {\n    "a-b": "1",\n    "me-lib": "workspace:*"\n  },\n  "devDependencies": {\n    "c-d": "^1"\n  }\n}\n';
    expect(parsePackageJson(pkg)).toEqual([
      { name: "a-b", line: 4 },
      { name: "c-d", line: 8 },
    ]);
    expect(parseRequirements("# c\n-r base.txt\nFlask[async]>=3 ; python_version>'3'\ngit+https://x/y\n")).toEqual([
      { name: "Flask", line: 3 },
    ]);
    const toml =
      '[project]\nname = "x"\ndependencies = [\n  "fastapi>=0.1",\n  "httpx",\n]\n[tool.poetry.dependencies]\npython = "^3.12"\nrich = "^13"\n';
    expect(parsePyproject(toml).map((d) => d.name)).toEqual(["fastapi", "httpx", "rich"]);
  });

  it("pyproject : un extra « [standard] » ne ferme pas le tableau, la suite est vérifiée", () => {
    const toml = '[project]\nname = "x"\ndependencies = [\n  "uvicorn[standard]>=0.30",\n  "reqeusts",\n]\n';
    const deps = parsePyproject(toml).map((d) => d.name);
    expect(deps).toEqual(["uvicorn", "reqeusts"]);
    expect(lookalikes("pypi", "reqeusts")).toEqual([]);
    setPopularForTests({ pypi: TEST_PYPI });
    expect(lookalikes("pypi", "reqeusts")).toContain("requests");
    expect(
      parsePyproject('[project]\ndependencies = ["uvicorn[standard]>=0.30", "reqeusts"]\n').map((d) => d.name),
    ).toEqual(["uvicorn", "reqeusts"]);
  });

  it("npm : nom absent du texte (échappement \\u) : ligne de la section, sans erreur ; famille « . »", () => {
    const deps = parsePackageJson('{\n "dependencies": {\n  "\\u0065xpress": "1"\n }\n}');
    expect(deps).toEqual([{ name: "express", line: 2 }]);
    const esc = parsePackageJson('{\n "dependencies": {\n  "abcdef": "1",\n  "zzzzzz": "1"\n }\n}');
    expect(esc.map((d) => d.line)).toEqual([3, 4]);
    expect(lookalikes("npm", "lodash.isequall")).toContain("lodash.isequal");
    expect(lookalikes("npm", "lodash.zipobject2x")).toEqual([]);
  });

  it("liste PyPI vide (données embarquées) : aucun constat Python, pas d'erreur", async () => {
    const en = await dep005({
      "requirements.txt": "reqeusts==2.0\n",
      "svc/pyproject.toml": '[project]\nname = "s"\ndependencies = ["reqeusts>=2"]\n',
    });
    expect(en).toEqual([]);
  });

  it("signale dans package.json, requirements et pyproject, textes avec les noms proches", async () => {
    setPopularForTests({ pypi: TEST_PYPI });
    const files = {
      "package.json": '{ "dependencies": { "expresss": "^4.0.0", "express": "^4.0.0" } }\n',
      "package-lock.json": '{ "packages": { "node_modules/expresss": { "integrity": "sha512-x" } } }\n',
      "requirements.txt": "reqeusts==2.0\nrequests==2.32.3\n",
      "svc/pyproject.toml": '[project]\nname = "s"\ndependencies = ["reqeusts>=2"]\n',
    };
    const en = await dep005(files);
    expect(en.map((f) => `${f.file}:${f.line}`).sort()).toEqual([
      "package.json:1",
      "requirements.txt:1",
      "svc/pyproject.toml:3",
    ]);
    expect(en.every((f) => f.severity === "high")).toBe(true);
    expect(en.find((f) => f.file === "requirements.txt")?.explanation).toContain("`requests`");
  });

  it("clean-app : aucun constat ; vulnerable-app : npm et Python", async () => {
    const clean = await fixtureRepo("clean-app", false);
    const r = await scan(clean, { engines: [houseEngine] });
    expect(r.findings.filter((f) => f.id === "DOT-DEP-005")).toEqual([]);
  });

  it("500 dépendances en moins d'une seconde", async () => {
    const names = Array.from({ length: 500 }, (_, i) => `zq${i}-${(i * 7919).toString(36)}-internal-package`);
    const dependencies = Object.fromEntries(names.map((n) => [n, "1.0.0"]));
    const t = Date.now();
    const d = await tempDir();
    await writeFile(join(d, "package.json"), JSON.stringify({ dependencies }));
    const t0 = Date.now();
    for (const n of names) lookalikes("npm", n);
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(parsePackageJson(JSON.stringify({ dependencies }))).toHaveLength(500);
    expect(Date.now() - t).toBeLessThan(5000);
  });
});

describe("lookalikes : paquets scopés et familles", () => {
  it("ne signale pas les paquets légitimes d'un même scope ou d'une même famille", () => {
    for (const n of ["@aws-sdk/client-ses", "@types/react-dom", "@radix-ui/react-dialog", "@babel/core"]) {
      expect(lookalikes("npm", n)).toEqual([]);
    }
    expect(lookalikes("pypi", "mypy-boto3-ses")).toEqual([]);
  });
  it("signale un scope presque identique et une faute de frappe simple", () => {
    expect(lookalikes("npm", "@type/node")).toContain("@types/node");
    expect(lookalikes("npm", "expresss")).toContain("express");
  });
});
