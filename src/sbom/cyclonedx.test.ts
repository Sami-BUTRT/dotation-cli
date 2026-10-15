import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { tempDir } from "../test/helpers.js";
import {
  collectComponents,
  parseBunLock,
  parseGoMod,
  parseNpmLock,
  parsePnpmLock,
  parseRequirements,
  parseTomlPackages,
  parseYarnLock,
  purl,
  toCycloneDx,
} from "./cyclonedx.js";

const SHA512 = "sha512-AAEC"; // 3 octets : 000102

describe("lecture des lockfiles", () => {
  it("npm v3 (dépendances de dev, paquet lié, sous-dossier) et v1", () => {
    const v3 = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app" },
        "node_modules/@scope/a": { version: "1.0.0", integrity: SHA512 },
        "node_modules/b": { version: "2.0.0", dev: true },
        "node_modules/a/node_modules/c": { version: "3.0.0" },
        "packages/x": { version: "0.0.1", link: true },
      },
    });
    expect(parseNpmLock(v3, "package-lock.json").map((c) => `${c.name}@${c.version}${c.dev ? " dev" : ""}`)).toEqual([
      "@scope/a@1.0.0",
      "b@2.0.0 dev",
      "c@3.0.0",
    ]);
    expect(parseNpmLock(v3, "x")[0]?.hash).toEqual({ alg: "SHA-512", content: "000102" });
    const v1 = JSON.stringify({ dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } } });
    expect(parseNpmLock(v1, "x").map((c) => c.name)).toEqual(["a", "b"]);
  });

  it("pnpm v6 et v9, yarn v1 et Berry, bun", () => {
    const pnpm =
      "lockfileVersion: '9.0'\npackages:\n  '@scope/a@1.0.0':\n    resolution: {integrity: sha512-AAEC}\n  b@2.0.0(react@18.3.1):\n    resolution: {}\n  /c@3.0.0:\n    dev: true\n";
    expect(parsePnpmLock(pnpm, "x").map((c) => `${c.name}@${c.version}`)).toEqual([
      "@scope/a@1.0.0",
      "b@2.0.0",
      "c@3.0.0",
    ]);
    const yarn1 =
      '# yarn lockfile v1\n\n"@scope/a@^1.0.0", "@scope/a@^1.0.1":\n  version "1.0.2"\n  integrity sha512-AAEC\n\nb@^2.0.0:\n  version "2.1.0"\n';
    expect(parseYarnLock(yarn1, "x").map((c) => `${c.name}@${c.version}`)).toEqual(["@scope/a@1.0.2", "b@2.1.0"]);
    const berry =
      '__metadata:\n  version: 8\n\n"c@npm:^3.0.0":\n  version: 3.0.4\n  resolution: "c@npm:3.0.4"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n';
    expect(parseYarnLock(berry, "x").map((c) => `${c.name}@${c.version}`)).toEqual(["c@3.0.4"]);
    const bun = '{\n  "lockfileVersion": 1,\n  "packages": {\n    "a": ["a@1.2.3", "", {}, "sha512-AAEC"],\n  },\n}\n';
    expect(parseBunLock(bun, "x")[0]).toMatchObject({ name: "a", version: "1.2.3", hash: { content: "000102" } });
  });

  it("requirements figés, uv / poetry / Cargo, go.mod", () => {
    expect(
      parseRequirements("flask==3.0.3\nrequests>=2\nDjango[argon2]===5.1 ; python_version>'3'\n", "x").map(
        (c) => c.name,
      ),
    ).toEqual(["flask", "Django"]);
    const uv =
      '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "anyio"\nversion = "4.6.0"\nsource = { registry = "https://pypi.org/simple" }\n\n[package.metadata]\nx = 1\n';
    expect(parseTomlPackages(uv, "x", "pypi").map((c) => `${c.name}@${c.version}`)).toEqual(["anyio@4.6.0"]);
    const gomod =
      "module x\n\ngo 1.26\n\nrequire github.com/jackc/pgx/v5 v5.11.0\n\nrequire (\n\tgolang.org/x/sync v0.24.0 // indirect\n)\n";
    expect(parseGoMod(gomod, "x").map((c) => `${c.name}@${c.version}`)).toEqual([
      "golang.org/x/sync@v0.24.0",
      "github.com/jackc/pgx/v5@v5.11.0",
    ]);
  });

  it("purl", () => {
    expect(purl({ ecosystem: "npm", name: "@types/node", version: "22.0.0", source: "" })).toBe(
      "pkg:npm/%40types/node@22.0.0",
    );
    expect(purl({ ecosystem: "pypi", name: "Typing_Extensions", version: "4.12.2", source: "" })).toBe(
      "pkg:pypi/typing-extensions@4.12.2",
    );
    expect(purl({ ecosystem: "golang", name: "github.com/jackc/pgx/v5", version: "v5.11.0", source: "" })).toBe(
      "pkg:golang/github.com/jackc/pgx/v5@v5.11.0",
    );
  });
});

describe("SBOM du projet", () => {
  it("rassemble les lockfiles, sans doublon, en CycloneDX 1.6", async () => {
    const d = await tempDir();
    await writeFile(
      join(d, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" } } }),
    );
    await mkdir(join(d, "web"));
    await writeFile(
      join(d, "web", "pnpm-lock.yaml"),
      "packages:\n  a@1.0.0:\n    resolution: {integrity: sha512-AAEC}\n",
    );
    await writeFile(join(d, "requirements.txt"), "flask==3.0.3\n");
    const comps = await collectComponents(d);
    expect(comps.map(purl)).toEqual(["pkg:npm/a@1.0.0", "pkg:pypi/flask@3.0.3"]);
    expect(comps[0]?.hash?.content).toBe("000102");
    const bom = toCycloneDx("demo", comps, {
      serial: "00000000-0000-4000-8000-000000000000",
      timestamp: "2026-10-14T00:00:00Z",
    });
    expect(bom).toMatchObject({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      metadata: { component: { name: "demo" } },
    });
    expect(bom.components[1]).toEqual({
      type: "library",
      "bom-ref": "pkg:pypi/flask@3.0.3",
      name: "flask",
      version: "3.0.3",
      purl: "pkg:pypi/flask@3.0.3",
      properties: [{ name: "dotation:source", value: "requirements.txt" }],
    });
  });
});
