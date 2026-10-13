// Globs minimalistes (sans dépendance) : **, *, ?, {a,b}. Chemins relatifs avec « / ».
// Un motif sans « / » s'applique au nom du fichier, quel que soit son dossier (comme .gitignore).

const cache = new Map<string, RegExp>();

export function globToRegExp(glob: string): RegExp {
  const hit = cache.get(glob);
  if (hit) return hit;
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // « **/ » : zéro ou plusieurs dossiers ; « ** » final : tout.
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (c === "{") {
      const end = glob.indexOf("}", i);
      if (end === -1) re += "\\{";
      else {
        re += `(?:${glob
          .slice(i + 1, end)
          .split(",")
          .map((p) => p.replace(/[.+^$()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*"))
          .join("|")})`;
        i = end;
      }
    } else re += c.replace(/[.+^$()|[\]\\]/g, "\\$&");
  }
  const rx = new RegExp(`^${re}$`);
  cache.set(glob, rx);
  return rx;
}

export function matchGlob(path: string, glob: string): boolean {
  const target = glob.includes("/") ? path : (path.split("/").pop() ?? path);
  return globToRegExp(glob).test(target);
}

export function matchAny(path: string, globs: readonly string[]): boolean {
  return globs.some((g) => matchGlob(path, g));
}
