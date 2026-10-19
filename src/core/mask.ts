// Masquage des secrets. Règle : la valeur complète d'un secret ne sort jamais d'un moteur.

// Préfixes de type connus, montrés pour reconnaître la clé ; un secret « générique » ne montre que sa fin.
const PREFIX =
  /^(?:[sr]k_(?:live|test)_|pk_(?:live|test)_|gh[pousr]_|github_pat_|sk-ant-|sk-proj-|sk-svcacct-|xox[baprs]-|SG\.|glpat-|npm_|AIza)/;
const MAX_SNIPPET = 160;

/**
 * « sk_live_51Habcd…wxyz » -> « sk_live_****wxyz ».
 * Garde le préfixe de type (utile pour reconnaître la clé) et 4 caractères de fin, jamais plus d'un tiers du secret.
 */
export function maskSecret(secret: string): string {
  const s = secret.trim();
  if (s.length < 12) return "****";
  const prefix = PREFIX.exec(s)?.[0] ?? "";
  const tail = s.length >= 20 ? s.slice(-4) : "";
  if (prefix.length + tail.length > s.length / 3 + 4) return `****${tail}`;
  return `${prefix}****${tail}`;
}

/** Remplace chaque occurrence des secrets dans une ligne par leur forme masquée, puis tronque. */
export function redactLine(line: string, secrets: readonly string[]): string {
  let out = line;
  for (const s of secrets) {
    if (s.length > 0) out = out.split(s).join(maskSecret(s));
  }
  return truncate(out.trim());
}

/**
 * Seuls noms lisibles après le séparateur : `process.env.X` et `import.meta.env.X`, et seulement placés comme dans du
 * code (après une espace ou « ( { , ! ? | & »), jamais en début de valeur. Pas d'autre exception : chaque tolérance
 * de lisibilité essayée (clés, NOMS_EN_MAJUSCULES, `secrets.X`) laissait passer une partie d'une valeur.
 */
const SAFE_REF = /(?<=[\s({,!?|&])(?:process\.env|import\.meta\.env)\.[A-Za-z_][A-Za-z0-9_]*/g;
/** Nom de variable d'environnement (MAJUSCULES_AVEC_SOULIGNÉ) : jamais masqué comme un jeton. */
const ENV_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
/** Premier séparateur d'affectation : « = » (ni « == », « => », « != », « <= », « >= ») ou « : ». */
const FIRST_SEP = /(?<![=!<>])=(?![=>])|:/;
/** Jeton long qui mélange lettres et chiffres (clé, jeton, hachage) : masqué même hors affectation. */
const TOKEN = /[A-Za-z0-9+/_.-]{20,}/g;

/** Remplace tout contenu non blanc d'un segment par « **** », en gardant ses espaces de bord. */
function maskRun(seg: string): string {
  if (seg.trim() === "") return seg;
  const lead = /^\s*/.exec(seg)?.[0] ?? "";
  const trail = /\s*$/.exec(seg)?.[0] ?? "";
  return `${lead}****${trail}`;
}

/** Ne garde que les noms sûrs (références, clés) ; tout le reste devient « **** ». */
function keepSafeRefs(s: string): string {
  let out = "";
  let last = 0;
  for (const m of s.matchAll(SAFE_REF)) {
    out += maskRun(s.slice(last, m.index)) + m[0];
    last = m.index + m[0].length;
  }
  return out + maskRun(s.slice(last));
}

/**
 * Masquage d'une ligne de règle « secret », par refus par défaut : on ne cherche pas à reconnaître la valeur
 * (il resterait toujours un cas oublié), on masque tout ce qui la suit. Après le premier « = » ou « : », seules les
 * références `process.env.X` / `import.meta.env.X` restent lisibles ; sans séparateur, tout est masqué à partir
 * du premier guillemet, et les jetons longs lettres + chiffres le sont partout. Le nom et la clé restent visibles
 * pour localiser le problème (fichier et ligne sont donnés à part).
 */
/** Avant le premier séparateur ou guillemet : un mot-clé éventuel puis UN mot (le nom) ; le reste est masqué. */
const HEAD = /^(\s*(?:(?:setenv|set|export|declare|readonly|local|typeset|const|let|var)\s+)?\S+)([\s\S]*)$/;

function keepHead(s: string): string {
  const m = HEAD.exec(s);
  if (!m) return s;
  const rest = m[2] ?? "";
  return rest.trim() === "" ? s : (m[1] as string) + maskRun(rest);
}

export function redactSecretLine(raw: string, secrets: readonly string[] = []): string {
  // Masquage avant toute troncature : une valeur coupée en deux ne serait plus reconnue.
  let line = raw.replace(/\r$/, "");
  for (const x of secrets) if (x.length > 0) line = line.split(x).join(maskSecret(x));
  // Coupure au premier séparateur (« = » ou « : ») ou au premier guillemet, selon ce qui vient d'abord.
  const sep = FIRST_SEP.exec(line);
  const quote = line.search(/["'`]/);
  const sepAt = sep ? sep.index : -1;
  let out: string;
  if (sepAt >= 0 && (quote < 0 || sepAt < quote)) {
    const len = (sep as RegExpExecArray)[0].length;
    out = keepHead(line.slice(0, sepAt)) + line.slice(sepAt, sepAt + len) + keepSafeRefs(line.slice(sepAt + len));
  } else if (quote >= 0) {
    out = keepHead(line.slice(0, quote)) + keepSafeRefs(line.slice(quote));
  } else {
    // Ni séparateur ni guillemet (« NOM valeur », « setenv NOM valeur ») : mot-clé éventuel et premier mot seulement.
    out = keepHead(line);
  }
  out = out.replace(TOKEN, (t) =>
    /\d/.test(t) && /[A-Za-z]/.test(t) && !t.includes("****") && !ENV_NAME.test(t) && !/^(?:process|import)\./.test(t)
      ? "****"
      : t,
  );
  return truncate(out.trim());
}

export function truncate(s: string, max = MAX_SNIPPET): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}
