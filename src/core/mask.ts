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

export function truncate(s: string, max = MAX_SNIPPET): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}
