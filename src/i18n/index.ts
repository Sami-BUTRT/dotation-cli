import { en } from "./en.js";
import { es } from "./es.js";
import { fr } from "./fr.js";
import { LANGS, type Lang, type Messages, type PartialMessages } from "./types.js";
import { zh } from "./zh.js";

export { LANGS, type Lang, type Messages, type Texts } from "./types.js";

function merge(base: Messages, over: PartialMessages): Messages {
  const out = { ...base } as Record<string, unknown>;
  for (const [k, v] of Object.entries(over)) {
    out[k] = { ...(base[k as keyof Messages] as object), ...(v as object) };
  }
  return out as unknown as Messages;
}

const CATALOG: Record<Lang, Messages> = { fr, en, es: merge(en, es), zh: merge(en, zh) };

export function messages(lang: Lang): Messages {
  return CATALOG[lang];
}

export function isLang(v: string): v is Lang {
  return (LANGS as readonly string[]).includes(v);
}

/**
 * Langue des messages : anglais, sauf choix explicite (DOTATION_LANG, --lang, « lang » dans .dotation.yml).
 * La locale système n'est plus suivie : le CLI est en anglais par défaut, partout.
 */
export function detectLang(env: NodeJS.ProcessEnv = process.env): Lang {
  const code = env.DOTATION_LANG?.trim().toLowerCase().slice(0, 2);
  if (code === "cn") return "zh";
  return code && isLang(code) ? code : "en";
}

/** Texte dans la langue voulue, sinon anglais, sinon la première langue disponible. */
export function pick<T>(byLang: Partial<Record<Lang, T>>, lang: Lang): T | undefined {
  return byLang[lang] ?? byLang.en ?? byLang.fr ?? Object.values(byLang)[0];
}
