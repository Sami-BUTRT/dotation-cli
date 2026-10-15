// Neutralise les caractères de contrôle (ESC, BEL, retour chariot…) avant d'écrire dans le terminal : un dépôt
// analysé, ou la réponse de l'IA, pourrait sinon effacer des lignes, changer le titre ou réécrire l'affichage.
// Chaque caractère devient visible sous la forme \xNN.

// biome-ignore lint/suspicious/noControlCharactersInRegex: c'est précisément ce qu'on neutralise
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g;
// biome-ignore lint/suspicious/noControlCharactersInRegex: idem, en gardant retours à la ligne et tabulations
const CONTROL_MULTILINE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g;

const visible = (ch: string) =>
  `\\${ch.charCodeAt(0) > 0xff ? "u" : "x"}${ch
    .charCodeAt(0)
    .toString(16)
    .padStart(ch.charCodeAt(0) > 0xff ? 4 : 2, "0")}`;

/** Texte sur une ligne (chemin, extrait, titre). */
export function safeLine(s: string): string {
  return s.replace(CONTROL, visible);
}

/** Texte libre sur plusieurs lignes (réponse de l'IA) : \n et \t sont conservés. */
export function safeText(s: string): string {
  return s.replace(CONTROL_MULTILINE, visible);
}
