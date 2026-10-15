import { en } from "./en.js";
import type { Messages } from "./types.js";

export type { Messages, Texts } from "./types.js";

/** The CLI is English-only: a single message catalog. */
export function messages(): Messages {
  return en;
}

/** Notice printed once (stderr, human mode only) when a legacy language setting is present. */
export const LANG_IGNORED_NOTICE = "Note: dotation is now English-only; the 'lang' setting is ignored.";
