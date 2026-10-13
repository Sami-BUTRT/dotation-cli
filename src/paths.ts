import { fileURLToPath } from "node:url";

/** Chemin d'un dossier livré avec le paquet (rules/, engines/) ; marche depuis src/ (tests) comme depuis dist/. */
export function packagePath(rel: string): string {
  return fileURLToPath(new URL(`../${rel}`, import.meta.url));
}
