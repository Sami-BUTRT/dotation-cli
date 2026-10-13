// Où le CLI se télécharge : chaque version est une release GitHub (étiquette cli-vX.Y.Z) qui porte le paquet npm.
// « npm install -g <url> » l'installe en une commande, sans registre npm à nous ni script à exécuter.
import { VERSION } from "./version.js";

export const REPO = "Sami-BUTRT/dotation-cli";
export const TAG_PREFIX = "cli-v";

/** Paquet d'une version précise, ou de la dernière version publiée. */
export function tarballUrl(version?: string): string {
  return version
    ? `https://github.com/${REPO}/releases/download/${TAG_PREFIX}${version}/dotation-${version}.tgz`
    : `https://github.com/${REPO}/releases/latest/download/dotation.tgz`;
}

export function installCommand(version?: string): string {
  return `npm install -g ${tarballUrl(version)}`;
}

/** Version installée, figée : ce qu'on écrit dans les fichiers générés (CI, configuration MCP). */
export const PINNED_TARBALL = tarballUrl(VERSION);
