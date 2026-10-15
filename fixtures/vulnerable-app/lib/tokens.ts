// Fixture dotation : cryptographie et jetons mal utilisés. Ne pas corriger.
import { createHash } from "node:crypto";
import jwt from "jsonwebtoken";

export const resetToken = Math.random().toString(36).slice(2);
export const hash = (password: string) => createHash("sha256").update(password).digest("hex");

export function whoIs(token: string) {
  return jwt.decode(token);
}

export const loose = { algorithms: ["none"] };
