// Fixture dotation : aléa cryptographique, hachage lent, jeton vérifié.
import { randomBytes } from "node:crypto";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

export const resetToken = randomBytes(32).toString("base64url");
export const hash = (password: string) => argon2.hash(password);

export function whoIs(token: string) {
  return jwt.verify(token, process.env.JWT_SECRET ?? "", { algorithms: ["HS256"] });
}
