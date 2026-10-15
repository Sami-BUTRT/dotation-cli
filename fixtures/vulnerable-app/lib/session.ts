// Fixture dotation : cookie de session sans protection. Ne pas corriger.
import { cookies } from "next/headers";

export async function login(token: string) {
  (await cookies()).set("session", token, { httpOnly: false, path: "/" });
}
