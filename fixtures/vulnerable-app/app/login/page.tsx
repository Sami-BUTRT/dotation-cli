"use client";
// Fixture dotation : jeton de session dans localStorage. Ne pas corriger.
export default function Login() {
  const onLogin = (t: string) => localStorage.setItem("auth_token", t);
  return <button type="button" onClick={() => onLogin("x")}>Connexion</button>;
}
