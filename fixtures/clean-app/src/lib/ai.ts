// Fixture dotation : appel au modèle depuis le serveur, prompt fixe, sortie bornée, jamais exécutée.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const SYSTEM = "Tu réponds aux questions sur la sécurité, en trois phrases au plus.";

export async function answer(question: string) {
  const r = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    max_tokens: 300,
    messages: [
      { role: "system", content: SYSTEM },
      { role: "user", content: question.slice(0, 2000) },
    ],
  });
  return r.choices[0]?.message.content ?? "";
}
