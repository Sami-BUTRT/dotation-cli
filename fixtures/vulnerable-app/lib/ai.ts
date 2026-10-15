// Fixture dotation : appels à un modèle d'IA mal protégés. Ne pas corriger.
import { execSync } from "node:child_process";
import OpenAI from "openai";

const openai = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export async function answer(req: { body: { question: string } }) {
  const r = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "system", content: `Tu réponds sur le sujet ${req.body.question}` }],
  });
  const text = r.choices[0]?.message.content ?? "";
  execSync(text);
  return text;
}
