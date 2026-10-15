"use client";
// Fixture dotation : réponse du modèle insérée comme HTML. Ne pas corriger.
import { useChat } from "ai/react";

export default function Chat() {
  const { messages } = useChat();
  return messages.map((m) => <div key={m.id} dangerouslySetInnerHTML={{ __html: m.content }} />);
}
