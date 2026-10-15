"use client";
// Fixture dotation : réponse du modèle affichée comme du texte.
import { useChat } from "ai/react";

export default function Chat() {
  const { messages } = useChat();
  return messages.map((m) => <p key={m.id}>{m.content}</p>);
}
