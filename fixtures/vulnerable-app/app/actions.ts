"use server";
// Fixture dotation : Server Action qui écrit sans contrôle de l'appelant. Ne pas corriger.
import { prisma } from "@/lib/prisma";

export async function deleteProject(id: string) {
  await prisma.project.delete({ where: { id } });
}
