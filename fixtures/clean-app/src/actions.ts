"use server";
// Fixture dotation : Server Action qui vérifie la session et la propriété.
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function deleteProject(id: string) {
  const session = await auth();
  if (!session) throw new Error("unauthorized");
  await prisma.project.deleteMany({ where: { id, ownerId: session.user.id } });
}
