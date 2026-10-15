// Fixture dotation : route qui écrit en base sans vérifier l'appelant. Ne pas corriger.
import { prisma } from "@/lib/prisma";

export async function POST(req: Request) {
  const body = await req.json();
  const order = await prisma.order.create({ data: { item: body.item, qty: body.qty } });
  return Response.json(order);
}
