// Fixture dotation : même route, avec vérification de session.
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  const body = await req.json();
  const order = await prisma.order.create({ data: { item: body.item, qty: body.qty, userId: session.user.id } });
  return Response.json(order);
}
