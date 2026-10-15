// Fixture dotation : webhook Stripe sans vérification de signature. Ne pas corriger.
import Stripe from "stripe";

export async function handle(req: Request, stripe: Stripe) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await stripe.customers.retrieve(event.data.object.customer);
  }
}
