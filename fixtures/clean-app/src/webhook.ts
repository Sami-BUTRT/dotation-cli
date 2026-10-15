// Fixture dotation : webhook Stripe vérifié.
import Stripe from "stripe";

export async function handle(req: Request, stripe: Stripe) {
  const event = stripe.webhooks.constructEvent(
    await req.text(),
    req.headers.get("stripe-signature") ?? "",
    process.env.STRIPE_WEBHOOK_SECRET ?? "",
  );
  if (event.type === "checkout.session.completed") {
    await stripe.customers.retrieve(String(event.data.object.customer));
  }
}
