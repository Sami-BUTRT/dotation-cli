// Fixture dotation : erreurs et journaux. Ne pas corriger.
module.exports = (app, stripe) => {
  app.post("/pay", async (req, res) => {
    try {
      await stripe.charges.create(req.body.charge);
    } catch (e) {}
    console.log("clé", process.env.STRIPE_SECRET_KEY);
  });
  app.use((err, req, res, next) => {
    res.status(500).json({ error: err.stack });
  });
};
