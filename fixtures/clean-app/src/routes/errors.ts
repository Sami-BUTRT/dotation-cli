// Fixture dotation : erreurs traitées et journalisées sans secret.
import type { Express, NextFunction, Request, Response } from "express";

export default (app: Express, pay: (amount: number) => Promise<void>, log: (msg: string, meta: object) => void) => {
  app.post("/pay", async (req, res) => {
    try {
      await pay(Number(req.body.amount));
    } catch (e) {
      log("paiement refusé", { error: String(e) });
      return res.status(402).json({ error: "paiement refusé" });
    }
    console.log("paiement ok, mode :", process.env.NODE_ENV);
    res.status(204).end();
  });
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    log("erreur interne", { error: err.message });
    res.status(500).json({ error: "erreur interne" });
  });
};
