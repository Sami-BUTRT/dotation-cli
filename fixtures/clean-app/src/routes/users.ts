// Fixture dotation : champs choisis un par un.
import type { Express } from "express";

export default (app: Express, User: { create(d: { name: string; bio: string }): Promise<unknown> }) => {
  app.post("/users", async (req, res) => {
    const user = await User.create({ name: String(req.body.name), bio: String(req.body.bio) });
    res.json(user);
  });
};
