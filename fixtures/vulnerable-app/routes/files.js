// Fixture dotation : SSRF, redirection ouverte, traversée de chemin. Ne pas corriger.
const fs = require("fs");
const path = require("path");

module.exports = (app) => {
  app.get("/preview", async (req, res) => {
    const r = await fetch(req.query.url);
    res.send(await r.text());
  });
  app.get("/login/done", (req, res) => {
    res.redirect(req.query.next);
  });
  app.get("/download", (req, res) => {
    res.sendFile(path.join(__dirname, "uploads", req.query.name));
  });
};
