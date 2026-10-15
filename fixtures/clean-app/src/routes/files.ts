// Fixture dotation : mêmes besoins, sans SSRF, redirection ouverte ni traversée de chemin.
import path from "node:path";
import type { Express } from "express";

const ALLOWED_HOSTS = new Set(["images.example.com"]);
const FILES = new Map([["guide", path.join(__dirname, "uploads", "guide.pdf")]]);

export default (app: Express) => {
  app.get("/preview", async (req, res) => {
    const target = new URL(String(req.query.url));
    if (!ALLOWED_HOSTS.has(target.hostname)) return res.status(400).end();
    const r = await fetch(target, { redirect: "error" });
    res.send(await r.text());
  });
  app.get("/login/done", (req, res) => {
    const next = String(req.query.next ?? "/");
    res.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");
  });
  app.get("/download", (req, res) => {
    const file = FILES.get(String(req.query.name));
    if (!file) return res.status(404).end();
    res.sendFile(file);
  });
};
