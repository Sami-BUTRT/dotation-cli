// Fixture dotation : la même API, corrigée.
import { execFile } from "node:child_process";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import { Pool } from "pg";

const app = express();
app.use(cors({ origin: ["https://www.example.com"] }));

const db = new Pool({ user: "app", password: process.env.DATABASE_PASSWORD });
const jwtSecret = process.env.JWT_SECRET ?? "";

app.get("/users/:id", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(rows);
});

app.post("/login", (req, res) => {
  res.json({ token: jwt.sign({ sub: req.body.user }, jwtSecret) });
});

app.get("/convert", (req, res) => {
  execFile("convert", [String(req.query.file), "out.png"], () => res.send("ok"));
});

app.listen(3000);
