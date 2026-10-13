// Fixture dotation : API Express volontairement vulnérable. Ne pas corriger.
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const https = require("https");
const { Pool } = require("pg");

const app = express();
app.use(cors());

const db = new Pool({ user: "app", password: "FakeFixtureDbPass99" });
const agent = new https.Agent({ rejectUnauthorized: false });

app.get("/users/:id", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

app.post("/login", (req, res) => {
  const token = jwt.sign({ sub: req.body.user }, "fake-fixture-jwt-secret");
  res.json({ token });
});

app.get("/convert", (req, res) => {
  exec(`convert ${req.query.file} out.png`, () => res.send("ok"));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));
});

app.listen(3000, () => console.log("listening", agent));
