# Fixture dotation : API Python volontairement vulnérable. Ne pas corriger.
import sqlite3
import subprocess

import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

DEBUG = True

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])


@app.get("/items/{name}")
def item(name: str):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM items WHERE name = '{name}'")
    return cur.fetchall()


@app.get("/ping")
def ping(host: str):
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True).stdout


@app.post("/config")
def config(body: str):
    return yaml.load(body)
