import express from "express";
import router from "./scraper.ts";

const app = express();

// Global CORS — must be before all routes
app.use((_req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  next();
});

// Global OPTIONS preflight
app.options("/{*path}", (_req, res) => {
  res.sendStatus(204);
});

// Root — warm-up ping + Test button land here
app.get("/", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/api", router);

app.listen(3000, () => console.log("Running: http://localhost:3000"));
