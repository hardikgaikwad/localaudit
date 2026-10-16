// =====================================================================
// WARNING: INTENTIONALLY INSECURE DEMO CODE FOR LOCALAUDIT. DO NOT USE.
// =====================================================================
const express = require("express");
const cors = require("cors");
const https = require("https");
const { exec } = require("child_process");

const app = express();
app.use(cors());

app.get("/convert", (req, res) => {
  exec(`convert ${req.query.file} out.png`, (err, stdout) => res.send(stdout));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));
});

function newResetToken() {
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}

const agent = new https.Agent({ rejectUnauthorized: false });

app.get("/legacy", (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.send("ok");
});

app.listen(3000);
