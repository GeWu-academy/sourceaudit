const express = require('express');
const app = express();
app.get('/p', async (req, res) => {
  const u = new URL(req.query.u);
  const r = await fetch(req.query.u);
  res.send(await r.text());
});
