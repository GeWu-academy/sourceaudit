const path = require('path');
const fs = require('fs');

function read(req, res) {
  const p = path.join(__dirname, req.query.f);
  res.send(fs.readFileSync(p));
}
