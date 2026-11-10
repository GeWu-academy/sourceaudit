const path = require('path');
const fs = require('fs');
function read(req) {
  const p = path.resolve('/srv', req.query.f);
  return fs.readFileSync(req.query.f, 'utf8');
}
