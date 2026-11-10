const fs = require('fs');
const path = require('path');
const ROOT = fs.realpathSync('/data');
function readFile(name) {
  const p = path.resolve(ROOT, name);
  if (p !== ROOT && !p.startsWith(ROOT + path.sep)) throw new Error('bad');
  return fs.readFileSync(p, 'utf8');
}
