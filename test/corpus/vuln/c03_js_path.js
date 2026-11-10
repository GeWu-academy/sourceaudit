const fs = require('fs');
function readFile(name) {
  return fs.readFileSync('/data/' + name, 'utf8');
}
