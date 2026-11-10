const cp = require('child_process');

function esc(s) {
  return String(s).replace(/[&<>"']/g, function (c) { return c; });
}

function go(req) {
  cp.exec('ls ' + req.query.dir);
}
