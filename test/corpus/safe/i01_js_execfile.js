const { execFile } = require('child_process');
function ping(host) {
  execFile('ping', ['-c', '1', host], (e, out) => console.log(out));
}
