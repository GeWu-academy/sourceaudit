const { exec } = require('child_process');
function ping(host) {
  exec('ping -c 1 ' + host, (e, out) => console.log(out));
}
