const { execFile } = require('child_process');
module.exports = (req, res) => {
  execFile('sh', ['-c', 'ping -c1 ' + req.query.host], (e, o) => res.send(o));
};
