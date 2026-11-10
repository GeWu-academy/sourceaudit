const { exec } = require('child_process');
exec('tar -czf /tmp/a.tgz ' + process.argv[2]);
