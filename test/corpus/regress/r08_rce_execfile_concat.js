const { execFile } = require('child_process');
execFile('sh', ['-c', 'ping ' + process.argv[2]]);
