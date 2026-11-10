const jwt = require('jsonwebtoken');

function verify(token, key) {
  return jwt.verify(token, key, { algorithms: ['none'] });
}
