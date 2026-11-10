const serialize = require('node-serialize');
function load(s) {
  return serialize.unserialize(s);
}
