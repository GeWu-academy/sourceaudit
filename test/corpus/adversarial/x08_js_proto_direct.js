function merge(target, src) {
  for (const k in src) {
    target[k] = src[k];
  }
  return target;
}
module.exports = merge;
