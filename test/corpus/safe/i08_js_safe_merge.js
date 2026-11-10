function merge(target, src) {
  for (const k of Object.keys(src)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    target[k] = src[k];
  }
  return target;
}
