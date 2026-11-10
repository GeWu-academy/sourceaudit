const broad = /\/api\/[a-z0-9_/-]+/g;
function find(text) {
  const out = [];
  let m;
  while ((m = broad.exec(text)) !== null) { out.push(m[0]); }
  return out;
}
