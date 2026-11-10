function load(s) {
  try { return JSON.parse(s); } catch (e) { return null; }
}
