const ALLOW = new Set(['https://a.example.com', 'https://b.example.com']);
async function proxy(u) {
  const x = new URL(u);
  if (!ALLOW.has(x.origin)) throw new Error('bad origin');
  return (await fetch(x.toString())).text();
}
