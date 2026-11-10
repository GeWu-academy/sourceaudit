const axios = require('axios');
async function proxy(u) {
  const r = await axios.get(u);
  return r.data;
}
