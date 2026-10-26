const axios = require('axios');
async function a(req) {
  // ruleid: newsoc.js.ssrf
  return axios.get(req.query.url);
}
async function b(req) {
  const target = req.body.callback;
  // ruleid: newsoc.js.ssrf
  return fetch(target, { method: 'POST' });
}
function c(req) {
  // ruleid: newsoc.js.ssrf
  https.get('https://' + req.params.host + '/status', cb);
}
async function ok1() {
  // ok: newsoc.js.ssrf
  return axios.get('https://api.example.com/v1/items');
}
async function ok2(req) {
  // ok: newsoc.js.ssrf
  return axios.get('https://api.example.com/items', { params: { q: req.query.q } });
}
async function ok3(id) {
  // ok: newsoc.js.ssrf
  return fetch(`https://api.example.com/items/${id}`);
}

async function ok4(req) {
  // ok: newsoc.js.ssrf
  return axios.post('https://api.example.com/hooks', req.body);
}
