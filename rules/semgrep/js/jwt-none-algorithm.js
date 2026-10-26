const jwt = require('jsonwebtoken');
function a(p, k) {
  // ruleid: newsoc.js.jwt-none-algorithm
  return jwt.sign(p, k, { algorithm: 'none' });
}
function b(t, k) {
  // ruleid: newsoc.js.jwt-none-algorithm
  return jwt.verify(t, k, { algorithms: ['HS256', 'none'] });
}
function c(t, k) {
  // ruleid: newsoc.js.jwt-none-algorithm
  return jwt.verify(t, k, { algorithm: 'none' });
}
function ok1(p, k) {
  // ok: newsoc.js.jwt-none-algorithm
  return jwt.sign(p, k, { algorithm: 'HS256' });
}
function ok2(t, k) {
  // ok: newsoc.js.jwt-none-algorithm
  return jwt.verify(t, k, { algorithms: ['RS256'] });
}
function ok3(t, k) {
  // ok: newsoc.js.jwt-none-algorithm
  return jwt.verify(t, k);
}
