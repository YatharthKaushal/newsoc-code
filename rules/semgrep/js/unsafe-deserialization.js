const serialize = require('node-serialize');
function a(req) {
  // ruleid: newsoc.js.unsafe-deserialization
  return serialize.unserialize(req.body.data);
}
function b(req) {
  const raw = req.cookies.profile;
  // ruleid: newsoc.js.unsafe-deserialization
  return unserialize(raw);
}
function c(req) {
  // ruleid: newsoc.js.unsafe-deserialization
  return serialize.unserialize(Buffer.from(req.query.p, 'base64').toString());
}
function ok1(req) {
  // ok: newsoc.js.unsafe-deserialization
  return JSON.parse(req.body.data);
}
function ok2(stored) {
  // ok: newsoc.js.unsafe-deserialization
  return serialize.unserialize(stored);
}
function ok3() {
  // ok: newsoc.js.unsafe-deserialization
  return serialize.serialize({ a: 1 });
}
