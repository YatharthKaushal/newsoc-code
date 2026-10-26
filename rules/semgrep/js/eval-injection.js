const vm = require('vm');
function a(req, res) {
  // ruleid: newsoc.js.eval-injection
  res.send(String(eval(req.body.expr)));
}
function b(req) {
  const code = req.query.code;
  // ruleid: newsoc.js.eval-injection
  return new Function(code)();
}
function c(req) {
  // ruleid: newsoc.js.eval-injection
  vm.runInNewContext(req.params.script);
}
function ok1() {
  // ok: newsoc.js.eval-injection
  return eval('1 + 1');
}
function ok2(req) {
  // ok: newsoc.js.eval-injection
  return JSON.parse(req.body.json);
}
function ok3(expr) {
  // ok: newsoc.js.eval-injection
  return new Function('a', 'b', 'return a + b')(1, 2);
}
