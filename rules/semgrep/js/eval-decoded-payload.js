// SYNTHETIC test file for newsoc.js.eval-decoded-payload. The blobs below decode to harmless
// arithmetic ("1+1"); Semgrep parses this file, nothing runs it.
const vm = require('vm');

function a() {
  // ruleid: newsoc.js.eval-decoded-payload
  eval(atob('MSsx'));
}

function b(chunks) {
  // the split form: decode in one statement, run in another
  const joined = chunks.join('');
  const decoded = atob(joined);
  // ruleid: newsoc.js.eval-decoded-payload
  eval(decoded);
}

function c(blob) {
  // ruleid: newsoc.js.eval-decoded-payload
  new Function(Buffer.from(blob, 'base64').toString('utf8'))();
}

function d(hex) {
  // ruleid: newsoc.js.eval-decoded-payload
  vm.runInThisContext(Buffer.from(hex, 'hex').toString());
}

function e(blob) {
  // ruleid: newsoc.js.eval-decoded-payload
  (0, eval)(window.atob(blob));
}

function f(blob, filename) {
  // ruleid: newsoc.js.eval-decoded-payload
  module._compile(atob(blob), filename);
}

function g(blob) {
  const text = Buffer.from(blob, 'base64').toString('utf8');
  // ruleid: newsoc.js.eval-decoded-payload
  return Function(text)();
}

function h(blob) {
  // ruleid: newsoc.js.eval-decoded-payload
  return new vm.Script(atob(blob)).runInThisContext();
}

function ok1(token) {
  // ok: newsoc.js.eval-decoded-payload
  return JSON.parse(atob(token.split('.')[1]));
}

function ok2(blob, path) {
  const bytes = Buffer.from(blob, 'base64');
  // ok: newsoc.js.eval-decoded-payload
  require('fs').writeFileSync(path, bytes);
}

function ok3() {
  // ok: newsoc.js.eval-decoded-payload
  return new Function('a', 'b', 'return a + b')(1, 2);
}

function ok4(blob) {
  const text = atob(blob);
  // ok: newsoc.js.eval-decoded-payload
  console.log(text);
}

function ok5() {
  // ok: newsoc.js.eval-decoded-payload
  return eval('1 + 1');
}

function ok6(code) {
  // ok: newsoc.js.eval-decoded-payload
  return eval(Buffer.from(code, 'utf8').toString());
}

function ok7(blob) {
  const decoded = atob(blob);
  // ok: newsoc.js.eval-decoded-payload
  return decoded.length > 0 ? new Function('return 1')() : 0;
}

function ok8(source, blob) {
  // ok: newsoc.js.eval-decoded-payload
  return new vm.Script(source, { cachedData: Buffer.from(blob, 'base64') });
}
