function a(el, userHtml) {
  // ruleid: newsoc.js.inner-html-assignment
  el.innerHTML = userHtml;
}
function b(msg) {
  // ruleid: newsoc.js.inner-html-assignment
  document.write(msg);
}
function c(el, name) {
  // ruleid: newsoc.js.inner-html-assignment
  el.innerHTML = '<b>' + name + '</b>';
}
function ok1(el) {
  // ok: newsoc.js.inner-html-assignment
  el.innerHTML = '';
}
function ok2(el, html) {
  // ok: newsoc.js.inner-html-assignment
  el.innerHTML = DOMPurify.sanitize(html);
}
function ok3(el, text) {
  // ok: newsoc.js.inner-html-assignment
  el.textContent = text;
}
