function a(req, res) {
  // ruleid: newsoc.js.xss-reflected
  res.send('<h1>Hello ' + req.query.name + '</h1>');
}
function b(req, res) {
  // ruleid: newsoc.js.xss-reflected
  res.send(req.body.comment);
}
function c(req, res) {
  const q = req.params.q;
  // ruleid: newsoc.js.xss-reflected
  res.end(`<p>${q}</p>`);
}
function ok1(req, res) {
  // ok: newsoc.js.xss-reflected
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
}
function ok2(req, res) {
  // ok: newsoc.js.xss-reflected
  res.json({ name: req.query.name });
}
function ok3(req, res) {
  // ok: newsoc.js.xss-reflected
  res.send('<h1>Static</h1>');
}

function ok4(req, res) {
  // ok: newsoc.js.xss-reflected
  res.send({ user: req.query.user });
}
function ok5(req, reply) {
  // ok: newsoc.js.xss-reflected
  reply.send(req.body);
}
function ok6(req, res, users) {
  // ok: newsoc.js.xss-reflected
  res.send(users[req.params.id]);
}
function ok7(req, res) {
  const from = parseInt(req.params.from, 10);
  // ok: newsoc.js.xss-reflected
  res.send('page ' + from);
}
function ok8(req, res, result) {
  // ok: newsoc.js.xss-reflected
  res.end(JSON.stringify(result));
}
function d(req, res) {
  // ruleid: newsoc.js.xss-reflected
  res.status(404).send('Not found: ' + req.originalUrl);
}
function e(req, res) {
  // ruleid: newsoc.js.xss-reflected
  res.send(`<p>${req.url}</p>`);
}
