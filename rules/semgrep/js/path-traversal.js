const fs = require('fs');
const path = require('path');
function a(req, res) {
  // ruleid: newsoc.js.path-traversal
  fs.readFile(req.query.file, 'utf8', cb);
}
function b(req, res) {
  const p = path.join('/uploads', req.params.name);
  // ruleid: newsoc.js.path-traversal
  res.sendFile(p);
}
function c(req) {
  // ruleid: newsoc.js.path-traversal
  return fs.createReadStream('./data/' + req.body.name);
}
function ok1(req, res) {
  // ok: newsoc.js.path-traversal
  fs.readFile(path.join('/uploads', path.basename(req.query.file)), cb);
}
function ok2() {
  // ok: newsoc.js.path-traversal
  fs.readFileSync('/etc/app/config.json');
}
function ok3(req, res) {
  // ok: newsoc.js.path-traversal
  res.sendFile('/static/index.html');
}

function ok4(req) {
  // ok: newsoc.js.path-traversal
  fs.writeFileSync('/var/log/app.log', req.body.line);
}

function ok5(req, res) {
  // ok: newsoc.js.path-traversal
  res.download(req.params.file, { root: FILES_DIR }, cb);
}
function ok6(req, res) {
  // ok: newsoc.js.path-traversal
  res.sendFile(req.params.page, { root: '/srv/pages' });
}
function d(req, res) {
  // ruleid: newsoc.js.path-traversal
  fs.readFile('./public' + req.url, cb);
}
