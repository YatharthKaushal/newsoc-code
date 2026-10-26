function a(req, users) {
  // ruleid: newsoc.js.nosql-injection
  return users.findOne(req.body);
}
function b(req, users) {
  // ruleid: newsoc.js.nosql-injection
  return users.find({ username: req.body.username, password: req.body.password });
}
function c(req, users) {
  // ruleid: newsoc.js.nosql-injection
  return users.deleteOne({ _id: req.params.id });
}
function ok1(req, users) {
  // ok: newsoc.js.nosql-injection
  return users.findOne({ username: String(req.body.username) });
}
function ok2(users) {
  // ok: newsoc.js.nosql-injection
  return users.find({ active: true });
}
function ok3(req, users) {
  // ok: newsoc.js.nosql-injection
  return users.findOne({ username: `${req.body.username}` });
}

function ok4(req, User) {
  // ok: newsoc.js.nosql-injection
  return User.findOne({ where: { id: req.params.id } });
}
function ok5(req, Product) {
  // ok: newsoc.js.nosql-injection
  return Product.find({ where: { name: req.query.q }, limit: 10 });
}
function d(req, users) {
  // ruleid: newsoc.js.nosql-injection
  return users.updateOne({ token: req.cookies.token }, { $set: { used: true } });
}
