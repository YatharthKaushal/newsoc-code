function a(req, res) {
  // ruleid: newsoc.js.open-redirect
  res.redirect(req.query.next);
}
function b(req, res) {
  // ruleid: newsoc.js.open-redirect
  res.redirect(302, req.body.returnTo);
}
function c(req, res) {
  const to = req.params.to;
  // ruleid: newsoc.js.open-redirect
  res.redirect('//' + to);
}
function ok1(req, res) {
  // ok: newsoc.js.open-redirect
  res.redirect('/dashboard');
}
function ok2(req, res) {
  // ok: newsoc.js.open-redirect
  res.redirect(isSafeRedirect(req.query.next) ? req.query.next : '/');
}
function ok3(res, user) {
  // ok: newsoc.js.open-redirect
  res.redirect(`/users/${user.id}`);
}

function ok4(req, res) {
  const id = req.params.id;
  // ok: newsoc.js.open-redirect
  res.redirect('/user/' + id);
}
function d(req, res) {
  // ruleid: newsoc.js.open-redirect
  res.redirect(req.query.next + '/home');
}
