function a(req, db) {
  const sql = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  // ruleid: newsoc.js.sql-injection
  db.query(sql, (e, rows) => rows);
}
function b(req, knex) {
  // ruleid: newsoc.js.sql-injection
  return knex.raw(`SELECT * FROM t WHERE name = '${req.body.name}'`);
}
function c(req, conn) {
  // ruleid: newsoc.js.sql-injection
  conn.execute('DELETE FROM t WHERE id=' + req.params.id);
}
function ok1(req, db) {
  // ok: newsoc.js.sql-injection
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);
}
function ok2(req, db) {
  // ok: newsoc.js.sql-injection
  db.query('SELECT * FROM users WHERE id = $1', [req.body.id], cb);
}
function ok3(db) {
  // ok: newsoc.js.sql-injection
  db.query('SELECT 1');
}

function ok4(req, db) {
  const id = parseInt(req.query.id, 10);
  // ok: newsoc.js.sql-injection
  db.query('SELECT * FROM users WHERE id = ' + id, cb);
}
