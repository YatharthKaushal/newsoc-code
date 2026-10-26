const { exec, execSync, execFile } = require('child_process');
const child_process = require('child_process');

function a(req, res) {
  // ruleid: newsoc.js.command-injection
  exec('ls ' + req.query.dir, (e, out) => res.send(out));
}
function b(req) {
  const dir = req.body.dir;
  // ruleid: newsoc.js.command-injection
  execSync(`tar -czf out.tgz ${dir}`);
}
function c(req) {
  // ruleid: newsoc.js.command-injection
  child_process.exec(req.params.cmd);
}
function ok1() {
  // ok: newsoc.js.command-injection
  exec('ls -la /var/log');
}
function ok2(req) {
  // ok: newsoc.js.command-injection
  execFile('ls', ['-la', req.query.dir]);
}
function ok3(req) {
  const fixed = 'status';
  // ok: newsoc.js.command-injection
  execSync('git ' + fixed);
}

function ok4(req) {
  // ok: newsoc.js.command-injection
  exec('git log --oneline', { cwd: req.body.dir });
}
