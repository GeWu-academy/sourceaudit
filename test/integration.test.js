'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const bin = path.resolve(__dirname, '../bin/sourceaudit.js');
const sample = path.join(__dirname, 'corpus/vuln/a01_php_sqli.php');

function cli(args, cwd) {
  return spawnSync(process.execPath, [bin, ...args], { cwd, encoding: 'utf8' });
}
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sourceaudit-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const dir of ['one', 'two']) {
    fs.mkdirSync(path.join(root, dir));
    fs.copyFileSync(sample, path.join(root, dir, 'same.php'));
  }
  return root;
}
function report(args, cwd) {
  const result = cli(['-f', 'json', '--fail-on', 'none', ...args], cwd);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('overlapping directory and file targets are scanned once', t => {
  const root = fixture(t);
  const r = report([root, path.join(root, 'one/same.php'), root]);
  assert.equal(r.files, 2);
  assert.equal(r.summary.total, 2);
});
test('same-name files from separate roots retain distinct locations', t => {
  const root = fixture(t);
  const r = report([path.join(root, 'one'), path.join(root, 'two')]);
  assert.equal(new Set(r.findings.map(f => f.file)).size, 2);
  assert.equal(r.findings[0].absolute_path, path.join(root, 'one/same.php'));
});
test('globstar includes root files and single files obey exclusions', t => {
  const root = fixture(t);
  assert.equal(report([root, '--exclude', '**/same.php']).files, 0);
  assert.equal(report([path.join(root, 'one'), '--exclude', '**/same.php']).files, 0);
  assert.equal(report([sample, '--exclude', '*.php']).files, 0);
});
test('question mark does not match a directory separator', t => {
  const root = fixture(t);
  assert.equal(report([root, '--exclude', 'one?same.php']).files, 2);
});
test('invalid language is reported as an argument error', () => {
  const r = cli([sample, '--lang', 'pyhton']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /lang|语言/);
});
test('text findings include actionable fixes', () => {
  const r = cli([sample, '--no-color']);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /修复.*预处理/);
});
test('empty scan is distinguished from a clean scan', t => {
  const root = fixture(t);
  const r = cli([root, '--exclude', '**/*.php']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /未扫描到/);
  assert.doesNotMatch(r.stdout, /✓ 未发现问题/);
});
test('double dash allows a target beginning with a dash', t => {
  const root = fixture(t);
  fs.copyFileSync(sample, path.join(root, '-code.php'));
  assert.equal(report(['--', '-code.php'], root).files, 1);
});
test('partial scans retain findings and exit 2 even with fail-on none and quiet', t => {
  const root = fixture(t);
  const result = cli([sample, path.join(root, 'missing.php'), '-f', 'json', '-q', '--fail-on', 'none']);
  assert.equal(result.status, 2);
  const r = JSON.parse(result.stdout);
  assert.equal(r.status, 'partial');
  assert.equal(r.files, 1);
  assert.equal(r.summary.critical, 1);
  assert.match(result.stderr, /missing.php/);
});
test('reports can be saved and severity thresholds retain their CLI meaning', t => {
  const root = fixture(t);
  const out = path.join(root, 'audit.txt');
  const result = cli([sample, '--out', out, '--no-color', '--fail-on', 'none']);
  assert.equal(result.status, 0);
  assert.equal(fs.readFileSync(out, 'utf8'), result.stdout);
  assert.doesNotMatch(result.stdout, /\x1b\[/);
  assert.equal(cli([sample, '--fail-on', 'critical']).status, 1);
});
test('CLI SIGINT returns a cancelled report and exit code 130', t => {
  const root = fixture(t), archive = path.join(root, 'many.zip');
  const { zip } = require('../scripts/package-yilian');
  const code = fs.readFileSync(sample);
  fs.writeFileSync(archive, zip(Array.from({ length: 300 }, (_, i) => [`f${i}.php`, code])));
  const script = "process.argv = [process.execPath, process.argv[1], process.argv[2], '-f', 'json']; setTimeout(() => process.emit('SIGINT'), 60); require(process.argv[1]);";
  const result = spawnSync(process.execPath, ['-e', script, bin, archive], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 130, result.stderr);
  const r = JSON.parse(result.stdout);
  assert.equal(r.status, 'cancelled');
  assert.ok(r.files < 300);
  assert.match(result.stderr, /已取消/);
});
