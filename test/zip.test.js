'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scanPaths } = require('../lib/scanner');
const { zip } = require('../scripts/package-yilian');
const code = fs.readFileSync(path.join(__dirname, 'corpus/vuln/a01_php_sqli.php'));
function fixture(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sourceaudit-zip-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'source.zip');
  fs.writeFileSync(target, zip(files));
  return { root, target };
}
function method(target, index, value) {
  const data = fs.readFileSync(target);
  let offset = data.readUInt32LE(data.length - 6);
  for (let i = 0; i < index; i++) offset += 46 + data.readUInt16LE(offset + 28) + data.readUInt16LE(offset + 30) + data.readUInt16LE(offset + 32);
  data.writeUInt16LE(value, offset + 10);
  data.writeUInt16LE(value, data.readUInt32LE(offset + 42) + 8);
  fs.writeFileSync(target, data);
}
test('unsupported source entries make scan partial and preserve other results', async t => {
  const { target } = fixture(t, [['safe.php', '<?php echo "hello";'], ['vuln.php', code]]);
  method(target, 1, 12);
  const report = await scanPaths([target]);
  assert.equal(report.status, 'partial');
  assert.equal(report.files, 1);
  assert.equal(report.diagnostics.length, 1);
  assert.match(report.diagnostics[0].file, /vuln.php/);
  assert.match(report.diagnostics[0].message, /12/);
});
test('directory exclusions also exclude descendants in ZIP', async t => {
  const { root, target } = fixture(t, [['tests/a.php', code]]);
  const dir = path.join(root, 'tree');
  fs.mkdirSync(path.join(dir, 'tests'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'tests/a.php'), code);
  for (const exclude of ['tests', 'tests/']) {
    assert.equal((await scanPaths([dir], { exclude: [exclude] })).files, 0);
    assert.equal((await scanPaths([target], { exclude: [exclude] })).files, 0);
  }
});
test('excluded corrupt compressed entries are never decompressed', async t => {
  const { target } = fixture(t, [['good.php', code], ['tests/broken.php', 'invalid deflate']]);
  method(target, 1, 8);
  const report = await scanPaths([target], { exclude: ['tests'] });
  assert.equal(report.status, 'complete');
  assert.equal(report.files, 1);
  assert.equal(report.summary.critical, 1);
  assert.equal(report.skipped, 1);
});
