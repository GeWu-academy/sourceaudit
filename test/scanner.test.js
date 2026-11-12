'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadEngine } = require('../lib/engine');
const { scanPaths, scanCode } = require('../lib/scanner');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { zip } = require('../scripts/package-yilian');

test('compressed ZIP uses Node zlib independently of browser DecompressionStream', async () => {
  const original = global.DecompressionStream;
  global.DecompressionStream = undefined;
  try {
    const bytes = Buffer.from('UEsDBBQAAAgIAEZ0bF1CGZ1lXgAAAF4AAAAMAAAA5rqQ56CBL2EucGhws7EvyCjgUslMUbBVUIl3dw2JVs9MUY+15lIpBIqoB7v6uDqHKGgpuAX5+yqUFqcWFSuEe7gGuSpkptiqK+gpAHVac+VWFhfmZMYXlqYWVWqoJOfn5ekoqBRqWnMBAFBLAQIUABQAAAgIAEZ0bF1CGZ1lXgAAAF4AAAAMAAAAAAAAAAAAAACAAQAAAADmupDnoIEvYS5waHBQSwUGAAAAAAEAAQA6AAAAiAAAAAAA', 'base64');
    const engine = loadEngine();
    const entries = await engine.readZip(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
    assert.equal(entries[0].name, '源码/a.php');
    const report = scanCode(Buffer.from(entries[0].bytes).toString(), { filename: entries[0].name });
    assert.equal(report.findings[0].cat, 'sqli');
  } finally { global.DecompressionStream = original; }
});
test('read failures return partial results alongside successful scans', async () => {
  const report = await scanPaths([path.join(__dirname, 'missing.php'), path.join(__dirname, 'corpus/vuln/a01_php_sqli.php')]);
  assert.equal(report.status, 'partial');
  assert.equal(report.files, 1);
  assert.equal(report.diagnostics.length, 1);
  assert.equal(report.summary.critical, 1);
});
test('API filters retain taint and fix information', () => {
  const report = scanCode("<?php\n$id = $_GET['id'];\nmysqli_query($conn, $id);", { lang: 'php', cats: ['sqli'], minSev: 'high', lowconf: false });
  assert.equal(report.summary.critical, 1);
  assert.equal(report.findings[0].source.line, 2);
});
test('ZIP scan keeps archive locations, deduplicates targets and applies filters', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sourceaudit-zip-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const archive = path.join(dir, '代码.zip');
  const code = fs.readFileSync(path.join(__dirname, 'corpus/vuln/a01_php_sqli.php'));
  fs.writeFileSync(archive, zip([['src/app.php', code], ['vendor/lib.php', code], ['tests/test.php', code]]));
  const report = await scanPaths([archive, archive], { exclude: ['**/tests/**'] });
  assert.equal(report.files, 1);
  assert.equal(report.summary.critical, 1);
  assert.equal(report.findings[0].archive_path, archive);
  assert.equal(report.findings[0].archive_entry, 'src/app.php');
  assert.equal(report.findings[0].absolute_path, undefined);
});
test('scanning yields progress and cancellation preserves completed work', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sourceaudit-cancel-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const code = fs.readFileSync(path.join(__dirname, 'corpus/vuln/a01_php_sqli.php'));
  for (let i = 0; i < 20; i++) fs.writeFileSync(path.join(dir, `${i}.php`), code);
  const controller = new AbortController(), updates = [];
  const report = await scanPaths([dir], { signal: controller.signal, onProgress: update => {
    updates.push(update);
    if (update.files >= 2) controller.abort();
  } });
  assert.equal(report.status, 'cancelled');
  assert.equal(report.files, 2);
  assert.equal(report.summary.critical, 2);
  assert.ok(updates.length >= 2);
});
