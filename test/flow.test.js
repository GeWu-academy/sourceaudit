'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { scanCode } = require('../lib/scanner');
const high = (code, lang = 'php') => scanCode(code, { lang, lowconf: false }).findings.filter(f => ['critical', 'high'].includes(f.sev));

test('unconditional constant reassignment kills earlier taint', () => {
  assert.equal(high("<?php\n$x = $_GET['x'];\n$x = 'fixed';\nsystem($x);").length, 0);
});
test('future sources cannot taint earlier calls', () => {
  assert.equal(high("<?php\n$x = 'fixed';\nsystem($x);\n$x = $_GET['x'];").length, 0);
});
test('aliases retain their own assignment histories', () => {
  const results = high("<?php\n$x = $_GET['x'];\n$y = $x;\n$x = 'fixed';\nsystem($y);\nsystem($x);");
  assert.deepEqual(results.map(f => f.line), [5]);
});
test('named function locals do not leak between functions', () => {
  assert.equal(high("<?php\nfunction a() {\n$x = $_GET['x'];\n}\nfunction b() {\n$x = 'fixed';\nsystem($x);\n}").length, 0);
});
test('conditional overwrite does not erase taint after the branch', () => {
  assert.ok(high("<?php\n$x = $_GET['x'];\nif ($flag) { $x = 'fixed'; }\nsystem($x);").length);
});
test('calls inside an overwritten branch use the branch value', () => {
  const results = high("<?php\n$x = $_GET['x'];\nif ($flag) {\n$x = 'fixed';\nsystem($x);\n}\nsystem($x);");
  assert.deepEqual(results.map(f => f.line), [7]);
});
test('statement order on a single line is preserved', () => {
  assert.equal(high("<?php\n$x = $_GET['x']; $x = 'fixed'; system($x);").length, 0);
});
test('JavaScript and Python reassignment and function scope', () => {
  assert.equal(high("let x = req.query.x;\nx = 'fixed';\nexec(x);", 'node').length, 0);
  assert.equal(high("x = request.args.get('x')\nx = 'fixed'\nos.system(x)", 'python').length, 0);
  assert.equal(high("def a():\n    x = request.args.get('x')\ndef b():\n    x = 'fixed'\n    os.system(x)", 'python').length, 0);
});
test('inline source in an assignment call retains a traced finding', () => {
  const results = high("<?php\n$xml = simplexml_load_string($_POST['xml'], 'SimpleXMLElement', LIBXML_NOENT);");
  assert.ok(results.some(f => f.rule === 'awdpplus' && f.source.line === 2));
});
test('loop-carried taint reaches calls in the next iteration', () => {
  assert.ok(high("<?php\n$x = 'fixed';\nwhile ($flag) {\nsystem($x);\n$x = $_GET['x'];\n}").length);
  assert.equal(high("<?php\nwhile ($flag) {\n$x = 'fixed';\nsystem($x);\n$x = $_GET['x'];\n}").length, 0);
});
