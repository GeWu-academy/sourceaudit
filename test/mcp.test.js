'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const bin = path.resolve(__dirname, '../bin/sourceaudit-mcp.js');
const sample = path.join(__dirname, 'corpus/vuln/a01_php_sqli.php');
function session(messages) {
  const result = spawnSync(process.execPath, [bin], {
    input: messages.map(m => JSON.stringify({ jsonrpc: '2.0', ...m })).join('\n') + '\n',
    encoding: 'utf8', timeout: 15000
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  return result.stdout.trim().split('\n').map(line => JSON.parse(line)).sort((a, b) => a.id - b.id);
}
const init = { id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'YiLianQianYan', version: 'test' } } };
const initialized = { method: 'notifications/initialized' };

test('YiLian discovery fallback, handshake, catalog and ping work over stdio', () => {
  const replies = session([
    { id: 0, method: 'server/discover', params: {} }, init, initialized,
    { id: 2, method: 'tools/list' }, { id: 3, method: 'ping' }
  ]);
  assert.equal(replies.length, 4);
  assert.equal(replies[0].error.code, -32601);
  assert.equal(replies[1].result.protocolVersion, '2025-11-25');
  assert.deepEqual(replies[2].result.tools.map(t => t.name), ['sourceaudit_scan', 'sourceaudit_scan_code', 'sourceaudit_rules', 'sourceaudit_report', 'sourceaudit_release_report']);
  assert.ok(replies[2].result.tools.filter(t => t.name !== 'sourceaudit_release_report').every(t => t.annotations.readOnlyHint));
  assert.ok(replies[2].result.tools.every(t => t.outputSchema.type === 'object'));
  assert.deepEqual(replies[3].result, {});
});
test('path and pasted-code tools report the same real taint chain', () => {
  const replies = session([init, initialized,
    { id: 2, method: 'tools/call', params: { name: 'sourceaudit_scan', arguments: { targets: [sample], min_severity: 'high' } } },
    { id: 3, method: 'tools/call', params: { name: 'sourceaudit_scan_code', arguments: { code: fs.readFileSync(sample, 'utf8'), filename: 'sample.php' } } },
    { id: 4, method: 'tools/call', params: { name: 'sourceaudit_rules', arguments: {} } }
  ]);
  for (const reply of replies.slice(1, 3)) {
    assert.equal(reply.result.isError, false);
    const report = JSON.parse(reply.result.content[0].text);
    assert.equal(report.status, 'complete');
    assert.equal(report.findings[0].cat, 'sqli');
    assert.equal(report.findings[0].source.line, 2);
    assert.match(report.findings[0].fix, /预处理/);
  }
  assert.equal(JSON.parse(replies[3].result.content[0].text).sum, 331);
});
test('scan errors are tool errors, with diagnostics preserved', () => {
  const replies = session([init, initialized,
    { id: 2, method: 'tools/call', params: { name: 'sourceaudit_scan', arguments: { targets: [path.join(__dirname, 'missing.php')] } } },
    { id: 3, method: 'tools/call', params: { name: 'sourceaudit_scan_code', arguments: { code: 'hello', lang: 'wrong' } } },
    { id: 4, method: 'tools/call', params: { name: 'not_a_tool', arguments: {} } }
  ]);
  assert.equal(replies[1].result.isError, true);
  assert.equal(JSON.parse(replies[1].result.content[0].text).status, 'partial');
  assert.equal(replies[2].result.isError, true);
  assert.equal(replies[3].error.code, -32602);
});
