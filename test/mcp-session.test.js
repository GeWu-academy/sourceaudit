'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');

async function client(t) {
  const process = spawn(global.process.execPath, [path.join(__dirname, '../bin/sourceaudit-mcp.js')]);
  t.after(() => process.kill());
  const lines = readline.createInterface({ input: process.stdout });
  const pending = new Map(), received = [];
  let next = 1;
  const api = {
    received,
    notify(method, params) { process.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n'); },
    request(method, params = {}) {
      const id = next++;
      const result = new Promise(resolve => pending.set(id, resolve));
      process.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      return { id, result };
    },
    async call(name, args) { return (await api.request('tools/call', { name, arguments: args }).result).result; }
  };
  lines.on('line', line => {
    const message = JSON.parse(line); received.push(message);
    if (message.id !== undefined) { pending.get(message.id)?.(message); pending.delete(message.id); }
    else api.onNotification?.(message);
  });
  await api.request('initialize', { protocolVersion: '2025-11-25' }).result;
  api.notify('notifications/initialized', {});
  return api;
}
function fixture(t, count) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sourceaudit-session-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const code = fs.readFileSync(path.join(__dirname, 'corpus/vuln/a01_php_sqli.php'));
  for (let i = 0; i < count; i++) fs.writeFileSync(path.join(root, `f${i}.php`), code);
  return root;
}
test('structured reports are paged, filterable, and explicitly releasable', { timeout: 15000 }, async t => {
  const root = fixture(t, 25), api = await client(t);
  const result = await api.call('sourceaudit_scan', { targets: [root] });
  assert.ok(result.structuredContent);
  const report = result.structuredContent;
  assert.equal(report.summary.total, 25);
  assert.equal(report.findings.length, 20);
  assert.equal(report.page.has_more, true);
  const next = await api.call('sourceaudit_report', { report_id: report.report_id, offset: 20 });
  assert.equal(next.structuredContent.findings.length, 5);
  assert.equal(next.structuredContent.page.has_more, false);
  const filtered = await api.call('sourceaudit_report', { report_id: report.report_id, file: report.findings[0].file });
  assert.equal(filtered.structuredContent.page.total, 1);
  const released = await api.call('sourceaudit_release_report', { report_id: report.report_id });
  assert.equal(released.structuredContent.released, true);
  assert.equal((await api.call('sourceaudit_report', { report_id: report.report_id })).isError, true);
});
test('MCP progress allows ping and cancellation while scanning', { timeout: 15000 }, async t => {
  const root = fixture(t, 100), api = await client(t);
  let ping, cancelled = false;
  let cancellationSent;
  const cancellation = new Promise(resolve => { cancellationSent = resolve; });
  const request = api.request('tools/call', { name: 'sourceaudit_scan', arguments: { targets: [root] }, _meta: { progressToken: 'scan-progress' } });
  api.onNotification = message => {
    if (message.method === 'notifications/progress' && message.params.progress >= 2 && !cancelled) {
      cancelled = true;
      ping = api.request('ping');
      api.notify('notifications/cancelled', { requestId: request.id, reason: '用户取消' });
      cancellationSent();
    }
  };
  await cancellation;
  assert.deepEqual((await ping.result).result, {});
  const result = await api.call('sourceaudit_report', { request_id: String(request.id) });
  assert.equal(result.structuredContent.status, 'cancelled');
  assert.ok(result.structuredContent.files >= 2 && result.structuredContent.files < 100);
  assert.equal(api.received.some(m => m.id === request.id), false);
  const updates = api.received.filter(m => m.method === 'notifications/progress');
  assert.ok(updates.every(m => m.params.progressToken === 'scan-progress'));
  assert.ok(updates.every((m, i) => !i || m.params.progress > updates[i - 1].params.progress));
});
