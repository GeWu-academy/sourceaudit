'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { build } = require('../scripts/package-yilian');
const { loadEngine } = require('../lib/engine');
const { version } = require('../package.json');

test('YiLian package contains valid declared resources and runnable absolute MCP config', async t => {
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'sourceaudit-package-'));
  t.after(() => fs.rmSync(output, { recursive: true, force: true }));
  const result = build(output);
  const bytes = fs.readFileSync(result.packagePath);
  const entries = await loadEngine().readZip(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
  assert.deepEqual(entries.map(e => e.name), ['plugin.json', 'skills/sourceaudit/SKILL.md']);
  const manifest = JSON.parse(Buffer.from(entries[0].bytes).toString());
  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.id, 'yilian.sourceaudit');
  assert.equal(manifest.version, version);
  assert.ok(manifest.contributes.features.every(f => manifest.contributes.skills.includes(f.target.contribution)));
  assert.match(Buffer.from(entries[1].bytes).toString(), /sourceaudit_scan_code/);
  const config = JSON.parse(fs.readFileSync(result.configPath, 'utf8'));
  assert.equal(config.enabled, false);
  assert.ok(path.isAbsolute(config.command));
  assert.ok(path.isAbsolute(config.args[0]));
  assert.equal(manifest.contributes.mcp_server_templates[0].command, config.command);
  const running = spawnSync(config.command, config.args, {
    input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25' } }) + '\n',
    cwd: os.tmpdir(), encoding: 'utf8', timeout: 15000
  });
  assert.equal(running.status, 0, running.stderr);
  assert.equal(JSON.parse(running.stdout).result.serverInfo.name, 'sourceaudit');
  const again = build(output);
  assert.deepEqual(fs.readFileSync(again.packagePath), bytes);
});
