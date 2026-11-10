#!/usr/bin/env node
/* 回归自测：用带已知答案的语料验证引擎没被改坏。
 *
 *   node test/run.js          跑全部 5 套语料，只打汇总
 *   node test/run.js -v       逐文件打印漏报/误报
 *   node test/run.js --json   机器可读输出
 *
 * 退出码：0 = 全部通过，1 = 有回归。
 *
 * 语料来源与 LingOps 仓库的 tests/awdp-corpus 一致（同一份引擎，同一批答案）。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const { loadEngine, DEFAULT_ENGINE, ROOT } = require('../lib/engine');

const VERBOSE = process.argv.includes('-v') || process.argv.includes('--verbose');
const JSONOUT = process.argv.includes('--json');
const CORPUS = path.join(__dirname, 'corpus');

const LANG = { '.php': 'php', '.py': 'python', '.js': 'node', '.java': 'java', '.go': 'go', '.rb': 'ruby', '.cs': 'csharp', '.asp': 'asp' };

// expect: hit = 每个文件都必须报出问题；clean = 一个都不许报；high = 必须报出高危以上
const SUITES = [
  { dir: 'vuln', expect: 'hit', label: '真漏洞' },
  { dir: 'safe', expect: 'clean', label: '安全代码' },
  { dir: 'regress', expect: 'hit', label: '回归' },
  { dir: 'modern', expect: 'hit', label: '新型漏洞' },
  {
    dir: 'adversarial', expect: 'high', label: '对抗语料',
    // 已文档化的盲区：obj[k]=v 与 arr[i]=x 在无类型信息时不可区分，只报低置信
    knownMiss: ['x08_js_proto_direct.js']
  }
];

const engine = loadEngine(DEFAULT_ENGINE);

function scanFile(file) {
  const lang = LANG[path.extname(file)];
  if (!lang) return null;
  const r = engine.analyzeText(file, fs.readFileSync(file, 'utf8'), lang, {});
  return Array.isArray(r) ? r : (r && r.findings) || [];
}

const results = [];
let failed = 0;

for (const suite of SUITES) {
  const dir = path.join(CORPUS, suite.dir);
  if (!fs.existsSync(dir)) continue;
  const rows = [];
  for (const name of fs.readdirSync(dir).sort()) {
    const findings = scanFile(path.join(dir, name));
    if (!findings) continue;
    const hasHigh = findings.some(f => f.sev === 'high' || f.sev === 'critical');
    let ok;
    if (suite.expect === 'clean') ok = findings.length === 0;
    else if (suite.expect === 'high') ok = hasHigh;
    else ok = findings.length > 0;
    const known = !ok && (suite.knownMiss || []).includes(name);
    if (!ok && !known) failed++;
    rows.push({
      file: name,
      ok: ok || known,
      known,
      findings: findings.map(f => `${f.sev}/${f.cat}/${f.name}@${f.line}`)
    });
  }
  const known = rows.filter(r => r.known).length;
  const pass = rows.filter(r => r.ok).length - known;
  results.push({ suite: suite.label, dir: suite.dir, expect: suite.expect, pass, known, total: rows.length, rows });
}

if (!results.length) {
  console.error(`没找到语料目录：${CORPUS}`);
  process.exit(2);
}

/* 端到端：确认 CLI 真能跑起来（引擎能加载 ≠ 命令行能用） */
function cliSmoke() {
  const bin = path.join(ROOT, 'bin', 'sourceaudit.js');
  const sample = path.join(CORPUS, 'vuln');
  try {
    const out = execFileSync(process.execPath, [bin, sample, '-q', '--no-color', '--fail-on', 'none'],
      { encoding: 'utf8' });
    return { ok: /文件/.test(out) && /严重/.test(out), out: out.trim() };
  } catch (err) {
    return { ok: false, out: String(err.message || err) };
  }
}

const smoke = cliSmoke();
if (!smoke.ok) failed++;

if (JSONOUT) {
  console.log(JSON.stringify({
    engine: { path: path.relative(ROOT, DEFAULT_ENGINE), version: engine.VERSION },
    suites: results.map(r => ({ suite: r.suite, expect: r.expect, pass: r.pass, known: r.known, total: r.total })),
    cli: smoke,
    failed
  }, null, 2));
  process.exit(failed ? 1 : 0);
}

console.log(`引擎  ${path.relative(ROOT, DEFAULT_ENGINE)}  v${engine.VERSION}`);
console.log('');
for (const r of results) {
  const scored = r.total - r.known;
  const rate = scored ? (r.pass / scored * 100).toFixed(1) : '100.0';
  const mark = r.pass === scored ? '✅' : '❌';
  const extra = r.known ? `  （另有 ${r.known} 个已知盲区不计分）` : '';
  console.log(`  ${r.suite.padEnd(6, '　')} ${String(r.pass).padStart(3)}/${String(scored).padEnd(3)} ${rate.padStart(5)}%  ${mark}${extra}`);
  if (VERBOSE) {
    for (const row of r.rows) {
      if (row.ok && !row.known) continue;
      const tag = row.known ? '已知盲区' : (r.expect === 'clean' ? '误报' : '漏报');
      console.log(`      ${tag}  ${row.file}`);
      for (const f of row.findings) console.log(`          ${f}`);
    }
  }
}

console.log('');
console.log(`  CLI  ${smoke.ok ? '✅ ' + smoke.out : '❌ ' + smoke.out}`);
console.log('');
console.log(failed ? `❌ ${failed} 项未通过` : '全部通过 ✅');
process.exit(failed ? 1 : 0);
