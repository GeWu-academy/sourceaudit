#!/usr/bin/env node
/* sourceaudit · 源码漏洞审计命令行（跨行污点分析）
 *
 * 引擎来自 LingOps 深度审计（awdpplus.js，跨行污点分析），本项目自带一份副本
 * engine/awdpplus.js，运行时从该文件切出分析段 —— 不做二次实现，规则只有一份。
 * 用 `npm run sync-engine -- <LingOps 目录>` 从上游同步规则。
 *
 * 用法：
 *   sourceaudit <目录|文件|.zip> [选项]
 *
 * 需要 Node.js >= 18（依赖 DecompressionStream / Blob / Response 解 zip）
 */
'use strict';

const fs = require('fs');
const path = require('path');

const { loadEngine, stats, DEFAULT_ENGINE } = require('../lib/engine');
const PKG = require('../package.json');

/* ------------------------------------------------------------------ 参数解析 */

const HELP = `
sourceaudit · 源码漏洞审计

用法
  sourceaudit <目录|文件|.zip> [更多路径...] [选项]

选项
  -f, --format <text|json>   输出格式（默认 text）
  -s, --min-sev <级别>       只显示不低于该级别的问题：critical|high|medium|low（默认 low）
  -c, --cat <类别>           只看指定漏洞类别，逗号分隔（rce,sqli,xss,...）
  -l, --lang <语言>          只扫指定语言：php|java|go|python|node|ruby|asp|csharp
      --exclude <glob>       排除路径，可重复，如 --exclude 'tests/*'
      --vendor               不跳过 vendor/node_modules/dist 等第三方目录（默认跳过）
      --no-lowconf           不输出「未追到污点来源」的低置信提示
      --fail-on <级别>       出现该级别及以上问题时退出码为 1（默认 high，设 none 关闭）
      --engine <路径>        指定引擎文件（默认内置 engine/awdpplus.js）
      --list-rules           打印规则统计后退出
  -o, --out <文件>           结果同时写入文件
  -q, --quiet                只输出汇总行
      --no-color             关闭颜色
  -v, --version              版本
  -h, --help                 本帮助

退出码
  0  未发现达到 --fail-on 级别的问题
  1  发现达到 --fail-on 级别的问题
  2  参数或运行错误

示例
  sourceaudit ./src
  sourceaudit ./src -s high -f json -o report.json
  sourceaudit challenge.zip --exclude 'vendor/*' -q
  sourceaudit app/ --list-rules
`.trim();

function parseArgs(argv) {
  const a = {
    targets: [], format: 'text', minSev: 'low', cats: null, lang: null,
    exclude: [], vendor: false, lowconf: true, failOn: 'high',
    engine: DEFAULT_ENGINE, listRules: false, out: null, quiet: false, color: null
  };
  const need = (i, name) => {
    if (i + 1 >= argv.length) throw new Error(`选项 ${name} 需要一个值`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    switch (v) {
      case '-h': case '--help': a.help = true; break;
      case '-v': case '--version': a.version = true; break;
      case '-f': case '--format': a.format = need(i, v); i++; break;
      case '-s': case '--min-sev': a.minSev = need(i, v); i++; break;
      case '-c': case '--cat': a.cats = need(i, v).split(',').map(s => s.trim()).filter(Boolean); i++; break;
      case '-l': case '--lang': a.lang = need(i, v); i++; break;
      case '--exclude': a.exclude.push(need(i, v)); i++; break;
      case '--vendor': a.vendor = true; break;
      case '--no-lowconf': a.lowconf = false; break;
      case '--fail-on': a.failOn = need(i, v); i++; break;
      case '--engine': a.engine = path.resolve(need(i, v)); i++; break;
      case '--list-rules': a.listRules = true; break;
      case '-o': case '--out': a.out = need(i, v); i++; break;
      case '-q': case '--quiet': a.quiet = true; break;
      case '--no-color': a.color = false; break;
      default:
        if (v.startsWith('-') && v !== '-') throw new Error(`未知选项：${v}`);
        a.targets.push(v);
    }
  }
  return a;
}

/* ------------------------------------------------------------------ 路径过滤 */

const GLOB_MAX = 256;

function globToRe(g) {
  if (g.length > GLOB_MAX) throw new Error(`--exclude 通配符过长（${g.length} > ${GLOB_MAX}）：${g.slice(0, 40)}…`);
  const s = g.replace(/\\/g, '/').replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*')
    .replace(/\?/g, '.').replace(/\u0000/g, '.*');
  try {
    return new RegExp(`^${s}$`); // nosec: 模式来自使用者的 --exclude，且已限长
  } catch (e) {
    throw new Error(`--exclude 通配符无法解析：${g}`);
  }
}

function collectFromDir(root, opts, engine) {
  const out = [];
  const exRes = opts.exclude.map(globToRe);
  const walk = (dir, rel) => {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const ent of ents) {
      const full = path.join(dir, ent.name);
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.name === '.DS_Store') continue;
      if (exRes.some(re => re.test(r))) continue;
      if (ent.isDirectory()) {
        if (!opts.vendor && engine.SKIP_DIR.test(r + '/')) continue;
        walk(full, r);
      } else if (ent.isFile()) {
        const ex = engine.extOf(r);
        if (engine.SKIP_EXT[ex]) continue;
        const lang = engine.langOf(r);
        if (!lang) continue;
        if (opts.lang && lang !== opts.lang) continue;
        out.push({ path: r, full, lang });
      }
    }
  };
  walk(root, '');
  return out;
}

/* ------------------------------------------------------------------ 文件读取 */

const MAX_FILE = 3 * 1024 * 1024;

function pushText(engine, bag, name, bytes, opts) {
  const ex = engine.extOf(name);
  if (engine.SKIP_EXT[ex]) return bag.skipped++;
  const lang = engine.langOf(name);
  if (!lang) return bag.skipped++;
  if (opts.lang && lang !== opts.lang) return bag.skipped++;
  if (bytes.length > MAX_FILE) return bag.skipped++;
  const text = engine.decodeText(bytes);
  if (text.indexOf('\u0000') >= 0) return bag.skipped++;
  bag.files.push({ path: name, text, lang, size: bytes.length });
  bag.added++;
}

async function gather(engine, opts) {
  const bag = { files: [], added: 0, skipped: 0 };
  for (const target of opts.targets) {
    const abs = path.resolve(target);
    let st;
    try { st = fs.statSync(abs); } catch (e) { throw new Error(`路径不存在：${target}`); }

    if (st.isDirectory()) {
      const list = collectFromDir(abs, opts, engine);
      for (const f of list) pushText(engine, bag, f.path, fs.readFileSync(f.full), opts); // nosec: 扫描目标就是使用者指定的路径
    } else if (/\.zip$/i.test(abs)) {
      const buf = fs.readFileSync(abs);
      const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
      const entries = await engine.readZip(ab);
      const exRes = opts.exclude.map(globToRe);
      for (const e of entries) {
        const p = e.name.replace(/\\/g, '/');
        if (p.startsWith('__MACOSX/') || /(^|\/)\.DS_Store$/.test(p)) { bag.skipped++; continue; }
        if (exRes.some(re => re.test(p))) { bag.skipped++; continue; }
        if (!opts.vendor && engine.SKIP_DIR.test(p)) { bag.skipped++; continue; }
        pushText(engine, bag, p, e.bytes, opts);
      }
    } else {
      pushText(engine, bag, path.basename(abs), fs.readFileSync(abs), opts);
    }
  }
  return bag;
}

/* ------------------------------------------------------------------ 输出 */

const ANSI = { critical: '\x1b[91m', high: '\x1b[33m', medium: '\x1b[93m', low: '\x1b[36m' };
const RESET = '\x1b[0m', DIM = '\x1b[2m', BOLD = '\x1b[1m', GREEN = '\x1b[92m';

function makePainter(enabled) {
  return (code, s) => (enabled ? code + s + RESET : s);
}

function pad(s, n) { return s + ' '.repeat(Math.max(0, n - s.length)); }

function renderText(findings, meta, paint) {
  const L = [];
  const { critical, high, medium, low } = meta.summary;

  L.push('');
  L.push(`  ${paint(BOLD, 'sourceaudit')} ${meta.version} ${paint(DIM, '· 跨行污点分析引擎')}`);
  L.push(paint(DIM, `  ${meta.files} 个文件（${meta.langStr}），跳过 ${meta.skipped} 个`));
  L.push('');

  if (!findings.length) {
    L.push(`  ${paint(GREEN, '✓ 未发现问题')}`);
    L.push('');
    return L.join('\n');
  }

  for (const f of findings) {
    const loc = `${f.file}:${f.line}`;
    const locStr = loc.length > 40 ? '…' + loc.slice(-39) : loc;
    L.push(`  ${paint(ANSI[f.sev] || '', pad(f.sev.toUpperCase(), 9))}${pad(locStr, 41)}${paint(DIM, f.cat)}`);
    L.push(`  ${' '.repeat(9)}${paint(BOLD, f.name)}`);
    if (f.code) L.push(paint(DIM, `  ${' '.repeat(9)}│ ${f.code.slice(0, 140)}`));
    if (f.source) {
      L.push(paint(DIM, `  ${' '.repeat(9)}└ 污点来源 L${f.source.line} ${f.source.label}` +
        (f.source.code ? ` · ${f.source.code.slice(0, 70)}` : '')));
    }
    if (f.sanitized) L.push(paint(DIM, `  ${' '.repeat(9)}└ 已检测到净化处理，降级为 low`));
  }

  L.push('');
  L.push(paint(DIM, '  ' + '─'.repeat(56)));
  const parts = [
    `严重 ${paint(ANSI.critical, String(critical))}`,
    `高危 ${paint(ANSI.high, String(high))}`,
    `中危 ${paint(ANSI.medium, String(medium))}`,
    `低危 ${paint(ANSI.low, String(low))}`
  ];
  L.push(`  ${parts.join('  ·  ')}   合计 ${meta.summary.total} 处 / ${meta.files} 文件 / ${meta.elapsed_ms}ms`);
  L.push('');
  return L.join('\n');
}

function renderRules(engine) {
  const L = [];
  const langs = Object.keys(engine.LANG_LABEL);
  let ns = 0, nk = 0;
  const P = engine.PATTERNS;
  L.push('');
  L.push(`  规则统计（引擎 v${engine.VERSION}）`);
  L.push('');
  L.push('  语言        污点来源   危险函数   静态特征');
  for (const lg of langs) {
    const s = (engine.SOURCES[lg] || []).length;
    const k = (engine.SINKS[lg] || []).length;
    const p = P.filter(x => !x.lang || x.lang.includes(lg)).length;
    ns += s; nk += k;
    L.push(`  ${pad(engine.LANG_LABEL[lg], 12)}${pad(String(s), 10)}${pad(String(k), 10)}${p}`);
  }
  L.push(paintLine('  ' + '─'.repeat(44)));
  L.push(`  ${pad('合计', 12)}${pad(String(ns), 10)}${pad(String(nk), 10)}${P.length}` +
    `     = ${ns + nk + P.length} 条`);
  L.push('');
  L.push('  注：静态特征多为多语言共用，按语言分列之和会大于总数。');
  L.push(`  漏洞类别 ${Object.keys(engine.CAT_LABEL).length} 类`);
  L.push('');
  return L.join('\n');
}

function paintLine(s) { return s; }

/* ------------------------------------------------------------------ 主流程 */

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help) { console.log(HELP); return 0; }

  const engine = loadEngine(opts.engine);

  if (opts.version) { console.log(`sourceaudit ${PKG.version} (engine ${engine.VERSION})`); return 0; }
  if (opts.listRules) { console.log(renderRules(engine)); return 0; }

  if (!opts.targets.length) { console.error(HELP); return 2; }
  if (!(opts.minSev in engine.SEV_ORDER)) throw new Error(`--min-sev 取值无效：${opts.minSev}`);
  if (opts.failOn !== 'none' && !(opts.failOn in engine.SEV_ORDER)) throw new Error(`--fail-on 取值无效：${opts.failOn}`);
  if (!['text', 'json'].includes(opts.format)) throw new Error(`--format 取值无效：${opts.format}`);

  const t0 = Date.now();
  const bag = await gather(engine, opts);

  const raw = [];
  for (const f of bag.files) {
    try {
      const res = engine.analyzeText(f.path, f.text, f.lang, { lowConfidence: opts.lowconf });
      for (const r of res) raw.push(r);
    } catch (e) {
      if (!opts.quiet) console.error(`  ! 分析失败 ${f.path}: ${e.message}`);
    }
  }

  const minOrder = engine.SEV_ORDER[opts.minSev];
  const findings = raw
    .filter(f => engine.SEV_ORDER[f.sev] <= minOrder)
    .filter(f => !opts.cats || opts.cats.includes(f.cat))
    .sort((a, b) => {
      const d = engine.SEV_ORDER[a.sev] - engine.SEV_ORDER[b.sev];
      if (d) return d;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      return a.line - b.line;
    });

  const summary = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
  for (const f of findings) summary[f.sev] = (summary[f.sev] || 0) + 1;

  const langCount = {};
  for (const f of bag.files) langCount[f.lang] = (langCount[f.lang] || 0) + 1;
  const langStr = Object.keys(langCount)
    .sort((a, b) => langCount[b] - langCount[a])
    .map(l => `${engine.LANG_LABEL[l] || l}×${langCount[l]}`).join(' ') || '无可扫描文件';

  const meta = {
    tool: 'sourceaudit',
    version: PKG.version,
    engine_version: engine.VERSION,
    engine: opts.engine,
    targets: opts.targets,
    files: bag.files.length,
    skipped: bag.skipped,
    langStr,
    elapsed_ms: Date.now() - t0,
    summary
  };

  const useColor = opts.color === null ? (process.stdout.isTTY && !process.env.NO_COLOR) : opts.color;
  const paint = makePainter(useColor);

  let output;
  if (opts.format === 'json') {
    output = JSON.stringify({ ...meta, findings }, null, 2);
  } else if (opts.quiet) {
    output = `sourceaudit: ${bag.files.length} 文件 · 严重 ${summary.critical} 高危 ${summary.high} ` +
      `中危 ${summary.medium} 低危 ${summary.low} · ${meta.elapsed_ms}ms`;
  } else {
    output = renderText(findings, meta, paint);
  }

  console.log(output);
  if (opts.out) {
    fs.writeFileSync(opts.out, output.endsWith('\n') ? output : output + '\n', 'utf8');
    if (!opts.quiet) console.error(`  已写入 ${opts.out}`);
  }

  if (opts.failOn === 'none') return 0;
  const failOrder = engine.SEV_ORDER[opts.failOn];
  const hit = findings.some(f => engine.SEV_ORDER[f.sev] <= failOrder);
  return hit ? 1 : 0;
}

main().then(code => process.exit(code)).catch(err => {
  console.error(`sourceaudit: ${err.message}`);
  process.exit(2);
});
