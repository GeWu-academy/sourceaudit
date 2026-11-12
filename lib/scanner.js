'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { loadEngine, DEFAULT_ENGINE } = require('./engine');
const PKG = require('../package.json');
const { zipEntries } = require('./zip-reader');
const { setImmediate: yieldTurn } = require('node:timers/promises');
const MAX_FILE = 3 * 1024 * 1024;
let builtinEngine;
const getEngine = () => (builtinEngine ||= loadEngine());
const slash = value => value.replace(/\\/g, '/');

function globToRe(pattern) {
  if (pattern.length > 256) throw new Error('--exclude 通配符过长（上限 256）');
  const glob = slash(pattern);
  let source = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      i++;
      if (glob[i + 1] === '/') { source += '(?:.*/)?'; i++; }
      else source += '.*';
    } else if (c === '*') source += '[^/]*';
    else if (c === '?') source += '[^/]';
    else source += /[.+^${}()|[\]\\]/.test(c) ? '\\' + c : c;
  }
  return new RegExp(`^${source}$`); // nosec: 使用者指定的排除模式
}

function optionsFor(options, engine) {
  const opts = { minSev: 'low', cats: null, lang: null, lowconf: true, exclude: [], vendor: false, ...options };
  if (!Object.hasOwn(engine.SEV_ORDER, opts.minSev)) throw new Error(`--min-sev 取值无效：${opts.minSev}`);
  if (opts.lang && !Object.hasOwn(engine.LANG_LABEL, opts.lang)) throw new Error(`--lang 语言无效：${opts.lang}`);
  for (const cat of opts.cats || []) {
    if (!Object.hasOwn(engine.CAT_LABEL, cat)) throw new Error(`--cat 类别无效：${cat}`);
  }
  return opts;
}

function createScan(engine, opts, targets) {
  const started = Date.now();
  const raw = [], diagnostics = [], langCount = {};
  let files = 0, skipped = 0;
  function analyze(name, text, lang, location) {
    try {
      const findings = engine.analyzeText(name, text, lang, { lowConfidence: opts.lowconf });
      raw.push(...findings.map(f => ({ ...f, ...location })));
      files++;
      langCount[lang] = (langCount[lang] || 0) + 1;
    } catch (error) { diagnostics.push({ file: name, message: error.message }); }
  }
  return {
    progress() { return { files, skipped, processed: files + skipped + diagnostics.length }; },
    skip() { skipped++; },
    error(file, error) { diagnostics.push({ file, message: error.message }); },
    analyze,
    bytes(name, bytes, lang, location) {
      if (bytes.length > MAX_FILE) { skipped++; return; }
      const text = engine.decodeText(bytes);
      if (text.includes('\0')) { skipped++; return; }
      analyze(name, text, lang, location);
    },
    finish() {
      const findings = raw.filter(f => engine.SEV_ORDER[f.sev] <= engine.SEV_ORDER[opts.minSev])
        .filter(f => !opts.cats || opts.cats.includes(f.cat))
        .sort((a, b) => engine.SEV_ORDER[a.sev] - engine.SEV_ORDER[b.sev]
          || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line);
      const summary = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
      for (const f of findings) summary[f.sev]++;
      return {
        tool: 'sourceaudit', version: PKG.version, engine_version: engine.VERSION,
        analysis_revision: 'sourceaudit-flow-1',
        engine: engine.__path, targets, files, skipped,
        status: opts.signal?.aborted ? 'cancelled' : diagnostics.length ? 'partial' : files ? 'complete' : 'empty',
        diagnostics,
        langStr: Object.keys(langCount).sort((a, b) => langCount[b] - langCount[a])
          .map(lang => `${engine.LANG_LABEL[lang]}×${langCount[lang]}`).join(' ') || '无可扫描文件',
        elapsed_ms: Date.now() - started, summary, findings
      };
    }
  };
}

async function scanPaths(targets, options = {}) {
  if (!Array.isArray(targets) || !targets.length || targets.some(t => typeof t !== 'string' || !t.trim())) {
    throw new Error('targets 需要至少一个文件、目录或 ZIP 路径');
  }
  const engine = options.engine && options.engine !== DEFAULT_ENGINE ? loadEngine(options.engine) : getEngine();
  const opts = optionsFor(options, engine);
  const scan = createScan(engine, opts, targets);
  const excludes = opts.exclude.map(globToRe);
  const seen = new Set();
  const roots = [...new Set(targets.map(t => path.resolve(t)))];
  const multi = roots.length > 1;
  async function checkpoint(name) {
    opts.onProgress?.({ ...scan.progress(), phase: 'scanning', current_file: name });
    await yieldTurn();
    return !opts.signal?.aborted;
  }
  const excluded = name => {
    const segments = name.split('/');
    return segments.some((_, index) => {
      const parent = segments.slice(0, index + 1).join('/');
      return excludes.some(re => re.test(parent) || re.test(parent + '/'));
    });
  };
  function language(name) {
    const lang = engine.langOf(name);
    return !engine.SKIP_EXT[engine.extOf(name)] && (!opts.lang || opts.lang === lang) ? lang : null;
  }
  function once(full) {
    const real = fs.realpathSync(full);
    const key = process.platform === 'win32' ? real.toLowerCase() : real;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }
  function file(full, relative, target) {
    if (excluded(relative) || !language(relative)) { scan.skip(); return; }
    try {
      if (!once(full)) return;
      if (fs.statSync(full).size > MAX_FILE) { scan.skip(); return; }
      const name = multi ? slash(full) : relative;
      scan.bytes(name, fs.readFileSync(full), language(relative), { absolute_path: full, target }); // nosec: 用户提供的审计目标
    } catch (error) { scan.error(full, error); }
  }
  async function walk(dir, relative, target) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (error) { scan.error(dir, error); return; }
    for (const entry of entries) {
      if (opts.signal?.aborted) break;
      const rel = relative ? `${relative}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (excluded(rel) || (!opts.vendor && engine.SKIP_DIR.test(rel + '/'))) continue;
        await walk(full, rel, target);
      } else if (entry.isFile()) {
        if (!await checkpoint(full)) break;
        file(full, rel, target);
      }
    }
  }
  for (const target of roots) {
    if (opts.signal?.aborted) break;
    let stat;
    try { stat = fs.statSync(target); }
    catch (error) { scan.error(target, error); continue; }
    if (stat.isDirectory()) await walk(target, '', target);
    else if (/\.zip$/i.test(target)) {
      if (excluded(path.basename(target))) { scan.skip(); continue; }
      try {
        if (!once(target)) continue;
        for await (const entry of zipEntries(target)) {
          if (!await checkpoint(`${target}!/${entry.name}`)) break;
          const rel = slash(entry.name);
          const lang = language(rel);
          if (!lang || excluded(rel) || rel.startsWith('__MACOSX/') || entry.size > MAX_FILE || (!opts.vendor && engine.SKIP_DIR.test(rel))) { scan.skip(); continue; }
          try {
            const bytes = await entry.read();
            scan.bytes(multi ? `${slash(target)}!/${rel}` : rel, bytes, lang, { target, archive_path: target, archive_entry: rel });
          } catch (error) { scan.error(`${target}!/${rel}`, error); }
        }
      } catch (error) { scan.error(target, error); }
    } else if (await checkpoint(target)) file(target, path.basename(target), target);
  }
  const report = scan.finish();
  opts.onProgress?.({ ...scan.progress(), phase: report.status, current_file: null });
  return report;
}

function scanCode(code, options = {}) {
  if (typeof code !== 'string') throw new Error('code 必须是代码文本');
  const engine = getEngine();
  const opts = optionsFor(options, engine);
  const filename = options.filename || 'snippet';
  const lang = opts.lang || engine.langOf(filename);
  if (!lang) throw new Error('请指定 lang 或带有效源码后缀的 filename');
  const scan = createScan(engine, opts, [filename]);
  scan.analyze(filename, code, lang, {});
  return scan.finish();
}

module.exports = { scanPaths, scanCode, getEngine, globToRe };
