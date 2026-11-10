#!/usr/bin/env node
/* 从 LingOps 安装包同步审计引擎（awdpplus.js）。
 *
 * 本项目不重写规则，只带一份上游引擎副本。上游（LingOps 的「🔬 深度审计」）改了规则，
 * 跑这个脚本把新引擎拉过来即可，行为与网页端保持一致。
 *
 * 用法：
 *   npm run sync-engine                  # 自动探测同级目录里的 LingOps 包
 *   npm run sync-engine -- /path/to/LingOps_v0.2_darwin_arm64
 *   node scripts/sync-engine.js --check  # 只比较，不写文件（不一致退出码 1，可挂 CI）
 *   node scripts/sync-engine.js --dry-run --no-test
 *
 * 环境变量 LINGOPS_HOME 可指定默认来源目录。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const { loadEngine, stats, ROOT, DEFAULT_ENGINE } = require('../lib/engine');

const ENGINE_REL = path.join('frontend', 'dist', 'assets_v2', 'lp-ext', 'awdpplus.js');
const META = path.join(ROOT, 'engine', 'ENGINE.json');

const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');
const short = h => h.slice(0, 12);

function die(msg) {
  console.error(`sync-engine: ${msg}`);
  process.exit(2);
}

/** 候选来源目录：参数 > LINGOPS_HOME > 同级 LingOps* 目录。 */
function candidates(arg) {
  if (arg) return [path.resolve(arg)];
  const out = [];
  if (process.env.LINGOPS_HOME) out.push(path.resolve(process.env.LINGOPS_HOME));
  const parent = path.resolve(ROOT, '..');
  let entries = [];
  try {
    entries = fs.readdirSync(parent, { withFileTypes: true });
  } catch (_) { /* 父目录不可读就算了 */ }
  for (const e of entries) {
    if (!e.isDirectory() || !/^LingOps/i.test(e.name)) continue;
    if (path.resolve(parent, e.name) === ROOT) continue;
    out.push(path.join(parent, e.name));
  }
  return out;
}

function resolveSource(arg) {
  for (const dir of candidates(arg)) {
    const file = path.join(dir, ENGINE_REL);
    if (fs.existsSync(file)) return { dir, file };
  }
  die(`找不到引擎文件。用法：node scripts/sync-engine.js <LingOps 包目录>\n` +
      `      需要目录下有 ${ENGINE_REL}`);
}

function writeMeta(sourceDir, sourceFile, hash, info) {
  // 只记相对信息，避免把本机绝对路径写进仓库
  fs.writeFileSync(META, JSON.stringify({
    source_package: path.basename(sourceDir),
    source_engine: path.relative(sourceDir, sourceFile).split(path.sep).join('/'),
    source_sha256: hash,
    engine_version: info.version,
    rules: info.rules,
    categories: info.categories,
    languages: info.languages,
    synced_at: new Date().toISOString()
  }, null, 2) + '\n');
}

function describe(engine) {
  const s = stats(engine);
  return {
    version: engine.VERSION,
    rules: { sources: s.total.src, sinks: s.total.sink, patterns: s.total.pat, total: s.sum },
    categories: s.categories,
    languages: Object.keys(engine.LANG_LABEL).length
  };
}

function main() {
  const argv = process.argv.slice(2);
  const flags = { check: false, dryRun: false, test: true };
  const positional = [];
  for (const a of argv) {
    if (a === '--check') flags.check = true;
    else if (a === '--dry-run') flags.dryRun = true;
    else if (a === '--no-test') flags.test = false;
    else if (a === '-h' || a === '--help') {
      console.log('用法: node scripts/sync-engine.js [LingOps 包目录] [--check] [--dry-run] [--no-test]');
      return 0;
    } else if (a.startsWith('-')) die(`未知选项：${a}`);
    else positional.push(a);
  }

  const src = resolveSource(positional[0]);
  const incoming = fs.readFileSync(src.file);
  const incomingHash = sha256(incoming);
  const currentHash = fs.existsSync(DEFAULT_ENGINE) ? sha256(fs.readFileSync(DEFAULT_ENGINE)) : null;

  console.log(`来源   ${src.file}`);
  console.log(`指纹   ${short(incomingHash)}  (当前 ${currentHash ? short(currentHash) : '无'})`);

  if (currentHash === incomingHash) {
    const now = describe(loadEngine(DEFAULT_ENGINE));
    writeMeta(src.dir, src.file, incomingHash, now);
    console.log('\n引擎已是最新，无需同步。');
    return 0;
  }
  if (flags.check) {
    console.error('\n引擎与上游不一致（--check 模式不写文件）。');
    return 1;
  }

  // 先落到临时文件验证，能切出分析段再替换，避免把坏引擎装进来
  const tmp = `${DEFAULT_ENGINE}.incoming`;
  fs.writeFileSync(tmp, incoming);
  let fresh;
  try {
    fresh = loadEngine(tmp);
  } catch (err) {
    fs.unlinkSync(tmp);
    die(`新引擎无法加载：${err.message}`);
  }

  const before = fs.existsSync(DEFAULT_ENGINE) ? describe(loadEngine(DEFAULT_ENGINE)) : null;
  const after = describe(fresh);

  console.log('');
  const row = (k, a, b) => console.log(`  ${k.padEnd(10)}${String(a).padStart(8)}${String(b).padStart(10)}`);
  console.log(`  ${'项目'.padEnd(8)}${'当前'.padStart(8)}${'同步后'.padStart(10)}`);
  row('版本', before ? before.version : '-', after.version);
  row('污点来源', before ? before.rules.sources : '-', after.rules.sources);
  row('危险函数', before ? before.rules.sinks : '-', after.rules.sinks);
  row('静态特征', before ? before.rules.patterns : '-', after.rules.patterns);
  row('合计', before ? before.rules.total : '-', after.rules.total);
  row('漏洞类别', before ? before.categories : '-', after.categories);

  if (flags.dryRun) {
    fs.unlinkSync(tmp);
    console.log('\n--dry-run：未写入。');
    return 0;
  }

  fs.renameSync(tmp, DEFAULT_ENGINE);
  writeMeta(src.dir, src.file, incomingHash, after);

  console.log(`\n已更新 ${path.relative(ROOT, DEFAULT_ENGINE)}，元信息写入 ${path.relative(ROOT, META)}。`);

  if (flags.test) {
    console.log('\n跑回归语料…');
    try {
      execFileSync(process.execPath, [path.join(ROOT, 'test', 'run.js')], { stdio: 'inherit' });
    } catch (_) {
      console.error('\n回归未通过 —— 新引擎有问题，或语料需要更新。用 git 回滚 engine/ 后排查。');
      return 1;
    }
  }
  return 0;
}

process.exit(main());
