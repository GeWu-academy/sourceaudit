/* 引擎加载：从 awdpplus.js 里切出「分析段」在 Node 里执行。
 *
 * awdpplus.js 是一个浏览器 IIFE：前半段是纯函数（规则表 + 分析器），
 * 后半段是 DOM / fetch / 定时器。命令行只要前半段，所以按边界切开，
 * 用 new Function 在只带一个空 window 的环境里跑 —— 不复制规则、不重写分析器，
 * 上游改了规则这里自动跟着变。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_ENGINE = path.join(ROOT, 'engine', 'awdpplus.js');

// 引擎段的结束位置。第一个是章节标题（稳定），第二个是紧随其后的函数名（兜底）。
const BOUNDARY_MARKERS = ['* 8. 与官方引擎对比', 'function getToken('];

const EXPORTS = [
  'VERSION', 'LANG_LABEL', 'SKIP_EXT', 'SKIP_DIR', 'SOURCES', 'SINKS',
  'SANITIZERS', 'PATTERNS', 'SEV_ORDER', 'SEV_LABEL',
  'CAT_LABEL', 'analyzeText', 'readZip', 'decodeText', 'langOf', 'extOf'
];

function findCut(src, enginePath) {
  for (const marker of BOUNDARY_MARKERS) {
    const idx = src.indexOf(marker);
    if (idx < 0) continue;
    const cut = src.lastIndexOf('/*', idx);
    if (cut >= 0) return cut;
  }
  throw new Error(`无法定位引擎边界：${enginePath} 结构已变化（见 lib/engine.js 的 BOUNDARY_MARKERS）`);
}

function loadEngine(enginePath = DEFAULT_ENGINE) {
  const src = fs.readFileSync(enginePath, 'utf8'); // nosec: 只读本地引擎文件，路径由使用者指定

  const head = src.slice(0, findCut(src, enginePath));
  const openIdx = head.indexOf('(function () {');
  if (openIdx < 0) throw new Error('无法定位引擎入口 IIFE');
  let body = head.slice(openIdx);

  // 去掉浏览器环境守卫（这两行会让第二次加载直接 return）
  body = body.replace(/if \(window\.__lpAwdpPlus\) return;/, '');
  body = body.replace(/window\.__lpAwdpPlus = true;/, '');

  const code = `${body}\n  return { ${EXPORTS.join(', ')} };\n})()`;
  const api = new Function('window', `return ${code}`)({}); // nosec: 执行的就是本仓库引擎，等同 node 加载模块

  if (typeof api.analyzeText !== 'function' || !api.SOURCES || !api.SINKS) {
    throw new Error('引擎加载不完整：analyzeText / SOURCES / SINKS 缺失');
  }
  api.__path = enginePath;
  return api;
}

/** 规则统计，`--list-rules` 和同步脚本共用。 */
function stats(engine) {
  const langs = Object.keys(engine.LANG_LABEL);
  const byLang = {};
  let src = 0, sink = 0;
  for (const lg of langs) {
    const s = (engine.SOURCES[lg] || []).length;
    const k = (engine.SINKS[lg] || []).length;
    const pat = engine.PATTERNS.filter(x => !x.lang || x.lang.includes(lg)).length;
    byLang[lg] = { src: s, sink: k, pat };
    src += s;
    sink += k;
  }
  const total = { src, sink, pat: engine.PATTERNS.length };
  return { byLang, total, sum: src + sink + total.pat, categories: Object.keys(engine.CAT_LABEL).length };
}

module.exports = { loadEngine, stats, DEFAULT_ENGINE, ROOT, BOUNDARY_MARKERS };
