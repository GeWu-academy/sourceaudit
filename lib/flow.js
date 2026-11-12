'use strict';

// 只处理传播；规则、净化器、漏洞分类仍由上游引擎提供。
const clone = state => Object.assign(Object.create(null), state); // nosec: 仅复制本地分析器的污点映射，目标没有原型

function statements(line) {
  const parts = [];
  let start = 0, quote = '', parens = 0;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if ('\'"`'.includes(c)) { quote = c; continue; }
    if (c === '(') parens++;
    if (c === ')') parens--;
    if ((c === ';' && parens === 0) || c === '{' || c === '}') {
      parts.push({ start, end: i + 1, text: line.slice(start, i), delimiter: c });
      start = i + 1;
    }
  }
  parts.push({ start, end: line.length + 1, text: line.slice(start), delimiter: '' });
  return parts;
}

function buildFlow(lines, lang, helpers, loopSeeds = new Map(), round = 0) {
  const { sources, idsOf, codeOnly, isNoise } = helpers;
  const states = [], labels = [], frames = [];
  const loopExits = new Map();
  let state = Object.create(null);
  const sourceLabels = text => sources.filter(source => {
    source.re.lastIndex = 0;
    return source.re.test(text);
  }).map(source => source.label);
  function close() {
    const frame = frames.pop();
    if (!frame) return;
    if (frame.kind === 'function') state = frame.before;
    else if (frame.kind === 'loop') {
      loopExits.set(frame.key, clone(state));
      state = Object.assign(clone(frame.before), state);
    } else if (frame.kind === 'branch') state = Object.assign(clone(frame.before), state);
  }
  for (let ln = 0; ln < lines.length; ln++) {
    const line = lines[ln];
    const indent = line.match(/^\s*/)[0].length;
    if (lang === 'python' && line.trim()) {
      while (frames.length && indent <= frames[frames.length - 1].indent) close();
    }
    const snapshots = [];
    // sink 最多回看当前及后续 8 行；快照只保留这些表达式引用的变量，避免全表按行复制。
    const referenced = idsOf(lines.slice(ln, ln + 9).join('\n'), lang);
    labels.push(sourceLabels(line));
    for (const part of statements(line)) {
      const text = part.text.trim();
      const clean = codeOnly(text, lang);
      const functionHeader = /\b(?:function\s*[\w$]*|func\s+(?:\([^)]*\)\s*)?\w+|def\s+\w+)\s*\(/.test(clean)
        || /=>\s*$/.test(clean)
        || (['java', 'csharp'].includes(lang) && /^(?:(?:public|private|protected|static|final|async|override)\s+)*[\w<>\[\],?]+\s+\w+\s*\([^;]*\)\s*(?:throws\s+\w+)?$/.test(clean));
      const branch = /\b(?:if|else|elif|for|while|switch|case|try|catch|except|finally|do|unless)\b/.test(clean);
      if (functionHeader && (part.delimiter === '{' || /:\s*$/.test(clean) || lang === 'ruby')) {
        frames.push({ kind: 'function', before: clone(state), indent });
        state = lang === 'php' ? Object.create(null) : clone(state);
        const params = /\(([^)]*)\)/.exec(clean)?.[1] || '';
        for (const id of idsOf(params, lang)) delete state[id];
      } else {
        const opensBlock = part.delimiter === '{' || (lang === 'python' && /:\s*$/.test(clean))
          || (lang === 'ruby' && /^(?:if|unless|while|for)\b/.test(clean));
        const before = branch || opensBlock ? clone(state) : null;
        const assignment = [...clean.matchAll(/(?:^|[\s;,])([$A-Za-z_][$\w]*)(\s*(?:\[[^\]]*\])*)\s*(\+=|\.=|:=|=(?!=|>))\s*([\s\S]*)/g)].find(match => {
          const prefix = clean.slice(0, match.index);
          return (prefix.match(/\(/g) || []).length === (prefix.match(/\)/g) || []).length;
        });
        const rhs = assignment ? text.slice(assignment.index + assignment[0].length - assignment[4].length) : text;
        const hits = sourceLabels(rhs);
        const origin = hits.length ? { line: ln + 1, label: hits[0] }
          : idsOf(rhs, lang).map(id => state[id]).find(Boolean);
        if (assignment) {
          const name = assignment[1];
          if (origin) state[name] = origin;
          else if (!assignment[2].trim() && ['=', ':='].includes(assignment[3])) delete state[name];
        } else if (hits.length) {
          for (const id of idsOf(text, lang)) if (!isNoise(id)) state[id] = origin;
        }
        // 无花括号的单行条件赋值也有未执行路径。
        if (branch && assignment && part.delimiter !== '{') state = Object.assign(before, state);
        if (opensBlock) {
          const loop = /\b(?:for|while|do)\b/.test(clean);
          const key = `${ln}:${part.start}`;
          frames.push({ kind: loop ? 'loop' : branch ? 'branch' : 'block', before, indent, key });
          if (loop && loopSeeds.has(key)) state = Object.assign(clone(state), loopSeeds.get(key));
        }
      }
      const snapshot = Object.create(null);
      for (const id of referenced) if (state[id]) snapshot[id] = state[id];
      for (const source of sources) {
        source.re.lastIndex = 0;
        const match = source.re.exec(text);
        if (match) for (const id of idsOf(match[0], lang)) {
          if (!isNoise(id)) snapshot[id] = { line: ln + 1, label: source.label };
        }
      }
      snapshots.push({ start: part.start, end: part.end, state: snapshot });
      if (part.delimiter === '}' || (lang === 'ruby' && /^end\b/.test(text))) close();
    }
    states.push(snapshots);
  }
  while (frames.length) close();
  let changed = false;
  for (const [key, exit] of loopExits) {
    const seed = clone(loopSeeds.get(key));
    for (const [name, origin] of Object.entries(exit)) {
      if (!seed[name]) { seed[name] = origin; changed = true; }
    }
    loopSeeds.set(key, seed);
  }
  if (changed && round < 7) return buildFlow(lines, lang, helpers, loopSeeds, round + 1);
  return {
    sources: labels,
    at(line, offset) {
      const parts = states[line];
      return (parts.find(part => offset >= part.start && offset < part.end) || parts[parts.length - 1]).state;
    }
  };
}

function applyFlow(body) {
  const start = body.indexOf('    // 第一遍：标记 source 行，建立污点集合');
  const end = body.indexOf('    // 第三遍：sink 匹配', start);
  if (start < 0 || end < 0) throw new Error('引擎传播接口已变化，请更新 lib/flow.js 适配');
  body = body.slice(0, start) + `    var flow = buildFlow(lines, lang, { sources: sources, idsOf: idsOf, codeOnly: codeOnly, isNoise: isNoise });
    var lineSrc = flow.sources;
    var tainted;

` + body.slice(end);
  body = body.replace('      var idsL = idsOf(L, lang);', '      tainted = flow.at(ln2, 0);\n      var idsL = idsOf(L, lang);');
  body = body.replace('        var argTaint = null;', '        tainted = flow.at(ln2, mm.index);\n        var argTaint = null;');
  // 每一个调用位置都应保留，不能因共享同一来源而丢掉后续调用。
  body = body.replace("var key = S.cat + '|' + S.name + '|' + (useTaint ? useTaint.line : ln2 + 1);", "var key = S.cat + '|' + S.name + '|' + ln2;");
  return body;
}

module.exports = { buildFlow, applyFlow };
