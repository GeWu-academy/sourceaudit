'use strict';
const readline = require('node:readline');
const { scanPaths, scanCode, getEngine } = require('./scanner');
const { stats } = require('./engine');
const { version } = require('../package.json');
const { createReports } = require('./reports');

const languages = ['php', 'java', 'go', 'python', 'node', 'ruby', 'asp', 'csharp'];
const filters = {
  min_severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'], default: 'low', description: '最低显示严重度' },
  categories: { type: 'array', items: { type: 'string' }, description: '漏洞类别；可用 sourceaudit_rules 查询' },
  lang: { type: 'string', enum: languages, description: '源码语言；默认从文件名识别' },
  include_low_confidence: { type: 'boolean', default: true, description: '包含未追溯到输入来源的提示' }
};
const pageSize = { type: 'integer', minimum: 1, default: 20, description: '每页问题数；完整总数始终保留在 summary' };
const annotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const TOOLS = [
  {
    name: 'sourceaudit_scan', title: '扫描源码路径',
    description: '本地审计目录、文件或 ZIP。返回漏洞行、污点来源、修复建议和文件绝对路径。targets 使用本机绝对路径；不修改源码。',
    inputSchema: { type: 'object', properties: {
      targets: { type: 'array', minItems: 1, items: { type: 'string' }, description: '要审计的目录、文件或 ZIP 绝对路径' },
      ...filters, limit: pageSize,
      exclude: { type: 'array', items: { type: 'string' }, description: '相对目标根的 glob 排除模式，如 **/tests/**' },
      include_vendor: { type: 'boolean', default: false, description: '包含 node_modules、vendor 等目录' }
    }, required: ['targets'], additionalProperties: false }, annotations
  },
  {
    name: 'sourceaudit_scan_code', title: '审计代码片段',
    description: '直接分析对话中的代码文本。提供带后缀的 filename 或指定 lang；返回污点链与修复建议。',
    inputSchema: { type: 'object', properties: {
      code: { type: 'string', description: '待分析的完整代码文本' },
      filename: { type: 'string', description: '展示名及语言识别，例如 app.php' }, ...filters, limit: pageSize
    }, required: ['code'], additionalProperties: false }, annotations
  },
  {
    name: 'sourceaudit_rules', title: '查询审计规则',
    description: '查询内置引擎版本、各语言规则数量和可筛选的漏洞类别。',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }, annotations
  },
  {
    name: 'sourceaudit_report', title: '查看审计报告详情',
    description: '获取当前会话已扫描报告的下一页，或按文件、类别、严重度筛选。取消扫描后可用原扫描的 request_id 获取已完成部分。',
    inputSchema: { type: 'object', properties: {
      report_id: { type: 'string', description: '扫描返回的报告 ID' },
      request_id: { type: 'string', description: '原始扫描的 JSON-RPC 请求 ID，以字符串传入；与 report_id 二选一' },
      offset: { type: 'integer', minimum: 0, default: 0 }, limit: pageSize,
      file: { type: 'string', description: '报告中的 file / absolute_path / archive_entry 精确值' },
      category: { type: 'string' }, min_severity: filters.min_severity
    }, additionalProperties: false }, annotations
  },
  {
    name: 'sourceaudit_release_report', title: '释放审计报告',
    description: '释放当前 MCP 会话内的报告；不修改被扫描源码。',
    inputSchema: { type: 'object', properties: { report_id: { type: 'string' } }, required: ['report_id'], additionalProperties: false },
    annotations: { ...annotations, readOnlyHint: false }
  }
];
const reportSchema = {
  type: 'object', required: ['status', 'summary', 'findings', 'report_id', 'page'],
  properties: {
    status: { type: 'string', enum: ['complete', 'empty', 'partial', 'cancelled'] },
    summary: { type: 'object' }, findings: { type: 'array', items: { type: 'object' } },
    report_id: { type: 'string' }, page: { type: 'object' }
  }
};
for (const tool of TOOLS) tool.outputSchema = ['sourceaudit_scan', 'sourceaudit_scan_code', 'sourceaudit_report'].includes(tool.name)
  ? reportSchema : { type: 'object' };
const VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

function validateArguments(tool, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('arguments 必须为对象');
  for (const key of tool.inputSchema.required || []) {
    if (!(key in args)) throw new Error(`缺少参数 ${key}`);
  }
  for (const [key, value] of Object.entries(args)) {
    const field = tool.inputSchema.properties[key];
    if (!field) throw new Error(`未知参数 ${key}`);
    if (field.type === 'array') {
      if (!Array.isArray(value) || value.some(item => typeof item !== 'string') || value.length < (field.minItems || 0)) throw new Error(`${key} 必须为字符串数组`);
    } else if (field.type === 'integer') {
      if (!Number.isInteger(value) || value < field.minimum) throw new Error(`${key} 必须为不小于 ${field.minimum} 的整数`);
    } else if (typeof value !== field.type) throw new Error(`${key} 必须为 ${field.type}`);
    if (field.enum && !field.enum.includes(value)) throw new Error(`${key} 取值无效：${value}`);
  }
}

function createSession(notify = () => {}) {
  const reports = createReports(), active = new Map();
  async function handle(message) {
    if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') return rpcError(message?.id ?? null, -32600, 'Invalid Request');
    const { id, method, params = {} } = message;
    if (method === 'notifications/cancelled') {
      active.get(String(params.requestId))?.controller.abort();
      return null;
    }
    if (id === undefined) return null;
    let result;
    if (method === 'initialize') {
      result = {
        protocolVersion: VERSIONS.includes(params.protocolVersion) ? params.protocolVersion : VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'sourceaudit', version },
        instructions: '本地源码审计。先查看 status 和 diagnostics；默认返回前 20 条问题，用 sourceaudit_report 分页。报告保存在当前会话，使用完可释放。静态命中需结合上下文核实。'
      };
    } else if (method === 'ping') result = {};
    else if (method === 'tools/list') result = { tools: TOOLS };
    else if (method === 'tools/call') {
      const tool = TOOLS.find(t => t.name === params.name);
      if (!tool) return rpcError(id, -32602, `未知工具：${params.name}`);
      let operation;
      try {
        const args = params.arguments || {};
        validateArguments(tool, args);
        let report;
        if (['sourceaudit_scan', 'sourceaudit_scan_code'].includes(tool.name)) {
          let finish;
          operation = { controller: new AbortController(), done: new Promise(resolve => { finish = resolve; }), finish: () => finish() };
          active.set(String(id), operation);
          let lastProgress = -1;
          const progressToken = params._meta?.progressToken;
          const options = {
            minSev: args.min_severity ?? 'low', cats: args.categories, lang: args.lang,
            lowconf: args.include_low_confidence ?? true, exclude: args.exclude ?? [], vendor: args.include_vendor ?? false,
            filename: args.filename, signal: operation.controller.signal,
            onProgress(update) {
              if (progressToken === undefined || operation.controller.signal.aborted || update.processed <= lastProgress) return;
              lastProgress = update.processed;
              notify({ jsonrpc: '2.0', method: 'notifications/progress', params: {
                progressToken, progress: update.processed,
                message: `已扫描 ${update.files} 个文件，跳过 ${update.skipped} 个` + (update.current_file ? ` · ${update.current_file}` : '')
              } });
            }
          };
          const full = tool.name === 'sourceaudit_scan' ? await scanPaths(args.targets, options) : scanCode(args.code, options);
          const report_id = reports.save(full, id);
          report = reports.page({ report_id, limit: args.limit });
          // 标准取消通知不响应原请求；已完成部分可通过 request_id 显式读取。
          if (operation.controller.signal.aborted) return null;
        } else if (tool.name === 'sourceaudit_report') {
          if (args.request_id) await active.get(args.request_id)?.done;
          report = reports.page(args);
        } else if (tool.name === 'sourceaudit_release_report') report = reports.release(args.report_id);
        else {
          const engine = getEngine();
          report = { engine_version: engine.VERSION, ...stats(engine), languages: engine.LANG_LABEL, category_labels: engine.CAT_LABEL };
        }
        result = { content: [{ type: 'text', text: JSON.stringify(report) }], structuredContent: report, isError: ['partial', 'cancelled'].includes(report.status) };
      } catch (error) {
        result = { content: [{ type: 'text', text: error.message }], isError: true };
      } finally {
        if (operation) { active.delete(String(id)); operation.finish(); }
      }
    } else return rpcError(id, -32601, `Method not found: ${method}`);
    return { jsonrpc: '2.0', id, result };
  }
  return { handle, close() { reports.clear(); } };
}

async function serve(input = process.stdin, output = process.stdout) {
  const send = response => { if (response) output.write(JSON.stringify(response) + '\n'); };
  const session = createSession(send);
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  const pending = new Set();
  function dispatch(message) {
    const work = (Array.isArray(message)
      ? Promise.all(message.map(request => session.handle(request))).then(responses => { const valid = responses.filter(Boolean); if (valid.length) send(valid); })
      : session.handle(message).then(send));
    pending.add(work);
    work.finally(() => pending.delete(work));
  }
  try {
    for await (const line of lines) {
      if (!line.trim()) continue;
      let message;
      try { message = JSON.parse(line); }
      catch { send(rpcError(null, -32700, 'Parse error')); continue; }
      dispatch(message);
    }
    await Promise.all(pending);
  } finally { session.close(); }
}

module.exports = { serve, createSession, TOOLS };
