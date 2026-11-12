'use strict';
const { randomUUID } = require('node:crypto');
const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function createReports() {
  const reports = new Map(), requests = new Map();
  return {
    save(report, requestId) {
      const id = randomUUID();
      reports.set(id, report);
      requests.set(String(requestId), id);
      return id;
    },
    page(args) {
      const id = args.report_id || requests.get(args.request_id);
      const report = reports.get(id);
      if (!report) throw new Error('报告不存在或已释放；请重新扫描');
      const filtered = report.findings.filter(f => !args.file || [f.file, f.absolute_path, f.archive_entry].includes(args.file))
        .filter(f => !args.category || f.cat === args.category)
        .filter(f => !args.min_severity || ORDER[f.sev] <= ORDER[args.min_severity]);
      const offset = args.offset ?? 0, limit = args.limit ?? 20;
      return { ...report, report_id: id, findings: filtered.slice(offset, offset + limit),
        page: { offset, limit, total: filtered.length, has_more: offset + limit < filtered.length } };
    },
    release(id) {
      const released = reports.delete(id);
      for (const [request, report] of requests) if (report === id) requests.delete(request);
      return { report_id: id, released };
    },
    clear() { reports.clear(); requests.clear(); }
  };
}
module.exports = { createReports };
