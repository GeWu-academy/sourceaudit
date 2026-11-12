---
name: sourceaudit
description: 审计本地源码目录、文件、ZIP 或对话中的代码片段，解释污点来源和修复建议。需要已连接的 Sourceaudit MCP 服务。
---

# 源码审计

当用户希望审查代码漏洞、定位危险调用或了解修复方式时使用。

1. 从当前请求确定审计对象。已有明确路径或代码就直接使用；缺少对象时询问源码路径或代码片段。
2. 在宿主当前工具目录找到 Sourceaudit 服务的工具（实际工具名可能带宿主前缀）：
   - `sourceaudit_scan`：传入 `targets` 绝对路径数组；支持目录、单文件和 ZIP。可按 `min_severity`、`categories`、`lang` 筛选，使用 `exclude` 排除测试或生成代码。
   - `sourceaudit_scan_code`：传入 `code`，以及带后缀的 `filename` 或 `lang`。
   - `sourceaudit_rules`：查询支持的语言和漏洞类别。
   - `sourceaudit_report`：使用 `report_id` 读取后续页，支持 `offset`、`limit`、精确 `file`、`category`、`min_severity`。默认每页 20 条；`summary` 是原扫描总计，`page.total` 是当前过滤后的总数，不能用本页条数代替总数。
   - `sourceaudit_release_report`：用户结束本次查看后释放会话内报告，不修改源码。
3. 优先读取 `structuredContent`；兼容客户端也可解析 `content[0].text`。先检查 `status`、`files`、`diagnostics`。`partial` 表示部分失败，应列出失败文件；`empty` 表示没有扫到可分析文件，不能报告“代码安全”；`cancelled` 表示用户取消，仅展示已完成部分。
4. 按严重度呈现结果，每条包含文件与行号、问题类型、代码行、污点来源和 `fix`。本地文件使用 `absolute_path` 定位；ZIP 使用 `archive_path` 与 `archive_entry`。代码片段的行号以传入文本为准。
5. 区分完整污点链、静态特征和低置信命中。静态分析发现需要结合上下文确认，不宣称已经验证可利用。保留用户选择的语言、类别和严重度筛选条件。
6. 用户只要求审计时返回报告；用户要求修复时依据问题位置修改并复扫。

支持进度通知的客户端可在工具调用 `_meta.progressToken` 中指定 token。取消使用 `notifications/cancelled` 及原始请求 ID，原请求不再响应；客户端知道该 ID 时可用 `sourceaudit_report` 的 `request_id`（字符串）获取已完成部分。报告仅在当前服务会话内有效，断开重连后需重新扫描。

本工具覆盖 PHP、Java/JSP、Go、Python、Node.js/TypeScript、Ruby、ASP/ASPX、C#。不支持 Rust 语义审计，也不做跨文件数据流分析。

若工具目录没有 Sourceaudit 服务，说明尚未完成连接。引导用户在能力中心导入生成的 `sourceaudit-mcp.json`，再到 MCP 管理中连接；插件包安装或模板出现不等于工具已连接。
