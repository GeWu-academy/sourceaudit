# 忆涟千言接入说明

Sourceaudit 1.2.0 提供声明式插件和独立 stdio MCP 服务。CLI、Node API 和 MCP 使用同一个扫描核心及内置 LingOps 引擎。

## 本机安装

在 Sourceaudit 仓库目录执行：

```powershell
npm run package:yilian
```

不需要安装 npm 依赖。生成：

- `dist/yilian/sourceaudit-yilian-1.2.0.zip`：根目录为 `plugin.json`，包含源码审计 Skill 和“更多功能 / 工作区”入口。
- `dist/yilian/sourceaudit-mcp.json`：忆涟千言“单个 MCP 服务 JSON”导入格式，`enabled:false`；启动命令为当前 Node 可执行文件绝对路径，参数为 MCP 入口绝对路径。

生成配置指向当前源码安装目录，ZIP 不复制 Node 或执行文件。保留该目录；移动目录、切换 Node 或迁移机器后，在目标位置重新生成。

1. 打开忆涟千言能力中心的导入页面（`/capabilities?category=import`），通过受管包导入上传 ZIP，检查预览后安装并启用插件。
2. 在同页选择“单个 MCP 服务 JSON”，粘贴 `sourceaudit-mcp.json` 的完整内容并导入。不要用 `mcpServers` 包装；宿主此入口读取单个服务对象。
3. 进入 MCP 管理，选择“Sourceaudit 源码审计”，连接并刷新工具目录。
4. 目录应出现 `sourceaudit_scan`、`sourceaudit_scan_code`、`sourceaudit_rules`、`sourceaudit_report`、`sourceaudit_release_report`。从“源码审计”功能入口进入对话，或直接要求审计代码。

导入模板、启用插件和连接 MCP 是不同操作。只有连接成功、工具目录可用后才能执行审计。无需修改宿主源码。

## 调用示例

路径扫描：

```json
{
  "targets": ["F:/my-project/src"],
  "min_severity": "high",
  "exclude": ["**/tests/**"],
  "include_low_confidence": false
}
```

代码片段：

```json
{
  "filename": "app.php",
  "code": "<?php\n$id = $_GET['id'];\nmysqli_query($conn, $id);"
}
```

路径扫描参数支持 `categories`、`lang`、`include_vendor`；`sourceaudit_rules` 不需要参数。优先读取 MCP `structuredContent`，兼容客户端也可解析 `content[0].text`。工具声明含 `outputSchema`。

工具仅读取目标源码，不执行目标代码、不发起网络请求、不自动写入修复。读取权限沿用启动进程的本机权限；插件不额外实现路径沙箱或权限策略。引擎路径固定为包内引擎，MCP 不暴露 CLI 的 `--engine` 参数。

## 分页、进度与取消

扫描默认返回 20 条问题，可设置 `limit`。`summary` 始终是该次扫描的完整总计；`page.total` 是当前页筛选条件下的总数，`page.has_more` 指示是否还有下一页。CLI 与 Node API 仍返回完整报告。

调用 `sourceaudit_report` 获取详情：

```json
{"report_id":"扫描结果返回的 ID","offset":20,"limit":20}
```

可附加 `file`（精确匹配报告 file/absolute_path/archive_entry）、`category`、`min_severity`。不需要重新读取源码。调用 `sourceaudit_release_report` 并传入 `report_id` 可释放报告；报告仅保存在当前 MCP 会话内存中，断开后不可跨会话恢复。

客户端在工具调用 `params._meta.progressToken` 中给出 token，服务通过 `notifications/progress` 返回已处理数和当前文件。在扫描文件之间可处理 ping 与取消。标准取消为 `notifications/cancelled`，参数 `requestId` 使用原始 JSON-RPC 请求 ID；取消后不响应原请求。需要已完成部分时，调用 `sourceaudit_report` 并传 `request_id`（原 ID 的字符串形式），报告会标记 `cancelled`。

CLI 在交互终端显示进度，Ctrl+C 后输出已完成报告，退出码 130；`-q` 关闭进度。Node API 调用示例：

```js
const controller = new AbortController();
const report = await scanPaths(paths, {
  signal: controller.signal,
  onProgress: update => console.error(update.files, update.current_file)
});
```

取消在文件之间生效；单个文件的同步分析及正在进行的一次解压需要先结束。源码片段分析仍同步执行。这里实现了协议能力，宿主 UI 是否展示进度或主动发送取消还取决于其调用方，未宣称宿主界面已增加进度控件。

## 结果解释

- `status: complete`：已完成扫描；没有命中只表示当前筛选和分析能力下没有发现。
- `status: empty`：没有可分析的源码文件；检查目录、文件后缀和筛选设置。
- `status: cancelled`：扫描被取消，仅包含已完成部分；查询该报告时 MCP 返回 `isError:true`。
- `status: partial`：部分读取、ZIP 解析或分析失败；`diagnostics` 给出路径及原因，成功扫描部分仍返回。MCP 此时返回 `isError:true`，CLI 返回退出码 2。
- `files` 是成功分析的文件数。`skipped` 是遍历中遇到但被过滤的文件数，不展开计数被整目录排除的内容。
- 本地命中包含 `absolute_path` 与 `target`；ZIP 命中包含 `archive_path` 与 `archive_entry`，包内文件不落盘。
- 重叠路径和重复目标不会重复扫描本地文件。单目标显示相对路径；多目标显示完整路径，避免同名文件混淆。
- 报告保留原有 `source`、`fix`、`sanitized`、`rule` 字段。`awdpplus-lowconf` 需要结合上下文核实。

上游引擎副本与规则指纹不变；报告额外提供 `analysis_revision: sourceaudit-flow-1`。传播模块按语句顺序维护状态、隔离常见函数局部变量、合并条件分支，并进行最多 8 轮循环传播。它不是完整 AST/控制流图分析，复杂闭包、动态调用与特殊多行语法仍需结合上下文复核。

支持 PHP、Java/JSP、Go、Python、Node.js/TypeScript、Ruby、ASP/ASPX、C#；不支持 Rust 语义分析，也没有跨文件数据流。审计忆涟千言自身时可覆盖受支持的前端源码，不能把该结果当作 Rust 后端审计结论。

## 协议与验证范围

宿主源码核对基线：`2817d110b945c2d919aa3019fed458388ae799fc`，核对时间 2026-11-12；工作区源码为实际接口依据，提交号不代表工作区无改动。

- `backend/src/plugin/manifest.rs`：schema_version 1、Skill 路径、功能入口、MCP 模板。
- `frontend/src/features/capabilities/StructuredImport.tsx`：单服务 JSON 导入且保持停用。
- `backend/src/integrations/mcp/transport/stdio.rs`：先请求 `server/discover`，收到 -32601 后调用 `initialize`，协议 `2025-11-25`。

进度与取消遵循 [MCP Progress](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress) 和 [MCP Cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation)。

实现遵循 [MCP stdio 传输](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)、[初始化与协商](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) 和 [工具调用](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) 格式。也支持协商 2025-06-18、2025-03-26、2024-11-05；不宣称实现宿主 2026-07-28 扩展，使用其已有兼容分支。

运行 `npm test` 验证原有语料及新增 CLI/API/ZIP/MCP/打包测试。MCP 测试通过真实 Node 子进程执行宿主相同的探测、初始化、工具发现和调用顺序；生成配置还在不同工作目录下启动验证。

2026-11-12 本机验证结果：

| 检查 | 结果 |
| --- | --- |
| Windows / Node 24.15.0，`npm test` | 原有 104 个计分语料及 CLI 冒烟通过；35 项集成测试通过 |
| Windows / Node 18，`npm exec --yes --package=node@18 -- npm test` | 同一完整测试集通过 |
| 原有已知盲区 | 1 个，不计入 104 项通过数 |
| 自扫 `bin lib scripts test/run.js --fail-on low` | 11 个文件、0 命中、退出码 0 |
| 插件 ZIP | Python 标准库独立读取及 CRC 校验通过，根清单和 Skill 路径正确 |
| npm 包 | 包含扫描 API、流分析、ZIP 读取器、分页报告、MCP 入口、插件资源和接入说明 |
| 引擎 SHA-256 | `e46ac1879f5d7fcf438a4d9c673622d442b11130129b5adfaa63ef8cbecca791`，与原有 ENGINE.json 一致 |
| 差异格式 | `git diff --check` 通过 |

Windows 检出曾把引擎换行转换为 CRLF；已用 `.gitattributes` 固定 LF，保持上游内容和字节指纹一致。CI 已添加 Windows/Ubuntu × Node 18/20/22 矩阵；该矩阵尚未推送执行，本机通过不代表远端 CI 已通过。

当前完成代码契约核对和本机进程级验证，尚未在忆涟千言运行界面内导入、启用插件并完成模型对话调用。宿主界面安装、授权状态及模型选择工具的效果需与上述测试分开判断。

## 停用和卸载

先在 MCP 管理断开/停用并删除 Sourceaudit 服务，再停用/卸载声明式插件。插件卸载不代替删除独立 MCP 配置。最后按需移除本地源码安装目录，审计目标源码不受影响。
