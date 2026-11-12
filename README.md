# sourceaudit

[![CI](https://github.com/GeWu-academy/sourceaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/GeWu-academy/sourceaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%E2%89%A518-brightgreen)

> 源码审计，逐行溯源。

**本地源码审计工具，提供 CLI、Node.js API 和 stdio MCP 服务。** 支持目录、单文件、ZIP 和代码片段，返回问题位置、污点来源与修复建议，可用于代码复核、AWD/AWDP 源码检查和 CI。

- **331 条规则**：66 条污点来源、212 条危险调用、53 条静态特征，覆盖 26 类问题。
- **8 种语言**：PHP、Java/JSP、Go、Python、Node.js/TypeScript、Ruby、ASP/ASPX、C#。
- **零 npm 依赖**，Node.js ≥ 18；扫描不联网、不执行目标代码。
- 输出文本或 JSON，支持筛选、排除、进度、取消和 CI 退出码。
- 可接入支持 stdio 的 MCP 客户端，并生成忆涟千言声明式插件包。

规则来自 [LingOps](https://github.com/GeWu-academy/LingOps-Enhanced) 的深度审计引擎。上游副本保存在 `engine/awdpplus.js`；本项目在加载时接入顺序污点传播模块，继续复用上游的规则、危险调用匹配和净化器。

## 目录

- [1. 1.2.0 更新](#1-120-更新)
- [2. 安装与快速开始](#2-安装与快速开始)
- [3. CLI 选项](#3-cli-选项)
- [4. 扫描范围与排除规则](#4-扫描范围与排除规则)
- [5. 报告与退出码](#5-报告与退出码)
- [6. Node.js API](#6-nodejs-api)
- [7. MCP 与忆涟千言](#7-mcp-与忆涟千言)
- [8. CI 集成与测试](#8-ci-集成与测试)
- [9. 规则与引擎同步](#9-规则与引擎同步)
- [10. 能力边界](#10-能力边界)
- [11. 项目结构](#11-项目结构)
- [许可与致谢](#许可与致谢)

## 1. 1.2.0 更新

| 方面 | 行为 |
| --- | --- |
| 污点传播 | 按语句顺序处理覆盖赋值、别名和常见函数作用域；合并条件分支并保留循环迭代的数据流 |
| 多目标扫描 | 重复、重叠目标只分析一次；不同目标的同名文件保留可区分的位置 |
| ZIP | 先筛选、后逐条读取和解压；无法处理的源码条目进入诊断，不再静默记为扫描完成 |
| 排除规则 | 修复 `**/` 零层匹配与 `?` 单层匹配；目录和 ZIP 共用父目录排除语义 |
| 报告 | 展示修复建议、低置信说明和完整路径，区分完成、空扫描、部分失败、取消 |
| 交互 | CLI 显示进度并支持 Ctrl+C；MCP 支持结构化结果、分页、进度与取消 |
| 兼容性 | Windows/Ubuntu CI 矩阵覆盖 Node 18/20/22；ZIP 解压使用 Node 原生 zlib |

例如，以下代码不应将第 4 行的输入作为第 3 行调用的污点来源：

```php
<?php
$x = 'fixed';
system($x);
$x = $_GET['x'];
```

1.2.0 修复了这类严重误报。低置信提示仍应结合上下文复核，静态分析结果不等于漏洞已被证实可利用。

## 2. 安装与快速开始

要求 **Node.js ≥ 18**。Windows、Linux 和 macOS 均可使用 `node` 启动。以下从源码安装，不依赖 npm 注册表中是否已发布对应版本。

```bash
git clone https://github.com/GeWu-academy/sourceaudit.git
cd sourceaudit

# 无需 npm install，即可扫描仓库中的样例
node bin/sourceaudit.js test/corpus/vuln --fail-on none

# 扫描自己的项目或源码包
node bin/sourceaudit.js ./src -s high
node bin/sourceaudit.js challenge.zip -f json -o report.json
```

如需全局命令，在仓库目录执行：

```bash
npm install -g .
sourceaudit ./src
```

也可将本地源码安装为另一个项目的开发依赖：

```bash
npm install --save-dev /path/to/sourceaudit
npx sourceaudit ./src -s high
```

发现达到阈值的问题时默认返回退出码 1。只想查看结果时使用 `--fail-on none`；参数错误和扫描失败仍返回非零退出码。

## 3. CLI 选项

```text
sourceaudit <目录|文件|ZIP> [更多路径...] [选项]
```

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `-f, --format <text\|json>` | `text` | 报告格式 |
| `-s, --min-sev <级别>` | `low` | `critical`、`high`、`medium`、`low` |
| `-c, --cat <类别>` | 全部 | 逗号分隔，例如 `rce,sqli,xss` |
| `-l, --lang <语言>` | 自动识别 | `php`、`java`、`go`、`python`、`node`、`ruby`、`asp`、`csharp` |
| `--exclude <glob>` | 无 | 排除相对路径，可重复 |
| `--vendor` | 关闭 | 包含默认跳过的第三方或构建目录 |
| `--no-lowconf` | 关闭 | 不输出未追溯到污点来源的低置信提示 |
| `--fail-on <级别\|none>` | `high` | 达到阈值时退出码 1，`none` 关闭命中阈值 |
| `--engine <路径>` | 内置引擎 | 指定兼容的本地引擎文件 |
| `--list-rules` | — | 输出各语言的规则统计 |
| `-o, --out <文件>` | 无 | 同时保存报告，文本文件不含 ANSI 颜色码 |
| `-q, --quiet` | 关闭 | 文本格式仅输出汇总，关闭进度；错误诊断仍输出 |
| `--no-color` | 关闭 | 关闭颜色；重定向或设置 `NO_COLOR` 时也自动关闭 |
| `-v, --version` | — | 显示工具和上游引擎版本 |
| `-h, --help` | — | 显示帮助 |
| `--` | — | 后续参数全部视为目标路径，适用于以 `-` 开头的文件名 |

```bash
sourceaudit ./app ./services -s high --no-lowconf
sourceaudit ./src -c rce,sqli --exclude '**/tests/**'
sourceaudit -f json --fail-on none -- -example.php
```

## 4. 扫描范围与排除规则

- 按后缀识别支持的源码。JavaScript、TypeScript、JSX、TSX 使用 `node` 语言规则。
- 默认跳过 `node_modules`、`vendor`、`.git`、`dist`、`build`、`target`、`.idea`、`.vscode`、`__pycache__`、`bower_components`、`.next`、`coverage` 目录；`--vendor` 可包含这些目录。
- 跳过非源码后缀、单文件大于 3 MiB 的内容以及解码后包含 NUL 的二进制内容。
- ZIP 内容不解压到磁盘。支持 Store 和 Deflate；不支持的源码压缩方式、加密条目等会产生诊断。ZIP64 不受支持。
- ZIP 在解压前应用路径、语言、文件大小等筛选，被排除的条目无需解压。

`--exclude` 使用 glob：`*` 匹配单层，`**` 可跨目录，`?` 匹配单个非目录分隔字符，`**/` 可匹配零层目录。模式相对于每个目标根，父目录命中后其子文件也被排除。

```bash
sourceaudit . --exclude 'tests' --exclude '**/*.min.js'
sourceaudit challenge.zip --exclude 'tests/' --exclude '**/fixtures/**'
```

`tests` 与 `tests/` 都能排除目标根下的测试目录；任意层级的测试目录可用 `**/tests/**`。

## 5. 报告与退出码

文本报告按严重度、文件和行号排序，展示代码行、污点来源及修复建议。交互终端显示扫描进度；Ctrl+C 保留已完成部分，取消在文件处理边界生效。

JSON 报告示意如下，路径、耗时和源码内容以实际扫描为准：

```json
{
  "tool": "sourceaudit",
  "version": "1.2.0",
  "engine_version": "1.3.9",
  "analysis_revision": "sourceaudit-flow-1",
  "engine": "/tools/sourceaudit/engine/awdpplus.js",
  "targets": ["/project/src/app.php"],
  "files": 1,
  "skipped": 0,
  "status": "complete",
  "diagnostics": [],
  "langStr": "PHP×1",
  "elapsed_ms": 20,
  "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1},
  "findings": [{
    "file": "app.php",
    "absolute_path": "/project/src/app.php",
    "target": "/project/src/app.php",
    "lang": "php",
    "line": 4,
    "cat": "sqli",
    "sev": "critical",
    "name": "SQL 执行",
    "fix": "使用预处理语句绑定参数",
    "sanitized": false,
    "source": {"line": 2, "label": "$_GET/$_POST 数组取值", "varName": "$q", "code": "$id = $_GET['id'];"},
    "code": "$r = mysqli_query($conn, $q);",
    "rule": "awdpplus"
  }]
}
```

| `status` | 含义 |
| --- | --- |
| `complete` | 本次扫描完成；没有命中表示当前筛选与分析能力下没有发现 |
| `empty` | 没有可分析的文件，应检查路径、文件后缀和筛选条件 |
| `partial` | 存在读取、解压或分析失败；成功部分保留，原因见 `diagnostics` |
| `cancelled` | 用户取消；仅包含已完成部分 |

`files` 是成功分析的文件数；`skipped` 不展开统计被整目录排除的子文件。本地问题包含 `absolute_path` 和 `target`；ZIP 问题包含 `archive_path` 与 `archive_entry`。单目标通常显示相对文件名，多目标显示可区分的完整路径。

`rule` 区分结果类型：`awdpplus` 表示追踪到污点来源，`awdpplus-static` 表示静态特征命中，`awdpplus-lowconf` 表示未追踪到来源。三者都需要结合实际代码上下文判断。

| 退出码 | 含义 |
| --- | --- |
| `0` | 没有达到 `--fail-on` 阈值的问题；空扫描也可能返回 0，应同时检查状态 |
| `1` | 当前筛选结果中存在达到阈值的问题 |
| `2` | 参数、引擎加载或扫描错误，包含部分扫描失败 |
| `130` | 用户取消扫描 |

严重度和类别筛选同时影响展示与阈值判断。`--fail-on none` 不会把读取失败或取消改成成功。

## 6. Node.js API

在仓库根目录使用 `require('.')`；安装为依赖后使用 `require('sourceaudit')`。API 返回完整报告，不分页。

```js
const { scanPaths, scanCode } = require('.');

async function main() {
  const controller = new AbortController();
  const report = await scanPaths(['./src'], {
    minSev: 'high',
    cats: ['sqli', 'rce'],
    exclude: ['**/tests/**'],
    lowconf: false,
    signal: controller.signal,
    onProgress: update => console.error(update.files, update.current_file)
  });
  console.log(report.status, report.summary);

  const snippet = scanCode("<?php\n$id = $_GET['id'];\nmysqli_query($conn, $id);", {
    filename: 'app.php'
  });
  console.log(snippet.findings);
}

main().catch(error => { console.error(error); process.exitCode = 1; });
```

共同筛选参数为 `minSev`、`cats`、`lang`、`lowconf`。`scanPaths` 另外接受 `exclude`、`vendor`、`engine`、`signal`、`onProgress`；`scanCode` 使用 `filename` 推断语言，也可直接指定 `lang`，同步返回结果。调用 `controller.abort()` 可取消路径扫描，当前文件处理结束后生效。

## 7. MCP 与忆涟千言

### stdio MCP

客户端使用 Node 可执行文件和 MCP 入口的绝对路径启动服务：

```text
command: /absolute/path/to/node
args: ["/absolute/path/to/sourceaudit/bin/sourceaudit-mcp.js"]
```

Windows 使用对应的 `node.exe` 路径。服务通过 stdin/stdout 交换 JSON-RPC，stdout 不输出普通日志；扫描结果在 `structuredContent` 和兼容的 `content[0].text` 中返回。支持协商 2025-11-25、2025-06-18、2025-03-26、2024-11-05。

| 工具 | 用途 |
| --- | --- |
| `sourceaudit_scan` | 扫描本机目录、文件或 ZIP，`targets` 为路径数组 |
| `sourceaudit_scan_code` | 分析 `code`，通过 `filename` 或 `lang` 指定语言 |
| `sourceaudit_rules` | 查询规则数量、支持的语言和类别 |
| `sourceaudit_report` | 按报告 ID 分页，或按文件、类别、严重度筛选 |
| `sourceaudit_release_report` | 释放当前会话内的报告 |

MCP 参数使用 `min_severity`、`categories`、`include_low_confidence`、`include_vendor` 等命名，与 Node API 的参数名不同。扫描默认返回 20 条问题；`summary` 是扫描总计，`page.total` 是当前过滤后的总数，`page.has_more` 表示是否还有下一页。

```json
{"report_id":"扫描返回的 ID","offset":20,"limit":20}
```

报告只存在于当前 MCP 会话内存中。调用方可传入 `_meta.progressToken` 接收进度；取消使用 `notifications/cancelled` 和原请求 ID。取消后原请求不再响应，已完成部分可通过 `sourceaudit_report` 的字符串参数 `request_id` 获取。

### 忆涟千言插件

在仓库目录执行：

```bash
npm run package:yilian
```

生成以下本机制品：

- `dist/yilian/sourceaudit-yilian-1.2.0.zip`：声明式插件，包含源码审计 Skill、功能入口与 MCP 模板。
- `dist/yilian/sourceaudit-mcp.json`：单个 MCP 服务导入配置，默认 `enabled:false`。

在忆涟千言能力中心导入并启用 ZIP，再通过“单个 MCP 服务 JSON”导入配置，进入 MCP 管理连接并刷新工具。插件安装、模板出现与服务连接是不同状态。

配置绑定生成时的 Node 和源码绝对路径；ZIP 不包含 Node 或服务程序。请保留源码目录，移动目录或迁移机器后重新生成。详细步骤、分页和取消示例见 [忆涟千言接入说明](docs/yilian-integration.md)。

目前已验证宿主源码接口与本机 MCP 进程调用；宿主界面中的实际导入、启用和模型对话调用尚未验证。

## 8. CI 集成与测试

```yaml
name: source audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: '22'
      # 本例在 sourceaudit 仓库执行；接入其他项目时先安装本工具。
      - run: node bin/sourceaudit.js bin lib scripts test/run.js -s high -f json -o report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sourceaudit-report
          path: report.json
```

测试命令：

```bash
npm test                 # 全部语料、CLI 冒烟及集成测试
npm run test:integration # CLI/API/污点流/ZIP/MCP/打包测试
npm run test:verbose     # 逐文件显示语料中的误报和漏报
node test/run.js --json  # 语料与 CLI 冒烟的机器可读结果
```

仓库有 105 个语料样本，其中 104 个计分、1 个已知盲区不计分：

| 语料集 | 计分样本 | 验证内容 |
| --- | ---: | --- |
| `vuln` | 34 | 典型漏洞能够命中 |
| `safe` | 27 | 已知安全写法不产生误报 |
| `regress` | 12 | 历史问题回归 |
| `modern` | 17 | 新框架与语法场景 |
| `adversarial` | 14 | 对抗写法达到高危及以上；另有 1 个已知盲区 |

1.2.0 本机验证：Windows Node 18、Node 24 均通过上述语料、CLI 冒烟和 35 项集成测试。测试覆盖顺序赋值、作用域、循环传播、ZIP 跳过与诊断、分页、真实 stdio 调用、进度取消和插件打包。测试集通过不代表所有源码都能正确分类。

仓库 CI 配置 Windows/Ubuntu × Node 18/20/22，并检查源码自扫与上游引擎指纹；实际执行状态以 PR 的 Checks 为准。

## 9. 规则与引擎同步

```bash
node bin/sourceaudit.js --list-rules
npm run sync-engine -- /path/to/LingOps-package
node scripts/sync-engine.js --check
node scripts/sync-engine.js --dry-run
```

默认可从同级 LingOps 包目录探测来源，或通过 `LINGOPS_HOME` 指定。同步脚本读取包内 `frontend/dist/assets_v2/lp-ext/awdpplus.js`，比较 SHA-256，验证加载接口，更新引擎及 `ENGINE.json`；发生更新后运行语料和适配测试，`--no-test` 可跳过。

`engine/awdpplus.js` 保持上游内容，使用 LF 换行保证 Windows 检出后的字节指纹一致。规则变更应修改上游后同步；本地顺序传播在 `lib/flow.js` 维护，加载适配在 `lib/engine.js`。上游结构变化时需更新适配并重跑测试。报告分别记录 `engine_version` 与 `analysis_revision`。

已确认的误报可在命中行或上一行加注释：

```php
// lingops:ignore 已人工核实此处的路径来源
$data = file_get_contents($path);
```

忽略标记会从报告和统计中移除该命中，应在复核后使用。仓库内的 `nosec` 注释也按这一机制解释。

## 10. 能力边界

- 只做静态分析，不执行目标代码，不验证运行期可利用性。
- 使用轻量语义分析，非完整 AST 或控制流图；循环传播最多 8 轮。复杂闭包、动态调用、特殊多行语法可能需要人工核实。
- 不做跨文件数据流，不自动识别任意自定义框架封装。
- 不支持 Rust 语义审计。扫描忆涟千言前端的结果不能代表其 Rust 后端。
- 已知盲区：无类型信息时，JavaScript `obj[k] = v` 与 `arr[i] = x` 难以区分，对应样本仅产生低置信提示。
- 取消在文件之间生效；单文件同步分析或正在进行的一次解压需先结束。
- 读取范围沿用当前进程的本机权限。CLI 的 `--engine` 会执行用户选择的引擎代码；MCP 使用固定内置引擎，不提供该参数。

## 11. 项目结构

```text
sourceaudit/
├── bin/
│   ├── sourceaudit.js          # CLI 参数、报告、进度与退出码
│   └── sourceaudit-mcp.js      # stdio 服务入口
├── lib/
│   ├── engine.js              # 上游引擎加载与规则统计
│   ├── flow.js                # 顺序、作用域和循环传播
│   ├── scanner.js             # 路径与代码扫描 API
│   ├── zip-reader.js          # ZIP 枚举及按需解压
│   ├── reports.js             # 会话报告、分页和释放
│   └── mcp.js                 # MCP 工具、进度和取消
├── engine/                    # 上游引擎副本与 ENGINE.json
├── plugin/                    # 忆涟千言清单和 Skill
├── scripts/
│   ├── sync-engine.js         # 上游规则同步
│   └── package-yilian.js      # 插件与本机 MCP 配置生成
├── test/                      # 语料与集成测试
├── docs/yilian-integration.md # 忆涟千言接入说明
└── package.json
```

## 许可与致谢

本项目使用 [MIT License](LICENSE)，由 [GeWu-academy](https://github.com/GeWu-academy/sourceaudit) 维护。引擎与规则来自 [LingOps](https://github.com/GeWu-academy/LingOps-Enhanced)，感谢原作者 zhanglinglingc 与相关贡献者。

请在自己拥有或已获授权的源码上使用。
