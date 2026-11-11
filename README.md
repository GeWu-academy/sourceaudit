# sourceaudit

[![CI](https://github.com/GeWu-academy/sourceaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/GeWu-academy/sourceaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%E2%89%A518-brightgreen)

> 源码审计，逐行溯源。

**源码漏洞审计命令行工具。** 给它一个目录、一个文件、或者一个 zip，它会告诉你：**哪一行有问题、这个变量从哪来、该怎么修。**

为 AWD / AWDP 那种「几十分钟内必须揪出对手能打穿的洞」的场景打造，也适用于日常代码审计和 CI 卡口。

- 跨行污点分析，不是「正则匹配关键词」——`$q = $_GET['id']` 拼进第 4 行的 `mysqli_query()`，能追出来
- **331 条规则**（污点来源 66 / 危险函数 212 / 静态特征 53），**26 类漏洞**，**8 种语言**（PHP / Java / Go / Python / Node.js / Ruby / ASP / C#）
- 目录、单文件、`.zip` 直接吃，**零 npm 依赖**，只要 Node ≥ 18
- 输出彩色文本 / JSON，退出码可挂 CI
- 引擎来自 [LingOps](https://github.com/GeWu-academy/LingOps-Enhanced) 的「🔬 深度审计」，本项目自带一份副本，**规则只有一份，不存在两套实现漂移**

```
$ sourceaudit ./src -s critical

sourceaudit 1.0.0 · 跨行污点分析引擎
  34 个文件（PHP×10 Python×8 Node.js×7 Java/JSP×3 Go×3 Ruby×3），跳过 0 个

  CRITICAL a01_php_sqli.php:4                       sqli
           SQL 执行
           │ $r = mysqli_query($conn, $q);
           └ 污点来源 L2 $_GET/$_POST 数组取值 · $id = $_GET['id'];
  CRITICAL a02_php_rce.php:3                        rce
           命令执行函数
           │ system("ping -c 1 " . $host);
           └ 污点来源 L2 $_GET/$_POST 数组取值 · $host = $_GET['host'];

  ────────────────────────────────────────────────────────
  严重 5  ·  高危 0  ·  中危 0  ·  低危 0   合计 5 处 / 34 文件 / 15ms
```

---

## 目录

- [一、它解决什么问题](#一它解决什么问题)
- [二、为什么不是「正则扫关键词」](#二为什么不是正则扫关键词)
- [三、安装](#三安装)
- [四、快速开始](#四快速开始)
- [五、看懂输出](#五看懂输出)
- [六、选项全表](#六选项全表)
- [七、退出码与 CI 集成](#七退出码与-ci-集成)
- [八、JSON 输出](#八json-输出)
- [九、规则集](#九规则集)
- [十、同步引擎（上游更新了规则怎么办）](#十同步引擎上游更新了规则怎么办)
- [十一、自测](#十一自测)
- [十二、限制](#十二限制)
- [十三、目录结构](#十三目录结构)
- [十四、免责与致谢](#十四免责与致谢)

---

## 一、它解决什么问题

AWD / AWDP 的 Fix 阶段，你要在几十分钟里把自己那套别人写的 PHP/Java 源码过一遍，找出能被对手打穿的洞。现实是：

| 现状 | 结果 |
|---|---|
| 人工 `grep eval(`、`grep system(` | 漏掉拼接出来的、绕了一层变量的、藏在 include 里的 |
| IDE 全局搜索 `$_GET` | 几百个命中，九成是安全的（过了 `intval`、用了预处理） |
| 商业 SAST | 装不上、跑不动、报告看不懂、比赛机器没网 |
| 网页版扫描器 | 要开浏览器、要传包、一次一个、没法批量、没法进 CI |

这个工具就是把这四件事收拢成一条命令：

```bash
sourceaudit challenge.zip -s high
```

三秒内给你一张按严重度排好的清单，每条都带「污点来源」，也就是**这个危险参数是从哪个 `$_GET` 流过来的**——这是判断真漏洞还是误报的关键信息。

---

## 二、为什么不是「正则扫关键词」

普通扫描器看到 `mysqli_query($conn, $q)` 只会想「有个变量进 SQL 了」，于是：

- 报 `$q = "SELECT * FROM t WHERE id=" . intval($id)` → **误报**
- 漏 `$q` 是在第 2 行拼的、第 4 行才用 → **漏报**（如果它只扫单行）

sourceaudit 做的是**跨行污点传播**：

```
source（$_GET / $_POST / $_FILES / $_COOKIE / request.getParameter / req.query ...）
   ↓ 赋值、拼接、函数传参、数组下标
sanitizer（intval / (int) / htmlspecialchars / PreparedStatement / escapeshellarg ...）→ 降级或消解
   ↓
sink（system / mysqli_query / include / unserialize / Runtime.exec ...）→ 报
```

所以它能同时做到：

- 报出「第 2 行 `$id = $_GET['id']`，第 4 行进了 SQL」这种**跨行**链路
- 不报「过了 `intval`」的写法（`sanitized: true`，严重度自动降级）
- 把「追不到来源的危险函数」单独标成低置信（`awdpplus-lowconf`），不跟真漏洞混在一起

规则表本身就是一份「坏模式清单」：66 条污点来源、212 个危险函数、53 条静态特征，覆盖 RCE / SQLi / LFI / 文件上传 / 反序列化 / SSRF / XSS / XXE / 路径穿越 / 弱加密 / 硬编码凭据等 26 类。

---

## 三、安装

### 方式 1：克隆即用（推荐）

```bash
git clone https://github.com/GeWu-academy/sourceaudit.git
cd sourceaudit
chmod +x bin/sourceaudit.js
./bin/sourceaudit.js ./your-source
```

`bin/sourceaudit.js` 带 shebang，`chmod +x` 后可直接执行；也可以 `node bin/sourceaudit.js ...`。
不需要 `npm install`——本项目零依赖。

### 方式 2：全局命令

```bash
git clone https://github.com/GeWu-academy/sourceaudit.git
cd sourceaudit
npm install -g .
sourceaudit ./your-source          # 任意目录下可用
```

> macOS 上 `npm install -g` 若报 `operation was rejected by your operating system`（全局目录属 root），
> 二选一：命令前加 `sudo`，或者
> `npm config set prefix ~/.npm-global` 再把 `~/.npm-global/bin` 加进 `PATH`。

### 方式 3：装进某个项目，只在该项目里用

```bash
cd /path/to/your-project
npm install --save-dev /path/to/sourceaudit
npx sourceaudit ./src -s high
```

适合给单个仓库加审计卡口（配合 `package.json` 的 `scripts.audit`）。

### 环境要求

| 项 | 要求 | 说明 |
|---|---|---|
| Node.js | **≥ 18** | ZIP 输入依赖 `DecompressionStream('deflate-raw')`；低于 18 时目录/单文件照扫 |
| 第三方依赖 | **0 个** | 纯标准库，不需要 `npm install` |
| 网络 | 不需要 | 纯本地静态分析，不联网 |

---

## 四、快速开始

```bash
# 扫一个目录（递归）
sourceaudit ./app

# 比赛发的源码包，直接扔进去
sourceaudit challenge.zip

# 只看能拿 shell 的
sourceaudit ./src -c rce,upload,lfi,deserialization

# 只要高危以上，出 JSON 报告
sourceaudit ./src -s high -f json -o report.json

# 一行汇总，适合批量循环
sourceaudit ./src -q
```

扫描范围（与 LingOps 网页端一致）：

- **跳过目录**：`node_modules`、`vendor`、`.git`、`dist`、`build`、`target`、`.idea`、`.vscode`、`__pycache__`、`bower_components`、`.next`、`coverage`（`--vendor` 可关掉这条规则）
- **跳过文件**：二进制（含 `\0`）、单文件 > 3MB、`.png/.jpg/.zip/.so/.exe/.min/.css` 等非源码后缀
- **认的语言**：PHP / Java(JSP) / Go / Python / Node.js / Ruby / ASP(ASPX) / C#，其余后缀不扫
- **ZIP**：只解到内存，不落盘，包内相对路径原样出现在报告里

---

## 五、看懂输出

### 5.1 文本格式

```
sourceaudit 1.0.0 · 跨行污点分析引擎
  34 个文件（PHP×10 Python×8 Node.js×7 Java/JSP×3 Go×3 Ruby×3），跳过 0 个

  CRITICAL a01_php_sqli.php:4                       sqli
           SQL 执行
           │ $r = mysqli_query($conn, $q);
           └ 污点来源 L2 $_GET/$_POST 数组取值 · $id = $_GET['id'];
```

| 行 | 含义 |
|---|---|
| `CRITICAL file:4  sqli` | 严重度 / 文件:行号 / 漏洞类别 |
| `SQL 执行` | 命中的危险函数名 |
| `│ 源码行` | 出问题的那一行原文 |
| `└ 污点来源 L2 ...` | **这个变量从哪来**，`L2` 是来源所在行号 |

严重度着色：`CRITICAL` 红、`HIGH` 橙、`MEDIUM` 黄、`LOW` 灰。重定向到文件或设 `NO_COLOR=1` 时自动关色。

### 5.2 只看汇总

```bash
$ sourceaudit ./src -q
sourceaudit: 34 文件 · 严重 5 高危 10 中危 2 低危 19 · 15ms
```

---

## 六、选项全表

| 选项 | 取值 | 默认 | 说明 |
|---|---|---|---|
| `-f, --format` | `text` \| `json` | `text` | 输出格式 |
| `-s, --min-sev` | `critical` \| `high` \| `medium` \| `low` | `low` | 只显示不低于该级别 |
| `-c, --cat` | 类别名，逗号分隔 | 全部 | 如 `rce,sqli,upload` |
| `-l, --lang` | `php` \| `java` \| `go` \| `python` \| `node` \| `ruby` \| `asp` \| `csharp` | 全部 | 只扫指定语言 |
| `--exclude` | glob | 无 | 排除路径，**可重复** |
| `--vendor` | — | 关闭 | 不跳过 `vendor/` `node_modules/` 等第三方目录 |
| `--no-lowconf` | — | 关闭 | 不输出「未追到污点来源」的低置信结果 |
| `--fail-on` | `critical` \| `high` \| `medium` \| `low` \| `none` | `high` | 达到该级别时退出码 1 |
| `--engine` | 文件路径 | `engine/awdpplus.js` | 指定引擎文件 |
| `--list-rules` | — | — | 打印规则统计后退出 |
| `-o, --out` | 文件路径 | 无 | 结果同时写入文件 |
| `-q, --quiet` | — | 关闭 | 只输出汇总行 |
| `--no-color` | — | 关闭 | 关 ANSI 颜色 |
| `-v, --version` | — | — | 版本（工具版本 + 引擎版本） |
| `-h, --help` | — | — | 帮助 |

`--exclude` 是 glob 不是正则：`*` 只匹配**单层**（不跨 `/`），`**` 跨目录，`?` 匹配单字符。

```bash
sourceaudit . --exclude 'vendor/**' --exclude 'tests/**' --exclude '*.min.js'
```

---

## 七、退出码与 CI 集成

| 退出码 | 含义 |
|---|---|
| `0` | 没有达到 `--fail-on` 级别的问题 |
| `1` | 有达到级别的问题 |
| `2` | 参数错误 / 路径不存在 / 引擎加载失败 |

### GitHub Actions

```yaml
name: audit
on: [push, pull_request]
jobs:
  awdp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - name: 源码审计
        run: node bin/sourceaudit.js . -s high --fail-on high -f json -o awdp-report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: awdp-report, path: awdp-report.json }
```

### pre-commit（只卡高危）

```bash
#!/bin/sh
# .git/hooks/pre-commit
sourceaudit . -s high --fail-on high -q || {
  echo "发现高危及以上问题，提交已阻止。详情：sourceaudit . -s high"
  exit 1
}
```

### 只想看不想卡

```bash
sourceaudit . --fail-on none    # 永远退出 0
```

---

## 八、JSON 输出

```bash
sourceaudit ./app -f json -o report.json
```

```json
{
  "tool": "sourceaudit",
  "version": "1.0.0",
  "engine_version": "1.3.9",
  "engine": "/path/to/engine/awdpplus.js",
  "targets": ["./app"],
  "files": 34,
  "skipped": 0,
  "langStr": "PHP×10 Python×8 Node.js×7 Java/JSP×3 Go×3 Ruby×3",
  "elapsed_ms": 20,
  "summary": { "critical": 5, "high": 10, "medium": 2, "low": 19, "total": 36 },
  "findings": [
    {
      "file": "a01_php_sqli.php",
      "lang": "php",
      "line": 4,
      "cat": "sqli",
      "sev": "critical",
      "name": "SQL 执行",
      "fix": "改用预处理语句 / 参数化查询",
      "sanitized": false,
      "source": {
        "line": 2,
        "label": "$_GET/$_POST 数组取值",
        "varName": "$id",
        "code": "$id = $_GET['id'];"
      },
      "code": "$r = mysqli_query($conn, $q);",
      "rule": "awdpplus"
    }
  ]
}
```

`rule` 三种取值，决定可信度：

| `rule` | 含义 | 建议 |
|---|---|---|
| `awdpplus` | 污点链路完整（source → sink） | 基本都是真漏洞 |
| `awdpplus-static` | 静态特征命中（`eval(`、弱哈希等） | 大概率真，看上下文 |
| `awdpplus-lowconf` | 危险函数命中但没追到污点来源 | 低置信，`--no-lowconf` 可关 |

`source: null` = 没追到来源；`sanitized: true` = 中间过了过滤函数（已降级但仍提示）。

---

## 九、规则集

```bash
$ sourceaudit --list-rules

规则统计（引擎 v1.3.9）

  语言        污点来源   危险函数   静态特征
  PHP         11        42        43
  Java/JSP    13        33        48
  Go          11        21        43
  Python      7         35        44
  Node.js     14        33        46
  Ruby        4         17        44
  ASP/ASPX    3         12        43
  C#          3         19        45
  ────────────────────────────────────────────
  合计          66        212       53     = 331 条

  注：静态特征多为多语言共用，按语言分列之和会大于总数。
  漏洞类别 26 类
```

**331 = 66 污点来源 + 212 危险函数 + 53 静态特征。**

### 误报怎么处理

在命中行（或上一行）加注释即可：

```php
// lingops:ignore 爬虫必须请求外部 URL
$html = file_get_contents($target);
```

```java
// lingops:ignore 路径来自白名单常量
new FileInputStream(path);
```

支持 `//`、`#`、`/* */`、`<!-- -->`。带标记的命中会在引擎里被直接丢弃，不进报告、不计入汇总——
所以只在**确认过是误报**时才加，别拿它当消音器。

工具本身就要读任意路径 / 出网的（爬虫、指纹识别、SSRF 测试器）属于正常情况——加标记，别改代码迎合扫描器。

---

## 十、同步引擎（上游更新了规则怎么办）

本项目的规则不是自己维护的，而是 `engine/awdpplus.js` —— 一份从 LingOps 带过来的引擎副本。
上游（LingOps 的「🔬 深度审计」）加规则后，用同步脚本拉过来：

```bash
# 自动探测同级目录里的 LingOps 包
npm run sync-engine

# 或者指定目录
npm run sync-engine -- /path/to/LingOps_v0.2_darwin_arm64

# 只比较不写（不一致退出码 1，可挂 CI 检查是否落后）
node scripts/sync-engine.js --check

# 先看看差多少，不落盘
node scripts/sync-engine.js --dry-run
```

脚本做的事：

1. 找 `<LingOps 包>/frontend/dist/assets_v2/lp-ext/awdpplus.js`
2. 算 sha256，与 `engine/awdpplus.js` 比对，相同就直接退出
3. 不同则先写到临时文件，**验证能切出分析段**（切不出就报错，不会装坏引擎）
4. 打印规则数变化（来源/危险函数/静态特征/类别/版本）
5. 原子替换，并把来源、指纹、规则数写进 `engine/ENGINE.json`
6. 自动跑一遍回归语料（`--no-test` 跳过）

> 环境变量 `LINGOPS_HOME` 可以指定默认来源目录。

**引擎为什么能直接搬**：`awdpplus.js` 是个浏览器 IIFE，前半段是纯函数（规则表 + 分析器），
后半段才是 DOM / fetch / 定时器。本项目按边界（注释块 `* 8. 与官方引擎对比`，兜底
`function getToken(`）把前半段切出来，用 `new Function` 在只带一个空 `window` 的环境里跑。
所以：**不复制规则、不重写分析器**，上游改了规则这边自动跟着变。

---

## 十一、自测

仓库自带 105 个**已知答案**的样本（故意埋洞的代码 + 正确写法 + 对抗样本），一条命令验证引擎：

```bash
npm test                # 只打汇总
npm run test:verbose    # 逐文件看漏报/误报
node test/run.js --json # 机器可读
```

```
引擎  engine/awdpplus.js  v1.3.9

  真漏洞　　　  34/34  100.0%  ✅
  安全代码　　  27/27  100.0%  ✅
  回归　　　　  12/12  100.0%  ✅
  新型漏洞　　  17/17  100.0%  ✅
  对抗语料　　  14/14  100.0%  ✅  （另有 1 个已知盲区不计分）

  CLI  ✅ sourceaudit: 34 文件 · 严重 5 高危 10 中危 2 低危 19 · 15ms

全部通过 ✅
```

| 语料 | 文件数 | 期望 | 说明 |
|---|---|---|---|
| `vuln` | 34 | 全命中 | 6 种语言的典型漏洞 |
| `safe` | 27 | **零误报** | 过了 `intval` / 预处理 / 白名单的正确写法 |
| `regress` | 12 | 全命中 | 历史上漏报过的写法（防回退） |
| `modern` | 17 | 全命中 | 新框架/新语法下的同类漏洞 |
| `adversarial` | 15 | 高危以上 | 刻意对抗的写法，1 个已文档化盲区 |

`--json` 里还包含 CLI 冒烟测试结果（引擎能加载 ≠ 命令行能用）。

---

## 十二、限制

1. **只做静态分析**，不跑代码、不连数据库——运行期才拼出来的 SQL 追不到
2. **不做跨文件数据流**：变量从 A 文件传到 B 文件就断了
3. **不认自定义框架封装**：自己写的 `db()->query()` 不在危险函数表里就不报（可加进引擎的 `SINKS`）
4. **ZIP 需要 Node ≥ 18**；老环境先手动解压
5. **已知盲区**：JS 里 `obj[k] = v` 与 `arr[i] = x` 在无类型信息时不可区分，只报低置信（`x08_js_proto_direct.js`）
6. **报告 ≠ 可利用**：报的是「污点能流到危险函数」，实际能不能打穿还要看过滤和上下文
7. 中文源码需要 Node 自带 full-ICU（Node ≥ 14 默认有）

### 信任边界（本工具的安全假设）

`sourceaudit` 是**本机命令行工具**：不监听端口、不联网、不接收外部输入。它的「危险能力」全都落在
使用者自己给的东西上，这是设计而不是缺陷：

| 能力 | 触发点 | 为什么不是漏洞 |
|---|---|---|
| 执行 JS | `--engine <文件>`、`sync-engine` 同步引擎 | 引擎本身就是代码，等同 `node <文件>`；只从可信的 LingOps 源同步 |
| 读任意文件 | 扫描目标路径 | 读文件就是这个工具的职责 |
| 动态正则 | `--exclude` 通配符 | 模式由使用者自己给，且已限长 256 字符 |

推论：**不要**把 `sourceaudit` 放进「`--engine` / `--exclude` / 目标路径来自不可信来源」的自动化链路。
本仓库自扫时对这些点标了 `nosec`（见「误报怎么处理」），CI 用 `--fail-on low` 保证不新增命中。

---

## 十三、目录结构

```
sourceaudit/
├── bin/
│   └── sourceaudit.js        # CLI 入口：参数解析、文件收集、报告渲染
├── lib/
│   └── engine.js            # 引擎加载（切出分析段）+ 规则统计
├── engine/
│   ├── awdpplus.js          # 引擎副本（来自 LingOps，勿手改）
│   └── ENGINE.json          # 来源包名 / sha256 / 规则数 / 同步时间
├── scripts/
│   └── sync-engine.js       # 从 LingOps 同步引擎
├── test/
│   ├── run.js               # 回归自测（105 个已知答案样本 + CLI 冒烟）
│   └── corpus/              # vuln / safe / regress / modern / adversarial
├── package.json
└── README.md
```

**`engine/awdpplus.js` 不要手改**——下次 `sync-engine` 会覆盖。要加规则就改上游 LingOps，然后同步过来。

---

## 十四、免责与致谢

### 用途限制

本工具只做**静态代码分析**，不发起任何网络请求、不执行被扫代码、不包含任何攻击载荷。
请在**你自己拥有或已获授权**的代码上使用；用于未经授权的目标可能违法。

### 致谢

引擎与规则来自 [LingOps](https://github.com/GeWu-academy/LingOps-Enhanced)（原作者 zhanglinglingc，
扩展由 GeWu-academy 维护）——没有那个干净利落的深度审计实现，就没有这个命令行壳。

本项目由 GeWu-academy 维护：[github.com/GeWu-academy/sourceaudit](https://github.com/GeWu-academy/sourceaudit)。

### 许可

MIT
