/* LingOps 前端扩展：AWDP 深度审计（跨行污点分析）
 *
 * 为什么需要它：
 *   官方 AWDP Break / Fix 扫描引擎是「污点门控 + 正则」——正则规则只在该行
 *   含 source（$_GET、getParameter、r.URL.Query() 等）或引用了被污染变量时才执行。
 *   因此跨行数据流（$a = $_GET['a']; ... system($a);）、纯字面量 sink、
 *   以及 Go 的命令执行（官方语义引擎只覆盖文件操作）全部漏报。
 *
 *   本扩展在浏览器内做真正的跨行污点传播：
 *     source 行 → 赋值/拼接/函数返回值/数组成员 传播 → sink 行
 *   并对每一类 sink 单独判断是否已净化（escapeshellarg / 预处理语句 / htmlspecialchars…）。
 */
(function () {
  'use strict';
  if (window.__lpAwdpPlus) return;
  window.__lpAwdpPlus = true;

  var VERSION = '1.3.9';

  /* =====================================================================
   * 1. 语言识别
   * ===================================================================== */
  var EXT_LANG = {
    php: 'php', phtml: 'php', php3: 'php', php4: 'php', php5: 'php', php7: 'php', phps: 'php', inc: 'php',
    java: 'java', jsp: 'java', jspx: 'java', jspf: 'java', tag: 'java',
    go: 'go',
    py: 'python', pyw: 'python',
    js: 'node', mjs: 'node', cjs: 'node', jsx: 'node', ts: 'node', tsx: 'node',
    rb: 'ruby', erb: 'ruby',
    asp: 'asp', aspx: 'asp', ashx: 'asp', asmx: 'asp', ascx: 'asp',
    cs: 'csharp', kt: 'java', scala: 'java', groovy: 'java'
  };
  var LANG_LABEL = {
    php: 'PHP', java: 'Java/JSP', go: 'Go', python: 'Python',
    node: 'Node.js', ruby: 'Ruby', asp: 'ASP/ASPX', csharp: 'C#'
  };
  var SKIP_EXT = {
    png: 1, jpg: 1, jpeg: 1, gif: 1, webp: 1, ico: 1, bmp: 1, svg: 1, psd: 1, ttf: 1, woff: 1, woff2: 1,
    eot: 1, mp3: 1, mp4: 1, avi: 1, mov: 1, wav: 1, zip: 1, gz: 1, tar: 1, rar: 1, '7z': 1, jar: 1, war: 1,
    exe: 1, dll: 1, so: 1, dylib: 1, class: 1, pyc: 1, lock: 1, map: 1, pdf: 1, doc: 1, docx: 1, xls: 1, xlsx: 1,
    min: 1, css: 1, scss: 1, less: 1
  };
  var SKIP_DIR = /(^|\/)(node_modules|vendor|\.git|dist|build|target|\.idea|\.vscode|__pycache__|bower_components|\.next|coverage)(\/|$)/i;

  function extOf(p) {
    var m = /\.([A-Za-z0-9_]+)$/.exec(p || '');
    return m ? m[1].toLowerCase() : '';
  }
  function langOf(p) {
    return EXT_LANG[extOf(p)] || null;
  }
  function baseName(p) {
    var a = String(p || '').split(/[\\/]/);
    return a[a.length - 1] || p;
  }

  /* =====================================================================
   * 2. source / sink / 净化函数 规则表
   * ===================================================================== */

  // ---- source：外部可控输入 ----
  var SOURCES = {
    php: [
      { re: /\$_(?:GET|POST|REQUEST|COOKIE)\b/g, label: '$_GET/$_POST 数组取值' },
      { re: /\binput\s*\(/gi, label: 'ThinkPHP input()' },
      { re: /\$_FILES\s*\[/g, label: '$_FILES 上传' },
      { re: /\$_(?:SERVER|ENV)\s*\[\s*['"](?:HTTP_[A-Z_]+|QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO|argv)['"]/g, label: '$_SERVER 头/URL' },
      { re: /\bgetallheaders\s*\(/gi, label: 'getallheaders()' },
      { re: /\bapache_request_headers\s*\(/gi, label: 'apache_request_headers()' },
      { re: /\bphp:\/\/input\b/gi, label: 'php://input' },
      { re: /\bfile_get_contents\s*\(\s*['"]php:\/\/input/gi, label: 'php://input' },
      { re: /\$argv\s*\[/g, label: '$argv 命令行' },
      { re: /\bfilter_input\s*\(/gi, label: 'filter_input()' },
      { re: /\b(?:readline|fgets)\s*\(\s*STDIN/gi, label: 'STDIN' }
    ],
    java: [
      { re: /\brequest\s*\.\s*getParameter(?:Values|Map)?\s*\(/g, label: 'request.getParameter' },
      { re: /\brequest\s*\.\s*getHeader(?:s|Names)?\s*\(/g, label: 'request.getHeader' },
      { re: /\brequest\s*\.\s*getInputStream\s*\(/g, label: 'request.getInputStream' },
      { re: /\brequest\s*\.\s*getReader\s*\(/g, label: 'request.getReader' },
      { re: /\brequest\s*\.\s*getCookies\s*\(/g, label: 'request.getCookies' },
      { re: /\brequest\s*\.\s*getQueryString\s*\(/g, label: 'request.getQueryString' },
      { re: /\brequest\s*\.\s*getPathInfo\s*\(/g, label: 'request.getPathInfo' },
      { re: /\bgetParameter(?:Values|Map)?\s*\(/g, label: 'getParameter()' },
      { re: /\bgetHeader\s*\(/g, label: 'getHeader()' },
      { re: /\bgetInputStream\s*\(/g, label: 'getInputStream()' },
      { re: /\bgetAttribute\s*\(/g, label: 'getAttribute()' },
      { re: /\b(?:args|argv)\s*\[/g, label: 'main args' },
      { re: /\bgetQueryString\s*\(/g, label: 'getQueryString()' }
    ],
    go: [
      { re: /\.\s*URL\s*\.\s*Query\s*\(\s*\)/g, label: 'r.URL.Query()' },
      { re: /\.\s*FormValue\s*\(/g, label: 'r.FormValue()' },
      { re: /\.\s*PostFormValue\s*\(/g, label: 'r.PostFormValue()' },
      { re: /\.\s*Form\s*\.\s*Get\s*\(/g, label: 'r.Form.Get()' },
      { re: /\.\s*Header\s*\.\s*Get\s*\(/g, label: 'r.Header.Get()' },
      { re: /\.\s*Cookie\s*\(/g, label: 'r.Cookie()' },
      { re: /\.\s*MultipartForm\b/g, label: 'r.MultipartForm' },
      { re: /\.\s*FormFile\s*\(/g, label: 'r.FormFile()' },
      { re: /\bc\s*\.\s*(?:Query|Param|PostForm|DefaultQuery)\s*\(/g, label: 'gin c.Query/Param' },
      { re: /\.\s*PathValue\s*\(/g, label: 'r.PathValue()' },
      { re: /\bos\s*\.\s*Args\s*\[/g, label: 'os.Args' }
    ],
    python: [
      { re: /\brequest\s*\.\s*(?:args|form|values|json|cookies|files|headers|data|GET|POST|body)\b/g, label: 'request.* 请求数据' },
      { re: /\brequest\s*\.\s*get_(?:json|data|argument|form)\s*\(/g, label: 'request.get_json()' },
      { re: /\brequest\s*\.\s*META\s*\[/g, label: 'request.META' },
      { re: /\bself\s*\.\s*request\s*\.\s*(?:GET|POST|body|query_params|data)\b/g, label: 'DRF request.*' },
      { re: /\bsys\s*\.\s*argv\s*\[/g, label: 'sys.argv' },
      { re: /\binput\s*\(/g, label: 'input()' },
      { re: /\bself\s*\.\s*(?:get_argument|get_query_argument|get_body_argument)\s*\(/g, label: 'Tornado get_argument' }
    ],
    node: [
      { re: /\breq\s*\.\s*(?:query|body|params|cookies|headers|files|file|url|path|hostname|rawBody)\b/g, label: 'req.query/body/params' },
      { re: /\breq\s*\.\s*(?:get|header|param)\s*\(/g, label: 'req.get()' },
      { re: /\bctx\s*\.\s*(?:query|request|params|headers|body|URL|url|state)\b/g, label: 'koa ctx.*' },
      // Web Fetch API / Next.js App Router：最常见的三种读参方式
      { re: /\brequest\s*\.\s*(?:formData|json|text|blob|arrayBuffer|body)\s*\(?/g, label: 'request.formData/json/text' },
      { re: /\bnew\s+URL\s*\(/g, label: 'new URL().searchParams' },
      { re: /\bsearchParams\s*\.\s*(?:get|getAll|has)\b/g, label: 'searchParams.get()' },
      { re: /\bcontext\s*\.\s*params\b|\bprops\s*\.\s*params\b/g, label: 'context.params (Next)' },
      // Fastify / NestJS / Express Router
      { re: /\brequest\s*\.\s*(?:body|query|params|headers|cookies|raw|id)\b/g, label: 'request.body (Fastify)' },
      { re: /@(?:Query|Param|Body|Headers|Req|Request)\s*\(/g, label: '@Query/@Param (Nest)' },
      { re: /\b(?:process|Deno)\s*\.\s*(?:argv|env)\b/g, label: 'process.argv/env' },
      { re: /\blocation\s*\.\s*(?:search|hash|href)\b/g, label: 'location.*' },
      { re: /\bdocument\s*\.\s*(?:URL|referrer|cookie)\b/g, label: 'document.*' },
      { re: /\bwindow\s*\.\s*name\b/g, label: 'window.name' },
      { re: /\b(?:getServerSideProps|getStaticProps)\s*\(\s*\{[^}]*\}\s*\)/g, label: 'Next getServerSideProps' }
    ],
    ruby: [
      { re: /\bparams\s*\[/g, label: 'params[]' },
      { re: /\brequest\s*\.\s*(?:params|headers|body|cookies|query_string)\b/g, label: 'request.*' },
      { re: /\bARGV\s*\[/g, label: 'ARGV' },
      { re: /\bgets\b/g, label: 'gets' }
    ],
    asp: [
      { re: /\bRequest\s*\.\s*(?:QueryString|Form|Cookies|ServerVariables|Item|Params)\b/gi, label: 'Request.*' },
      { re: /\bRequest\s*\[/gi, label: 'Request[]' },
      { re: /\bHttpContext\s*\.\s*Current\s*\.\s*Request\b/g, label: 'HttpContext.Request' }
    ],
    csharp: [
      { re: /\bRequest\s*\.\s*(?:Query|Form|Cookies|Headers|QueryString|Params|Body)\b/g, label: 'Request.*' },
      { re: /\bHttpContext\s*\.\s*Current\s*\.\s*Request\b/g, label: 'HttpContext.Request' },
      { re: /\bargs\s*\[/g, label: 'args[]' }
    ]
  };

  // ---- sink：危险汇聚点 ----
  var SINKS = {
    php: [
      { re: /\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|expect_popen)\s*\(/gi, cat: 'rce', sev: 'critical', name: '命令执行函数', fix: '改用白名单 + escapeshellarg()，避免拼接用户输入' },
      { re: /`[^`\n]*\$[A-Za-z_{]/g, cat: 'rce', sev: 'critical', name: '反引号执行命令', fix: '移除反引号，改用安全 API' },
      { re: /\beval\s*\(/gi, cat: 'rce', sev: 'critical', name: 'eval 代码执行', fix: '禁止把用户输入交给 eval' },
      { re: /\bassert\s*\(\s*[^'"\s)]/gi, cat: 'rce', sev: 'critical', name: 'assert 动态执行', fix: '移除 assert 动态执行' },
      { re: /\bcreate_function\s*\(/gi, cat: 'rce', sev: 'critical', name: 'create_function 代码执行', fix: '改用闭包' },
      { re: /\bpreg_replace\s*\(\s*['"][^'"]*\/[a-zA-Z]*e[a-zA-Z]*['"]/gi, raw: true, cat: 'rce', sev: 'critical', name: 'preg_replace /e 修饰符', fix: '改用 preg_replace_callback' },
      { re: /\b(?:call_user_func|call_user_func_array|forward_static_call)\s*\(/gi, cat: 'rce', sev: 'high', name: '动态函数调用', fix: '回调名白名单校验' },
      { re: /\$[A-Za-z_][A-Za-z0-9_]*\s*\(/g, cat: 'rce', sev: 'high', name: '变量函数调用', fix: '禁止用变量直接当函数名，改白名单 switch' },
      { re: /->\s*(?:fetch|display|show|assign|fetchSql)\s*\(/gi, cat: 'ssti', sev: 'critical', name: '模板渲染（模板注入/LFI）', fix: '模板名白名单，禁止用户控制模板路径' },
      { re: /\bsession_id\s*\(\s*[^)]/gi, cat: 'auth', sev: 'high', name: 'session_id 可控（会话固定）', fix: '登录成功后 session_regenerate_id(true)' },
      { re: /\b(?:include|include_once|require|require_once)\b\s*\(?\s*[^;]*\$/gi, cat: 'lfi', sev: 'critical', name: '文件包含（路径可控）', fix: '固定路径或白名单，禁用 URL 包装器' },
      { re: /\bunserialize\s*\(/gi, cat: 'deserialization', sev: 'critical', name: '反序列化', fix: '改用 json_decode，或 allowed_classes 白名单' },
      { re: /->\s*(?:query|exec|prepare|raw)\s*\(|\bmysqli?_query\s*\(|\bpg_query\s*\(|\bsqlite_query\s*\(/gi, cat: 'sqli', sev: 'critical', name: 'SQL 执行', fix: '使用预处理语句绑定参数' },
      { re: /\b(?:fopen|file_put_contents|file_get_contents|readfile|unlink|rename|copy|chmod|mkdir|rmdir|scandir|glob|filesize|file_exists|highlight_file|show_source|parse_ini_file|simplexml_load_file)\s*\(/gi, cat: 'path', sev: 'high', name: '文件操作（路径可控）', fix: 'basename() + realpath() 校验前缀' },
      { re: /\bcurl_setopt\s*\([^)]*CURLOPT_URL|\b(?:fsockopen|stream_socket_client)\s*\(/gi, cat: 'ssrf', sev: 'high', name: '出网请求（SSRF）', fix: '协议与目标白名单' },
      { re: /\bmove_uploaded_file\s*\(/gi, cat: 'upload', sev: 'critical', name: '文件上传落盘', fix: '扩展名白名单 + 随机重命名 + 禁止执行' },
      { re: /\b(?:header|setcookie|setrawcookie)\s*\(/gi, cat: 'header', sev: 'medium', name: '响应头/重定向注入', fix: '过滤 \\r\\n，跳转目标白名单' },
      { re: /\b(?:echo|print|printf|print_r|var_dump|vprintf)\b/gi, cat: 'xss', sev: 'medium', name: '输出未转义', fix: 'htmlspecialchars($x, ENT_QUOTES, "UTF-8")' },
      { re: /\bldap_(?:search|list|read|add|modify|delete|bind)\s*\(/gi, cat: 'ldap', sev: 'high', name: 'LDAP 操作（注入）', fix: 'ldap_escape() 转义 DN 与过滤器' },
      { re: /\bsimplexml_load_string\s*\(|\bDOMDocument\b|\bloadXML\s*\(|\bXMLReader\b/gi, cat: 'xxe', sev: 'high', name: 'XML 解析（XXE）', fix: '禁用外部实体 LIBXML_NOENT' },
      { re: /\bmail\s*\(/gi, cat: 'header', sev: 'medium', name: '邮件头注入', fix: '过滤换行符' },
      { re: /\b(?:extract|parse_str|import_request_variables)\s*\(/gi, cat: 'rce', sev: 'high', name: '变量覆盖', fix: '禁用 extract/parse_str 处理外部输入' },
      { re: /\bnew\s+Reflection(?:Class|Function|Method|Property)\s*\(/gi, cat: 'rce', sev: 'high', name: '反射调用', fix: '类名/方法名白名单' },
      { re: /\b(?:openssl_verify|openssl_decrypt)\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*['"]?(?:aes-128-ecb|des-ecb)/gi, cat: 'crypto', sev: 'high', name: 'ECB 模式加密', fix: '改用 AES-GCM' }
    ],
    java: [
      { re: /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/g, cat: 'rce', sev: 'critical', name: 'Runtime.exec 命令执行', fix: '改用 ProcessBuilder + 参数数组，禁止 sh -c' },
      { re: /\bnew\s+ProcessBuilder\s*\(/g, cat: 'rce', sev: 'critical', name: 'ProcessBuilder 命令执行', fix: '参数白名单校验' },
      { re: /\.\s*readObject\s*\(\s*\)|new\s+ObjectInputStream\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'Java 反序列化', fix: '使用 ObjectInputFilter 白名单' },
      { re: /\bXMLDecoder\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'XMLDecoder 反序列化', fix: '禁用 XMLDecoder' },
      { re: /\bcreateStatement\s*\(|\.\s*(?:executeQuery|executeUpdate|execute)\s*\(|createQuery\s*\(|createNativeQuery\s*\(/g, cat: 'sqli', sev: 'critical', name: 'SQL 执行', fix: '使用 PreparedStatement 绑定参数' },
      { re: /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|Unmarshaller|XMLReader)\b/g, cat: 'xxe', sev: 'high', name: 'XML 解析（XXE）', fix: 'setFeature 禁用外部实体' },
      { re: /\b(?:SpelExpressionParser|ExpressionParser|parseExpression)\s*\(|\bOgnl\b|\bMVEL\b|\bScriptEngine\b[^;]*\.\s*eval\s*\(|\.\s*eval\s*\(/g, cat: 'ssti', sev: 'critical', name: '表达式/脚本注入', fix: '禁止解析用户可控表达式' },
      { re: /\bnew\s+File(?:InputStream|OutputStream|Reader|Writer|Channel)?\s*\(|Files\s*\.\s*(?:read|write|copy|delete|move|newInputStream|newOutputStream|newBufferedReader)\s*\(|\bPaths\s*\.\s*get\s*\(/g, cat: 'path', sev: 'high', name: '文件操作（路径可控）', fix: 'getCanonicalPath 校验前缀白名单' },
      { re: /\bnew\s+URL\s*\(|\.\s*openConnection\s*\(|\bHttpURLConnection\b|\bHttpClient\b|\bRestTemplate\b|\bWebClient\b|\bOkHttpClient\b/g, cat: 'ssrf', sev: 'high', name: '出网请求（SSRF）', fix: '目标地址白名单' },
      { re: /\.\s*(?:getWriter|getOutputStream)\s*\(\s*\)\s*\.\s*(?:print|println|write)|Response\s*\.\s*Write\s*\(/g, cat: 'xss', sev: 'medium', name: '输出未转义', fix: 'HTML 实体转义' },
      { re: /MessageDigest\s*\.\s*getInstance\s*\(\s*"(?:MD5|SHA-?1)"/gi, cat: 'crypto', sev: 'medium', name: '弱哈希', fix: '改用 bcrypt/PBKDF2/Argon2' },
      { re: /\bnew\s+Random\s*\(/g, cat: 'random', sev: 'medium', name: '弱随机数', fix: '改用 SecureRandom' },
      { re: /\.\s*sendRedirect\s*\(/g, cat: 'redirect', sev: 'medium', name: '开放重定向', fix: '跳转目标白名单' },
      { re: /\bCipher\s*\.\s*getInstance\s*\(\s*"(?:AES|DES)(?:\/\w+)?\/ECB/g, cat: 'crypto', sev: 'high', name: 'ECB 模式加密', fix: '改用 AES/GCM/NoPadding' },
      { re: /\b(?:Class\s*\.\s*forName|\.\s*getMethod\s*\(|\.\s*getDeclaredMethod\s*\(|\.\s*invoke\s*\()/g, cat: 'rce', sev: 'high', name: '反射调用', fix: '类名/方法名白名单' }
    ],
    go: [
      { re: /\bexec\s*\.\s*Command(?:Context)?\s*\(/g, cat: 'rce', sev: 'critical', name: 'exec.Command 命令执行', fix: '参数数组 + 白名单，禁止 "sh","-c"' },
      { re: /\bos\s*\.\s*(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|Mkdir|MkdirAll|Rename|Chmod|Stat)\s*\(|\bioutil\s*\.\s*(?:ReadFile|WriteFile|ReadAll|ReadDir)\s*\(/g, cat: 'path', sev: 'high', name: '文件操作（路径可控）', fix: 'filepath.Base + 白名单目录' },
      { re: /\.\s*(?:Query|QueryRow|Exec|ExecContext|QueryContext)\s*\((?!\s*\))/g, cat: 'sqli', sev: 'critical', name: 'SQL 执行', fix: '使用 ? / $1 占位符参数' },
      { re: /\bfmt\s*\.\s*Sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|select|insert|update|delete)/g, cat: 'sqli', sev: 'critical', name: 'SQL 字符串拼接', fix: '改为参数化查询' },
      { re: /\bhttp\s*\.\s*(?:Get|Post|PostForm|Head)\s*\(|\.\s*Do\s*\(\s*req|client\s*\.\s*Do\s*\(/g, cat: 'ssrf', sev: 'high', name: '出网请求（SSRF）', fix: '目标地址白名单' },
      { re: /\btemplate\s*\.\s*(?:HTML|JS|URL|HTMLAttr|CSS)\s*\(/g, cat: 'xss', sev: 'medium', name: '未转义模板输出', fix: '使用默认转义（template.HTMLEscapeString）' },
      { re: /\btemplate\s*\.\s*(?:New|Must)\s*\(/g, cat: 'ssti', sev: 'high', name: '模板解析（模板注入）', fix: '模板内容固定，用户输入只作为数据传入 Execute' },
      { re: /\bmd5\s*\.\s*(?:New|Sum)\s*\(|\bsha1\s*\.\s*(?:New|Sum)\s*\(/g, cat: 'crypto', sev: 'medium', name: '弱哈希', fix: '改用 bcrypt/argon2' },
      { re: /\brand\s*\.\s*(?:Intn|Int|Int31|Int63|Float64|Perm|Shuffle)\s*\(/g, cat: 'random', sev: 'medium', name: '弱随机数（math/rand）', fix: '安全场景改用 crypto/rand' },
      { re: /\bInsecureSkipVerify\s*:\s*true/g, cat: 'config', sev: 'high', name: '跳过 TLS 证书校验', fix: '设为 false 并配置正确 RootCAs' },
      { re: /\bunsafe\s*\.\s*Pointer\s*\(|\breflect\s*\.\s*ValueOf\s*\(/g, cat: 'memory', sev: 'medium', name: 'unsafe/反射', fix: '避免对不可信输入做反射调用' },
      { re: /\byaml\s*\.\s*Unmarshal\s*\(|\bgob\s*\.\s*NewDecoder\s*\(/g, cat: 'deserialization', sev: 'high', name: '反序列化', fix: '校验输入来源，限制类型' }
    ],
    python: [
      { re: /\bos\s*\.\s*(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?)\s*\(/g, cat: 'rce', sev: 'critical', name: 'os 命令执行', fix: '改用 subprocess 参数列表' },
      { re: /\bsubprocess\s*\.\s*(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(/g, cat: 'rce', sev: 'critical', name: 'subprocess 命令执行', fix: 'shell=False + 参数列表' },
      { re: /\bshell\s*=\s*True/g, cat: 'rce', sev: 'critical', name: 'shell=True', fix: '改为 shell=False' },
      // 必须排除 re.compile() / regex.compile()：那是正则编译，不是代码编译。
      // 用 (?<![.\w]) 代替 \b，否则 Python 里每个常量正则都会被报成 eval/exec。
      { re: /(?<![.\w])(?:eval|exec|execfile|compile)\s*\(/g, cat: 'rce', sev: 'critical', name: 'eval/exec 动态执行', fix: '禁止执行不可信代码' },
      { re: /\b(?:pickle|cPickle|_pickle|dill|marshal|shelve)\s*\.\s*loads?\s*\(/g, cat: 'deserialization', sev: 'critical', name: '不安全反序列化', fix: '改用 json / 签名校验' },
      { re: /\byaml\s*\.\s*load\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'yaml.load 反序列化', fix: '改用 yaml.safe_load' },
      { re: /\b(?:etree|ElementTree|ET|lxml)\s*(?:\.\s*etree)?\s*\.\s*(?:fromstring|parse|XML|iterparse)\s*\(|\bXMLParser\s*\(|\bresolve_entities\s*=\s*True/g, cat: 'xxe', sev: 'high', name: 'XML 解析（XXE）', fix: 'resolve_entities=False，禁用 DTD 与外部实体' },
      { re: /\.\s*(?:execute|executemany|raw|extra)\s*\(/g, cat: 'sqli', sev: 'critical', name: 'SQL 执行', fix: '使用参数化查询（%s 占位符）' },
      { re: /\bopen\s*\(|\bos\s*\.\s*(?:remove|unlink|rename|replace|mkdir|makedirs|listdir|scandir)\s*\(|\bshutil\s*\.\s*(?:copy|move|rmtree)\s*\(/g, cat: 'path', sev: 'high', name: '文件操作（路径可控）', fix: 'os.path.basename + 白名单目录' },
      { re: /\b(?:requests|httpx|aiohttp)\s*\.\s*(?:get|post|put|delete|patch|request|head)\s*\(|\burllib\s*\.\s*request\s*\.\s*urlopen\s*\(|\bsession\s*\.\s*(?:get|post)\s*\(/g, cat: 'ssrf', sev: 'high', name: '出网请求（SSRF）', fix: '目标地址白名单' },
      { re: /\brender_template_string\s*\(|\bTemplate\s*\(|\bjinja2\s*\./g, cat: 'ssti', sev: 'critical', name: '模板注入（SSTI）', fix: '不要渲染用户提供的模板' },
      { re: /(?<=[\w\]\)])\s*\.\s*format\s*\(/g, cat: 'ssti', sev: 'medium', name: 'format 字符串注入', fix: '用户可控模板不要走 str.format，改用参数化渲染' },
      { re: /\b(?:ET|cElementTree|ElementTree|lxml)\s*\.\s*(?:parse|fromstring|XML)\s*\(|\bxml\s*\.\s*(?:etree|dom|sax)\b/g, cat: 'xxe', sev: 'high', name: 'XML 解析（XXE）', fix: '禁用外部实体解析' },
      { re: /\bsend_file\s*\(|\bsend_from_directory\s*\(|\bFileResponse\s*\(/g, cat: 'path', sev: 'high', name: '文件下载', fix: '校验路径在允许目录内' },
      { re: /\bhashlib\s*\.\s*(?:md5|sha1)\s*\(/g, cat: 'crypto', sev: 'medium', name: '弱哈希', fix: '改用 bcrypt/argon2/passlib' },
      { re: /\brandom\s*\.\s*(?:random|randint|randrange|choice|shuffle|sample)\s*\(/g, cat: 'random', sev: 'medium', name: '弱随机数', fix: '安全场景改用 secrets' },
      { re: /\bmark_safe\s*\(|\bHttpResponse\s*\(|\bMarkup\s*\(/g, cat: 'xss', sev: 'medium', name: '输出未转义', fix: '使用模板自动转义，避免 mark_safe' },
      { re: /\bjwt\s*\.\s*decode\s*\(/g, cat: 'auth', sev: 'high', name: 'JWT 解析', fix: '强制校验签名并指定 algorithms' },
      { re: /\bverify\s*=\s*False/g, cat: 'config', sev: 'high', name: '关闭 TLS 校验', fix: '移除 verify=False' },
      { re: /\bDEBUG\s*=\s*True/g, cat: 'config', sev: 'medium', name: '生产环境 DEBUG', fix: '生产环境设为 False' }
    ],
    node: [
      // 必须排除 RegExp.prototype.exec：re.exec(x) / broad.exec(x) 是正则匹配，
      // 不是命令执行。所以裸 exec( 用 (?<![.\w$])，另给真正的进程模块单独开一条。
      { re: /\b(?:child_process|childProcess|execSync|execFileSync|spawnSync)\b|\b(?:cp|shelljs|execa)\s*\.\s*exec\s*\(|(?<![.\w$])exec\s*\(|\bspawn\s*\(/g, cat: 'rce', sev: 'critical', name: '命令执行', fix: '改用 execFile/spawn 参数数组' },
      { re: /\beval\s*\(|new\s+Function\s*\(|\bvm\s*\.\s*run(?:InNewContext|InThisContext|InContext)?\s*\(/g, cat: 'rce', sev: 'critical', name: '动态代码执行', fix: '禁止 eval / new Function' },
      { re: /\brequire\s*\(\s*[^'"]/g, cat: 'rce', sev: 'high', name: '动态 require', fix: '模块名白名单' },
      // node-serialize / funcster 等把对象序列化成可执行函数，反序列化即 RCE
      { re: /\bunserialize\s*\(|\bnode-serialize\b/g, cat: 'deserialization', sev: 'critical', name: '不安全反序列化', fix: '改用 JSON.parse；必须保留时校验来源并禁用函数字段' },
      // 递归 merge 若不过滤 __proto__ 即可污染原型链
      { re: /(?<![.\w$])(?:deepMerge|merge|extend|defaultsDeep)\s*\(/g, cat: 'prototype', sev: 'medium', name: '深合并（原型污染风险）', fix: '过滤 __proto__ / constructor / prototype 键' },
      // execFile/spawn 的 argv 安全性会被 sh -c 完全抵消，等于命令拼接
      { re: /(?:execFile|execFileSync|spawn|spawnSync)\s*\(\s*['"](?:sh|bash|zsh|dash|cmd|powershell|pwsh)['"]\s*,\s*\[[^\]]*['"]-[a-z]*c/, raw: true, cat: 'rce', sev: 'critical', name: 'execFile/spawn 经 shell -c 执行', fix: '禁止经 sh -c 执行，直接 execFile 目标程序并传参数数组' },
      { re: /\.\s*(?:query|raw|execute)\s*\(|\bsequelize\s*\.\s*query\s*\(|\bknex\s*\.\s*raw\s*\(/g, cat: 'sqli', sev: 'critical', name: 'SQL 执行', fix: '参数化查询 / 绑定变量' },
      { re: /\bfs\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|appendFile|createReadStream|createWriteStream|rename|copyFile)\s*\(/g, cat: 'path', sev: 'high', name: '文件操作（路径可控）', fix: 'path.basename + 白名单目录' },
      { re: /\bres\s*\.\s*(?:send|write|end|render|sendFile)\s*\(|\binnerHTML\s*=|dangerouslySetInnerHTML/g, cat: 'xss', sev: 'medium', name: '输出未转义', fix: '转义或使用模板引擎自动转义' },
      { re: /\bfetch\s*\(|\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\(|\bhttps?\s*\.\s*(?:get|request)\s*\(/g, cat: 'ssrf', sev: 'high', name: '出网请求（SSRF）', fix: '目标地址白名单' },
      { re: /\bjwt\s*\.\s*decode\s*\(|\bjsonwebtoken\b/g, cat: 'auth', sev: 'high', name: 'JWT 处理', fix: '校验签名与算法白名单' },
      { re: /\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]/g, cat: 'crypto', sev: 'medium', name: '弱哈希', fix: '改用 bcrypt/argon2' },
      { re: /\bMath\s*\.\s*random\s*\(/g, cat: 'random', sev: 'medium', name: '弱随机数', fix: '改用 crypto.randomBytes' },
      { re: /\bres\s*\.\s*redirect\s*\(/g, cat: 'redirect', sev: 'medium', name: '开放重定向', fix: '跳转目标白名单' },
      { re: /__proto__|\bObject\s*\.\s*assign\s*\(|\blodash\s*\.\s*merge\s*\(|\.\s*merge\s*\(/g, cat: 'prototype', sev: 'medium', name: '原型污染风险', fix: '过滤 __proto__ / constructor / prototype' },
      { re: /\bnew\s+RegExp\s*\(|\bRegExp\s*\(\s*[^'"]/g, cat: 'redos', sev: 'medium', name: '动态正则（ReDoS）', fix: '转义输入并限制长度' },
      { re: /\b(?:xml2js|libxmljs|libxmljs2|fast-xml-parser|sax|xmldom|@xmldom\/xmldom|DOMParser)\b|\bXMLParser\s*\(|\bparseString\s*\(/g, cat: 'xxe', sev: 'high', name: 'XML 解析（XXE）', fix: '关闭实体展开（libxmljs: noent:false；fast-xml-parser: processEntities:false）' },
      { re: /\b(?:xmllint|xmlstarlet|xsltproc|unzip|tar|convert|ffmpeg)\b/g, cat: 'rce', sev: 'high', name: '外部命令 / 解析器调用', fix: '禁止把用户内容交给外部解析器；必须调用时去掉 --noent/--loaddtd' },
      { re: /\bmulter\s*\(|\bformidable\s*\(|\bbusboy\b|\bmultipart\b/g, cat: 'upload', sev: 'medium', name: '文件上传解析', fix: '限制扩展名/大小/MIME，落盘重命名' }
    ],
    ruby: [
      { re: /\bsystem\s*\(|\bexec\s*\(|`[^`]*#\{|\bIO\s*\.\s*popen|\bOpen3\s*\.|\bspawn\s*\(/g, cat: 'rce', sev: 'critical', name: '命令执行', fix: '使用数组形式参数，禁止 shell 字符串' },
      { re: /\beval\s*\(|\binstance_eval|\bclass_eval|\bsend\s*\(|\bpublic_send\s*\(/g, cat: 'rce', sev: 'high', name: '动态执行', fix: '方法名白名单' },
      { re: /\.\s*(?:where|find_by_sql|execute|exec_query)\s*\(/g, cat: 'sqli', sev: 'critical', name: 'SQL 执行', fix: '使用参数化 where(["x = ?", v])' },
      { re: /\bMarshal\s*\.\s*load\b|\bYAML\s*\.\s*load\s*\(/g, cat: 'deserialization', sev: 'critical', name: '反序列化', fix: '改用 JSON / YAML.safe_load' },
      { re: /\brender\s+(?:inline|text|html)\s*:/g, cat: 'xss', sev: 'medium', name: '输出未转义', fix: '使用 ERB 自动转义或 sanitize' },
      { re: /\bFile\s*\.\s*(?:open|read|write|delete|new)\s*\(|\bIO\s*\.\s*read\s*\(/g, cat: 'path', sev: 'high', name: '文件操作', fix: 'File.basename + 白名单' },
      { re: /\bopen\s*\(\s*[^)]*\|/g, cat: 'rce', sev: 'critical', name: 'open 管道执行', fix: '改用 IO.popen 数组形式' }
    ],
    asp: [
      { re: /\bServer\s*\.\s*CreateObject\s*\(/gi, cat: 'rce', sev: 'critical', name: 'COM 对象创建', fix: '对象 ProgID 白名单' },
      { re: /\bEval\s*\(|\bExecute\s*\(|\bExecuteGlobal\s*\(/gi, cat: 'rce', sev: 'critical', name: 'Eval/Execute 动态执行', fix: '禁止执行用户输入' },
      { re: /\bWScript\s*\.\s*Shell\b|\bShell\s*\.\s*Application\b/gi, cat: 'rce', sev: 'critical', name: 'Shell 执行', fix: '禁止调用 Shell' },
      { re: /\bServer\s*\.\s*MapPath\s*\(|\bFileSystemObject\b|\bADODB\s*\.\s*Stream\b/gi, cat: 'path', sev: 'high', name: '文件系统操作', fix: '路径白名单' },
      { re: /\bResponse\s*\.\s*Write\s*\(/gi, cat: 'xss', sev: 'medium', name: '输出未转义', fix: 'Server.HTMLEncode()' },
      { re: /\bResponse\s*\.\s*Redirect\s*\(/gi, cat: 'redirect', sev: 'medium', name: '开放重定向', fix: '跳转白名单' },
      { re: /\bSqlCommand\b|\bOleDbCommand\b|\.\s*ExecuteReader\s*\(|\bCommandText\s*=/gi, cat: 'sqli', sev: 'critical', name: 'SQL 执行', fix: '使用参数化 SqlParameter' },
      { re: /\bXmlDocument\b|\bXmlReader\b|\bXPathDocument\b/g, cat: 'xxe', sev: 'high', name: 'XML 解析（XXE）', fix: 'XmlReaderSettings DtdProcessing=Prohibit' }
    ],
    csharp: [
      { re: /\bProcess\s*\.\s*Start\s*\(|\bProcessStartInfo\b/g, cat: 'rce', sev: 'critical', name: '进程执行', fix: '参数白名单，禁止 cmd /c' },
      { re: /\bAssembly\s*\.\s*Load\b|\bActivator\s*\.\s*CreateInstance\s*\(|\bType\s*\.\s*GetType\s*\(/g, cat: 'rce', sev: 'high', name: '动态类型加载', fix: '类型名白名单' },
      { re: /\bSqlCommand\b|\bMySqlCommand\b|\bNpgsqlCommand\b|\bCommandText\s*=/g, cat: 'sqli', sev: 'critical', name: 'SQL 执行', fix: '使用参数化 SqlParameter' },
      { re: /\bFile\s*\.\s*(?:ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Delete|Open|Copy|Move)\s*\(/g, cat: 'path', sev: 'high', name: '文件操作', fix: 'Path.GetFileName + 白名单' },
      { re: /\bXmlDocument\b|\bXmlReader\b|\bXDocument\b|\bXmlTextReader\b/g, cat: 'xxe', sev: 'high', name: 'XML 解析（XXE）', fix: 'DtdProcessing = Prohibit' },
      { re: /\bBinaryFormatter\b|\bLosFormatter\b|\bNetDataContractSerializer\b|\bObjectStateFormatter\b|\bSoapFormatter\b/g, cat: 'deserialization', sev: 'critical', name: '不安全反序列化', fix: '改用 System.Text.Json / 白名单绑定器' },
      { re: /\bResponse\s*\.\s*Write\s*\(/g, cat: 'xss', sev: 'medium', name: '输出未转义', fix: 'HttpUtility.HtmlEncode' },
      { re: /\bResponse\s*\.\s*Redirect\s*\(/g, cat: 'redirect', sev: 'medium', name: '开放重定向', fix: '跳转白名单' },
      { re: /\bMD5\s*\.\s*Create\s*\(|\bSHA1\s*\.\s*Create\s*\(|\bDESCryptoServiceProvider\b/g, cat: 'crypto', sev: 'medium', name: '弱加密算法', fix: '改用 PBKDF2/AES-GCM' }
    ]
  };

  /* =====================================================================
   * 2b. 扩展规则集（v1.3.4）—— 补齐官方规则库缺的 sink，并覆盖 2021–2025
   *     年公开的高危漏洞家族（Log4Shell / Spring4Shell / Fastjson /
   *     SnakeYAML / PHP 流封装器 / pickle 家族 / Zip Slip / NoSQL 注入等）。
   *     只新增，不改动上表原有规则，回归基线不受影响。
   * ===================================================================== */
  var SINKS_EXT = {
    php: [
      { re: /\b(?:php|phar|zip|data|expect|glob|compress\.(?:zlib|bzip2|zstd)):\/\//gi, cat: 'lfi', sev: 'high', name: 'PHP 流封装器（php:// / phar:// / data://）', fix: '禁止用户输入进入 include/file 函数；文件名走白名单映射，并关闭 allow_url_include' },
      { re: /\bconvert\.(?:iconv|base64-(?:encode|decode))\./gi, cat: 'lfi', sev: 'critical', name: 'php://filter 过滤器链（iconv 链可构造任意内容）', fix: '禁止 include 使用 php://filter；升级 PHP 并禁用危险封装器' },
      { re: /\bphar\s*:\/\//gi, cat: 'deserialization', sev: 'critical', name: 'phar:// 元数据反序列化（PHP < 8.0）', fix: '升级 PHP 8+，或校验路径前缀禁止 phar://' },
      { re: /\bfile_put_contents\s*\(/gi, cat: 'upload', sev: 'high', name: 'file_put_contents 写文件（可落 webshell）', fix: '写入目录白名单 + 固定后缀，禁止写入 Web 根' },
      { re: /\$_FILES\s*\[[^\]]*\]\s*\[\s*['"](?:name|full_path)['"]\s*\]/gi, cat: 'upload', sev: 'high', name: '直接用客户端文件名落盘', fix: 'uniqid() 重命名 + 扩展名白名单' },
      { re: /\$\$[A-Za-z_]\w*/g, cat: 'rce', sev: 'high', name: '可变变量 $$var（可覆盖任意变量）', fix: '禁止用请求参数构造变量名' },
      { re: /\b(?:set_include_path|ini_set\s*\(\s*['"](?:auto_prepend_file|auto_append_file|allow_url_include))/gi, cat: 'config', sev: 'high', name: '运行时改写包含路径 / auto_prepend_file', fix: '禁止运行时修改包含路径，allow_url_include=Off' },
      { re: /\.(?:user\.ini|htaccess)\b/gi, cat: 'config', sev: 'medium', name: '.user.ini / .htaccess（上传可改解析配置）', fix: '禁止上传目录解析脚本，把该后缀列入黑名单' },
      { re: /\bphpinfo\s*\(\s*\)/gi, cat: 'info', sev: 'medium', name: 'phpinfo 暴露环境信息', fix: '生产环境删除 phpinfo 页面' },
      { re: /->\s*(?:where|whereRaw|order|orderRaw|field|group|having|table|alias)\s*\(\s*["'][^"']*\$|\bDb\s*::\s*(?:query|execute)\s*\(/gi, cat: 'sqli', sev: 'critical', name: 'ORM 原生拼接（ThinkPHP/Laravel 链式方法）', fix: '链式方法只接受字段名常量，值走参数绑定' },
      { re: /\bnew\s+SoapClient\s*\(/gi, cat: 'ssrf', sev: 'high', name: 'SoapClient（CRLF 注入 / SSRF）', fix: '禁止 user_agent、location 由用户控制' },
      { re: /\bserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/gi, cat: 'deserialization', sev: 'high', name: '把请求数据序列化进 Cookie/存储', fix: '签名 + 加密，或改用服务端会话' },
      { re: /\b__wakeup\s*\(|\b__destruct\s*\(|\b__toString\s*\(/g, cat: 'deserialization', sev: 'medium', name: '魔术方法（POP 链可利用点）', fix: '魔术方法内不要做文件/命令/网络操作；unserialize 加 allowed_classes' },
      { re: /\b(?:gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(\s*(?:base64_decode|substr|pack)/gi, cat: 'rce', sev: 'critical', name: '编码/压缩解码链（常见一句话木马）', fix: '定位并删除混淆代码' },
      { re: /\b(?:eval|assert|create_function|preg_replace)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)/gi, cat: 'rce', sev: 'critical', name: '解码后直接执行（webshell 特征）', fix: '删除混淆后门代码' },
      { re: /\bmd5\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, cat: 'crypto', sev: 'high', name: 'MD5 处理请求数据（可碰撞/可绕过）', fix: '改用 password_hash() / hash_equals()' },
      { re: /\b(?:file|file_get_contents|fopen)\s*\(\s*['"]\/etc\/(?:passwd|shadow)/gi, cat: 'path', sev: 'critical', name: '直接读取系统敏感文件', fix: '删除该读取逻辑' },
      { re: /\b(?:assert|eval)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)/gi, cat: 'rce', sev: 'critical', name: '请求参数直接进入代码执行（一句话木马）', fix: '删除该代码' }
    ],
    java: [
      { re: /\b(?:InitialContext|InitialDirContext|JndiLookup|JndiManager)\b|\.\s*lookup\s*\(/g, cat: 'rce', sev: 'critical', name: 'JNDI 注入（Log4Shell CVE-2021-44228 家族）', fix: '禁止 lookup 用户可控名称；log4j 升到 2.17.1+ 或移除 JndiLookup' },
      { lang: ['java'], re: /\bJSON\s*\.\s*parse(?:Object|Array)?\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'Fastjson JSON.parse（autoType 反序列化 RCE）', fix: 'fastjson 升到 1.2.83+/2.x 并开启 safeMode' },
      { lang: ['java'], re: /\b(?:autoTypeSupport|enableDefaultTyping|activateDefaultTyping)\b/g, cat: 'deserialization', sev: 'critical', name: '开启多态反序列化（autoType / defaultTyping）', fix: '关闭 autoType；Jackson 用白名单 PolymorphicTypeValidator' },
      { lang: ['java'], re: /\bYaml\s*\.\s*load\s*\(|\bnew\s+Yaml\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'SnakeYAML 反序列化', fix: '改用 SafeConstructor，禁止 !!javax / !!java 标签' },
      { lang: ['java'], re: /\bXStream\b|\.\s*fromXML\s*\(/g, cat: 'deserialization', sev: 'high', name: 'XStream 反序列化', fix: 'XStream 1.4.18+ 并配置 allowTypes 白名单' },
      { re: /\b(?:HessianInput|Hessian2Input|BurlapInput|Caucho)\b/g, cat: 'deserialization', sev: 'high', name: 'Hessian/Burlap 反序列化', fix: '限制可反序列化类型白名单' },
      { re: /\b(?:TemplatesImpl|InvokerTransformer|ChainedTransformer|ConstantTransformer|InstantiateTransformer|BadAttributeValueExpException)\b/g, cat: 'deserialization', sev: 'critical', name: '反序列化 gadget 类（ysoserial 链）', fix: '移除相关依赖；反序列化入口加 ObjectInputFilter 白名单' },
      { re: /\b(?:URLClassLoader|defineClass|GroovyShell|GroovyClassLoader)\b/g, cat: 'rce', sev: 'critical', name: '动态类加载 / Groovy 执行', fix: '禁止用户控制类路径与脚本内容' },
      { re: /\bclass\s*\.\s*module\s*\.\s*classLoader\b/g, cat: 'rce', sev: 'critical', name: 'Spring4Shell 参数绑定特征（CVE-2022-22965）', fix: '升级 Spring 5.3.18+/5.2.20+，或用 @InitBinder 拒绝 classLoader 字段' },
      { re: /\b(?:ELProcessor|ExpressionFactory|ValueExpression|createValueExpression)\b/g, cat: 'ssti', sev: 'critical', name: 'EL 表达式注入', fix: '禁止把用户输入拼进表达式' },
      { re: /\b(?:freemarker|FreeMarker|Velocity|SpringTemplateEngine|Thymeleaf)\b/g, cat: 'ssti', sev: 'high', name: '模板引擎（SSTI）', fix: '模板名白名单，禁止用户控制模板内容' },
      { re: /@(?:Select|Update|Insert|Delete)\s*\(\s*["'][^"']*\$\{/g, raw: true, cat: 'sqli', sev: 'critical', name: 'MyBatis ${} 拼接（SQL 注入）', fix: '改用 #{} 预编译占位符' },
      { re: /\b(?:ZipInputStream|ZipEntry|TarArchiveInputStream|TarArchiveEntry|ZipArchiveInputStream)\b/g, cat: 'zip', sev: 'high', name: '压缩包解压（Zip Slip 路径穿越）', fix: '解压前校验规范化路径必须在目标目录内' },
      { re: /\b(?:System\s*\.\s*load|System\s*\.\s*loadLibrary)\s*\(/g, cat: 'rce', sev: 'high', name: '加载本地动态库', fix: '库路径固定，禁止用户控制' },
      { re: /\b(?:ScriptEngineManager|Nashorn)\b/g, cat: 'rce', sev: 'high', name: '脚本引擎（可执行任意 JS）', fix: '禁止执行用户脚本，或使用沙箱' },
      { re: /\bjdbcTemplate\s*\.\s*(?:query|update|execute|batchUpdate)\s*\(/g, cat: 'sqli', sev: 'critical', name: 'JdbcTemplate 执行 SQL', fix: '使用 ? 占位符 + 参数数组' },
      { re: /\bnew\s+Cookie\s*\(|\.\s*addCookie\s*\(/g, cat: 'header', sev: 'medium', name: 'Cookie 写入（可注入 / 缺 HttpOnly）', fix: 'setHttpOnly(true) + setSecure(true) + SameSite' },
      { re: /\bnew\s+ServerSocket\s*\(/g, cat: 'ssrf', sev: 'medium', name: '原始 Socket 监听/通信', fix: '只监听必要网卡，目标地址白名单' }
    ],
    go: [
      { re: /\bexec\s*\.\s*Command(?:Context)?\s*\(\s*[^)]*['"](?:sh|bash|zsh|cmd|powershell)['"]\s*,\s*['"]-[a-z]*c['"]/g, cat: 'rce', sev: 'critical', name: 'exec.Command 经 shell -c 执行', fix: '直接 exec 目标程序并传参数数组，禁止 sh -c' },
      { re: /\bsyscall\s*\.\s*(?:Exec|ForkExec)\s*\(|\bplugin\s*\.\s*Open\s*\(/g, cat: 'rce', sev: 'high', name: '系统调用 / 动态插件加载', fix: '禁止加载用户可控的插件或程序' },
      { re: /\bfilepath\s*\.\s*Join\s*\([^)]*(?:r\s*\.\s*(?:URL|FormValue)|c\s*\.\s*(?:Param|Query)|req\s*\.)/g, cat: 'path', sev: 'high', name: 'filepath.Join 拼接用户输入', fix: 'filepath.Base + 白名单目录，并校验结果前缀' },
      { re: /\bhttp\s*\.\s*(?:ServeFile|FileServer|ServeContent)\s*\(/g, cat: 'path', sev: 'high', name: '静态文件服务（路径穿越）', fix: '用 http.Dir 限定根目录，禁止 .. 逃逸' },
      { re: /\b(?:zip|tar)\s*\.\s*(?:NewReader|OpenReader)\s*\(/g, cat: 'zip', sev: 'high', name: '压缩包解压（Zip Slip）', fix: '解压前 filepath.Clean 并校验前缀' },
      { re: /\bnet\s*\.\s*(?:Dial|DialTimeout|LookupHost|LookupIP)\s*\(/g, cat: 'ssrf', sev: 'medium', name: '出网连接（SSRF）', fix: '目标地址白名单' },
      { re: /\bxml\s*\.\s*Unmarshal\s*\(|\bxml\s*\.\s*NewDecoder\s*\(/g, cat: 'xxe', sev: 'high', name: 'XML 解析（实体展开）', fix: 'Decoder.Strict = true，禁用自定义 Entity 映射' },
      { re: /\bfmt\s*\.\s*Fprintf\s*\(\s*(?:w|resp|writer|ctx\s*\.\s*Writer)/g, cat: 'xss', sev: 'medium', name: '直接写响应（未转义）', fix: '用 html/template 或 html.EscapeString' },
      { re: /\bhttp\s*\.\s*Redirect\s*\(/g, cat: 'redirect', sev: 'medium', name: '开放重定向', fix: '跳转目标白名单' }
    ],
    python: [
      { re: /\b(?:torch|joblib|dill|cloudpickle|jsonpickle|pandas|numpy|keras|tensorflow)\s*\.\s*(?:load|loads|read_pickle|load_model)\s*\(/g, cat: 'deserialization', sev: 'critical', name: '模型/对象反序列化（pickle 家族可 RCE）', fix: '只加载可信模型；改用 safetensors 或 weights_only=True' },
      { re: /\ballow_pickle\s*=\s*True/g, cat: 'deserialization', sev: 'critical', name: 'numpy allow_pickle=True', fix: '改为 allow_pickle=False' },
      { re: /\btrust_remote_code\s*=\s*True/g, cat: 'rce', sev: 'critical', name: 'HuggingFace trust_remote_code（下载即执行）', fix: '改为 False，或固定 revision 后人工审计' },
      { re: /\byaml\s*\.\s*(?:unsafe_load|load_all|full_load)\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'yaml 不安全加载', fix: '改用 yaml.safe_load' },
      { re: /\b(?:mako|tornado)\s*\.\s*template\b|\bTemplate\s*\([^)]*\)\s*\.\s*render\s*\(/g, cat: 'ssti', sev: 'high', name: '模板渲染（SSTI）', fix: '模板内容固定，用户输入只作为变量传入' },
      { re: /\|\s*safe\b/g, cat: 'xss', sev: 'medium', name: 'Django 模板 |safe 关闭转义', fix: '移除 |safe，或先 escape() 再标记安全' },
      { re: /\b(?:tarfile|zipfile|shutil)\s*\.\s*(?:open|ZipFile|unpack_archive)\s*\(|\.\s*extractall\s*\(/g, cat: 'zip', sev: 'critical', name: '压缩包解压（Tar/Zip Slip）', fix: 'Python 3.12+ 用 filter="data"，旧版逐个校验成员路径' },
      { re: /\btempfile\s*\.\s*mktemp\s*\(/g, cat: 'path', sev: 'medium', name: 'tempfile.mktemp（TOCTOU 竞态）', fix: '改用 NamedTemporaryFile / mkstemp' },
      { re: /\bapp\s*\.\s*run\s*\([^)]*debug\s*=\s*True/g, cat: 'config', sev: 'high', name: 'Flask debug=True（Werkzeug 调试器可 RCE）', fix: '生产环境关闭 debug，改用 gunicorn/uwsgi' },
      { re: /\bcsrf_exempt\b/g, cat: 'auth', sev: 'medium', name: '关闭 CSRF 校验', fix: '仅对无状态 API 使用，并配合 SameSite/Token' },
      { re: /\b(?:ftplib|smtplib|telnetlib|paramiko)\s*\./g, cat: 'ssrf', sev: 'medium', name: '出网协议客户端（SSRF）', fix: '目标地址白名单' },
      { re: /\.\s*execute\s*\(\s*f['"]|\.\s*execute\s*\(\s*['"][^'"]*['"]\s*%\s*\(/g, cat: 'sqli', sev: 'critical', name: 'f-string / % 拼接 SQL', fix: '改用参数化查询 cursor.execute(sql, params)' },
      { re: /\btext\s*\(\s*f['"]/g, cat: 'sqli', sev: 'critical', name: 'SQLAlchemy text() 拼接 f-string', fix: '使用 text("... :x") + bindparams' },
      { re: /\bSECRET_KEY\s*=\s*['"]/g, cat: 'secret', sev: 'high', name: '硬编码 SECRET_KEY', fix: '从环境变量读取并定期轮换' },
      { re: /\bos\s*\.\s*(?:chmod|chown)\s*\(/g, cat: 'config', sev: 'medium', name: '运行时修改文件权限', fix: '最小权限，避免 0777' }
    ],
    node: [
      { re: /\b(?:ejs|pug|handlebars|nunjucks|hogan|mustache|doT)\s*\.\s*(?:render|renderString|compile|template)\s*\(/g, cat: 'ssti', sev: 'critical', name: '服务端模板渲染（SSTI）', fix: '模板名与内容固定，用户输入只作为上下文变量' },
      { re: /\b(?:res|reply)\s*\.\s*(?:sendFile|download)\s*\(/g, cat: 'path', sev: 'high', name: '文件下载（路径穿越）', fix: 'path.basename + 白名单根目录' },
      { re: /\bpath\s*\.\s*(?:join|resolve)\s*\([^)]*(?:req\s*\.\s*(?:query|params|body|headers)|process\s*\.\s*argv)/g, cat: 'path', sev: 'high', name: 'path.join 拼接用户输入', fix: 'path.basename + 校验结果在根目录内' },
      { lang: ['node', 'java', 'python'], re: /\balgorithms\s*:\s*\[\s*['"]none['"]/g, cat: 'auth', sev: 'critical', name: 'JWT 允许 none 算法（签名可绕过）', fix: '固定 algorithms: ["RS256"]，禁止 none' },
      { re: /\bcreateCipher\s*\(|\bcreateDecipher\s*\(/g, cat: 'crypto', sev: 'high', name: '已废弃 createCipher（固定 IV / 无认证）', fix: '改用 createCipheriv + AES-256-GCM' },
      { re: /\b(?:js-yaml|yaml)\s*\.\s*(?:load|loadAll)\s*\(/g, cat: 'deserialization', sev: 'high', name: 'YAML 反序列化（!!js/function 可 RCE）', fix: '使用 safeLoad / JSON_SCHEMA' },
      { re: /\bserialize-javascript\b|\bfuncster\b/g, cat: 'deserialization', sev: 'high', name: '序列化库可还原函数', fix: '改用 JSON，禁用函数字段' },
      { re: /\bvm\s*\.\s*compileFunction\s*\(|\bprocess\s*\.\s*(?:binding|dlopen)\s*\(/g, cat: 'rce', sev: 'critical', name: '底层执行接口', fix: '禁止执行用户代码' },
      { re: /\$where\b|\$regex\b|\$ne\s*:|\$gt\s*:/g, cat: 'nosqli', sev: 'critical', name: 'NoSQL 操作符注入（$where/$ne/$regex）', fix: '强制类型转换 + 键名白名单，禁止把 req.body 直接当查询条件' },
      { lang: ['node'], re: /\borigin\s*:\s*(?:true|['"]\*['"])|\bcredentials\s*:\s*true/g, cat: 'cors', sev: 'high', name: 'CORS 允许任意来源 + 携带凭据', fix: '来源白名单，禁止 * 与 credentials 共存' },
      { re: /\b(?:unzipper|adm-zip|archiver|tar-stream|node-tar)\b/g, cat: 'zip', sev: 'high', name: '压缩包解压（Zip Slip）', fix: '解压前校验 entry.path 规范化后在目标目录内' },
      { re: /\b(?:sequelize\s*\.\s*literal|knex\s*\.\s*raw)\s*\(/g, cat: 'sqli', sev: 'critical', name: 'ORM 原生 SQL 片段', fix: '参数绑定，禁止拼接用户输入' },
      { re: /\bhttpOnly\s*:\s*false/g, cat: 'config', sev: 'medium', name: 'Cookie 未设 HttpOnly', fix: 'httpOnly: true, secure: true, sameSite: "lax"' },
      { lang: ['node'], re: /\btrust\s+proxy\b/g, cat: 'config', sev: 'low', name: 'trust proxy 未限定（IP 可伪造）', fix: '显式配置可信代理列表' }
    ],
    ruby: [
      { re: /\bERB\s*\.\s*new\s*\(/g, cat: 'ssti', sev: 'high', name: 'ERB 模板渲染（SSTI/RCE）', fix: '模板内容固定，禁止渲染用户输入' },
      { re: /\bYAML\s*\.\s*(?:load_file|unsafe_load|load_stream)\s*\(|\bPsych\s*\.\s*load\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'YAML 不安全加载', fix: '改用 YAML.safe_load' },
      { lang: ['ruby'], re: /\bcreate_additions\s*:\s*true/g, cat: 'deserialization', sev: 'high', name: 'JSON.create 允许对象创建', fix: '去掉 create_additions' },
      { re: /\bredirect_to\s+[^\n]*params\b/g, cat: 'redirect', sev: 'high', name: '跳转目标取自参数', fix: '跳转白名单，或 allow_other_host: false' },
      { re: /\b(?:send_file|send_data)\s*\(/g, cat: 'path', sev: 'high', name: '文件下载（路径穿越）', fix: 'File.basename + 白名单根目录' },
      { re: /\braw\s*\(|\bhtml_safe\b/g, cat: 'xss', sev: 'medium', name: '关闭输出转义', fix: '移除 html_safe/raw，或先 sanitize' },
      { re: /\bconstantize\b/g, cat: 'rce', sev: 'high', name: '常量化（可加载任意类）', fix: '类名白名单' },
      { re: /\bFileUtils\s*\.\s*(?:rm_rf|cp_r|mv|chmod)\s*\(/g, cat: 'path', sev: 'high', name: '批量文件操作', fix: '路径白名单' },
      { re: /\bNet\s*::\s*HTTP\b|\bURI\s*\.\s*open\s*\(/g, cat: 'ssrf', sev: 'medium', name: '出网请求（SSRF）', fix: '目标地址白名单' },
      { re: /\bparams\s*\.\s*permit!/g, cat: 'auth', sev: 'high', name: 'permit! 批量赋值（可越权改字段）', fix: '显式 permit(:a, :b)，禁止 permit!' }
    ],
    asp: [
      { re: /\bServer\s*\.\s*(?:Execute|Transfer)\s*\(/gi, cat: 'lfi', sev: 'high', name: 'Server.Execute/Transfer（文件包含）', fix: '路径固定，禁止用户控制' },
      { re: /\b(?:MSXML2\s*\.\s*XMLHTTP|WinHttp\s*\.\s*WinHttpRequest|ServerXMLHTTP)\b/gi, cat: 'ssrf', sev: 'high', name: '服务端 HTTP 请求（SSRF）', fix: '目标地址白名单' },
      { re: /\bRequest\s*\.\s*(?:Form|QueryString|Cookies)\s*\([^)]*\)\s*&/gi, cat: 'sqli', sev: 'high', name: '请求参数直接拼接', fix: '使用 ADODB.Command 参数化' },
      { re: /\bCreateObject\s*\(\s*["']ADODB/gi, cat: 'sqli', sev: 'high', name: 'ADODB 连接（拼接易注入）', fix: '使用 ADODB.Command 参数化' }
    ],
    csharp: [
      { lang: ['csharp'], re: /\bTypeNameHandling\s*=\s*TypeNameHandling\s*\.\s*(?:All|Auto|Objects|Arrays)/g, cat: 'deserialization', sev: 'critical', name: 'Newtonsoft TypeNameHandling（反序列化 RCE）', fix: '改用 TypeNameHandling.None + 白名单 SerializationBinder' },
      { lang: ['csharp'], re: /\b(?:SimpleTypeResolver|JavaScriptTypeResolver)\b/g, cat: 'deserialization', sev: 'critical', name: 'JavaScriptSerializer 类型解析器（反序列化 RCE）', fix: '移除自定义 TypeResolver' },
      { re: /\bHtml\s*\.\s*Raw\s*\(/g, cat: 'xss', sev: 'medium', name: 'Html.Raw 关闭转义', fix: '移除 Html.Raw，或先 HtmlEncode' },
      { re: /\bPath\s*\.\s*Combine\s*\([^)]*(?:Request|query|input|param)/gi, cat: 'path', sev: 'high', name: 'Path.Combine 拼接请求参数', fix: 'Path.GetFileName + 校验前缀' },
      { re: /\bDirectory\s*\.\s*(?:GetFiles|GetDirectories|Delete|CreateDirectory|EnumerateFiles)\s*\(/g, cat: 'path', sev: 'medium', name: '目录操作（路径可控）', fix: '路径白名单' },
      { re: /\b(?:ZipFile\s*\.\s*ExtractToDirectory|TarFile\s*\.\s*ExtractToDirectory|ZipArchive)\b/g, cat: 'zip', sev: 'high', name: '压缩包解压（Zip Slip）', fix: '校验解压目标路径在根目录内' },
      { re: /\b(?:HttpClient|WebRequest\s*\.\s*Create|WebClient)\b/g, cat: 'ssrf', sev: 'medium', name: '出网请求（SSRF）', fix: '目标地址白名单' },
      { re: /\bDtdProcessing\s*=\s*DtdProcessing\s*\.\s*Parse\b|\bXmlResolver\s*=\s*new\s+XmlUrlResolver/g, cat: 'xxe', sev: 'critical', name: 'XML 允许 DTD / 外部解析器（XXE）', fix: 'DtdProcessing = Prohibit，XmlResolver = null' },
      { re: /\bDataSet\s*\.\s*ReadXml\s*\(/g, cat: 'xxe', sev: 'high', name: 'DataSet.ReadXml（XXE）', fix: '改用 XmlReader 并禁用 DTD' },
      { re: /\bResponse\s*\.\s*Cookies\s*\[[^\]]*\]\s*\.\s*HttpOnly\s*=\s*false/g, cat: 'config', sev: 'medium', name: 'Cookie 未设 HttpOnly', fix: 'HttpOnly = true，并设置 Secure/SameSite' }
    ]
  };
  Object.keys(SINKS_EXT).forEach(function (k) {
    SINKS[k] = (SINKS[k] || []).concat(SINKS_EXT[k]);
  });

  // ---- 净化函数：出现即降低该类别风险 ----
  var SANITIZERS = {
    // 数组形式传参（argv）不经过 shell，是安全的：subprocess.run(['ping',h]) / Open3.capture2('ping',h) / execFile('ping',[h])
    rce: [/escapeshellarg\s*\(/i, /escapeshellcmd\s*\(/i, /\bshlex\s*\.\s*quote\s*\(/i, /\bintval\s*\(/i, /\(int\)/i, /\bfilter_var\s*\([^)]*INT/i, /\bctype_digit\s*\(/i, /\bProcessBuilder\s*\([^)]*\)\s*$/, /subprocess\s*\.\s*\w+\s*\(\s*\[/, /Open3\s*\.\s*\w+\s*\(\s*['"]/, /\bshell\s*=\s*False/],
    // 参数化：SQL 串后紧跟第二个参数（绑定数组/元组）或 $1 占位符，即视为已绑定
    sqli: [/\bprepare\s*\(/i, /\$wpdb\s*->\s*prepare/i, /\bmysqli_real_escape_string\s*\(/i, /\bpg_escape_string\s*\(/i, /\bPDO\s*::\s*quote/i, /\baddslashes\s*\(/i, /\bintval\s*\(/i, /\(int\)/i, /PreparedStatement/i, /\bcreateNamedQuery\s*\(/i, /\?\s*\)/, /['"]\s*,\s*[\[(]/, /\$\d/, /\bsetString\s*\(/i],
    xss: [/\bhtmlspecialchars\s*\(/i, /\bhtmlentities\s*\(/i, /\bstrip_tags\s*\(/i, /\bhtml\s*\.\s*escape\s*\(/i, /\bmarkupsafe\s*\.\s*escape/i, /\bescapeHtml\b/i, /\bHtmlEncode\b/i, /\btextContent\b/, /\bServer\s*\.\s*HTMLEncode/i],
    lfi: [/\bbasename\s*\(/i, /\brealpath\s*\(/i, /\bin_array\s*\(/i, /\ballowlist\b/i, /\bstr_replace\s*\(\s*['"]\.\./i,
      // 数组下标取值（$map[$p]）说明目标来自服务端映射表，不是用户拼出来的路径
      /\$\w+\s*\[\s*\$\w+\s*\]/],
    path: [/\bbasename\s*\(/i, /\brealpath(?:Sync)?\s*\(/i, /\bresolve\s*\(/i, /\bfilepath\s*\.\s*Base\s*\(/i, /\bpath\s*\.\s*basename\s*\(/i, /\bos\s*\.\s*path\s*\.\s*basename\s*\(/i, /\bgetCanonicalPath\b/i, /\bPath\s*\.\s*GetFileName\s*\(/i, /\bFile\s*\.\s*basename\s*\(/i, /\bSecurePath\b/i],
    ssrf: [/\bfilter_var\s*\([^)]*URL/i, /\burlparse\b/i, /\bnew\s+URL\s*\(/i, /\bin_array\s*\(/i, /\ballowlist\b/i, /\bisPrivate\b/i, /\bloopback\b/i],
    deserialization: [/\ballowed_classes\b/i, /\bsafe_load\s*\(/i, /\bObjectInputFilter\b/i, /\bserialVersionUID\b/i],
    ssti: [/\bautoescape\b/i, /\bsandbox/i, /\bSandboxedEnvironment\b/i],
    redirect: [/\brawurlencode\s*\(/i, /\burlencode\s*\(/i, /\bin_array\s*\(/i, /\bstartswith\s*\(/i, /\ballowlist\b/i],
    header: [/\\r\\n/i, /\bstr_replace\s*\([^)]*\\r/i, /\brawurlencode\s*\(/i],
    ldap: [/\bldap_escape\s*\(/i],
    // 注意：LIBXML_NOENT / LIBXML_DTDLOAD 是「开启实体替换」，属于漏洞本身，
    // 绝不能当净化函数，否则所有 PHP XXE 都会被判定为「已净化」而直接丢弃。
    xxe: [/disallow-doctype-decl/i, /\bFEATURE_SECURE_PROCESSING\b/i, /\blibxml_disable_entity_loader\s*\(\s*true/i, /\bDtdProcessing\s*=\s*DtdProcessing\s*\.\s*Prohibit/i, /\bresolve_entities\s*=\s*False/i, /\bLIBXML_NONET\b/i],
    upload: [/\bpathinfo\s*\(/i, /\bgetimagesize\s*\(/i, /\bin_array\s*\(/i, /\buniqid\s*\(/i, /\brandom_bytes\s*\(/i, /\bwp_check_filetype\b/i,
      /\bbin2hex\s*\(/i, /\brandomUUID\s*\(/i, /\buuid4?\s*\(/i, /\bfinfo\b|\bmime_content_type\b/i],
    prototype: [/__proto__/]
  };

  // ---- 与污点无关的静态弱点（总是报告） ----
  var PATTERNS = [
    { re: /(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)[A-Za-z0-9_]*\s*(?::=|=|:)\s*(?!=)\s*['"][^'"\s]{6,}['"]/gi, cat: 'secret', sev: 'high', name: '硬编码凭据/密钥', fix: '改用环境变量或密钥管理服务' },
    { re: /\bdebug\s*=\s*True|\bdebug\s*=\s*true\b/g, cat: 'config', sev: 'high', name: '调试模式开启', fix: '生产环境关闭 debug，避免堆栈与调试器泄露' },
    { re: /\$[A-Za-z_][A-Za-z0-9_]*\s*==\s*\$[A-Za-z_]|['"][^'"]+['"]\s*==\s*\$[A-Za-z_]/g, cat: 'auth', sev: 'medium', name: '弱类型比较（type juggling）', fix: '改用 === 与 hash_equals()' },
    { re: /isset\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)[^)]*\)[^;]*\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*true/gi, cat: 'auth', sev: 'high', name: '请求参数直接提权', fix: '权限判定只从会话/服务端取，禁止由请求参数置位' },
    { re: /\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\./gi, cat: 'sqli', sev: 'high', name: 'SQL 字符串拼接', fix: '使用预处理语句绑定参数' },
    { re: /\bdefine\s*\(\s*['"][A-Z_]*(?:PASS|SECRET|KEY|TOKEN)[A-Z_]*['"]\s*,/g, cat: 'secret', sev: 'high', name: '硬编码凭据常量', fix: '改用环境变量' },
    { re: /\bAccess-Control-Allow-Origin\b[^;\n]{0,40}\*/g, cat: 'cors', sev: 'medium', name: 'CORS 允许任意源', fix: '改为固定来源白名单' },
    { re: /\bdisplay_errors\s*[=,]\s*(?:On|1|true)|ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?(?:On|1)/gi, cat: 'config', sev: 'low', name: '错误回显开启', fix: '生产环境关闭 display_errors' },
    { re: /\bini_set\s*\(\s*['"]allow_url_include['"]\s*,\s*['"]?(?:On|1)/gi, cat: 'config', sev: 'high', name: 'allow_url_include 开启', fix: '关闭 allow_url_include / allow_url_fopen' },
    { re: /\bset_time_limit\s*\(\s*0\s*\)/g, cat: 'config', sev: 'low', name: '取消脚本超时', fix: '设置合理超时' },
    { re: /\bchmod\s*\([^,]+,\s*0777/g, cat: 'config', sev: 'medium', name: '文件权限 0777', fix: '使用最小必要权限' },
    { re: /['"]\/etc\/(?:passwd|shadow)['"]/g, cat: 'info', sev: 'medium', name: '读取系统敏感文件', fix: '移除对系统文件的访问' },
    { re: /\b(?:x-powered-by|server)\b[^\n]{0,20}\d+\.\d+/gi, cat: 'info', sev: 'low', name: '版本号泄露', fix: '隐藏 Server / X-Powered-By 响应头' },
    { re: /\bTODO\b[^\n]{0,40}(?:security|auth|check|validate|sanitiz)/gi, cat: 'info', sev: 'low', name: '遗留安全 TODO', fix: '确认相关校验已实现' },
    { re: /\bmysql_query\s*\(/gi, cat: 'sqli', sev: 'high', name: '已废弃 mysql_* API', fix: '迁移到 PDO / mysqli 预处理' },
    { re: /\b(?:md5|sha1|crc32)\s*\(/gi, cat: 'crypto', sev: 'low', name: '弱哈希算法', fix: '密码改用 password_hash()，摘要改用 SHA-256+' },
    { re: /\b(?:rand|mt_rand|uniqid|lcg_value)\s*\(/gi, cat: 'random', sev: 'low', name: '弱随机数', fix: '安全场景改用 random_bytes()/random_int()' },
    { re: /\bstrcmp\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, cat: 'auth', sev: 'high', name: 'strcmp 比较用户输入（可绕过）', fix: '改用 hash_equals()' },
    { re: /['"]\s*==\s*['"]?\s*\$_(?:GET|POST|REQUEST)/gi, cat: 'auth', sev: 'medium', name: '用户输入弱比较', fix: '使用 === 与 hash_equals' },
    // 外部实体展开：XML 解析器一旦开这个开关，用户可控 XML 就能读文件 / SSRF / RCE
    { re: /['"]--noent['"]|['"]--loaddtd['"]|\bLIBXML_NOENT\b|\bLIBXML_DTDLOAD\b|\bsetExpandEntityReferences\s*\(\s*true|\bresolve_entities\s*=\s*True|\bDtdProcessing\s*\.\s*Parse\b/g, cat: 'xxe', sev: 'high', name: 'XML 外部实体展开已开启（XXE）', fix: 'xmllint 去掉 --noent/--loaddtd；libxml 不要 LIBXML_NOENT；Java 设 disallow-doctype-decl' },
    // 原型链污染：merge/clone 用户对象
    { re: /\b(?:Object\s*\.\s*assign|_\.\s*(?:merge|extend|defaultsDeep)|\$\.\s*extend\s*\(\s*true)\s*\(\s*(?:target|obj|config|options|\{\s*\})\s*,/g, cat: 'prototype', sev: 'medium', name: '深合并可能污染原型链', fix: '过滤 __proto__ / constructor / prototype 键' }
  ];

  /* =====================================================================
   * 4b. 扩展静态模式（v1.3.4）—— 2021–2025 年 CVE 家族特征、云凭据格式、
   *     请求头信任、webshell 特征、NoSQL/XPath 注入等与污点无关的固定特征。
   * ===================================================================== */
  var PATTERNS_EXT = [
    { re: /\$\{\s*jndi\s*:/gi, cat: 'rce', sev: 'critical', name: 'Log4Shell 特征串 ${jndi:...}', fix: 'log4j-core 升到 2.17.1+，移除 JndiLookup，并限制出网' },
    { re: /["']@type["']\s*:\s*["']/g, cat: 'deserialization', sev: 'high', name: 'JSON 多态类型字段 @type（Jackson/Fastjson）', fix: '关闭 defaultTyping/autoType，使用类型白名单' },
    { re: /\bAKIA[0-9A-Z]{16}\b/g, cat: 'secret', sev: 'critical', name: 'AWS Access Key', fix: '立即轮换并从代码移除，改用 IAM Role' },
    { re: /\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, cat: 'secret', sev: 'critical', name: 'GitHub Token', fix: '立即吊销，改用环境变量/Secrets' },
    { re: /\bsk-[A-Za-z0-9]{32,}\b/g, cat: 'secret', sev: 'critical', name: 'OpenAI API Key', fix: '立即吊销，改用环境变量' },
    { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, cat: 'secret', sev: 'high', name: 'Slack Token', fix: '立即吊销' },
    { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, cat: 'secret', sev: 'critical', name: '私钥硬编码', fix: '移除私钥，改用 KMS 或受权限保护的密钥文件' },
    { re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, cat: 'secret', sev: 'high', name: '硬编码 JWT', fix: 'JWT 不应写死在代码/配置里' },
    { re: /Access-Control-Allow-Credentials['"]?\s*[,:]\s*(?:true|['"]true)/gi, cat: 'cors', sev: 'high', name: 'CORS 允许携带凭据（配合 * 任意站点可读）', fix: '来源白名单，* 不可与 credentials 共存' },
    { re: /\bSameSite\s*=\s*None\b/gi, cat: 'config', sev: 'medium', name: 'Cookie SameSite=None（未配 Secure 则跨站可用）', fix: '改 Lax/Strict；必须 None 时同时设 Secure' },
    { re: /\bHttpOnly\s*=\s*false\b|\bhttpOnly\s*:\s*false\b/gi, cat: 'config', sev: 'medium', name: 'Cookie 未设 HttpOnly', fix: 'HttpOnly = true' },
    { re: /\$_SERVER\s*\[\s*['"]HTTP_X_FORWARDED_FOR|headers\s*\[\s*['"]x-forwarded-for|getHeader\s*\(\s*["']X-Forwarded-For/gi, cat: 'auth', sev: 'high', name: '信任 X-Forwarded-For（IP 可伪造）', fix: '只信任已知代理链，或改用真实对端地址' },
    { re: /\$_SERVER\s*\[\s*['"]HTTP_HOST|headers\s*\[\s*['"]host['"]|getHeader\s*\(\s*["']Host/gi, cat: 'header', sev: 'medium', name: '信任 Host 头（可污染绝对 URL / 缓存投毒）', fix: 'Host 白名单校验' },
    { re: /\bauto_prepend_file\b/gi, cat: 'config', sev: 'high', name: 'auto_prepend_file（常见后门手法）', fix: '禁止运行时修改' },
    { re: /\bdisplay_errors\s*=\s*On\b|ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?1/gi, cat: 'config', sev: 'medium', name: '生产环境打开错误回显', fix: 'display_errors=Off，错误只落日志' },
    { re: /\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(/gi, cat: 'rce', sev: 'critical', name: '解码后执行（webshell 特征）', fix: '删除混淆后门代码' },
    { re: /\b(?:system|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(?:POST|GET|REQUEST)/gi, cat: 'rce', sev: 'critical', name: '请求参数直接进入命令执行', fix: '删除该代码，或改为白名单命令' },
    { re: /\balg\s*:\s*['"]none['"]/gi, cat: 'auth', sev: 'critical', name: 'JWT alg=none', fix: '固定算法白名单' },
    { re: /\bpermit!|\bcsrf_exempt\b|AllowAnyOrigin\s*\(/gi, cat: 'auth', sev: 'medium', name: '关闭安全校验（批量赋值 / CSRF / CORS）', fix: '恢复校验，改用显式白名单' },
    { re: /\b0\.0\.0\.0\b/g, cat: 'config', sev: 'low', name: '监听 0.0.0.0（暴露到全部网卡）', fix: '只监听必要网卡，前置防火墙' },
    { re: /\bxpath\s*\(\s*['"][^'"]*['"]\s*\+|\bXPathExpression\b|\bevaluate\s*\(\s*['"][^'"]*['"]\s*\+/gi, cat: 'xpath', sev: 'high', name: 'XPath 拼接（XPath 注入）', fix: '参数化 XPath 表达式，转义单引号' },
    { re: /\b(?:phpinfo|var_dump)\s*\(\s*(?:\)|\$_(?:SERVER|ENV))/gi, cat: 'info', sev: 'low', name: '输出环境变量（信息泄露）', fix: '生产环境移除调试输出' }
  ];
  PATTERNS.push.apply(PATTERNS, PATTERNS_EXT);

  // 配置型特征没有「参数区」，sink 通道会因参数区无标识符而跳过，必须走静态模式
  PATTERNS.push(
    { lang: ['node', 'java', 'python'], re: /\balgorithms\s*:\s*\[\s*['"]none['"]/gi, cat: 'auth', sev: 'critical', name: 'JWT 允许 none 算法（签名可绕过）', fix: '固定 algorithms: ["RS256"]，禁止 none' },
    { lang: ['csharp'], re: /\bTypeNameHandling\s*=\s*TypeNameHandling\s*\./g, cat: 'deserialization', sev: 'critical', name: 'Newtonsoft TypeNameHandling 开启（反序列化 RCE）', fix: '改为 TypeNameHandling.None + 白名单 SerializationBinder' },
    { lang: ['csharp'], re: /\b(?:SimpleTypeResolver|JavaScriptTypeResolver)\b/g, cat: 'deserialization', sev: 'critical', name: 'JavaScriptSerializer 类型解析器（反序列化 RCE）', fix: '移除自定义 TypeResolver' },
    { lang: ['java'], re: /\b(?:autoTypeSupport|enableDefaultTyping|activateDefaultTyping)\b/g, cat: 'deserialization', sev: 'critical', name: '开启多态反序列化（autoType / defaultTyping）', fix: '关闭 autoType；Jackson 用白名单 PolymorphicTypeValidator' },
    { lang: ['java'], re: /\bYaml\s*\.\s*load\s*\(|\bnew\s+Yaml\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'SnakeYAML 反序列化', fix: '改用 SafeConstructor，禁止 !!javax / !!java 标签' },
    { lang: ['java'], re: /\bXStream\b|\.\s*fromXML\s*\(/g, cat: 'deserialization', sev: 'high', name: 'XStream 反序列化', fix: 'XStream 1.4.18+ 并配置 allowTypes 白名单' },
    { lang: ['java'], re: /\bJSON\s*\.\s*parse(?:Object|Array)?\s*\(/g, cat: 'deserialization', sev: 'critical', name: 'Fastjson JSON.parse（autoType 反序列化 RCE）', fix: 'fastjson 升级到 1.2.83+/2.x 并开启 safeMode' },
    { lang: ['ruby'], re: /\bcreate_additions\s*:\s*true/g, cat: 'deserialization', sev: 'high', name: 'JSON.create 允许对象创建', fix: '去掉 create_additions' },
    { lang: ['node'], re: /\bcredentials\s*:\s*true/g, cat: 'cors', sev: 'high', name: 'CORS 允许携带凭据', fix: '来源白名单，禁止与 * 共存' },
    { lang: ['node'], re: /\btrust\s+proxy\b/g, cat: 'config', sev: 'low', name: 'trust proxy 未限定（IP 可伪造）', fix: '显式配置可信代理列表' }
  );

  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  var SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危' };
  var SEV_COLOR = { critical: '#ff4d5e', high: '#ff8a3d', medium: '#ffd23d', low: '#6fcf97' };
  var CAT_LABEL = {
    rce: '命令/代码执行', sqli: 'SQL 注入', xss: 'XSS', lfi: '文件包含',
    path: '路径穿越/文件操作', deserialization: '反序列化', ssrf: 'SSRF',
    ssti: '模板注入', xxe: 'XXE', upload: '文件上传', header: '响应头注入',
    redirect: '开放重定向', ldap: 'LDAP 注入', crypto: '弱加密', random: '弱随机',
    auth: '认证缺陷', config: '配置缺陷', secret: '凭据泄露', cors: 'CORS',
    prototype: '原型污染', redos: 'ReDoS', memory: '内存安全', info: '信息泄露',
    nosqli: 'NoSQL 注入', xpath: 'XPath 注入', zip: '压缩包穿越'
  };

  /* =====================================================================
   * 3. 注释剔除（保留行号与字符串内容）
   * ===================================================================== */
  // JS/Ruby 正则字面量 /re/ 里可以出现引号，若当普通字符处理会把后面的字符串状态带乱，
  // 整段真实代码被当成字符串抹掉 → 漏报。这里用「前一个有效字符」判断 / 是除号还是正则起始。
  var RE_PREV = /[({[=,:;!&|?+\-*%^~<>]/;
  var RE_KW = /^(return|typeof|instanceof|in|of|new|delete|void|do|else|case|yield|await|throw)$/;
  function regexAllowed(text, i) {
    var d = text[i + 1];
    if (d === undefined || d === ' ' || d === '\t' || d === '=' || d === '\n') return false;
    var j = i - 1;
    while (j >= 0 && /\s/.test(text[j])) j--;
    if (j < 0) return true;
    var p = text[j];
    if (RE_PREV.test(p)) return true;
    if (/[A-Za-z0-9_$]/.test(p)) {
      var k = j;
      while (k >= 0 && /[A-Za-z0-9_$]/.test(text[k])) k--;
      return RE_KW.test(text.slice(k + 1, j + 1));
    }
    return false;
  }

  function stripComments(text, lang) {
    var out = '';
    var i = 0, n = text.length, state = 0; // 0 code 1 sq 2 dq 3 line 4 block 5 bt 6 py-docstring 7 regex
    var inClass = false;
    var heredocTag = '';
    var interpStack = [];   // JS 模板字符串 ${...} 嵌套栈：里面可以再套 `...`，不管就会把 // 当注释
    var triple = '';
    while (i < n) {
      var c = text[i], d = text[i + 1];
      if (state === 0) {
        if (interpStack.length) {
          // 在 ${...} 里：花括号要配对，配平后回到模板正文
          if (c === '}') {
            if (interpStack[interpStack.length - 1].brace === 0) { interpStack.pop(); state = 5; out += c; i++; continue; }
            interpStack[interpStack.length - 1].brace--;
          } else if (c === '{') {
            interpStack[interpStack.length - 1].brace++;
          }
        }
        // python 的 // 是整除、ruby 的 // 是空正则，都不是注释（当成注释会把后半行真实代码抹掉）
        if (c === '/' && d === '/' && lang !== 'python' && lang !== 'ruby') { state = 3; out += '  '; i += 2; continue; }
        // php heredoc / nowdoc：<<<EOT ... EOT 里的 /* 或 // 不是注释，
        // 当注释处理会把后面整段真实代码（含 sink）一起吞掉 → 漏报
        if (lang === 'php' && c === '<' && text.substr(i, 3) === '<<<') {
          var hm = /^<<<[ \t]*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/.exec(text.slice(i, i + 64));
          if (hm) { state = 8; heredocTag = hm[1]; out += text.substr(i, hm[0].length); i += hm[0].length; continue; }
        }
        if (c === '/' && d !== '/' && d !== '*' && (lang === 'node' || lang === 'ruby') && regexAllowed(text, i)) {
          state = 7; inClass = false; out += c; i++; continue;
        }
        if (c === '#' && (lang === 'php' || lang === 'python' || lang === 'ruby' || lang === 'asp')) {
          // php 的 #[Attribute] 不算注释；文件首行的 #! shebang 也不是注释（php 靠它跳过首行）
          if (!(lang === 'php' && d === '[') && !(i === 0 && d === '!')) { state = 3; out += ' '; i += 1; continue; }
        }
        if (c === '-' && d === '-' && (lang === 'asp')) { state = 3; out += '  '; i += 2; continue; }
        if (c === '/' && d === '*') { state = 4; out += '  '; i += 2; continue; }
        if (c === '<' && d === '%' && (lang === 'asp' || lang === 'java')) {
          // <%-- ... --%>
          if (text.substr(i, 4) === '<%--') { state = 4; out += '    '; i += 4; continue; }
        }
        if (lang === 'python' && ((c === '"' && text.substr(i, 3) === '"""') || (c === "'" && text.substr(i, 3) === "'''"))) {
          state = 6; triple = c; out += c + c + c; i += 3; continue;
        }
        if (c === "'") { state = 1; out += c; i++; continue; }
        if (c === '"') { state = 2; out += c; i++; continue; }
        if (c === '`') { state = 5; out += c; i++; continue; }
        out += c; i++; continue;
      }
      if (state === 3) {
        if (c === '\n') { state = 0; out += '\n'; i++; continue; }
        out += ' '; i++; continue;
      }
      if (state === 4) {
        if (c === '*' && d === '/') { state = 0; out += '  '; i += 2; continue; }
        if (c === '-' && d === '-' && text[i + 2] === '%' && text[i + 3] === '>') { state = 0; out += '    '; i += 4; continue; }
        out += (c === '\n' ? '\n' : ' '); i++; continue;
      }
      // 字符串内
      if (state === 6) {
        if (c === triple && text.substr(i, 3) === triple + triple + triple) { state = 0; out += triple + triple + triple; i += 3; continue; }
        out += (c === '\n' ? '\n' : ' '); i++; continue;
      }
      if (state === 8) {
        if (c === '\n') {
          var em = /^[ \t]*([A-Za-z_][A-Za-z0-9_]*)/.exec(text.slice(i + 1, i + 129));
          if (em && em[1] === heredocTag) { state = 0; out += '\n'; i++; continue; }
          out += '\n'; i++; continue;
        }
        out += ' '; i++; continue;
      }
      if (state === 5 && c === '$' && d === '{') {
        interpStack.push({ brace: 0 }); state = 0; out += '${'; i += 2; continue;
      }
      if (state === 7) {
        // 正则不跨行：碰到换行说明前面判错了（其实是除号），退回代码态
        if (c === '\n') { state = 0; inClass = false; out += '\n'; i++; continue; }
        if (c === '\\') { out += c + (d || ''); i += 2; continue; }
        if (c === '[') inClass = true;
        else if (c === ']') inClass = false;
        else if (c === '/' && !inClass) {
          state = 0; out += c; i++;
          while (i < n && /[a-z]/i.test(text[i])) { out += text[i]; i++; }   // flags
          continue;
        }
        out += c; i++; continue;
      }
      if (c === '\\') { out += c + (d || ''); i += 2; continue; }
      if (state === 1 && c === "'") { state = 0; out += c; i++; continue; }
      if (state === 2 && c === '"') { state = 0; out += c; i++; continue; }
      if (state === 5 && c === '`') { state = 0; out += c; i++; continue; }
      out += c; i++; continue;
    }
    return out;
  }

  /* =====================================================================
   * 4. 污点引擎
   * ===================================================================== */
  var IDENT_RES = [
    /[A-Za-z_$][A-Za-z0-9_$]*/g,                     // php / js / java / go
    /[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/g
  ];

  function findAllIdentifiers(line, lang) {
    var set = {};
    var re = /[A-Za-z_$][A-Za-z0-9_$]*(?:\s*(?:\.|->|::)\s*[A-Za-z_$][A-Za-z0-9_$]*)*/g;
    var m;
    while ((m = re.exec(line))) {
      var raw = m[0];
      // 记录完整链与链尾
      var parts = raw.split(/\s*(?:\.|->|::)\s*/);
      for (var i = 0; i < parts.length; i++) {
        if (parts[i]) set[parts[i]] = 1;
      }
      // 数组下标形式 a['x'] -> 记录 a
      var bracket = /\[[^\]]*\]/g, bm;
      while ((bm = bracket.exec(raw))) { /* noop */ }
    }
    // 记录 foo[ 形式的基名
    var re2 = /([A-Za-z_$][A-Za-z0-9_$]*)\s*\[/g, m2;
    while ((m2 = re2.exec(line))) { set[m2[1]] = 1; }
    var all = Object.keys(set);
    if (lang === 'php') {
      // PHP 只有 $var 才是变量；字符串插值 "$id" 也必须参与传播
      var only = [];
      for (var z = 0; z < all.length; z++) if (all[z].charAt(0) === '$') only.push(all[z]);
      return only;
    }
    return all;
  }

  // 取标识符：php 用原始行（保留 "$id" 插值），其他语言先抹掉字符串字面量
  function idsOf(text, lang) {
    return findAllIdentifiers(codeOnly(text, lang), lang);
  }

  // 人工复核标记的正则。写在被标记行本身或它的上一行都算。
  var IGNORE_RE = /(?:lingops|awdp)\s*:\s*(?:ignore|safe|fp|false-?positive)|noscan|nosec\b/i;
  // 占位符口令不算硬编码凭据（测试/示例里遍地都是，报出来只会淹没有效告警）
  var SECRET_PLACEHOLDER = /^(?:(?:secret|password|passwd|pass|test|testing|dummy|fake|example|sample|placeholder|changeme|change[_-]?me|none|null|todo|xxx)\d*|\*+|\.{3,}|<[^>]*>|your[_-][\w-]*)$/i;
  var suppressedCount = 0;

  // 有些校验天然写在调用点上方若干行（realpath/basename/finfo/随机名），
  // 污点追踪看不到这层关系，所以在「没追到污点」时允许回看有限行数。
  // 有污点时不回看，避免把真实漏洞降级。
  var SAN_LOOKBACK = { path: 8, ssrf: 8, upload: 6, lfi: 5, prototype: 6, sqli: 3 };

  // 净化结果必须真的流到 sink，否则就是「诱饵」：
  //   $p = realpath($f); readfile($f);   ← realpath 没用在 readfile 上，照样能穿越
  function lhsVar(line) {
    var m = /(?:^|[;,({}\[\n])\s*(?:var|let|const|my|local|final|string|int)?\s*\$?([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::=|=|<-)\s*(?!=)/.exec(line);
    if (!m) return null;
    var v = m[1];
    if (/^(?:var|let|const|return|if|else|for|while|switch|case|echo|print|then|do|new|await)$/.test(v)) return null;
    return v;
  }

  function flowsToSink(pl, region) {
    var v = lhsVar(pl);
    if (!v) return true;   // 行内净化（basename($_GET['f']) 直接内嵌）交给文本匹配
    var esc = v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // 前面不能是 . 或标识符字符（$ 允许，PHP 变量带 $）：req.query.u 里的 u 不是变量 u 的流动
    return new RegExp('(?:^|[^\\w.])' + esc + '(?![\\w$])').test(region);
  }

  function sanitizedFor(cat, region, originLine, linesArr, sinkLn) {
    var list = SANITIZERS[cat];
    if (!list) return false;
    for (var i = 0; i < list.length; i++) {
      if (list[i].test(region)) return true;
      if (!originLine || !list[i].test(originLine)) continue;
      // 污点源与 sink 同行 → 净化是内嵌的（basename($_GET['f']) 直接进 sink）
      if (!linesArr || originLine === linesArr[sinkLn]) return true;
      // 跨行时净化结果必须真的流到 sink 参数区，否则是诱饵：
      //   const u = new URL(req.query.u); fetch(req.query.u);
      if (flowsToSink(originLine, region)) return true;
    }
    // 回看不再因为「有污点源」而整体关闭：净化往往写在独立的赋值语句里
    //   $real = realpath($root . $f);  readfile($real);
    // 是否放宽交给 flowsToSink 判断——净化结果没流到 sink 就是诱饵，照样报。
    var lb = SAN_LOOKBACK[cat] || 0;
    if (linesArr && typeof sinkLn === 'number' && lb) {
      for (var b = 1; b <= lb; b++) {
        var pl = linesArr[sinkLn - b];
        if (!pl) continue;
        for (var j = 0; j < list.length; j++) {
          if (!list[j].test(pl)) continue;
          if (flowsToSink(pl, region)) return true;
        }
      }
    }
    return false;
  }

  // argv 数组形式本来是安全的，但一旦外面套 sh -c 就等于命令拼接，
  // 这种情况下所有 rce 净化规则都不成立。
  var SHELL_WRAPPER = /(?:execFile|spawn|Open3\s*\.\s*\w+|subprocess\s*\.\s*\w+|Popen|call|run)\s*\(\s*\[?\s*['"](?:sh|bash|zsh|dash|cmd|powershell|pwsh)['"]\s*,\s*['"]-[a-z]*c['"]/;

  // 原型污染的守卫（k === '__proto__'）几乎总是写在函数体内部，
  // 行级回看看不到，因此 prototype 类改用整文件判定。
  function fileSanitized(cat, fullText) {
    if (cat === 'prototype') return /__proto__/.test(fullText);
    return false;
  }

  // 这些类别的 sink 参数用字符串拼接出来，基本等于把可控值直接塞进语法结构
  // 不含 path / ssti：`dir + ".pil"`、`"{}".format()` 这类拼接在正常代码里太常见，
  // 升级只会制造噪声；SQL / 命令 / 头 / 跳转拼出来几乎必然是注入面。
  var CONCAT_SINK = { sqli: 1, nosql: 1, rce: 1, lfi: 1, xxe: 1, ldap: 1, header: 1, redirect: 1 };

  var MAX_CHAIN = 40;

  function analyzeText(path, rawText, lang, opts) {
    var findings = [];
    var untraced = [];   // 高风险 sink 但没追到污点来源，最后作为低置信提示输出
    var wantLow = !opts || opts.lowConfidence !== false;
    var text = stripComments(rawText, lang);
    var lines = text.split('\n');
    var srcLines = rawText.split('\n');
    var sources = SOURCES[lang] || [];
    var sinks = SINKS[lang] || [];

    // 第一遍：标记 source 行，建立污点集合
    var tainted = Object.create(null); // 变量名 -> {line, label}
    var taintLines = [];     // 每行的污点来源描述（供 sink 行判断）
    var lineSrc = [];        // 每行 source 标签

    for (var ln = 0; ln < lines.length; ln++) {
      var line = lines[ln];
      lineSrc[ln] = [];
      for (var s = 0; s < sources.length; s++) {
        sources[s].re.lastIndex = 0;
        if (sources[s].re.test(line)) lineSrc[ln].push(sources[s].label);
      }
      if (!lineSrc[ln].length) continue;

      // 该行声明的变量获得污点
      var decls = declTargets(line, lang);
      for (var d = 0; d < decls.length; d++) {
        if (!hasTaint(tainted, decls[d])) tainted[decls[d]] = { line: ln + 1, label: lineSrc[ln][0] };
      }
      // 整行所有标识符也算潜在污点（宽松：source 行内的变量都可能被污染）
      var ids = idsOf(line, lang);
      for (var q = 0; q < ids.length; q++) {
        if (isNoise(ids[q])) continue;
        if (!hasTaint(tainted, ids[q])) tainted[ids[q]] = { line: ln + 1, label: lineSrc[ln][0] };
      }
    }

    // 第二遍：迭代传播污点（多轮直到收敛）
    for (var round = 0; round < 8; round++) {
      var changed = false;
      for (var i2 = 0; i2 < lines.length; i2++) {
        var l2 = lines[i2];
        if (!l2 || /^\s*$/.test(l2)) continue;
        var ids2 = idsOf(l2, lang);
        var hit = null;
        for (var k = 0; k < ids2.length; k++) {
          var hv = hasTaint(tainted, ids2[k]);
          if (hv) { hit = hv; break; }
        }
        if (!hit) continue;
        // 该行若含赋值，则赋值目标继承污点
        var tg = declTargets(l2, lang);
        for (var t = 0; t < tg.length; t++) {
          if (isNoise(tg[t])) continue;
          if (!hasTaint(tainted, tg[t])) {
            tainted[tg[t]] = { line: hit.line, label: hit.label, via: hit.via || hit.line };
            changed = true;
          }
        }
        // 函数调用返回值赋给变量：var x = foo(tainted)
        var callAssign = /(?:var|let|const|val|def)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::=|=)\s*[^=]*(?:\([^)]*\))/.exec(l2);
        if (callAssign && callAssign[1] && !hasTaint(tainted, callAssign[1]) && !isNoise(callAssign[1])) {
          tainted[callAssign[1]] = { line: hit.line, label: hit.label, via: hit.via || hit.line };
          changed = true;
        }
      }
      if (!changed) break;
    }

    // 第三遍：sink 匹配
    var seen = Object.create(null);
    for (var ln2 = 0; ln2 < lines.length; ln2++) {
      var L = lines[ln2];
      if (!L || /^\s*$/.test(L)) continue;
      var idsL = idsOf(L, lang);
      var rowTaint = null;
      for (var a = 0; a < idsL.length; a++) {
        var rv = hasTaint(tainted, idsL[a]);
        if (rv) { rowTaint = { line: rv.line, label: rv.label, varName: idsL[a] }; break; }
      }
      var rowSrc = lineSrc[ln2].length > 0;
      if (/^\s*(?:import|from|package|using|namespace|#include|require\s*[('"])/.test(L)) continue;

      for (var sk = 0; sk < sinks.length; sk++) {
        var S = sinks[sk];
        S.re.lastIndex = 0;
        var mm = S.re.exec(S.raw ? L : codeOnly(L, lang));
        if (!mm) continue;

        // 取 sink 的参数区（支持跨行调用），只认参数区里的污点变量
        var region = L.slice(mm.index);
        var balance = 0, started = false, li = ln2;
        for (var guard = 0; guard < 8; guard++) {
          for (var ci = 0; ci < region.length; ci++) {
            var ch = region[ci];
            if (ch === '(') { balance++; started = true; }
            else if (ch === ')') { balance--; }
          }
          if (!started || balance <= 0) break;
          li++;
          if (li >= lines.length) break;
          region += '\n' + lines[li];
        }
        var argTaint = null;
        var argIds = idsOf(region, lang);
        var selfSet = Object.create(null);
        var selfIds = idsOf(mm[0], lang);
        for (var si = 0; si < selfIds.length; si++) selfSet[selfIds[si]] = 1;
        var candN = 0;
        for (var ai = 0; ai < argIds.length; ai++) {
          if (selfSet[argIds[ai]]) continue;
          candN++;
          var tv = hasTaint(tainted, argIds[ai]);
          if (tv) { argTaint = { line: tv.line, label: tv.label, varName: argIds[ai] }; break; }
        }
        if (!argTaint) {
          // 参数区完全没有标识符（如 include/return 后换行）才退回整行污点
          if (candN > 0) { if (wantLow) untraced.push({ ln: ln2, S: S }); continue; }
          // 参数区连标识符都没有（如 system("ls")），是纯静态调用，不算候选
          if (!rowTaint && !rowSrc) continue;
          argTaint = rowTaint;
        }
        var useTaint = argTaint;
        var isSanitized = sanitizedFor(S.cat, region, useTaint ? srcLines[useTaint.line - 1] : null, lines, ln2)
          || fileSanitized(S.cat, text);
        if (isSanitized && S.cat === 'rce' && SHELL_WRAPPER.test(srcLines[ln2] || '')) isSanitized = false;
        if (isSanitized && S.cat !== 'secret') continue;

        var key = S.cat + '|' + S.name + '|' + (useTaint ? useTaint.line : ln2 + 1);
        if (seen[key]) continue;
        seen[key] = 1;

        findings.push({
          file: path,
          lang: lang,
          line: ln2 + 1,
          cat: S.cat,
          sev: isSanitized ? 'low' : S.sev,
          name: S.name,
          fix: S.fix,
          sanitized: isSanitized,
          source: useTaint ? {
            line: useTaint.line,
            label: useTaint.label,
            varName: useTaint.varName,
            code: (srcLines[useTaint.line - 1] || '').trim()
          } : null,
          code: (srcLines[ln2] || '').trim().slice(0, 300),
          rule: 'awdpplus'
        });
      }
    }

    // 第四遍：静态弱点（与污点无关）
    for (var ln3 = 0; ln3 < lines.length; ln3++) {
      var L3 = lines[ln3];
      if (!L3) continue;
      for (var p = 0; p < PATTERNS.length; p++) {
        var P = PATTERNS[p];
        if (P.lang && P.lang.indexOf(lang) < 0) continue;
        P.re.lastIndex = 0;
        if (!P.re.test(L3)) continue;
        if (P.cat === 'secret') {
          var mv = /['"]([^'"\s]{6,})['"]/.exec(L3);
          if (mv && SECRET_PLACEHOLDER.test(mv[1])) continue;
        }
        findings.push({
          file: path, lang: lang, line: ln3 + 1, cat: P.cat, sev: P.sev,
          name: P.name, fix: P.fix, sanitized: false, source: null,
          code: (srcLines[ln3] || '').trim().slice(0, 300), rule: 'awdpplus-static'
        });
      }
    }

    // 第五遍：低置信兜底 —— 高破坏力 sink 在本文件内追不到 source 时不再静默丢弃。
    // 真实项目里数据流常常跨文件 / 经框架注入，完全依赖同文件污点会大量漏报。
    if (untraced.length) {
      // path/ssrf/prototype 的真实入口常常是函数参数（数据从框架/路由注入），
      // 同文件里追不到 source。不纳入兜底会系统性漏报，所以一并作为低危提示。
      var LOW_CATS = { rce: 1, deserialization: 1, xxe: 1, ssti: 1, lfi: 1, sqli: 1, path: 1, ssrf: 1, prototype: 1, nosqli: 1, zip: 1, xpath: 1 };
      var have = Object.create(null);
      var seenCat = Object.create(null);   // 兜底按类别去重，避免同一文件刷屏
      for (var fi = 0; fi < findings.length; fi++) have[findings[fi].line + '|' + findings[fi].cat] = 1;
      for (var ui = 0; ui < untraced.length; ui++) {
        var u = untraced[ui];
        if (!LOW_CATS[u.S.cat]) continue;
        var uk = (u.ln + 1) + '|' + u.S.cat;
        if (have[uk]) continue;
        if (seenCat[u.S.cat + '|' + u.S.name]) continue;
        seenCat[u.S.cat + '|' + u.S.name] = 1;
        have[uk] = 1;
        var uSan = sanitizedFor(u.S.cat, lines[u.ln], null, lines, u.ln) || fileSanitized(u.S.cat, text);
        if (uSan) continue;
        // 参数区在 sink 行上由字符串拼接构造（"SELECT ... " + id）时，拼接本身就是注入面，
        // 即使污点来源在别的文件/框架里追不到，也不再降级成低置信。
        var uLine = lines[u.ln] || '';
        var uConcat = !!CONCAT_SINK[u.S.cat] && /["']\s*\+|\+\s*["']/.test(uLine);
        findings.push({
          file: path, lang: lang, line: u.ln + 1, cat: u.S.cat, sev: uConcat ? 'high' : 'low',
          name: u.S.name + (uConcat ? '（字符串拼接构造，参数需确认可控）' : '（未追到污点来源）'),
          fix: u.S.fix + '；参数可能来自其它文件/框架注入，需人工确认是否可控',
          sanitized: false, source: null,
          code: (srcLines[u.ln] || '').trim().slice(0, 300), rule: 'awdpplus-lowconf'
        });
      }
    }

    // 人工复核标记：命中行或上一行带 lingops:ignore / lingops:safe / nosec 的，
    // 说明开发者已经确认过（例如上游已用 safe_outdir() 归一化），不再重复上报。
    if (findings.length) {
      var kept = [];
      for (var fj = 0; fj < findings.length; fj++) {
        var fLine = srcLines[findings[fj].line - 1] || '';
        var fPrev = srcLines[findings[fj].line - 2] || '';
        if (IGNORE_RE.test(fLine) || IGNORE_RE.test(fPrev)) { suppressedCount++; continue; }
        kept.push(findings[fj]);
      }
      findings = kept;
    }

    return findings;
  }

  function hasTaint(t, id) {
    if (!id || !(id in t)) return null;
    var v = t[id];
    if (!v || typeof v.line !== 'number') return null;
    return v;
  }

  // 把字符串字面量的内容抹掉（保留分隔符与行结构），避免把 "bypass" 当成变量。
  // 但字符串「插值」是真数据流，必须保留，否则 system("ls #{x}") / "WHERE id=$id" 会漏报：
  //   Ruby  #{expr}      PHP   "$var" / "{$var}"
  //   Python f"{expr}"   C#    $"{expr}"
  // JS 模板串用反引号，本来就不被当成字符串，天然保留。
  function codeOnly(line, lang) {
    var out = '', st = 0, interp = 0, dyn = false;
    for (var i = 0; i < line.length; i++) {
      var c = line[i], d = line[i + 1];
      if (st === 0) {
        if (c === "'" || c === '"') {
          st = c === "'" ? 1 : 2;
          var p = i > 0 ? line[i - 1] : '';
          // f"..." (python) / $"..." (csharp) 是插值字符串
          dyn = st === 2 && ((p === 'f' || p === 'F') || (p === '$' && lang !== 'php'));
          out += c;
        } else out += c;
        continue;
      }
      if (c === '\\') { out += '  '; i++; continue; }
      if (st === 1 && c === "'") { st = 0; out += c; continue; }
      if (st === 2 && c === '"' && interp === 0) { st = 0; out += c; continue; }
      // 插值开始
      if (interp === 0) {
        if (c === '#' && d === '{' && lang === 'ruby') { interp = 1; out += '  '; i++; continue; }
        if (c === '$' && d === '{' && lang !== 'php') { interp = 1; out += '  '; i++; continue; }
        if (c === '$' && lang === 'php' && d && /[A-Za-z_{]/.test(d)) {
          // PHP "$var" / "{$var}" 插值：整段保留，否则 $id 会被截成 $
          var j = i + 1;
          if (d === '{') { j++; }
          while (j < line.length && /[A-Za-z0-9_$]/.test(line[j])) j++;
          out += line.slice(i, j);
          i = j - 1;
          continue;
        }
        if (dyn && c === '{') { interp = 1; out += ' '; continue; }
      }
      if (interp > 0) {
        if (c === '{') interp++;
        else if (c === '}') interp--;
        out += c;
        continue;
      }
      out += ' ';
    }
    return out;
  }

  function isNoise(id) {
    if (!id) return true;
    if (/^(?:true|false|null|None|nil|this|self|new|var|let|const|function|return|if|else|for|while|echo|print|int|string|bool|float|void|public|private|protected|static|final|class|import|package|using|namespace|def|elif|then|end|do|try|catch|except|finally|throw|throws|switch|case|break|continue|default|extends|implements|interface|abstract|synchronized|override|virtual|async|await|typeof|instanceof|in|of|and|or|not|is|with|as|from|lambda|pass|global|nonlocal|yield|assert|del|raise|void|nullptr|make|map|chan|defer|go|select|range|struct|type|func|package)$/.test(id)) return true;
    return false;
  }

  // 提取赋值目标变量名
  function declTargets(line, lang) {
    var out = [];
    var re;
    if (lang === 'php') {
      re = /(?:^|[;,{(\s])(\$[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])*\s*(?:\.?=|\+=|\.=)/g;
    } else if (lang === 'python' || lang === 'ruby') {
      re = /(?:^|[\s;,(])([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*=(?!=)/g;
    } else if (lang === 'go') {
      re = /(?:^|[\s;,(])([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)(?!=)/g;
      // 多返回值：a, b := f()
      var multi = /([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*:?=/g, m3;
      while ((m3 = multi.exec(line))) { out.push(m3[1]); out.push(m3[2]); }
    } else {
      re = /(?:^|[\s;,(])(?:var|let|const|final|String|int|long|byte\[\]|Object|Map\s*<[^>]*>|[A-Z][A-Za-z0-9_<>,\[\] ]*)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:\[[^\]]*\])?\s*=(?!=)/g;
    }
    var m;
    while ((m = re.exec(line))) {
      if (m[1] && !isNoise(m[1])) out.push(m[1]);
    }
    // php 数组赋值 $a['k'] = ...
    if (lang === 'php') {
      var re2 = /\$([A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]*\]\s*(?:\.?=)/g, m2;
      while ((m2 = re2.exec(line))) { if (!isNoise(m2[1])) out.push(m2[1]); }
    }
    // 对象属性赋值 this.x = ...
    var re3 = /(?:this|self|@|_)\.?([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)/g, m4;
    while ((m4 = re3.exec(line))) { if (!isNoise(m4[1])) out.push(m4[1]); }
    if (lang === 'node') {
      // NestJS 装饰器参数：@Query('c') c: string
      var dec = /@(?:Query|Param|Body|Headers|Req|Request)\s*\([^)]*\)\s*([A-Za-z_$][A-Za-z0-9_$]*)/g, m5;
      while ((m5 = dec.exec(line))) { if (!isNoise(m5[1])) out.push(m5[1]); }
      // 解构：const { name, id: alias } = request.formData() / context.params
      var dst = /(?:const|let|var)\s*\{([^{}]*)\}\s*=/g, m6;
      while ((m6 = dst.exec(line))) {
        var segs = m6[1].split(',');
        for (var q = 0; q < segs.length; q++) {
          var nm = segs[q].split(':').pop().split('=')[0].replace(/\.\.\./g, '').trim();
          if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(nm) && !isNoise(nm)) out.push(nm);
        }
      }
      // 解构入参：({ params }) / ({ query })
      var dst2 = /(?:async\s*)?(?:function\s*[A-Za-z0-9_$]*\s*)?\(\s*\{([^{}]*)\}\s*\)/g, m7;
      while ((m7 = dst2.exec(line))) {
        var segs2 = m7[1].split(',');
        for (var q2 = 0; q2 < segs2.length; q2++) {
          var nm2 = segs2[q2].split(':').pop().split('=')[0].trim();
          if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(nm2) && !isNoise(nm2)) out.push(nm2);
        }
      }
    }
    var s = {}, r = [];
    for (var i = 0; i < out.length; i++) { if (!s[out[i]]) { s[out[i]] = 1; r.push(out[i]); } }
    return r;
  }

  /* =====================================================================
   * 5. ZIP 解析（原生 DecompressionStream）
   * ===================================================================== */
  function u16(dv, o) { return dv.getUint16(o, true); }
  function u32(dv, o) { return dv.getUint32(o, true); }

  async function readZip(buf) {
    var dv = new DataView(buf);
    var len = buf.byteLength;
    // 找 EOCD
    var eocd = -1;
    for (var i = len - 22; i >= 0 && i >= len - 66000; i--) {
      if (u32(dv, i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('不是有效的 ZIP 文件');
    var total = u16(dv, eocd + 10);
    var cdOff = u32(dv, eocd + 16);
    if (cdOff === 0xffffffff) throw new Error('不支持 ZIP64');

    var out = [];
    var p = cdOff;
    for (var n = 0; n < total; n++) {
      if (u32(dv, p) !== 0x02014b50) break;
      var method = u16(dv, p + 10);
      var csize = u32(dv, p + 20);
      var usize = u32(dv, p + 24);
      var fnLen = u16(dv, p + 28);
      var exLen = u16(dv, p + 30);
      var cmLen = u16(dv, p + 32);
      var lho = u32(dv, p + 42);
      var nameBytes = new Uint8Array(buf, p + 46, fnLen);
      var name;
      try { name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes); } catch (e) { name = ''; }
      p += 46 + fnLen + exLen + cmLen;
      if (!name || name.slice(-1) === '/') continue;

      // local header
      var lfnLen = u16(dv, lho + 26);
      var lexLen = u16(dv, lho + 28);
      var dataStart = lho + 30 + lfnLen + lexLen;
      var raw = new Uint8Array(buf, dataStart, csize);

      var bytes;
      if (method === 0) {
        bytes = raw;
      } else if (method === 8) {
        if (typeof DecompressionStream === 'undefined') throw new Error('当前浏览器不支持解压 deflate，请使用新版 Chrome/Edge');
        var ds = new DecompressionStream('deflate-raw');
        var stream = new Blob([raw]).stream().pipeThrough(ds);
        bytes = new Uint8Array(await new Response(stream).arrayBuffer());
      } else {
        continue; // 其它压缩算法跳过
      }
      out.push({ name: name, size: usize, bytes: bytes });
    }
    return out;
  }

  /* =====================================================================
   * 6. 文件收集
   * ===================================================================== */
  var state = {
    files: [],        // {path, text, lang}
    findings: [],
    scannedAt: null,
    lastZipName: '',
    lastZipBlob: null,
    filterSev: '',
    filterCat: '',
    query: '',
    showSanitized: false,
    skipVendor: true,
    lowConfidence: true,   // 高风险 sink 追不到 source 时也给低置信提示
    aiSession: null,
    aiBusy: false,
    aiError: '',
    official: null
  };

  function decodeText(bytes) {
    var u8 = bytes;
    if (u8.length > 2 && u8[0] === 0xff && u8[1] === 0xfe) return new TextDecoder('utf-16le').decode(u8.subarray(2));
    if (u8.length > 2 && u8[0] === 0xfe && u8[1] === 0xff) return new TextDecoder('utf-16be').decode(u8.subarray(2));
    var head = new TextDecoder('utf-8', { fatal: false }).decode(u8.subarray(0, Math.min(4096, u8.length)));
    if (/\uFFFD/.test(head)) {
      try { return new TextDecoder('gbk').decode(u8); } catch (e) { /* fallthrough */ }
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(u8);
  }

  async function ingestZip(file) {
    var buf = await file.arrayBuffer();
    var entries = await readZip(buf);
    var added = 0, skipped = 0;
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var path = e.name.replace(/\\/g, '/');
      if (path.startsWith('__MACOSX/') || /(^|\/)\.DS_Store$/.test(path)) { skipped++; continue; }
      if (state.skipVendor && SKIP_DIR.test(path)) { skipped++; continue; }
      var ex = extOf(path);
      if (SKIP_EXT[ex]) { skipped++; continue; }
      var lang = langOf(path);
      if (!lang) { skipped++; continue; }
      if (e.bytes.length > 3 * 1024 * 1024) { skipped++; continue; }
      var text = decodeText(e.bytes);
      if (text.indexOf('\u0000') >= 0) { skipped++; continue; }
      state.files.push({ path: path, text: text, lang: lang, size: e.bytes.length });
      added++;
    }
    return { added: added, skipped: skipped, total: entries.length };
  }

  function ingestSingleFile(name, text) {
    var lang = langOf(name);
    if (!lang) return false;
    state.files.push({ path: name, text: text, lang: lang, size: text.length });
    return true;
  }

  /* =====================================================================
   * 7. 扫描执行
   * ===================================================================== */
  function runScan() {
    var t0 = performance.now();
    state.findings = [];
    suppressedCount = 0;
    for (var i = 0; i < state.files.length; i++) {
      var f = state.files[i];
      try {
        var res = analyzeText(f.path, f.text, f.lang, { lowConfidence: state.lowConfidence });
        for (var j = 0; j < res.length; j++) state.findings.push(res[j]);
      } catch (e) {
        console.warn('[awdpplus] analyze failed', f.path, e);
      }
    }
    state.findings.sort(function (a, b) {
      var d = (SEV_ORDER[a.sev] || 9) - (SEV_ORDER[b.sev] || 9);
      if (d) return d;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      return a.line - b.line;
    });
    state.scannedAt = new Date();
    state.elapsed = Math.round(performance.now() - t0);
    return state.findings;
  }

  /* =====================================================================
   * 8. 与官方引擎对比
   * ===================================================================== */
  function getToken() {
    try {
      return localStorage.getItem('lingops_token') || localStorage.getItem('token') || '';
    } catch (e) { return ''; }
  }

  async function compareOfficial(zipFile, scanType) {
    var tok = getToken();
    if (!tok) throw new Error('未登录，无法调用官方扫描接口');
    var fd = new FormData();
    fd.append('file', zipFile, zipFile.name);
    fd.append('scan_type', scanType || 'webshell');
    var r = await fetch('/api/v1/awdp/scan-upload', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + tok },
      body: fd
    });
    if (!r.ok) throw new Error('上传失败 HTTP ' + r.status);
    var j = await r.json();
    var jobId = j && j.data && j.data.id;
    if (!jobId) throw new Error('未拿到任务 ID');

    for (var t = 0; t < 90; t++) {
      await new Promise(function (res) { setTimeout(res, 700); });
      var rr = await fetch('/api/v1/awdp/scan-jobs/' + jobId, {
        headers: { Authorization: 'Bearer ' + tok }
      });
      if (!rr.ok) continue;
      var jj = await rr.json();
      var d = jj && jj.data;
      if (!d) continue;
      var job = d.job || {};
      if (job.status === 'completed' || job.status === 'failed') {
        return {
          jobId: jobId,
          status: job.status,
          totalFiles: job.total_files,
          scannedFiles: job.scanned_files,
          findingsCount: job.findings_count,
          ruleCount: job.rule_count,
          findings: d.findings || []
        };
      }
    }
    throw new Error('官方扫描超时（>60s）');
  }

  /* =====================================================================
   * 9. UI
   * ===================================================================== */
  var CSS = [
    '#lp-ap{position:fixed;inset:0;z-index:2147483500;background:#0d1117;color:#d5dae2;',
    'font:13px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;display:flex;flex-direction:column}',
    '#lp-ap *{box-sizing:border-box}',
    '#lp-ap .hd{display:flex;align-items:center;gap:12px;padding:10px 16px;background:#161b22;border-bottom:1px solid #263041;flex:0 0 auto}',
    '#lp-ap .hd h2{margin:0;font-size:15px;font-weight:600;color:#e6edf3}',
    '#lp-ap .hd .sub{font-size:12px;color:#7d8794}',
    '#lp-ap .hd .sp{flex:1}',
    '#lp-ap .x{cursor:pointer;border:1px solid #30363d;background:#21262d;color:#c9d1d9;border-radius:6px;padding:4px 12px;font-size:12px}',
    '#lp-ap .x:hover{background:#30363d}',
    '#lp-ap .bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:10px 16px;background:#11161d;border-bottom:1px solid #21262d;flex:0 0 auto}',
    '#lp-ap .btn{cursor:pointer;border:1px solid #30363d;background:#21262d;color:#c9d1d9;border-radius:6px;padding:5px 12px;font-size:12px;white-space:nowrap}',
    '#lp-ap .btn:hover{background:#30363d;border-color:#484f58}',
    '#lp-ap .btn.pri{background:#1f6feb;border-color:#1f6feb;color:#fff}',
    '#lp-ap .btn.pri:hover{background:#388bfd}',
    '#lp-ap .btn:disabled{opacity:.45;cursor:not-allowed}',
    '#lp-ap input[type=text]{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:5px 10px;font-size:12px;min-width:200px}',
    '#lp-ap select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:5px 8px;font-size:12px}',
    '#lp-ap label.ck{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:#8b949e;cursor:pointer}',
    '#lp-ap .body{flex:1;overflow:auto;padding:14px 16px}',
    '#lp-ap .drop{border:2px dashed #30363d;border-radius:10px;padding:36px;text-align:center;color:#7d8794;transition:.15s;cursor:pointer}',
    '#lp-ap .drop:hover,#lp-ap .drop.on{border-color:#1f6feb;background:#111a2b;color:#a5b3c4}',
    '#lp-ap .drop b{display:block;font-size:14px;color:#c9d1d9;margin-bottom:6px}',
    '#lp-ap .stats{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}',
    '#lp-ap .st{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:8px 14px;min-width:96px}',
    '#lp-ap .st i{display:block;font-style:normal;font-size:11px;color:#7d8794}',
    '#lp-ap .st b{font-size:17px;font-weight:600}',
    '#lp-ap .filelist{max-height:150px;overflow:auto;background:#0b0f14;border:1px solid #21262d;border-radius:8px;padding:6px 10px;font:11px/1.7 ui-monospace,Menlo,Consolas,monospace;color:#7d8794;margin-bottom:10px}',
    '#lp-ap .row{background:#161b22;border:1px solid #21262d;border-left:3px solid #30363d;border-radius:8px;padding:10px 12px;margin-bottom:8px}',
    '#lp-ap .row.critical{border-left-color:#ff4d5e}',
    '#lp-ap .row.high{border-left-color:#ff8a3d}',
    '#lp-ap .row.medium{border-left-color:#ffd23d}',
    '#lp-ap .row.low{border-left-color:#6fcf97}',
    '#lp-ap .r1{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:5px}',
    '#lp-ap .tag{font-size:10px;padding:1px 7px;border-radius:20px;font-weight:600;letter-spacing:.3px}',
    '#lp-ap .cat{font-size:10px;padding:1px 7px;border-radius:4px;background:#21262d;color:#8b949e}',
    '#lp-ap .fname{font:11px ui-monospace,Menlo,Consolas,monospace;color:#58a6ff;word-break:break-all}',
    '#lp-ap .lno{font:11px ui-monospace,monospace;color:#7d8794}',
    '#lp-ap .ttl{font-weight:600;color:#e6edf3;font-size:13px}',
    '#lp-ap code,#lp-ap .code{display:block;font:11px/1.65 ui-monospace,Menlo,Consolas,monospace;background:#0b0f14;border:1px solid #1b2129;border-radius:6px;padding:6px 9px;margin-top:5px;color:#9fb0c4;white-space:pre-wrap;word-break:break-all}',
    '#lp-ap .chain{color:#ffb86c}',
    '#lp-ap .fix{font-size:11px;color:#7ee787;margin-top:4px}',
    '#lp-ap .fix b{color:#4b8b52;font-weight:600}',
    '#lp-ap .san{font-size:10px;color:#6fcf97;border:1px solid #2b4a37;border-radius:4px;padding:0 6px}',
    '#lp-ap .empty{text-align:center;color:#5c6773;padding:50px 0;font-size:13px}',
    '#lp-ap .warn{background:#2a1f10;border:1px solid #6b4a12;color:#e3b341;border-radius:8px;padding:8px 12px;font-size:12px;margin-bottom:10px}',
    '#lp-ap .cmp{background:#101a26;border:1px solid #1f3a5c;border-radius:8px;padding:10px 12px;margin-bottom:10px;font-size:12px}',
    '#lp-ap .cmp b{color:#58a6ff}',
    '#lp-ap .cmp .miss{color:#ff8a3d}',
    '#lp-ap .prog{height:3px;background:#1f6feb;width:0;transition:width .2s}',
    '#lp-ap .aicard{background:#0f1a12;border:1px solid #1f4d2b;border-radius:10px;padding:10px 12px;margin:10px 0;font-size:12px}',
    '#lp-ap .aihd{display:flex;align-items:center;gap:8px;margin-bottom:8px;color:#7ee787;font-weight:600}',
    '#lp-ap .aihd .s{font-weight:400;color:#6b8f74;font-size:11px}',
    '#lp-ap .aihd .sp{flex:1}',
    '#lp-ap .airow{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:6px}',
    '#lp-ap .airow>span.k{color:#7d8794;min-width:56px}',
    '#lp-ap .airow a{color:#58a6ff;word-break:break-all;text-decoration:none;font:11px ui-monospace,Menlo,monospace}',
    '#lp-ap .airow a:hover{text-decoration:underline}',
    '#lp-ap .airow code{display:inline;margin:0;padding:2px 6px;background:#0b0f14;border:1px solid #1b2129;border-radius:5px;font:11px ui-monospace,Menlo,monospace;color:#9fb0c4;word-break:break-all}',
    '#lp-ap .aitip{color:#6b8f74;font-size:11px;line-height:1.7;border-top:1px dashed #1f4d2b;padding-top:6px;margin-top:4px}',
    '#lp-ap .aitip b{color:#e3b341;font-weight:600}',
    '#lp-ap-toast{position:fixed;right:18px;bottom:18px;z-index:2147483600;max-width:420px;background:#0f1a12;border:1px solid #1f4d2b;border-radius:10px;padding:12px 14px;color:#c9d1d9;font:12px/1.65 -apple-system,"PingFang SC",sans-serif;box-shadow:0 8px 28px rgba(0,0,0,.5)}',
    '#lp-ap-toast .t{display:flex;align-items:center;gap:8px;color:#7ee787;font-weight:600;margin-bottom:6px}',
    '#lp-ap-toast .t .x{margin-left:auto;cursor:pointer;color:#7d8794}',
    '#lp-ap-toast a{color:#58a6ff;word-break:break-all;font:11px ui-monospace,Menlo,monospace;text-decoration:none}',
    '#lp-ap-toast .b{display:flex;gap:6px;margin-top:8px}',
    '#lp-ap-toast button{cursor:pointer;border:1px solid #30363d;background:#21262d;color:#c9d1d9;border-radius:6px;padding:3px 10px;font-size:11px}',
    '#lp-ap-toast button:hover{background:#30363d}'
  ].join('');

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function ensureUI() {
    if (document.getElementById('lp-ap')) return document.getElementById('lp-ap');
    var st = document.createElement('style');
    st.textContent = CSS;
    document.head.appendChild(st);

    var root = document.createElement('div');
    root.id = 'lp-ap';
    root.innerHTML =
      '<div class="hd">' +
      '  <h2>🔬 AWDP 深度审计</h2>' +
      '  <span class="sub">跨行污点分析 · v' + VERSION + '</span>' +
      '  <span class="sp"></span>' +
      '  <button class="x" id="lp-ap-close">关闭</button>' +
      '</div>' +
      '<div class="bar">' +
      '  <button class="btn pri" id="lp-ap-scan">开始审计</button>' +
      '  <button class="btn" id="lp-ap-official">对比官方引擎</button>' +
      '  <button class="btn" id="lp-ap-export">导出 JSON</button>' +
      '  <button class="btn" id="lp-ap-md">导出 Markdown</button>' +
      '  <button class="btn" id="lp-ap-clear">清空</button>' +
      '  <input type="text" id="lp-ap-q" placeholder="搜索文件 / 变量 / 规则…">' +
      '  <select id="lp-ap-sev">' +
      '    <option value="">全部等级</option><option value="critical">严重</option>' +
      '    <option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option>' +
      '  </select>' +
      '  <select id="lp-ap-cat"><option value="">全部类型</option></select>' +
      '  <label class="ck"><input type="checkbox" id="lp-ap-san"> 显示已净化</label>' +
      '  <label class="ck"><input type="checkbox" id="lp-ap-vendor" checked> 跳过依赖目录</label>' +
      '  <label class="ck" title="高风险 sink 在本文件追不到 source 时也提示"><input type="checkbox" id="lp-ap-lowconf" checked> 低置信兜底</label>' +
      '</div>' +
      '<div class="body" id="lp-ap-body"></div>';
    document.body.appendChild(root);

    root.querySelector('#lp-ap-close').onclick = function () { root.remove(); };
    root.querySelector('#lp-ap-scan').onclick = doScan;
    root.querySelector('#lp-ap-official').onclick = doCompare;
    root.querySelector('#lp-ap-export').onclick = exportJson;
    root.querySelector('#lp-ap-md').onclick = exportMd;
    root.querySelector('#lp-ap-clear').onclick = function () {
      state.files = []; state.findings = []; state.official = null;
      state.lastZipBlob = null; state.lastZipName = '';
      state.aiSession = null; state.aiError = '';
      renderBody();
    };
    root.querySelector('#lp-ap-q').oninput = function (e) { state.query = e.target.value.toLowerCase(); renderResults(); };
    root.querySelector('#lp-ap-sev').onchange = function (e) { state.filterSev = e.target.value; renderResults(); };
    root.querySelector('#lp-ap-cat').onchange = function (e) { state.filterCat = e.target.value; renderResults(); };
    root.querySelector('#lp-ap-san').onchange = function (e) { state.showSanitized = e.target.checked; renderResults(); };
    root.querySelector('#lp-ap-vendor').onchange = function (e) { state.skipVendor = e.target.checked; };
    root.querySelector('#lp-ap-lowconf').onchange = function (e) {
      state.lowConfidence = e.target.checked;
      if (state.files.length) { runScan(); renderResults(); }
    };

    renderBody();
    return root;
  }

  function renderBody() {
    var body = document.querySelector('#lp-ap-body');
    if (!body) return;
    if (!state.files.length) {
      body.innerHTML =
        '<div class="drop" id="lp-ap-drop">' +
        '  <b>拖入 ZIP / 源码文件，或点击选择</b>' +
        '  支持 PHP · Java/JSP · Go · Python · Node.js · Ruby · ASP/ASPX · C#<br>' +
        '  <span style="font-size:11px">会递归解析 ZIP，自动跳过 vendor / node_modules / 二进制</span>' +
        '</div>' +
        '<input type="file" id="lp-ap-file" multiple style="display:none">' +
        '<input type="file" id="lp-ap-dir" webkitdirectory directory multiple style="display:none">' +
        '<div style="margin-top:10px;display:flex;gap:8px">' +
        '  <button class="btn" id="lp-ap-pick">选择文件</button>' +
        '  <button class="btn" id="lp-ap-pickdir">选择文件夹</button>' +
        '</div>' +
        '<div class="warn" style="margin-top:16px">' +
        '  <b>为什么官方扫描器识别不到？</b><br>' +
        '  官方引擎是「污点门控 + 正则」：正则规则只在该行含 source 或引用了被污染变量时才执行，' +
        '  且 Go 语义引擎只覆盖文件操作、不传播二级变量。因此跨行数据流（<code style="display:inline;padding:0;border:0;background:none">$a=$_GET[..]; system($a);</code>）会被漏报。<br>' +
        '  本扩展在浏览器内做真正的跨行传播：source 行 → 赋值/拼接/函数返回/数组成员 → sink 行，并对每类 sink 判断是否已净化。' +
        '</div>';
      bindDrop();
      return;
    }

    var filesHtml = state.files.slice(0, 300).map(function (f) {
      return esc(f.path) + '  <span style="color:#4b5563">(' + LANG_LABEL[f.lang] + ' · ' + fmtSize(f.size) + ')</span>';
    }).join('<br>');
    if (state.files.length > 300) filesHtml += '<br>… 共 ' + state.files.length + ' 个文件';

    body.innerHTML =
      '<div class="filelist">' + filesHtml + '</div>' +
      '<div class="stats" id="lp-ap-stats"></div>' +
      '<div id="lp-ap-ai"></div>' +
      '<div id="lp-ap-cmp"></div>' +
      '<div id="lp-ap-results"></div>';
    renderAiCard();
    renderResults();
  }

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function renderResults() {
    var statsEl = document.querySelector('#lp-ap-stats');
    var resEl = document.querySelector('#lp-ap-results');
    var cmpEl = document.querySelector('#lp-ap-cmp');
    if (!statsEl || !resEl) return;

    // 统计
    var bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    var byCat = {};
    var filesHit = {};
    for (var i = 0; i < state.findings.length; i++) {
      var f = state.findings[i];
      bySev[f.sev] = (bySev[f.sev] || 0) + 1;
      byCat[f.cat] = (byCat[f.cat] || 0) + 1;
      filesHit[f.file] = 1;
    }
    var langCount = {};
    for (var k = 0; k < state.files.length; k++) {
      langCount[state.files[k].lang] = (langCount[state.files[k].lang] || 0) + 1;
    }

    var langStr = Object.keys(langCount).map(function (l) { return LANG_LABEL[l] + '×' + langCount[l]; }).join(' · ');
    statsEl.innerHTML =
      '<div class="st"><i>文件</i><b>' + state.files.length + '</b></div>' +
      '<div class="st"><i>命中文件</i><b style="color:#ff8a3d">' + Object.keys(filesHit).length + '</b></div>' +
      '<div class="st"><i>问题总数</i><b>' + state.findings.length + '</b></div>' +
      (suppressedCount ? '<div class="st"><i>已忽略</i><b style="color:#8b949e">' + suppressedCount + '</b></div>' : '') +
      '<div class="st"><i>严重</i><b style="color:#ff4d5e">' + (bySev.critical || 0) + '</b></div>' +
      '<div class="st"><i>高危</i><b style="color:#ff8a3d">' + (bySev.high || 0) + '</b></div>' +
      '<div class="st"><i>中危</i><b style="color:#ffd23d">' + (bySev.medium || 0) + '</b></div>' +
      '<div class="st"><i>低危</i><b style="color:#6fcf97">' + (bySev.low || 0) + '</b></div>' +
      '<div class="st"><i>耗时</i><b>' + (state.elapsed || 0) + '<span style="font-size:11px">ms</span></b></div>' +
      (langStr ? '<div class="st" style="min-width:auto"><i>语言分布</i><b style="font-size:11px;font-weight:400;color:#8b949e">' + esc(langStr) + '</b></div>' : '');

    // 类型下拉
    var sel = document.querySelector('#lp-ap-cat');
    if (sel && sel.options.length <= 1) {
      Object.keys(byCat).sort(function (a, b) { return byCat[b] - byCat[a]; }).forEach(function (c) {
        var o = document.createElement('option');
        o.value = c; o.textContent = (CAT_LABEL[c] || c) + ' (' + byCat[c] + ')';
        sel.appendChild(o);
      });
    }

    // 官方对比
    if (cmpEl) cmpEl.innerHTML = renderCompare();

    // 列表
    var list = state.findings.filter(function (f) {
      if (!state.showSanitized && f.sanitized) return false;
      if (state.filterSev && f.sev !== state.filterSev) return false;
      if (state.filterCat && f.cat !== state.filterCat) return false;
      if (state.query) {
        var hay = (f.file + ' ' + f.name + ' ' + f.code + ' ' + (f.source ? f.source.varName : '')).toLowerCase();
        if (hay.indexOf(state.query) < 0) return false;
      }
      return true;
    });

    if (!state.findings.length) {
      resEl.innerHTML = '<div class="empty">点击「开始审计」运行跨行污点分析</div>';
      return;
    }
    if (!list.length) {
      resEl.innerHTML = '<div class="empty">没有符合筛选条件的问题</div>';
      return;
    }

    var html = [];
    for (var n = 0; n < list.length; n++) {
      var x = list[n];
      var col = SEV_COLOR[x.sev] || '#8b949e';
      html.push(
        '<div class="row ' + x.sev + '">' +
        '<div class="r1">' +
        '<span class="tag" style="background:' + col + '22;color:' + col + ';border:1px solid ' + col + '55">' + (SEV_LABEL[x.sev] || x.sev) + '</span>' +
        '<span class="cat">' + esc(CAT_LABEL[x.cat] || x.cat) + '</span>' +
        '<span class="ttl">' + esc(x.name) + '</span>' +
        (x.sanitized ? '<span class="san">已净化</span>' : '') +
        '<span class="sp" style="flex:1"></span>' +
        '<span class="fname">' + esc(x.file) + '</span>' +
        '<span class="lno">:' + x.line + '</span>' +
        '</div>' +
        (x.source
          ? '<div class="chain" style="font-size:11px">污点链：L' + x.source.line + ' <code style="display:inline;padding:0 4px;border:0;background:#1b2129">' +
            esc(x.source.label) + '</code> → 变量 <code style="display:inline;padding:0 4px;border:0;background:#1b2129">' +
            esc(x.source.varName) + '</code> → L' + x.line + ' sink</div>' +
            '<div class="code" style="color:#7d8794">L' + x.source.line + ': ' + esc(x.source.code) + '</div>'
          : '') +
        '<div class="code">L' + x.line + ': ' + esc(x.code) + '</div>' +
        '<div class="fix"><b>修复：</b>' + esc(x.fix) + '</div>' +
        '</div>'
      );
    }
    resEl.innerHTML = html.join('');
  }

  function renderCompare() {
    var o = state.official;
    if (!o) return '';
    if (o.error) return '<div class="warn">官方引擎对比失败：' + esc(o.error) + '</div>';
    var offFiles = {};
    for (var i = 0; i < (o.findings || []).length; i++) {
      var fp = o.findings[i].file_path || o.findings[i].file || '';
      offFiles[fp.replace(/^\/+/, '')] = 1;
    }
    var offBase = {};
    Object.keys(offFiles).forEach(function (p) { offBase[baseName(p)] = 1; });

    var mineFiles = {};
    for (var j = 0; j < state.findings.length; j++) mineFiles[state.findings[j].file] = 1;

    var missed = [];
    Object.keys(mineFiles).forEach(function (p) {
      if (offFiles[p] || offBase[baseName(p)]) return;
      missed.push(p);
    });

    return '<div class="cmp">' +
      '<b>官方引擎</b>：扫描 ' + (o.scannedFiles || 0) + '/' + (o.totalFiles || 0) + ' 文件，' +
      '规则 ' + (o.ruleCount || 0) + ' 条，产出 <b>' + (o.findingsCount || 0) + '</b> 条 findings，命中 ' +
      Object.keys(offBase).length + ' 个文件<br>' +
      '<b>深度审计</b>：命中 ' + Object.keys(mineFiles).length + ' 个文件<br>' +
      (missed.length
        ? '<span class="miss">官方漏报的 ' + missed.length + ' 个文件：</span>' +
          missed.slice(0, 25).map(function (p) { return '<code style="display:inline;padding:0 4px;border:0;background:#1b2129">' + esc(p) + '</code>'; }).join(' ') +
          (missed.length > 25 ? ' …' : '')
        : '<span style="color:#6fcf97">官方引擎已覆盖深度审计命中的全部文件</span>') +
      '</div>';
  }

  function bindDrop() {
    var drop = document.querySelector('#lp-ap-drop');
    var fileIn = document.querySelector('#lp-ap-file');
    var dirIn = document.querySelector('#lp-ap-dir');
    var pick = document.querySelector('#lp-ap-pick');
    var pickDir = document.querySelector('#lp-ap-pickdir');
    if (!drop) return;

    drop.onclick = function () { fileIn.click(); };
    if (pick) pick.onclick = function () { fileIn.click(); };
    if (pickDir) pickDir.onclick = function () { dirIn.click(); };

    ['dragenter', 'dragover'].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('on'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('on'); });
    });
    drop.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files) handleFiles(e.dataTransfer.files);
    });
    fileIn.onchange = function (e) { handleFiles(e.target.files); };
    dirIn.onchange = function (e) { handleFiles(e.target.files); };
  }

  async function handleFiles(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    if (!files.length) return;
    var root = document.querySelector('#lp-ap');
    var body = document.querySelector('#lp-ap-body');
    body.innerHTML = '<div class="empty">正在解析 ' + files.length + ' 个文件…</div>';

    var zipCount = 0, fileCount = 0, skipped = 0;
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      var nm = f.name || '';
      var rel = f.webkitRelativePath || nm;
      if (/\.zip$/i.test(nm)) {
        try {
          var r = await ingestZip(f);
          zipCount++; fileCount += r.added; skipped += r.skipped;
          state.lastZipBlob = f;
          state.lastZipName = nm;
        } catch (e) {
          console.warn('[awdpplus] zip failed', nm, e);
          alert('解析 ZIP 失败：' + nm + '\n' + e.message);
        }
      } else {
        var lang = langOf(rel);
        if (!lang) { skipped++; continue; }
        if (state.skipVendor && SKIP_DIR.test(rel)) { skipped++; continue; }
        if (f.size > 3 * 1024 * 1024) { skipped++; continue; }
        var txt = await f.text();
        if (txt.indexOf('\u0000') >= 0) { skipped++; continue; }
        state.files.push({ path: rel, text: txt, lang: lang, size: f.size });
        fileCount++;
      }
    }
    state.official = null;
    state.aiSession = null;
    state.aiError = '';
    renderBody();
    if (fileCount) doScan();
    if (fileCount) createAiSession({ silent: true });
    else alert('没有可分析的源码文件（跳过 ' + skipped + ' 个非源码/依赖/二进制文件）');
  }

  function doScan() {
    if (!state.files.length) { alert('请先上传 ZIP 或源码文件'); return; }
    runScan();
    renderResults();
  }

  async function doCompare() {
    if (!state.lastZipBlob) {
      alert('对比官方引擎需要原始 ZIP 文件。请以 ZIP 形式重新上传后再试。');
      return;
    }
    var btn = document.querySelector('#lp-ap-official');
    btn.disabled = true; btn.textContent = '对比中…';
    try {
      state.official = await compareOfficial(state.lastZipBlob, 'webshell');
    } catch (e) {
      state.official = { error: e.message };
    }
    btn.disabled = false; btn.textContent = '对比官方引擎';
    renderResults();
  }

  function download(name, text, mime) {
    var blob = new Blob([text], { type: mime || 'application/octet-stream' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 3000);
  }

  function stamp() {
    var d = new Date();
    function p(n) { return n < 10 ? '0' + n : '' + n; }
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
  }

  function exportJson() {
    if (!state.findings.length) { alert('还没有扫描结果'); return; }
    download('awdp-deep-scan-' + stamp() + '.json', JSON.stringify({
      tool: 'LingOps awdpplus',
      version: VERSION,
      generated_at: new Date().toISOString(),
      files: state.files.length,
      findings: state.findings
    }, null, 2), 'application/json');
  }

  function exportMd() {
    if (!state.findings.length) { alert('还没有扫描结果'); return; }
    var byFile = {};
    state.findings.forEach(function (f) { (byFile[f.file] = byFile[f.file] || []).push(f); });
    var out = [];
    out.push('# AWDP 深度审计报告\n');
    out.push('- 生成时间：' + new Date().toLocaleString('zh-CN'));
    out.push('- 分析文件：' + state.files.length + ' 个');
    out.push('- 问题总数：' + state.findings.length + ' 条（严重 ' +
      state.findings.filter(function (f) { return f.sev === 'critical'; }).length + ' / 高危 ' +
      state.findings.filter(function (f) { return f.sev === 'high'; }).length + '）\n');
    Object.keys(byFile).sort().forEach(function (fp) {
      out.push('\n## ' + fp + '\n');
      out.push('| 行 | 等级 | 类型 | 问题 | 污点来源 | 修复建议 |');
      out.push('|---|---|---|---|---|---|');
      byFile[fp].forEach(function (f) {
        out.push('| ' + f.line + ' | ' + (SEV_LABEL[f.sev] || f.sev) + ' | ' +
          (CAT_LABEL[f.cat] || f.cat) + ' | ' + f.name + ' | ' +
          (f.source ? 'L' + f.source.line + ' ' + f.source.label + ' → ' + f.source.varName : '静态') + ' | ' +
          f.fix + ' |');
      });
    });
    download('awdp-deep-scan-' + stamp() + '.md', out.join('\n'), 'text/markdown');
  }

  /* =====================================================================
   * 9.5 AI 修复包（本地链接）
   *   上传 ZIP 后把源码 + 扫描结果落盘到 ~/LingOps-AWDP/<id>/，
   *   并由扩展后端(12801)提供只读 HTTP 链接，供本地/在线 AI 读取后修漏洞。
   * ===================================================================== */
  function aiBase() {
    var host = location.hostname || '127.0.0.1';
    return location.protocol + '//' + host + ':12801';
  }

  function copyText(text, okMsg) {
    var done = function () { toast('已复制：' + (okMsg || ''), 1400); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
      fallbackCopy(text); done();
    }
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;left:-9999px;top:0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* ignore */ }
    ta.remove();
  }

  function toast(msg, ms) {
    var el = document.getElementById('lp-ap-toast-tip');
    if (!el) {
      el = document.createElement('div');
      el.id = 'lp-ap-toast-tip';
      el.style.cssText = 'position:fixed;left:50%;bottom:28px;transform:translateX(-50%);z-index:2147483647;' +
        'background:#161b22;border:1px solid #30363d;color:#e6edf3;border-radius:8px;padding:6px 14px;' +
        'font:12px -apple-system,"PingFang SC",sans-serif;box-shadow:0 6px 20px rgba(0,0,0,.5)';
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.opacity = '1';
    clearTimeout(el.__t);
    el.__t = setTimeout(function () { el.style.opacity = '0'; }, ms || 1800);
  }

  function fileToBase64(file) {
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onload = function () {
        var s = String(fr.result || '');
        resolve(s.slice(s.indexOf(',') + 1));
      };
      fr.onerror = function () { reject(fr.error || new Error('读取 ZIP 失败')); };
      fr.readAsDataURL(file);
    });
  }

  function findingsPayload() {
    return (state.findings || []).map(function (f) {
      return {
        sev: f.sev, cat: f.cat, name: f.name, file: f.file, line: f.line,
        code: f.code || '', fix: f.fix || '', sanitized: !!f.sanitized,
        source: f.source ? { line: f.source.line, label: f.source.label, varName: f.source.varName } : null
      };
    });
  }

  function scanType() {
    return /\/awdp\/fix\b/.test(location.pathname) ? 'fix' : 'break';
  }

  async function createAiSession(opts) {
    opts = opts || {};
    var zipBlob = opts.zipBlob || state.lastZipBlob;
    var name = opts.name || state.lastZipName || ('awdp-' + scanType() + '.zip');
    if (!zipBlob && !(state.files && state.files.length)) {
      if (!opts.silent) toast('请先上传 ZIP 或源码文件');
      return null;
    }
    if (state.aiBusy) return state.aiSession;
    state.aiBusy = true;
    state.aiError = '';
    if (!opts.silent) renderAiCard();

    var payload = {
      name: name,
      scan_type: opts.scanType || scanType(),
      engine: 'awdpplus',
      findings: findingsPayload()
    };
    try {
      if (zipBlob) {
        payload.zip = await fileToBase64(zipBlob);
      } else {
        payload.files = state.files.map(function (f) { return { path: f.path, text: f.text }; });
      }
      var res = await fetch(aiBase() + '/api/awdp/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
      state.aiSession = data;
      state.aiBusy = false;
      renderAiCard();
      if (opts.onDone) opts.onDone(data);
      return data;
    } catch (e) {
      state.aiBusy = false;
      state.aiError = (e && e.message) || String(e);
      console.warn('[awdpplus] AI 修复包生成失败', e);
      renderAiCard();
      if (!opts.silent) toast('生成失败：' + state.aiError + '（扩展后端 12801 是否在运行？）', 4000);
      return null;
    }
  }

  function renderAiCard() {
    var box = document.querySelector('#lp-ap-ai');
    if (!box) return;
    var s = state.aiSession;
    if (state.aiBusy) {
      box.innerHTML = '<div class="aicard"><div class="aihd">🤖 AI 修复包<span class="s">正在生成…</span></div></div>';
      return;
    }
    if (!s) {
      if (!state.aiError) { box.innerHTML = ''; return; }
      box.innerHTML = '<div class="aicard"><div class="aihd" style="color:#ff8a3d">🤖 AI 修复包<span class="s">' +
        esc(state.aiError) + '</span><span class="sp"></span>' +
        '<button class="btn" id="lp-ap-ai-retry">重试</button></div>' +
        '<div class="aitip">需要扩展后端在 <code>127.0.0.1:12801</code> 运行：' +
        '<code>python3 ext/lp_scan_server.py --port 12801</code></div></div>';
      var rb = box.querySelector('#lp-ap-ai-retry');
      if (rb) rb.onclick = function () { createAiSession(); };
      return;
    }
    var sev = s.by_sev || {};
    box.innerHTML =
      '<div class="aicard">' +
      '  <div class="aihd">🤖 AI 修复包<span class="s">' + s.file_count + ' 文件 · ' + s.finding_count +
      ' 问题（严重 ' + (sev.critical || 0) + ' / 高危 ' + (sev.high || 0) + ' / 中危 ' + (sev.medium || 0) +
      ' / 低危 ' + (sev.low || 0) + '）</span><span class="sp"></span>' +
      '    <button class="btn" id="lp-ap-ai-open">打开目录页</button>' +
      '    <button class="btn" id="lp-ap-ai-rebuild">重新生成</button>' +
      '  </div>' +
      '  <div class="airow"><span class="k">本地链接</span>' +
      '    <a href="' + esc(s.url) + '" target="_blank" rel="noopener">' + esc(s.url) + '</a>' +
      '    <button class="btn" id="lp-ap-ai-copylink">复制链接</button></div>' +
      '  <div class="airow"><span class="k">磁盘目录</span><code>' + esc(s.dir) + '</code>' +
      '    <button class="btn" id="lp-ap-ai-copydir">复制路径</button></div>' +
      '  <div class="airow"><span class="k">交给 AI</span>' +
      '    <button class="btn pri" id="lp-ap-ai-copyprompt">复制 AI 提示词</button>' +
      '    <button class="btn" id="lp-ap-ai-copybundle">复制全文源码</button>' +
      '    <a class="btn" href="' + esc(s.links.bundle) + '" target="_blank" rel="noopener" style="text-decoration:none;color:#c9d1d9">bundle.md</a>' +
      '    <a class="btn" href="' + esc(s.links.bundle_txt) + '" target="_blank" rel="noopener" style="text-decoration:none;color:#c9d1d9">bundle.txt</a>' +
      '    <a class="btn" href="' + esc(s.links.attack_plan) + '" target="_blank" rel="noopener" style="text-decoration:none;color:#ff8a3d">⚔️ attack-plan.md</a>' +
      '    <a class="btn" href="' + esc(s.links.fix_plan) + '" target="_blank" rel="noopener" style="text-decoration:none;color:#6fcf97">🛡️ fix-plan.md</a>' +
      '    <a class="btn" href="' + esc(s.links.prompt) + '" target="_blank" rel="noopener" style="text-decoration:none;color:#c9d1d9">prompt.txt</a>' +
      '    <a class="btn pri" href="' + esc(s.url) + 'local-ai.md" target="_blank" rel="noopener" style="text-decoration:none;color:#0d1117">🤖 local-ai.md</a>' +
      '    <a class="btn" href="' + esc(s.url) + 'make_patch.py" target="_blank" rel="noopener" style="text-decoration:none;color:#c9d1d9">📦 make_patch.py</a>' +
      '    <a class="btn" href="' + esc(s.url) + 'extract_files.py" target="_blank" rel="noopener" style="text-decoration:none;color:#c9d1d9">🧩 extract_files.py</a>' +
      '  </div>' +
      '  <div class="aitip"><b>本地 AI（Cursor / Claude Desktop / Copilot / Ollama / LM Studio）</b> → 把 <b>🤖 local-ai.md</b> 整篇丢给它，它直接写 <code>fixed/</code>，再跑 <code>python3 make_patch.py fixed/ --apply-to &lt;靶场根目录&gt;</code>。' +
      '<br>在线 AI（ChatGPT / Claude / DeepSeek）打不开 127.0.0.1 → 先「复制 AI 提示词」，再「复制全文源码」或上传 <code>bundle.md</code>。' +
      '<br><b>⚔️ attack-plan.md</b> = 每条漏洞的入口 / payload / flag 位置；<b>🛡️ fix-plan.md</b> = 根因 / 最小改动 / 验证方法。两个文件都能直接丢给 AI。' +
      '单文件按需读取：<code>' + esc(s.links.raw) + '相对路径</code></div>' +
      '</div>';

    if (!s.links.attack_plan) { s.links.attack_plan = s.url + 'attack-plan.md'; }
    if (!s.links.fix_plan) { s.links.fix_plan = s.url + 'fix-plan.md'; }
    var q = function (id) { return box.querySelector('#' + id); };
    q('lp-ap-ai-open').onclick = function () { window.open(s.url, '_blank', 'noopener'); };
    q('lp-ap-ai-rebuild').onclick = function () { createAiSession(); };
    q('lp-ap-ai-copylink').onclick = function () { copyText(s.url, '本地链接'); };
    q('lp-ap-ai-copydir').onclick = function () { copyText(s.dir, '磁盘目录'); };
    q('lp-ap-ai-copyprompt').onclick = function () {
      fetch(s.links.prompt).then(function (r) { return r.text(); }).then(function (t) {
        copyText(t, 'AI 提示词');
      }, function () {
        copyText('请读取 ' + s.dir + ' 下的源码与 findings.json，逐条复核漏洞并给出最小改动修复。', 'AI 提示词');
      });
    };
    q('lp-ap-ai-copybundle').onclick = function () {
      var btn = q('lp-ap-ai-copybundle');
      btn.disabled = true; btn.textContent = '读取中…';
      fetch(s.links.bundle).then(function (r) { return r.text(); }).then(function (t) {
        copyText(t, '全文源码（' + Math.round(t.length / 1024) + ' KB）');
      }, function () {
        toast('读取失败，请直接点 bundle.md 打开后全选复制', 3000);
      }).then(function () { btn.disabled = false; btn.textContent = '复制全文源码'; });
    };
  }

  /* 官方 Break / Fix 页上传 ZIP 时自动生成链接（不改官方逻辑，只旁路监听） */
  var hookedInputs = typeof WeakSet === 'function' ? new WeakSet() : null;

  function hookOfficialUpload() {
    if (!/\/awdp\/(break|fix)\b/.test(location.pathname)) return;
    var inputs = document.querySelectorAll('input[type=file]');
    for (var i = 0; i < inputs.length; i++) {
      var inp = inputs[i];
      if (hookedInputs && hookedInputs.has(inp)) continue;
      if (hookedInputs) hookedInputs.add(inp);
      inp.addEventListener('change', async function (e) {
        var f = e.target.files && e.target.files[0];
        if (!f || !/\.zip$/i.test(f.name || '')) return;
        // 顺手在本地跑一遍深度审计，让修复包里带上问题清单
        try {
          await ingestZip(f);
          state.lastZipBlob = f;
          state.lastZipName = f.name;
          state.official = null;
          runScan();
        } catch (err) {
          console.warn('[awdpplus] 自动审计失败', err);
        }
        createAiSession({ zipBlob: f, name: f.name, silent: true, onDone: function (s) { showAiToast(s); } });
      }, true);
    }
  }

  function showAiToast(s) {
    var old = document.getElementById('lp-ap-toast');
    if (old) old.remove();
    var el = document.createElement('div');
    el.id = 'lp-ap-toast';
    el.innerHTML =
      '<div class="t">🤖 AI 修复包已生成<span class="x" id="lp-at-x">✕</span></div>' +
      '<div>' + s.file_count + ' 个源码文件 · ' + s.finding_count + ' 条问题</div>' +
      '<a href="' + esc(s.url) + '" target="_blank" rel="noopener">' + esc(s.url) + '</a>' +
      '<div class="b">' +
      '  <button id="lp-at-open">打开</button>' +
      '  <button id="lp-at-link">复制链接</button>' +
      '  <button id="lp-at-prompt">复制提示词</button>' +
      '  <button id="lp-at-dir">复制目录</button>' +
      '</div>';
    document.body.appendChild(el);
    el.querySelector('#lp-at-x').onclick = function () { el.remove(); };
    el.querySelector('#lp-at-open').onclick = function () { window.open(s.url, '_blank', 'noopener'); };
    el.querySelector('#lp-at-link').onclick = function () { copyText(s.url, '本地链接'); };
    el.querySelector('#lp-at-dir').onclick = function () { copyText(s.dir, '磁盘目录'); };
    el.querySelector('#lp-at-prompt').onclick = function () {
      fetch(s.links.prompt).then(function (r) { return r.text(); })
        .then(function (t) { copyText(t, 'AI 提示词'); },
              function () { copyText('请读取 ' + s.dir + ' 下的源码与 findings.json，逐条复核漏洞并给出最小改动修复。', 'AI 提示词'); });
    };
    setTimeout(function () { if (el.parentNode) el.remove(); }, 60000);
  }

  /* =====================================================================
   * 10. 按钮注入
   * ===================================================================== */
  var BTN_ID = 'lp-ap-trigger';
  var TARGETS = [
    { path: /\/awdp\/break\b/, anchor: '上传文件 / ZIP' },
    { path: /\/awdp\/fix\b/, anchor: '上传文件 / ZIP' }
  ];

  function addPageButton() {
    if (document.getElementById(BTN_ID)) return;
    var cur = TARGETS.filter(function (t) { return t.path.test(location.pathname); })[0];
    if (!cur) return;
    var btns = Array.prototype.slice.call(document.querySelectorAll('button'));
    var target = null;
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].textContent.replace(/\s+/g, ' ').trim() === cur.anchor) { target = btns[i]; break; }
    }
    if (!target) return;
    var b = document.createElement('button');
    b.id = BTN_ID;
    b.type = 'button';
    b.className = target.className;
    b.textContent = '🔬 深度审计';
    b.title = '跨行污点分析：补齐官方扫描器因污点门控而漏报的漏洞';
    b.style.marginLeft = '8px';
    b.onclick = function (e) {
      e.preventDefault(); e.stopPropagation();
      ensureUI();
    };
    target.parentNode.insertBefore(b, target.nextSibling);
  }

  // DOM 一变就重试注入：React 渲染完当帧就能出按钮，不用等 2 秒轮询
  function watchDom(fn) {
    var queued = false;
    function run() {
      queued = false;
      try { fn(); } catch (e) { console.warn('[awdpplus] 注入失败', e); }
    }
    function kick() {
      if (queued) return;
      queued = true;
      if (window.requestAnimationFrame) window.requestAnimationFrame(run);
      else setTimeout(run, 16);
    }
    run();
    if (window.MutationObserver) {
      try {
        new MutationObserver(kick).observe(document.documentElement, { childList: true, subtree: true });
      } catch (e) { /* 老浏览器退回轮询 */ }
    }
    setInterval(run, 5000); // 兜底：没有 DOM 变化时也补齐
  }

  function boot() {
    watchDom(function () { addPageButton(); hookOfficialUpload(); });
    console.log('[awdpplus] v' + VERSION + ' loaded — 在 AWDP Break / Fix 页面点击「🔬 深度审计」');
  }

  // 调试入口
  window.__lpAwdpPlusApi = {
    analyzeText: analyzeText,
    stripComments: stripComments,   // 供回归测试校验「注释/docstring 屏蔽」是否过度
    analyzeFile: function (path, text, opts) { return analyzeText(path, text, langOf(path) || 'php', opts); },
    state: state,
    open: ensureUI,
    createAiSession: createAiSession,
    version: VERSION
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
