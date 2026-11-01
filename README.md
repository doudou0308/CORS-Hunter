# CORS Hunter

**面向 Burp Suite 的 CORS 配置检测与浏览器复核扩展。**

从经过 Burp 的流量中生成独立探测请求，检查 Origin、凭证许可和必要的预检条件，再通过浏览器复核实际读取能力。

![Version](https://img.shields.io/badge/version-1.0.1-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![API](https://img.shields.io/badge/Burp_API-legacy_Extender-orange)

**[下载插件 JAR](https://github.com/doudou0308/CORS-Hunter/raw/refs/heads/main/dist/CORS-Hunter-1.0.1.jar)** · **[下载完整项目 ZIP](https://github.com/doudou0308/CORS-Hunter/archive/refs/heads/main.zip)** · [校验文件](SHA256SUMS.txt) · [更新记录](CHANGELOG.md) · [反馈问题](https://github.com/doudou0308/CORS-Hunter/issues)

[安装](#安装) · [控件说明](#控件) · [结果判读](#判定) · [本地靶场](#local-demo) · [源码构建](#源码与构建) · [常见问题](#常见问题) · [许可与来源](#许可与来源)

## 功能概览

| 功能 | 当前支持 |
| --- | --- |
| 自动检测 | 默认仅 Burp Scope 内的 GET/HEAD；保留原始消息，单独构造探测请求 |
| Origin 规则 | 随机 Origin、`null`、可选域名前后缀及自定义 Origin |
| 策略检查 | 精确匹配 ACAO/ACAC，识别重复 ACAO，并检查必要的 OPTIONS 预检 |
| 探测控制 | 去重、防递归标记、有界队列、间隔与预算、失败冷却、暂停及手动重扫 |
| 证据查看 | 原始、探测、预检共六个请求/响应查看器；支持发送到 Repeater |
| 浏览器复核 | 导出本地 HTML，支持普通 fetch 和 null Origin sandbox，由用户点击发送 |
| 结果整理 | 筛选、CSV 导出及 Information / Tentative issue |

自动结果是待复核的策略信号。Origin 反射、`ACAO: *` 或 `CREDENTIAL_POLICY` 均不能单独证明敏感信息泄露；浏览器认证条件和数据敏感性仍需验证。

## 版本与验证

| 项目 | 说明 |
| --- | --- |
| 当前版本 | **1.0.1**；修复导航请求头引起的错误预检，增加 Navigation -> fetch 开关 |
| 安装方式 | **Java 扩展，无需 Jython**；JAR 不包含 Burp API 类或第三方运行依赖 |
| 本机反馈 | Burp Suite Professional 2025.7 / Java 24；本地 reflect 正例、strict 反例及携带测试 Cookie 的浏览器读取链路已反馈通过 |
| 自动化验证 | OpenJDK 17 编译为 Java 8 字节码；83 个 Java 回归断言及导出页 JavaScript 模拟测试通过 |
| 验证边界 | 本地同 site、跨 Origin 测试不代表跨 site Cookie 策略或所有真实业务均已验证；详见 [验证记录](TEST-REPORT.md) |

首次使用建议按下方步骤安装，再运行[本地靶场](#local-demo)。只需安装插件时下载 JAR；需要靶场、测试和源码时下载完整项目 ZIP。

## 安装

先[下载 CORS-Hunter-1.0.1.jar](https://github.com/doudou0308/CORS-Hunter/raw/refs/heads/main/dist/CORS-Hunter-1.0.1.jar)，然后：

1. 停用旧 CORSScanner，以免两个插件同时重复请求。
2. 打开 Burp **Extensions → Installed → Add**。
3. Extension type 选择 **Java**，选择 `dist/CORS-Hunter-1.0.1.jar`，然后 Next。
4. Output 出现 `CORS Hunter 1.0.1 loaded`，主界面出现 **CORS Hunter** 标签页。
5. 在 Burp **Target → Scope** 中加入授权测试目标。插件默认只自动检测 scope 内的 GET/HEAD，流量经过 Proxy、Repeater 等工具即可触发，不要求额外配置 Scanner live audit。

若加载失败：查看该扩展 Errors，把完整报错和 Burp / Java 版本发回。不要将 API 依赖 JAR 作为扩展安装。

## 1.0.1 导航请求修复

1.0.0 会将浏览器导航中的长 Accept、Upgrade-Insecure-Requests 和刷新缓存头视作脚本 fetch 必须携带的字段，导致本地 reflect 靶场被预检拦截。

默认开启 **Navigation -> fetch**。仅当原请求明确带 `Sec-Fetch-Mode: navigate` 且方法为 GET/HEAD 时，构造一个 fetch 变体：Accept 改为 `*/*`，移除 Upgrade-Insecure-Requests、Cache-Control 和 Pragma。认证及自定义业务头仍保留；它们需要预检时仍然严格检查。非导航请求不会被这项修复放宽。

这是变体探测，不是原始导航的完全等价重放；Accept/缓存变化可能改变响应内容。结果 Reason 会注明，点击行时底部可直接查看。关闭该选项可恢复严格原头模式，随后用 Rescan selected 重新扫描。浏览器复核页优先采用实际 probe 的头，不再重新带回导航 Accept。

升级：移除旧插件，加载 1.0.1 JAR，保持 scope、Auto GET/HEAD、Navigation -> fetch 勾选，刷新 reflect 接口。已有靶场可以继续运行，无须重启。

## 这版已实现

- 精确匹配 ACAO 和 ACAC，拒绝 Origin 子串误匹配、重复 ACAO、无效 ACAC 值。
- 默认检测随机 Origin 与 `null`；可选目标域前后缀规则，以及一个自定义、符合序列化要求的 Origin。
- 识别方法及脚本请求头的预检需求。必要时先发送无 Cookie / Authorization 的 OPTIONS，验证方法、请求头、Origin、凭证许可；预检不通过，不重放实际请求。
- 自动只检测 GET/HEAD。POST / PUT / PATCH / DELETE 仅能从右键菜单手动确认后检测，按原始 byte[] 保留正文。拒绝带正文 GET/HEAD、方法覆盖头和 Transfer-Encoding 请求。
- scope 检查、包含协议/端口/方法/query/请求摘要的去重、标记头防递归、单 worker、有界队列、间隔限制、请求预算、慢请求及失败冷却。
- 所有 Swing 模型更新回 EDT；原始、探测和预检各有独立请求/响应查看器及真实消息上下文。
- 发送到 Repeater、筛选、CSV、浏览器复核 HTML、Information / Tentative issue 及去重。
- 浏览器复核页只在本地显示结果，无外传接收地址，不自动发送，不导出 Cookie / Authorization / 原始正文；支持普通 fetch 与 null Origin sandbox 模式。

## 控件

| 控件 | 行为 |
| --- | --- |
| Auto GET/HEAD | 自动接收符合条件的新流量；关闭后已有任务仍执行 |
| Scope only | 默认勾选；入队及每次发送前重新检查 scope |
| Extra origin rules | 增加目标主机名的前后缀边界规则；IP 不生成这两类 |
| Add info issues | 对 2xx 的 CREDENTIAL_POLICY 写入标准 issue；不认定为已确认漏洞 |
| Interval ms | 请求起始间隔，默认 500 ms，最小 200 ms；全局单 worker |
| Pause + cancel queued | 暂停入队，取消排队，在途请求返回后不继续下一步 |
| Resume | 恢复接收；已取消任务需重新触发 |
| Reset dedup/budget | 仅空闲时重置去重、issue 记录、请求计数与故障冷却 |
| Navigation -> fetch | 默认开启；仅导航 GET/HEAD 使用最小 fetch 变体，保留业务头并注明差异 |
| Set custom Origin | 输入 `https://example.invalid` 等完整 Origin，不能带路径、末尾 `/` 或默认端口；清空后点击可删除 |
| Send probe to Repeater | 发送实际探测请求；预检被阻止时发送 OPTIONS。双击行同样有效 |
| Rescan selected | 用原始消息再次手动扫描；仍检查 scope；写操作需要确认 |
| Export browser check | 导出选中结果的 HTML 复核页 |
| Export CSV | 导出全部已显示结果；不受筛选限制；字段引用及公式前缀加固 |
| Clear results | 只清显示与查看器，不取消任务、不清去重 |

**Origin 不等于 URL**：例如 `https://a.example/path` 无效；`https://a.example` 有效。自动生成的 .invalid Origin 不需要真实服务器即可检查服务端反射，但浏览器复核要使用你控制的真实 Origin。

## 判定

| Result | 含义 |
| --- | --- |
| CREDENTIAL_POLICY | 所测 Origin 的实际响应允许凭证模式；需要的预检也通过。尚未确认浏览器能携带认证或返回敏感数据 |
| NONCREDENTIAL_POLICY | 非凭证模式的授权条件通过，但本次 Burp 重放仍可能携带原认证，不能推断匿名泄露 |
| PREFLIGHT_BLOCKED | 所需预检未通过，未发送实际业务请求 |
| HEADER_ONLY | 有 CORS 头，但不满足当前 Origin / 凭证 / 预检条件 |
| REDIRECT | 收到 3xx，插件不编排后续 Location 请求；需要单独复核最终地址 |
| MISS | 所测 Origin 未获得许可，不代表不存在其他 CORS 缺陷 |
| ERROR | 请求失败、冷却、超出预算/大小或其他异常，查看 Reason 与 Errors |

Info issue 附原始、预检、探测消息。结果保留 HTTP 状态；非 2xx 的实际响应也可能符合头部条件，但默认不会为它生成 issue。CORS 协议条件通过不等于漏洞；公开数据、浏览器 Cookie 策略、未知的 Bearer Token 和业务条件都需要人工判断。

<a id="local-demo"></a>

## 本地验收（推荐先做）

需要 Python 3。下载并解压完整项目 ZIP，进入含有 `README.md` 的项目目录后运行：

```powershell
python demo\demo_server.py --api-port 18000 --page-port 18001
```

启动只监听 127.0.0.1 的两个服务：API 为 `http://127.0.0.1:18000`，复核页服务为 `http://127.0.0.1:18001`。本例显式指定 18000/18001（脚本默认端口为 8000/8001）。端口冲突时可用 `--api-port` / `--page-port` 更改，并相应修改下列地址。所有返回数据都是假数据。

1. 在 Burp Target scope 加入 `http://127.0.0.1:18000`。推荐用 Burp 内置浏览器访问以下接口：

   | 接口 | 预期 |
   | --- | --- |
   | `/api/reflect` | random 和 null 通常均为 CREDENTIAL_POLICY |
   | `/api/strict` | 不接受所测 Origin，通常 HEADER_ONLY |
   | `/api/null` | null 为 CREDENTIAL_POLICY，random 为 MISS |
   | `/api/wildcard` | NONCREDENTIAL_POLICY；不能作为凭证读取成功 |
   | `/api/invalid` | HEADER_ONLY，不能被子串误报 |
   | `/api/duplicate` | HEADER_ONLY，不能接受重复 ACAO |

2. 选中 `/api/reflect` 的结果，点击 **Send probe to Repeater**，打开 `Repeater → CORS-1`，确认 Origin、目标主机、端口与请求正确，再点击 Send。插件按钮只导入请求，不会替你点 Repeater Send。
3. 在 Repeater 创建 `GET /api/preflight-denied`，加入 `X-Demo: 1` 并发送。插件会发现需要预检，得到 PREFLIGHT_BLOCKED；实际业务请求不会被插件重放。看 Preflight 标签页确认 OPTIONS 中没有 Cookie/Authorization。
4. 选中 reflect 结果，导出 HTML 到 `demo/pages/check.html`，打开 `http://127.0.0.1:18001/check.html`，点击确认并发送，应显示“浏览器已读取响应”。null 规则可勾选 sandbox 模式再测试。
5. 验证 Cookie：先在同一个浏览器直接访问 API 两次，确认 `cookie_received: true`；再回到 18001 的复核页，勾选 `credentials: include`、不勾选 sandbox，向 `/api/reflect` 发送一次。若可读取且 `cookie_received: true`，表示该本地条件下实现了携带测试 Cookie 的跨 Origin 读取。将目标改为 `/api/strict`，预期无法读取；失败原因仍应结合 DevTools 核对。
6. 测试 scope 移除、重复访问、暂停/恢复和手动重扫。检查 sent/queued 与本地 API 日志，确认不会出现无界递归。

18000 与 18001 是不同 Origin，但属于相同 site。此测试证明跨 Origin 读取链路可工作，不代替真实跨 site Cookie 条件验证。GET 接口可能有副作用，请先用本地假数据验收。

## 限制和预算

- legacy makeHttpRequest 没有单次超时或可靠取消。在 Burp 项目的网络连接设置中使用有限超时。暂停/卸载无法撤回已发送请求；等待超时不代表服务端没有执行。
- 默认每个上下文 2 个 Origin；开启扩展规则最多 4 个，加 custom 最多 5 个。每个 Origin 通常 1 个请求，需要预检时最多 2 个，即最多约 10 次。scope 变化、停止、预检失败和错误会提前终止。
- 全局单 worker，队列 64；最多 3000 个请求上下文、12000 次实际调用、512 个目标 origin、300 条 issue 和 200 条显示结果；最多 128 个待处理 UI 结果。超过显示上限后不再保存新表格行，dropped 增长；可以 Clear 后重新手动检测。issue 可能独立保留。
- 请求上限 64 KiB；原始/探测完整响应上限 512 KiB。仅限制插件保留与分析，不限制 Burp 底层接收超大响应的内存。
- 去重使用完整请求摘要，包含身份与 query。追踪头或 Cookie 变化会增加上下文；手动重扫可绕过已完成项，但不会重复同一在途任务。
- 单次网络调用超过 10 秒，或目标连续 3 次失败，返回后冷却该 origin 30 秒。不是可取消的请求超时。
- 请求头来源无法从代理流量完全还原；预检判断是保守重建。保留业务头/认证，清理 Origin、Referer、条件缓存、Range、逐跳头和不适合重放的协议字段；这也可能改变部分业务行为。需结合浏览器复核。
- OPTIONS 不主动携带凭证，但 Burp 项目级 session/macro 或其他扩展可能再次修改请求。探测标记头可见；不要让其他扩展删除它。
- 本插件未实现 Location 跟随循环；仍应在实际 Burp 版本确认网络栈和其他扩展没有额外改变流程。
- 后缀/前缀规则只是白名单边界线索，不证明攻击者可控制该主机。任意畸形 Origin、接受 null、缺少 Vary 或公开资源允许跨域都不应自动升级成高危。
- 浏览器复核页不会设置 Origin；实际由页面托管地址或 sandbox 决定。自定义头/正文需要手动填写；Cookie 由浏览器管理。页面显示成功后也不会自动将插件结果标成漏洞。
- CSV 前缀防护不是所有表格软件及重新保存流程的通用保证；导出 URL 可能含敏感 query，分享前自行检查。

## 源码与构建

源码使用 Java 8 语言/API、legacy Extender API 2.3。安装 JAR 不含 API 类或第三方运行依赖。无需 Montoya、Jython 或外部运行服务。

有 Python 3 和 JDK 17+ 时，在源码根目录运行：

```powershell
python build.py --test
```

脚本会下载并校验固定版本 API 依赖，编译、运行 Java 回归测试，再生成 `dist/CORS-Hunter-1.0.1.jar`。如果无法下载，将对应依赖手动放到 `lib/burp-extender-api-2.3.jar` 后重试；校验不匹配时不会编译。

可选：有 Node.js 时运行 `node tests/browser_check_test.js` 检查导出页面脚本的普通 fetch、sandbox 和消息回传模拟路径（先运行上述 Java 测试生成页面）。这不是浏览器 CORS 实测。

也提供 pom.xml 供 IDE/Maven 导入；本包实际验证的构建入口是 build.py。测试细节见 TEST-REPORT.md，来源见 NOTICE.md。


## 常见问题

- **访问接口后没有结果**：确认 Auto GET/HEAD 已开启、插件未暂停、URL 在 Target Scope 内，且流量实际经过 Burp。相同原始请求可能已去重；可手动重扫，或空闲时 Reset dedup/budget。查看扩展 Errors 与底部状态。
- **HTTP 为 0、结果为 ERROR**：不是 CORS 判定。检查靶场进程、端口、目标服务及 Errors；先确认同一个请求在 Repeater 中能正常收到响应。
- **PREFLIGHT_BLOCKED 显示 204**：204 是 OPTIONS 的响应状态，不表示 CORS 许可通过；需检查 Preflight Request/Response 及 Reason。
- **浏览器 Failed to fetch**：可能是预期的 CORS 拦截，也可能是网络、TLS、Cookie 或其他浏览器限制；用 DevTools 的 Network/Console 核对，不能直接认定安全。
- **出现 JSONP 候选 URL**：其他扫描扩展产生的请求也可能触发本插件。排查时先停用 JSONP 等主动扫描扩展，避免交叉放大。
- **500 是多少秒**：Interval ms 使用毫秒，500 为 0.5 秒；低流量测试可设为 5000（5 秒）。

## 许可与来源

本项目原创代码采用 [MIT License](LICENSE)。项目根据 CORSScanner 审查需求重新实现，并非上游官方版本；参考来源和 API 依赖说明见 [NOTICE.md](NOTICE.md)。MIT 许可不改变上游项目或第三方依赖自身的许可。

请只对有测试授权的目标使用。写操作需人工确认，GET 接口也可能存在业务副作用。
