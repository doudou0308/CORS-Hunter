# 本地验证记录

日期：2026-11-01

## 环境与构建

- OpenJDK 17.0.20；通过其 javac 模块使用 `--release 8` 编译。
- 官方 Maven 发布：burp-extender-api 2.3，SHA-256 `0b9b16048e1a3d10bb8f36219bb7dfa637dad2d54e116199d3506b4174518e54`。
- Python 3 构建脚本；Node.js 24.22.1 用于导出页面脚本模拟。
- 实际执行 `python3 build.py --test` 与 `node tests/browser_check_test.js`。

## 1.0.1 故障复现与回归

使用截图对应的导航头形态（Sec-Fetch-Mode: navigate、长 Accept、Upgrade-Insecure-Requests、Cache-Control、Pragma）在 1.0.0 上复现失败断言：插件只发送 OPTIONS，实际 GET 被阻止。修复后直接发送调整后的 fetch GET，并显式注明表示可能变化。

新增正反例覆盖：开启/关闭导航变体、非导航长 Accept 保持严格预检、自定义业务头仍被预检限制、Authorization 仍需预检且实际保留、PoC 不回填导航 Accept 且不泄露认证。

## 结果

Java 回归：**83 个断言通过**。覆盖：

- 精确 ACAO/ACAC、前后缀误匹配、大小写、重复 ACAO、凭证模式不接受通配符。
- null Origin、匿名通配符、预检状态/方法/请求头，Authorization 不被通配符替代。
- 简单请求头分类、Range 分类、字节正文截取和二进制 POST 原样构造。
- Transfer-Encoding 请求拒绝重放，避免把 chunk framing 当作实体正文。
- scope、自动写操作限制、标记头、防重复任务、issue 合并。
- 预检失败只发送 OPTIONS，无 Cookie，阻止业务请求重放。
- 请求暂停后不继续下一 Origin；队列 64 的溢出拒绝与卸载清队列。
- 127.0.0.1 临时 HTTP 服务的真实网络请求及结果判定。
- 无图形环境下初始化 Swing；消息查看器真实 service/request 上下文；Repeater 调用与编号。
- CSV 危险前缀、含换行的公式、JS 字符串转义、Origin 格式验证。

浏览器复核页 JavaScript：语法、普通 fetch 模拟、sandbox srcdoc 脚本、postMessage 来源及结果回传均通过。测试也检查自定义头内的 `<` 不被改变。未使用真实浏览器验证 CORS 执行。

本地 demo：使用 loopback HTTP 客户端核对 reflect / strict / null / wildcard / invalid / duplicate / preflight-denied 响应特征（见打包时验证输出）。

打包校验：`burp/BurpExtender.class` 入口存在；不包含 Burp API 接口类或测试类；全部扩展 class 为 Java 8 字节码（major 52）。

## 维护者本机反馈

维护者在 **Burp Suite Professional 2025.7 / Java 24** 环境反馈 1.0.1 可加载、本地 reflect 接口出现 CREDENTIAL_POLICY；通过 18001 复核页读取 18000 的 reflect 接口，得到 HTTP 200 和 `cookie_received: true`，strict 接口复核则未能读取。证据来源为维护者提交的截图及结果文本，未将个人环境截图纳入开源仓库。

这覆盖了本地基础检测与浏览器读取链路，不是完整兼容性认证。18000 和 18001 跨 Origin 但同 site，不证明跨 site Cookie 限制被绕过。

## 仍待验证

本地测试替身不能覆盖 Burp 的消息标准化、项目级 session/macro、HTTP/2、其他扩展、所有 UI 操作与网络超时行为。

也未验证真实站点的 Cookie / SameSite、浏览器第三方 Cookie 策略、浏览器预检缓存及数据敏感性。README 提供本地安装、假数据靶场和浏览器复核步骤。自动结果和 issue 都不代表漏洞已确认。

## 开源发布准备检查

再次运行 Java 83 断言及导出页 JavaScript 测试通过。重构建 JAR 的各 ZIP 条目内容与原 1.0.1 安装包完全一致，发布保留原 JAR 及 SHA-256；构建的 ZIP 时间戳不同不会被误记为功能变更。打包仅包含项目源码、测试、文档、loopback 靶场和当前安装包，不包含 API 依赖、构建中间文件、浏览器导出记录或个人截图。
