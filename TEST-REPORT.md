# 1.0.2 测试版验证记录

日期：2026-11-01

## 自动化环境与结果

- OpenJDK 17.0.20，以 `--release 8` 编译扩展；Python 3 构建，Node.js 24.22.1 验证导出页脚本。
- legacy Extender API 2.3，provided 依赖，不打包到扩展。
- `python3 build.py --test`：**103 个 Java 断言通过**。
- `node tests/browser_check_test.js`：普通 fetch、sandbox 和消息回传模拟通过；不是浏览器 CORS 实测。

## 启动窗口复现与修复

先阻塞测试 EDT，让扩展注册回调。在 1.0.1 上新增断言失败：`HTTP listener must register before EDT initialization finishes`，证实 HTTP listener 注册依赖 UI 初始化完成。

1.0.2 同步注册 HTTP listener。测试在注册回调内投递唯一一个外部响应，让两次探测在 UI 初始化入队前完成；解除 EDT 阻塞后，两条结果正常显示，无需刷新。另一个场景在 UI 已就绪后投递首次响应，也只触发两次默认探测。探测回流计数为 SELF，不会递归。

此复现证明一个实际代码缺陷，不证明维护者报告的每个“首次不出、刷新才出”都与启动窗口同因；特别是 UI 早已就绪后的异常，需要实机诊断计数和请求证据继续定位。

## 回归范围

- 保留原 1.0.1 的 CORS 精确匹配、ACAC 大小写、重复 ACAO、凭证通配符、预检和 Authorization 规则。
- 原始字节正文、导航变体、自定义业务头、CSV/HTML/JS 转义、PoC 不导出认证。
- 本地 loopback HTTP 请求；暂停、队列预算、卸载、Scope、防递归、去重及 Repeater。
- 新增 received/SELF/QUEUED/SCOPE/DUPLICATE/AUTO_OFF/PAUSED/WRITE_BLOCKED 计数、卸载后停止观察、诊断不含认证。
- Scope 拒绝不会污染去重；同一请求在满足 Scope 后可入队；写操作仍不能自动重放。
- Swing 初始化、缓冲结果显示和消息编辑器更新在 EDT；状态更新通过 invokeLater。

## 维护者已经反馈的实机结果（1.0.1）

Burp Suite Professional 2025.7 / Java 24 下，本地 reflect 正例和 strict 反例已反馈；Web Security Academy 基础 Origin 反射靶场出现 random/null CREDENTIAL_POLICY。更换靶场实例后，从本地复核页实际读取了当前账户的用户名、邮箱、API key 等响应内容。

以上只说明特定版本、账户和浏览器条件下链路成立，不证明所有 Cookie 策略均可通过。旧实例失效是此前复核失败的合理解释，未将其记录为最终证实的根因。仓库不包含个人环境截图或会话值。

## 尚待验证

**1.0.2 尚未在维护者的 Burp 2025.7 / Java 24 中实际加载。** 自动化测试使用 Burp API 替身，不能覆盖实际 HTTP/2、其他扩展、项目 session/macro、超时、所有 UI 操作和浏览器策略。

本版保留 legacy API 单次请求超时/取消的限制，不新增浏览器自动执行或历史自动补扫。
