# CHANGELOG

## 1.0.1 — 2026-11-01

- 修复导航头导致 reflect 接口错误落入 PREFLIGHT_BLOCKED：仅导航 GET/HEAD 可转换为明确标注的 fetch 变体。
- 保留业务鉴权和自定义头的预检；非导航长 Accept 仍按标准检查。
- 增加 Navigation -> fetch 开关，行选择后底部显示 Reason；PoC 使用实际探测头。
- 增加导航、关闭开关、非导航长 Accept、自定义头及 Authorization 回归；共 83 个断言通过。

## 1.0.0 — 2026-11-01

- 基于审查结论重新实现 Java legacy API CORS 扩展，独立命名 CORS Hunter。
- 精确 CORS 响应头校验及预检方法/头/凭证条件检查。
- 安全默认值：scope、GET/HEAD；非只读方法需手动确认；原始字节正文；拒绝不等价的特殊请求。
- 单 worker、有界队列、去重、速率/请求预算、失败与慢请求冷却、暂停和卸载协作退出。
- 独立 UI、EDT 模型更新、正确消息 controller、Repeater、CSV 及浏览器复核页面。
- Information/Tentative issue；配置线索与浏览器可利用性明确分开。
- 提供源码、构建脚本、63 断言回归测试及 loopback 假数据靶场。
- Java 24 + Burp 2025.7 实机验收待用户完成。
