# 来源说明

本实现由本次 CORSScanner 源码审查及更新需求重新编写，参考项目：https://github.com/zzzskd/CORSScanner （审查提交 bd274e66347fbdecd831872091849e53b2ddf5cf）。未复制或打包该仓库的 Java 源文件、README 或二进制；这不是原作者发布的官方版本。原仓库未发现明确 LICENSE，本包不为其添加或声明 MIT 授权。

CORS 判定参考 WHATWG Fetch Standard：https://fetch.spec.whatwg.org/ 。扩展基于 PortSwigger legacy Extender API 2.3 编译，API 由 Burp 提供；安装 JAR 不打包 API 类。源码构建需要下载该依赖，其自身许可见对应 Maven 发布与 https://github.com/PortSwigger/burp-extender-api 。

本项目独立编写的代码以 MIT License 发布，版权归 doudou0308，详见 LICENSE。该授权仅覆盖本项目，不授予上游 CORSScanner 或 PortSwigger API 的任何额外权利。
