# Android 漏洞扫描平台 — 核心技术实施文档

> **文档定位**：本文档不是产品方案，而是可直接指导开发的**技术实施指南**。
> 聚焦于：如何确保漏洞准确率、如何自动验证真伪、如何生成可执行复现脚本、如何通过调用链追踪避免误报。

---

## 一、核心问题定义

平台要解决的不是"能不能扫到东西"，而是三个工程问题：

| 问题 | 具体含义 |
|------|---------|
| **准确率** | 报出来的是真漏洞，不是看到代码就报 |
| **完整性** | 每个漏洞附带可直接执行的复现命令/脚本 |
| **自动验证** | 平台自己在真机上跑一遍，确认漏洞成立再报 |

---

## 二、漏洞准确率保证机制 — 五层过滤模型

### 2.1 设计思路

绝大多数工具误报的根本原因：**看到代码模式就报，不管上下文。**

本平台采用**五层递进过滤**，每一层都是一道关卡，只有全部通过才进正式报告：

```
Layer 1: 入口可达性验证
    ↓ 通过
Layer 2: 参数可控性验证  
    ↓ 通过
Layer 3: 路径可行性验证（调用链闭环）
    ↓ 通过
Layer 4: 危险动作真实性验证
    ↓ 通过
Layer 5: 真机动态验证
    ↓ 通过
→ 正式漏洞（VERIFIED_REAL）
```

任何一层不通过 → 降级或丢弃。

### 2.2 Layer 1: 入口可达性验证

**目标**：确认漏洞入口外部是否真的能触达。

**实现方法**：

```python
def verify_entry_reachable(component, manifest):
    """
    验证组件是否真正外部可达
    不是 exported=true 就算可达，还要看权限保护
    """
    # 1. 检查 exported 状态
    if not component.exported:
        # 隐式 exported: 有 intent-filter 且无 permission
        if not component.has_intent_filter:
            return False, "NOT_EXPORTED"
    
    # 2. 检查权限保护
    if component.permission:
        perm = manifest.get_permission_def(component.permission)
        if perm and perm.protection_level in ['signature', 'signatureOrSystem']:
            return False, "SIGNATURE_PROTECTED"
        # normal/dangerous 权限 → 外部 App 可申请，仍然可达
    
    # 3. 检查是否有可构造的触发方式
    trigger_methods = []
    if component.intent_filters:
        for f in component.intent_filters:
            if f.has_action('android.intent.action.VIEW') and f.data_schemes:
                trigger_methods.append({
                    'type': 'deeplink',
                    'scheme': f.data_schemes,
                    'host': f.data_hosts,
                    'path': f.data_paths
                })
            else:
                trigger_methods.append({
                    'type': 'explicit_intent',
                    'action': f.actions,
                    'category': f.categories
                })
    
    if not trigger_methods:
        # 纯 exported 无 filter，只能通过显式 Intent
        trigger_methods.append({
            'type': 'explicit_component',
            'component_name': component.full_name
        })
    
    return True, trigger_methods
```

**过滤效果**：排除约 40% 的误报（signature 保护、非 exported、无触发路径）。

### 2.3 Layer 2: 参数可控性验证

**目标**：确认关键参数是否真正来自外部输入，而不是内部硬编码。

**实现方法**：

```python
def verify_param_controllable(method, param_name, ir):
    """
    追踪参数来源，判断是否外部可控
    """
    sources = ir.trace_param_source(method, param_name)
    
    controllable_sources = []
    for source in sources:
        if source.type == 'INTENT_EXTRA':
            # Intent 传入 → 外部可控
            controllable_sources.append(source)
        elif source.type == 'INTENT_DATA_URI':
            # getData().getQueryParameter() → 外部可控
            controllable_sources.append(source)
        elif source.type == 'BUNDLE_ARG':
            # Fragment arguments → 需追踪谁设置的
            setter = ir.find_bundle_setter(source)
            if setter and setter.is_external:
                controllable_sources.append(source)
        elif source.type == 'HARDCODED':
            # 硬编码字符串 → 不可控，跳过
            pass
        elif source.type == 'SHARED_PREF':
            # SharedPreferences → 通常不可控（除非有对应写入漏洞）
            pass
        elif source.type == 'CONTENT_PROVIDER_RESULT':
            # Provider 返回 → 需进一步判断该 Provider 是否外部可写
            pass
    
    if not controllable_sources:
        return False, "PARAM_NOT_CONTROLLABLE"
    
    return True, controllable_sources
```

**关键规则**：
- `getIntent().getStringExtra("url")` → 可控 ✅
- `getString(R.string.base_url)` → 不可控 ❌
- `SharedPreferences.getString("token")` → 通常不可控 ❌
- `getIntent().getData().getQueryParameter("target")` → 可控 ✅
- `BuildConfig.API_HOST` → 不可控 ❌

**过滤效果**：再排除约 25% 误报（参数来自内部配置、硬编码）。

### 2.4 Layer 3: 路径可行性验证（调用链闭环）

**目标**：从入口到危险动作，中间的条件分支是否真的能走通。

**这是最核心的一层，详见第三章"调用链追踪引擎"。**

### 2.5 Layer 4: 危险动作真实性验证

**目标**：最终触发的动作是否真的有安全影响。

```python
def verify_sink_dangerous(sink, context):
    """
    不是所有 loadUrl 都危险，不是所有 startActivity 都是漏洞
    """
    if sink.type == 'WEBVIEW_LOAD_URL':
        # loadUrl 危险的前提：WebView 注册了 JSBridge
        webview_class = context.get_webview_class(sink)
        if not webview_class:
            return False, "NO_WEBVIEW_CONTEXT"
        
        has_jsbridge = ir.find_jsbridge_registration(webview_class)
        has_file_access = ir.check_setting(webview_class, 'setAllowFileAccess', True)
        has_universal = ir.check_setting(webview_class, 'setAllowUniversalAccessFromFileURLs', True)
        
        if not has_jsbridge and not has_file_access and not has_universal:
            return False, "WEBVIEW_NO_DANGEROUS_CONFIG"
        
        # 有 JSBridge → 检查 Bridge 方法是否有危险能力
        if has_jsbridge:
            dangerous_methods = classify_jsbridge_methods(has_jsbridge)
            if not dangerous_methods:
                return False, "JSBRIDGE_NO_DANGEROUS_METHOD"
            return True, {'jsbridge_methods': dangerous_methods}
    
    elif sink.type == 'START_ACTIVITY':
        # startActivity 本身不一定是漏洞
        # 只有当 Intent 完全由外部控制时才危险（Intent Redirection）
        intent_source = context.get_intent_construction(sink)
        if intent_source.is_fully_controlled:
            return True, {'type': 'intent_redirection'}
        else:
            return False, "INTENT_PARTIALLY_CONTROLLED"
    
    elif sink.type == 'INSTALL_APK':
        # installApk 几乎总是危险的
        return True, {'type': 'arbitrary_install'}
    
    # ... 其他 sink 类型
```

**过滤效果**：排除约 15% 误报（WebView 无 Bridge、startActivity 目标固定等）。

### 2.6 Layer 5: 真机动态验证

**目标**：在真机上实际执行，确认漏洞可复现。

**详见第四章"自动验证与 PoC 生成引擎"。**

### 2.7 五层过滤的综合效果

| 层 | 过滤目标 | 典型误报排除率 | 累计准确率 |
|---|---------|-------------|----------|
| Layer 1 | 入口不可达 | ~40% | 60% |
| Layer 2 | 参数不可控 | ~25% | 75% |
| Layer 3 | 路径不可行 | ~30% | 85% |
| Layer 4 | 动作无危害 | ~15% | 90% |
| Layer 5 | 真机验证失败 | ~5% | 95%+ |

**最终目标：正式报告准确率 ≥ 90%。**

---


## 三、调用链追踪引擎 — 确保不误报的核心算法

### 3.1 为什么必须有调用链

**反面案例**（典型误报）：

```java
// 扫描器看到这一行就报 "Deeplink URL 注入 → WebView 加载"
String url = getIntent().getData().getQueryParameter("url");
```

但实际上下文是：

```java
String url = getIntent().getData().getQueryParameter("url");
if (url == null) return;
if (!url.startsWith("https://www.myapp.com/")) return;  // 严格白名单
if (!url.endsWith(".html")) return;
webView.loadUrl(url);  // 实际上很安全
```

**没有调用链追踪，就会把安全代码报成漏洞。**

### 3.2 调用链追踪算法

#### 3.2.1 核心数据结构

```python
@dataclass
class TraceNode:
    node_id: str
    node_type: str  # SOURCE / TAINT / GUARD / TRANSFORM / SINK
    class_name: str
    method_name: str
    line_number: int
    code_snippet: str
    
    # GUARD 节点专用
    guard_type: str = None      # WHITELIST / PERMISSION / NULL_CHECK / SIGNATURE
    guard_result: str = None    # PASS / BLOCK / BYPASS_POSSIBLE
    bypass_reason: str = None   # 绕过原因

@dataclass 
class TraceEdge:
    from_node: str
    to_node: str
    edge_type: str  # DATA_FLOW / CONTROL_FLOW / CALL
    param_name: str = None
    condition: str = None

@dataclass
class VulnTrace:
    trace_id: str
    source: TraceNode
    sink: TraceNode
    path: List[TraceNode]
    edges: List[TraceEdge]
    guards: List[TraceNode]     # 路径上的所有校验点
    overall_feasibility: str    # FEASIBLE / BLOCKED / BYPASS_POSSIBLE
    confidence: float           # 0.0 - 1.0
```

#### 3.2.2 追踪算法伪代码

```python
def trace_vulnerability(source_node, sink_node, ir):
    """
    从 SOURCE 到 SINK 的完整追踪
    核心：不是找到路径就报，而是评估路径上每个 GUARD 是否可绕过
    """
    # Step 1: 找所有可能路径（BFS/DFS，限制深度避免爆炸）
    all_paths = ir.find_paths(
        start=source_node,
        end=sink_node,
        max_depth=15,          # 最大追踪深度
        max_paths=10,          # 最多保留 10 条候选路径
        follow_calls=True,     # 跨方法追踪
        follow_interfaces=True # 追踪接口实现
    )
    
    if not all_paths:
        return None  # 无可达路径，不报
    
    # Step 2: 对每条路径，识别并评估所有 GUARD
    best_path = None
    best_score = 0
    
    for path in all_paths:
        guards = identify_guards(path, ir)
        path_score = evaluate_path_feasibility(path, guards, ir)
        
        if path_score > best_score:
            best_score = path_score
            best_path = path
    
    # Step 3: 根据最优路径的得分决定是否报告
    if best_score >= 0.8:
        return VulnTrace(
            confidence=best_score,
            overall_feasibility='FEASIBLE',
            ...
        )
    elif best_score >= 0.5:
        return VulnTrace(
            confidence=best_score,
            overall_feasibility='BYPASS_POSSIBLE',
            ...
        )
    else:
        return None  # 路径不可行，不报


def identify_guards(path, ir):
    """
    识别路径上的所有安全校验点
    """
    guards = []
    for node in path:
        # 条件判断中包含参数校验
        if node.is_condition:
            checked_var = node.get_checked_variable()
            if checked_var and checked_var.is_tainted:
                guard = classify_guard(node, ir)
                guards.append(guard)
    return guards


def evaluate_path_feasibility(path, guards, ir):
    """
    评估路径可行性得分
    1.0 = 完全可行（无 guard 或所有 guard 可绕过）
    0.0 = 完全不可行（存在不可绕过的 guard）
    """
    if not guards:
        return 1.0  # 无任何校验，路径完全可行
    
    score = 1.0
    for guard in guards:
        guard_score = evaluate_single_guard(guard, ir)
        score *= guard_score  # 多个 guard 连乘
    
    return score


def evaluate_single_guard(guard, ir):
    """
    评估单个 GUARD 的可绕过性
    """
    if guard.guard_type == 'NULL_CHECK':
        # 空值检查 → 只要参数非空就能过，不影响利用
        return 0.95
    
    elif guard.guard_type == 'WHITELIST_PREFIX':
        # url.startsWith("https://trust.com")
        # 可绕过：https://trust.com.evil.com
        return 0.8
    
    elif guard.guard_type == 'WHITELIST_CONTAINS':
        # url.contains("trust.com")
        # 可绕过：https://evil.com/trust.com/poc
        return 0.85
    
    elif guard.guard_type == 'WHITELIST_REGEX_STRICT':
        # Pattern.matches("^https://(www\\.)?trust\\.com/.*$", url)
        # 严格正则，难以绕过
        return 0.1
    
    elif guard.guard_type == 'WHITELIST_DOMAIN_PARSE':
        # Uri.parse(url).getHost().equals("trust.com")
        # 需要检查是否有 @、端口、Unicode 等绕过
        bypasses = check_uri_parse_bypasses(guard, ir)
        return 0.6 if bypasses else 0.2
    
    elif guard.guard_type == 'PERMISSION_CHECK':
        # checkCallingPermission() 
        return 0.1  # 几乎不可绕过
    
    elif guard.guard_type == 'SIGNATURE_CHECK':
        # 签名校验
        return 0.05  # 极难绕过
    
    elif guard.guard_type == 'TOKEN_VERIFY':
        # Token/Session 校验
        return 0.3  # 需要获取 token
    
    else:
        return 0.5  # 未知类型，保守评分
```

#### 3.2.3 白名单绕过分析器（关键模块）

```python
class WhitelistBypassAnalyzer:
    """
    专门分析 URL 白名单的绕过可能性
    这是 Deeplink→WebView 类漏洞的核心判断点
    """
    
    def analyze(self, guard_node, ir):
        """
        返回: (can_bypass: bool, bypass_methods: list, confidence: float)
        """
        check_method = guard_node.get_check_implementation()
        
        if not check_method:
            # 找不到实现，保守处理
            return True, ["IMPLEMENTATION_UNKNOWN"], 0.5
        
        results = []
        
        # 1. startsWith 检查 → 子域名绕过
        if self._is_starts_with(check_method):
            prefix = self._extract_prefix(check_method)
            results.append({
                'method': 'SUBDOMAIN_BYPASS',
                'payload': f'{prefix}.evil.com/poc',
                'confidence': 0.85
            })
        
        # 2. contains 检查 → 路径包含绕过
        if self._is_contains(check_method):
            keyword = self._extract_keyword(check_method)
            results.append({
                'method': 'PATH_INCLUDE_BYPASS', 
                'payload': f'https://evil.com/{keyword}/poc',
                'confidence': 0.9
            })
        
        # 3. endsWith 检查 → 参数附加绕过
        if self._is_ends_with(check_method):
            suffix = self._extract_suffix(check_method)
            results.append({
                'method': 'QUERY_APPEND_BYPASS',
                'payload': f'https://evil.com/poc?x={suffix}',
                'confidence': 0.7
            })
        
        # 4. Uri.parse().getHost() 检查 → @ 符号 / 端口 / Unicode 绕过
        if self._is_uri_host_check(check_method):
            domain = self._extract_domain(check_method)
            results.extend([
                {'method': 'AT_SIGN_BYPASS', 
                 'payload': f'https://{domain}@evil.com/poc', 'confidence': 0.6},
                {'method': 'BACKSLASH_BYPASS',
                 'payload': f'https://{domain}\\@evil.com/poc', 'confidence': 0.4},
                {'method': 'FRAGMENT_BYPASS',
                 'payload': f'https://evil.com/#{domain}', 'confidence': 0.3},
            ])
        
        # 5. 正则匹配检查 → 分析正则强度
        if self._is_regex_check(check_method):
            regex = self._extract_regex(check_method)
            weaknesses = self._analyze_regex_weakness(regex)
            if weaknesses:
                results.extend(weaknesses)
            else:
                return False, [], 0.1  # 强正则，无法绕过
        
        # 6. 多条件 AND → 所有条件都要满足
        # 7. 多条件 OR → 任意一个满足即可
        
        if results:
            best = max(results, key=lambda x: x['confidence'])
            return True, results, best['confidence']
        
        return False, [], 0.1
```

### 3.3 防漏扫策略 — 确保攻击面全覆盖

#### 3.3.1 攻击面枚举清单（不遗漏）

```python
SCAN_CHECKLIST = {
    'manifest_level': [
        'exported_activities',
        'exported_services', 
        'exported_receivers',
        'exported_providers',
        'deeplink_schemes',
        'applink_hosts',
        'backup_allowed',
        'debuggable',
        'cleartext_traffic',
        'custom_permissions_weak',
    ],
    'code_level': [
        'webview_loadurl_external',
        'webview_jsbridge_exposed',
        'webview_file_access',
        'webview_universal_access',
        'webview_debug_enabled',
        'provider_query_no_check',
        'provider_openfile_traversal',
        'intent_redirection',
        'pending_intent_mutable',
        'broadcast_sensitive_data',
        'log_sensitive_info',
        'crypto_hardcoded_key',
        'crypto_weak_algorithm',
        'network_cleartext_sensitive',
        'install_flow_external',
        'download_url_external',
        'zip_path_traversal',
        'file_provider_root_path',
        'task_affinity_hijack',
        'fragment_injection',
        'sql_injection_provider',
        'path_traversal_file_read',
    ],
    'logic_level': [
        'auth_inconsistent_guard',
        'privilege_escalation_path',
        'race_condition_toctou',
    ]
}
```

#### 3.3.2 覆盖率检查

```python
def check_scan_coverage(scan_results, apk_info):
    """
    扫描完成后，自动检查是否有遗漏
    """
    coverage_report = {}
    
    # 检查所有 exported 组件是否都被分析过
    for component in apk_info.exported_components:
        if component.name not in scan_results.analyzed_components:
            coverage_report[component.name] = 'NOT_ANALYZED'
    
    # 检查所有 Deeplink 是否都被追踪过
    for deeplink in apk_info.deeplinks:
        if deeplink not in scan_results.traced_deeplinks:
            coverage_report[f'deeplink:{deeplink}'] = 'NOT_TRACED'
    
    # 检查所有 JSBridge 方法是否都被归类过
    for bridge in apk_info.jsbridge_methods:
        if bridge not in scan_results.classified_bridges:
            coverage_report[f'jsbridge:{bridge}'] = 'NOT_CLASSIFIED'
    
    # 检查所有 Provider 是否都被测试过
    for provider in apk_info.exported_providers:
        if provider not in scan_results.tested_providers:
            coverage_report[f'provider:{provider}'] = 'NOT_TESTED'
    
    return coverage_report
```

---


## 四、自动验证与 PoC 生成引擎

### 4.1 设计原则

**每个被判定为 CODE_PROVEN 及以上的漏洞，平台必须自动生成可执行的验证方案。**

不是"告诉用户去验证"，而是：
1. 自动生成验证命令/脚本
2. 如果设备连接 → 自动执行
3. 自动判断执行结果是否证明漏洞成立
4. 自动保存证据

### 4.2 PoC 生成状态机

```python
class PoCGenerator:
    """
    根据漏洞类型和调用链，自动生成对应的 PoC
    """
    
    def generate(self, finding: VulnTrace) -> PoCBundle:
        vuln_type = finding.classify_type()
        
        if vuln_type == 'DEEPLINK_TO_WEBVIEW':
            return self._gen_deeplink_webview_poc(finding)
        elif vuln_type == 'JSBRIDGE_DIRECT_CALL':
            return self._gen_jsbridge_poc(finding)
        elif vuln_type == 'PROVIDER_DATA_LEAK':
            return self._gen_provider_query_poc(finding)
        elif vuln_type == 'PROVIDER_PATH_TRAVERSAL':
            return self._gen_provider_traversal_poc(finding)
        elif vuln_type == 'INTENT_REDIRECTION':
            return self._gen_intent_redirect_poc(finding)
        elif vuln_type == 'EXPORTED_DANGEROUS_ACTION':
            return self._gen_exported_action_poc(finding)
        elif vuln_type == 'INSTALL_FLOW_HIJACK':
            return self._gen_install_hijack_poc(finding)
        else:
            return self._gen_generic_poc(finding)
    
    def _gen_deeplink_webview_poc(self, finding):
        """
        Deeplink → WebView → JSBridge 的完整 PoC 生成
        """
        # 从调用链中提取关键信息
        scheme = finding.extract_scheme()
        host = finding.extract_host()
        path = finding.extract_path()
        param = finding.extract_url_param_name()  # 如 "url", "target", "redirect"
        bridge_name = finding.extract_bridge_name()  # 如 "android", "native"
        dangerous_methods = finding.extract_dangerous_methods()
        whitelist_bypass = finding.get_bypass_payload()
        
        # 生成 PoC HTML
        poc_html = self._build_jsbridge_poc_html(bridge_name, dangerous_methods)
        
        # 生成 ADB 命令
        if whitelist_bypass:
            payload_url = whitelist_bypass
        else:
            payload_url = "http://127.0.0.1:8080/poc.html"
        
        adb_command = (
            f'adb shell am start -W -a android.intent.action.VIEW '
            f'-d "{scheme}://{host}{path}?{param}={payload_url}"'
        )
        
        # 生成完整 PoC Bundle
        return PoCBundle(
            type='DEEPLINK_WEBVIEW_JSBRIDGE',
            steps=[
                Step(
                    order=1,
                    description="启动本地 PoC HTTP 服务",
                    command="python3 -m http.server 8080 --directory ./poc/",
                    expected="服务器启动，监听 8080 端口"
                ),
                Step(
                    order=2,
                    description="设置 ADB 端口映射",
                    command="adb reverse tcp:8080 tcp:8080",
                    expected="返回 8080"
                ),
                Step(
                    order=3,
                    description="触发 Deeplink",
                    command=adb_command,
                    expected="目标 App WebView 打开并加载 PoC 页面"
                ),
                Step(
                    order=4,
                    description="观察结果",
                    command=f'adb logcat -s WebView JSBridge -d | tail -20',
                    expected="日志中出现 JSBridge 方法调用记录"
                ),
            ],
            files={
                'poc/poc.html': poc_html
            },
            verification_script=self._build_auto_verify_script(finding),
            frida_script=self._build_frida_hook_script(finding) if finding.needs_root else None
        )
    
    def _build_jsbridge_poc_html(self, bridge_name, methods):
        """动态生成 JSBridge 测试页面"""
        method_calls = ""
        for m in methods:
            if m.params:
                params_str = ', '.join([f'"{p.example_value}"' for p in m.params])
            else:
                params_str = ""
            method_calls += f'''
    try {{
        var r_{m.name} = window.{bridge_name}.{m.name}({params_str});
        log('[+] {m.name}() = ' + JSON.stringify(r_{m.name}));
    }} catch(e) {{
        log('[-] {m.name}() error: ' + e.message);
    }}
'''
        
        return f'''<!DOCTYPE html>
<html>
<head><title>Security PoC</title></head>
<body>
<h3>JSBridge Security Test</h3>
<pre id="log"></pre>
<script>
function log(msg) {{
    document.getElementById('log').textContent += msg + '\\n';
    // 同时输出到 console 便于 logcat 抓取
    console.log('POC_RESULT: ' + msg);
}}

if (window.{bridge_name}) {{
    log('[+] Bridge "{bridge_name}" found');
    // 枚举所有方法
    var methods = [];
    for (var k in window.{bridge_name}) {{ methods.push(k); }}
    log('[*] Methods: ' + methods.join(', '));
    
    // 调用危险方法
{method_calls}
}} else {{
    log('[-] Bridge "{bridge_name}" NOT found');
}}
</script>
</body>
</html>'''

    def _build_auto_verify_script(self, finding):
        """
        生成自动验证脚本 — 平台自己执行并判断结果
        """
        return f'''#!/bin/bash
# Auto-verification script for: {finding.title}
# Generated by scanner platform

set -e

PACKAGE="{finding.package_name}"
RESULT_FILE="/tmp/verify_result_{finding.trace_id}.json"

echo '{{"status": "running", "finding_id": "{finding.trace_id}"}}' > $RESULT_FILE

# Step 1: 确保目标 App 运行
adb shell am force-stop $PACKAGE 2>/dev/null || true
sleep 1

# Step 2: 启动本地 PoC 服务（后台）
mkdir -p /tmp/poc_server/
cat > /tmp/poc_server/poc.html << 'POCEOF'
{finding.poc_html_content}
POCEOF
python3 -m http.server 8080 --directory /tmp/poc_server/ &
POC_PID=$!
sleep 1

# Step 3: 端口映射
adb reverse tcp:8080 tcp:8080

# Step 4: 清空 logcat
adb logcat -c

# Step 5: 触发漏洞
{finding.trigger_command}
sleep 3

# Step 6: 抓取 logcat 判断结果
LOGCAT=$(adb logcat -d | grep -i "POC_RESULT\\|JSBridge\\|loadUrl")

# Step 7: 判断验证结果
if echo "$LOGCAT" | grep -q "POC_RESULT.*found"; then
    VERIFIED=true
    echo '{{"status": "VERIFIED", "finding_id": "{finding.trace_id}", "evidence": "bridge_accessible"}}' > $RESULT_FILE
elif echo "$LOGCAT" | grep -q "POC_RESULT.*NOT found"; then
    VERIFIED=false
    echo '{{"status": "FAILED", "finding_id": "{finding.trace_id}", "reason": "bridge_not_accessible"}}' > $RESULT_FILE
else
    VERIFIED=unknown
    echo '{{"status": "INCONCLUSIVE", "finding_id": "{finding.trace_id}", "reason": "no_poc_output"}}' > $RESULT_FILE
fi

# Step 8: 截图作为证据
adb shell screencap -p /sdcard/poc_screenshot.png
adb pull /sdcard/poc_screenshot.png /tmp/evidence_{finding.trace_id}.png 2>/dev/null || true

# Step 9: 保存完整 logcat
adb logcat -d > /tmp/logcat_{finding.trace_id}.txt

# Cleanup
kill $POC_PID 2>/dev/null || true
adb reverse --remove tcp:8080 2>/dev/null || true

echo "Verification complete. Result: $VERIFIED"
cat $RESULT_FILE
'''

    def _build_frida_hook_script(self, finding):
        """
        生成 Frida Hook 脚本 — 用于 Root 环境深度验证
        """
        hooks = []
        
        # Hook loadUrl 确认实际加载的 URL
        if finding.has_webview_load:
            hooks.append(f'''
    // Hook WebView.loadUrl
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function(url) {{
        console.log("[HOOK] WebView.loadUrl: " + url);
        send({{"type": "webview_load", "url": url}});
        this.loadUrl(url);
    }};
''')
        
        # Hook 白名单校验方法，确认绕过
        if finding.guard_method:
            hooks.append(f'''
    // Hook whitelist check
    var CheckerClass = Java.use("{finding.guard_class}");
    CheckerClass.{finding.guard_method}.implementation = function() {{
        var args = Array.prototype.slice.call(arguments);
        var originalResult = this.{finding.guard_method}.apply(this, args);
        console.log("[HOOK] {finding.guard_method}(" + args.join(", ") + ") = " + originalResult);
        send({{"type": "guard_check", "args": args.toString(), "result": originalResult.toString()}});
        return originalResult;
    }};
''')
        
        # Hook JSBridge 危险方法
        for method in finding.dangerous_jsbridge_methods:
            hooks.append(f'''
    // Hook JSBridge.{method.name}
    var BridgeClass = Java.use("{method.class_name}");
    BridgeClass.{method.name}.implementation = function() {{
        var args = Array.prototype.slice.call(arguments);
        console.log("[HOOK] JSBridge.{method.name}(" + args.join(", ") + ")");
        send({{"type": "jsbridge_call", "method": "{method.name}", "args": args.toString()}});
        return this.{method.name}.apply(this, args);
    }};
''')
        
        return f'''// Frida hook script for: {finding.title}
// Usage: frida -U -f {finding.package_name} -l this_script.js --no-pause

Java.perform(function() {{
    console.log("[*] Hooks installed for {finding.package_name}");
    
{''.join(hooks)}
    
    console.log("[*] All hooks active. Trigger the vulnerability now.");
}});
'''



### 4.3 Provider 漏洞自动验证

```python
def generate_provider_poc(finding):
    """
    Provider 数据泄露的自动验证
    """
    authority = finding.provider_authority
    uri_paths = finding.provider_uris
    
    commands = []
    for uri_path in uri_paths:
        full_uri = f"content://{authority}/{uri_path}"
        
        # 尝试查询
        commands.append({
            'description': f'查询 {uri_path}',
            'command': f'adb shell content query --uri {full_uri}',
            'success_indicator': 'Row:',  # 有数据返回说明可读
            'failure_indicator': 'Permission Denial'
        })
        
        # 尝试带条件查询
        commands.append({
            'description': f'条件查询 {uri_path}',
            'command': f'adb shell content query --uri {full_uri} --where "_id=1"',
            'success_indicator': 'Row:',
            'failure_indicator': 'Permission Denial'
        })
    
    # 自动执行并判断
    verify_script = f'''#!/bin/bash
RESULT="FAILED"
echo "Testing Provider: {authority}"

'''
    for cmd in commands:
        verify_script += f'''
echo ">>> {cmd['description']}"
OUTPUT=$({cmd['command']} 2>&1)
echo "$OUTPUT"
if echo "$OUTPUT" | grep -q "{cmd['success_indicator']}"; then
    RESULT="VERIFIED"
    echo "[+] SUCCESS: Data accessible"
fi
if echo "$OUTPUT" | grep -q "{cmd['failure_indicator']}"; then
    echo "[-] Blocked: Permission denied"
fi
'''
    
    verify_script += f'''
echo ""
echo "Final Result: $RESULT"
'''
    return verify_script
```

### 4.4 验证结果自动判定

```python
class VerificationJudge:
    """
    自动判断验证结果：成功 / 失败 / 不确定
    """
    
    def judge(self, vuln_type, execution_output, logcat, screenshot=None):
        if vuln_type == 'DEEPLINK_TO_WEBVIEW':
            return self._judge_deeplink_webview(execution_output, logcat)
        elif vuln_type == 'PROVIDER_DATA_LEAK':
            return self._judge_provider_leak(execution_output)
        elif vuln_type == 'JSBRIDGE_CALL':
            return self._judge_jsbridge(logcat)
        # ...
    
    def _judge_deeplink_webview(self, output, logcat):
        """Deeplink → WebView 验证判定"""
        indicators = {
            'VERIFIED': [
                'POC_RESULT.*found',      # PoC 页面成功执行
                'loadUrl.*127.0.0.1',     # WebView 加载了我们的 PoC
                'loadUrl.*poc.html',
            ],
            'PARTIAL': [
                'Activity.*started',       # Activity 启动了但不确定 WebView
            ],
            'FAILED': [
                'Permission Denial',
                'SecurityException',
                'does not match',          # 白名单拒绝
                'Activity not found',
            ]
        }
        
        combined = output + '\n' + logcat
        
        for indicator in indicators['VERIFIED']:
            if re.search(indicator, combined, re.IGNORECASE):
                return 'VERIFIED', f"Matched: {indicator}"
        
        for indicator in indicators['FAILED']:
            if re.search(indicator, combined, re.IGNORECASE):
                return 'FAILED', f"Blocked by: {indicator}"
        
        for indicator in indicators['PARTIAL']:
            if re.search(indicator, combined, re.IGNORECASE):
                return 'PARTIAL', "Activity started but WebView load unconfirmed"
        
        return 'INCONCLUSIVE', "No clear indicators found"
    
    def _judge_provider_leak(self, output):
        """Provider 泄露验证判定"""
        if 'Row:' in output and 'Permission Denial' not in output:
            # 有数据返回且无权限拒绝
            row_count = output.count('Row:')
            return 'VERIFIED', f"Returned {row_count} rows of data"
        elif 'Permission Denial' in output:
            return 'FAILED', "Permission denied"
        elif 'No result found' in output:
            return 'PARTIAL', "Accessible but no data (table may be empty)"
        else:
            return 'INCONCLUSIVE', "Unexpected output"
```

---

## 五、不漏扫保证 — 多维度攻击面发现

### 5.1 问题：为什么会漏扫

| 漏扫原因 | 解决方案 |
|---------|---------|
| 只扫 Manifest 不扫代码 | 代码级路由分析（动态注册的 Receiver 等） |
| 只扫直接调用不扫间接调用 | 跨方法/跨类追踪（CallGraph） |
| 混淆后类名变了匹配不到 | 基于行为模式匹配（不依赖类名） |
| 反射调用看不到目标 | 反射参数静态解析 + 动态 Hook |
| 动态加载的 DEX 没分析 | 脱壳 + 二级 DEX dump |
| Fragment/Router 路由看不到 | 识别主流路由框架（ARouter/Navigation） |
| WebView 自定义协议没覆盖 | shouldOverrideUrlLoading 全量分析 |

### 5.2 多入口发现策略

```python
class EntryPointDiscovery:
    """
    不依赖单一方式，多策略并行发现所有外部入口
    """
    
    def discover_all(self, apk_info, ir):
        entries = []
        
        # 策略1: Manifest 声明的导出组件
        entries += self._from_manifest(apk_info)
        
        # 策略2: 代码中动态注册的 Receiver
        entries += self._from_dynamic_receivers(ir)
        
        # 策略3: 自定义 URL Scheme 处理
        entries += self._from_url_scheme_handlers(ir)
        
        # 策略4: DeepLinkDispatcher / Router 框架注解
        entries += self._from_router_annotations(ir)
        
        # 策略5: ContentProvider 的 UriMatcher 路由
        entries += self._from_provider_uri_matcher(ir)
        
        # 策略6: WebView shouldOverrideUrlLoading 中的自定义协议
        entries += self._from_webview_url_intercept(ir)
        
        # 策略7: 通过 FileProvider 暴露的路径
        entries += self._from_file_provider_paths(apk_info)
        
        # 策略8: PendingIntent 可被外部触发的场景
        entries += self._from_pending_intents(ir)
        
        # 去重
        entries = self._deduplicate(entries)
        
        return entries
    
    def _from_router_annotations(self, ir):
        """
        识别 ARouter / Navigation 等路由框架的注解
        """
        entries = []
        # ARouter: @Route(path = "/web/open")
        for annotation in ir.find_annotations('Route'):
            path = annotation.get_param('path')
            target_class = annotation.target_class
            entries.append(EntryPoint(
                type='ROUTER_ANNOTATION',
                path=path,
                target=target_class,
                framework='ARouter'
            ))
        
        # Navigation Component: nav_graph.xml 中的 deepLink
        for nav_link in ir.find_nav_deep_links():
            entries.append(EntryPoint(
                type='NAV_DEEP_LINK',
                path=nav_link.uri,
                target=nav_link.destination
            ))
        
        return entries
```

### 5.3 规则补全机制

```python
class RuleCompleteness:
    """
    确保规则覆盖所有已知漏洞类型
    每次扫描结束后自检
    """
    
    REQUIRED_CHECKS = [
        # (检查项, 触发条件, 严重度)
        ('DEEPLINK_WEBVIEW', 'has_deeplink AND has_webview', 'HIGH'),
        ('JSBRIDGE_EXPOSURE', 'has_jsbridge', 'HIGH'),
        ('PROVIDER_LEAK', 'has_exported_provider', 'MEDIUM'),
        ('PROVIDER_TRAVERSAL', 'has_provider_openfile', 'HIGH'),
        ('INTENT_REDIRECT', 'has_startactivity_from_intent', 'HIGH'),
        ('PENDING_INTENT_MUTABLE', 'has_pending_intent', 'HIGH'),
        ('INSTALL_HIJACK', 'has_package_installer', 'CRITICAL'),
        ('CRYPTO_WEAKNESS', 'has_crypto_usage', 'MEDIUM'),
        ('BACKUP_LEAK', 'manifest_allow_backup', 'LOW'),
        ('TASK_HIJACK', 'has_task_affinity', 'MEDIUM'),
        ('ZIP_TRAVERSAL', 'has_zip_extraction', 'HIGH'),
        ('FILE_PROVIDER_WIDE', 'has_file_provider', 'MEDIUM'),
        ('LOG_LEAK', 'has_log_calls', 'LOW'),
        ('CLEARTEXT_TRAFFIC', 'has_http_calls', 'MEDIUM'),
    ]
    
    def check_completeness(self, apk_info, scan_results):
        """扫描后检查是否有规则应该触发但没触发"""
        missed = []
        for check_name, condition, severity in self.REQUIRED_CHECKS:
            if self._evaluate_condition(condition, apk_info):
                # 条件满足，检查是否有对应结果
                if check_name not in scan_results.triggered_rules:
                    missed.append({
                        'rule': check_name,
                        'reason': f'Condition [{condition}] met but rule not triggered',
                        'severity': severity
                    })
        return missed
```

---

## 六、项目技术栈与模块划分

### 6.1 推荐技术栈

| 层 | 技术选型 | 理由 |
|---|---------|------|
| 语言 | Python 3.11+ | 安全工具生态最丰富、jadx/apktool 调用方便 |
| 反编译 | jadx (CLI) + apktool + androguard | jadx 出 Java、apktool 出 smali、androguard 做 IR |
| IR/调用图 | androguard + 自建 CallGraph | androguard 内置 DEX 解析和方法调用分析 |
| 动态验证 | subprocess (ADB) + frida-python | ADB 命令执行 + Frida RPC |
| 任务调度 | Celery + Redis | 异步任务、批量扫描 |
| 数据存储 | PostgreSQL + 文件系统 | 结构化数据 + 证据文件 |
| Web 后端 | FastAPI | 高性能 API |
| Web 前端 | React + Ant Design | 快速搭建工作台 |
| 报告生成 | Jinja2 模板 + markdown | 多格式导出 |

### 6.2 模块划分与职责

```
scanner/
├── core/
│   ├── input/              # 输入处理（APK/包名/批量）
│   ├── decompile/          # 反编译引擎（jadx/apktool/androguard）
│   ├── unpack/             # 脱壳引擎（frida-dexdump/BlackDex 集成）
│   └── ir/                 # 中间表示构建（CallGraph/DataFlow/ComponentMap）
│
├── analysis/
│   ├── rules/              # 规则定义（YAML + Python handler）
│   │   ├── deeplink.py
│   │   ├── webview.py
│   │   ├── jsbridge.py
│   │   ├── provider.py
│   │   ├── install_flow.py
│   │   ├── intent_redirect.py
│   │   ├── auth_check.py
│   │   └── ...
│   ├── trace/              # 调用链追踪引擎
│   │   ├── path_finder.py        # 路径搜索
│   │   ├── guard_analyzer.py     # GUARD 识别与评估
│   │   ├── whitelist_bypass.py   # 白名单绕过分析
│   │   ├── taint_tracker.py      # 污点传播追踪
│   │   └── feasibility.py        # 路径可行性评分
│   └── filter/             # 五层过滤器
│       ├── entry_filter.py       # Layer 1
│       ├── param_filter.py       # Layer 2
│       ├── path_filter.py        # Layer 3
│       ├── sink_filter.py        # Layer 4
│       └── verify_filter.py      # Layer 5
│
├── verification/
│   ├── engine.py           # 验证引擎主逻辑
│   ├── adb_executor.py     # ADB 命令执行器
│   ├── frida_executor.py   # Frida Hook 执行器
│   ├── poc_server.py       # 本地 PoC HTTP 服务
│   ├── judge.py            # 验证结果自动判定
│   └── evidence.py         # 证据收集与存储
│
├── poc_gen/
│   ├── generator.py        # PoC 生成主逻辑
│   ├── templates/          # 各类 PoC 模板
│   │   ├── deeplink_webview.py
│   │   ├── provider_query.py
│   │   ├── jsbridge_html.py
│   │   ├── frida_hooks.py
│   │   └── intent_trigger.py
│   └── builder.py          # 命令/脚本构建器
│
├── report/
│   ├── generator.py        # 报告生成
│   ├── templates/          # 报告模板（SRC/审计/小白）
│   └── formatter.py        # 格式化输出
│
├── web/
│   ├── api/                # FastAPI 路由
│   ├── models/             # 数据模型
│   └── services/           # 业务逻辑
│
├── device/
│   ├── manager.py          # 设备池管理
│   ├── detector.py         # 环境探测
│   └── scheduler.py        # 设备调度
│
└── config/
    ├── rules.yaml          # 规则配置
    ├── sinks.yaml          # 危险 API 列表
    ├── sources.yaml        # 外部输入源列表
    └── bypasses.yaml       # 已知绕过模式库
```

### 6.3 核心流程图

```
输入 APK
    │
    ▼
[反编译] jadx + apktool + androguard
    │
    ▼
[构建 IR] CallGraph + ComponentMap + DataFlow
    │
    ▼
[规则扫描] 所有规则并行执行 → 输出候选链路（不是漏洞！）
    │
    ▼
[五层过滤]
    ├── Layer 1: 入口可达？ → 否 → 丢弃
    ├── Layer 2: 参数可控？ → 否 → 丢弃
    ├── Layer 3: 路径可行？ → 否 → 降为 ATTACK_SURFACE
    ├── Layer 4: 动作危险？ → 否 → 丢弃
    └── Layer 5: 真机验证   → 失败 → 降为 CODE_PROVEN（如果路径可行）
    │
    ▼
[PoC 生成] 为每个通过的漏洞生成：ADB命令 + Frida脚本 + PoC HTML
    │
    ▼
[自动执行]（如果设备连接）
    │
    ▼
[结果判定] VERIFIED / FAILED / INCONCLUSIVE
    │
    ▼
[报告输出] 分桶 → 格式化 → 导出
```

---

## 七、开发优先级与里程碑

### Phase 1（4周）：最小可用 — 静态扫描 + 调用链

**必须完成**：
- [ ] APK 输入 → jadx 反编译 → androguard IR 构建
- [ ] Manifest 解析 → 攻击面列表
- [ ] Deeplink → WebView → JSBridge 调用链追踪（最核心场景）
- [ ] 五层过滤的前4层实现
- [ ] CLI 输出 JSON 格式结果

**验收**：输入 3 个真实 APK，输出的漏洞有完整调用链，误报 ≤ 2 个。

### Phase 2（4周）：动态验证 + PoC 生成

**必须完成**：
- [ ] ADB 命令执行器
- [ ] Deeplink 触发 + logcat 抓取
- [ ] Provider query 自动执行
- [ ] PoC HTML 自动生成
- [ ] 验证结果自动判定
- [ ] 证据文件保存

**验收**：连接真机后，至少 50% 的 CODE_PROVEN 漏洞能自动升级为 VERIFIED_REAL。

### Phase 3（4周）：Root 验证 + Frida

**必须完成**：
- [ ] Frida 脚本自动生成
- [ ] Hook 白名单校验确认绕过
- [ ] Hook JSBridge 方法确认调用
- [ ] Hook loadUrl 确认 URL
- [ ] Root 命令执行器

**验收**：Root 环境下，80% 的漏洞能自动完成验证。

### Phase 4（4周）：报告 + Web 界面

**必须完成**：
- [ ] SRC 报告模板
- [ ] Web 任务创建
- [ ] 漏洞列表 + 详情页
- [ ] 调用链可视化
- [ ] 证据查看/下载

**验收**：生成的报告可直接提交 SRC。

---

## 八、关键设计决策总结

| 决策 | 选择 | 理由 |
|------|------|------|
| 先静态还是先动态 | 先静态发现，再动态验证 | 静态提供路径，动态确认结果 |
| 怎么避免误报 | 五层递进过滤 | 每层都是一道关卡 |
| 怎么避免漏扫 | 多策略入口发现 + 覆盖率自检 | 不依赖单一方式 |
| 调用链追踪深度 | 最大 15 层 | 太浅漏掉跨方法链，太深性能爆炸 |
| 白名单如何判断 | 专用 BypassAnalyzer | 这是准确率的胜负手 |
| 验证失败怎么办 | 降为 CODE_PROVEN 而不是丢弃 | 代码证据仍有价值 |
| 没设备怎么办 | 只输出代码证明 + 可执行脚本 | 用户拿到脚本自己跑也行 |
| 规则怎么写 | YAML 描述 + Python handler | 方便扩展、热加载 |
| IR 用什么 | androguard 内置 | 不重复造轮子 |
| 怎么处理混淆 | 行为模式匹配 + 标记未知 | 宁可不报也不瞎报 |

---

## 九、与你原方案的对应关系

| 原方案章节 | 本文档对应内容 |
|-----------|-------------|
| 调用链与证据图引擎 | 第三章：完整追踪算法+代码实现 |
| 动态验证引擎 | 第四章：PoC 自动生成+自动执行+结果判定 |
| 漏洞评级与误报控制 | 第二章：五层过滤模型 |
| 通用规则体系 | 第五章：多维度攻击面发现+规则补全 |
| 报告生成规范 | 第四章 PoC 模板（报告内容来源于 PoC 执行结果） |

**核心补充**：
1. 白名单绕过分析器（原方案完全没有）
2. 验证结果自动判定逻辑（原方案只说"要验证"没说怎么判断结果）
3. 覆盖率自检机制（原方案没有防漏扫策略）
4. 五层过滤的具体实现代码（原方案只有概念）
5. 完整的项目目录结构和模块职责划分

---

*文档结束。本文档配合 scanner_universal_commercial_plan_v2.md 使用，一个定方向，一个定实现。*
