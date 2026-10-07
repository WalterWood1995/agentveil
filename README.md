# AgentVeil · 给 AI Agent 用的安全浏览器

[English summary](#english-summary) · [中国大陆安装指南](INSTALL-CN.md) · MIT License

AgentVeil 让 Agent 安全地**检索、抓取网页、交互式浏览**，并与其他 Agent **端到端加密通信**。
它的核心设计只有一句话：**所有流量只走你指定的加密隧道（Tor 或你自己的翻墙线路），隧道一断就全部拒绝，绝不退回直连。**

它以 MCP 服务器的形式提供 14 个工具，Claude Code 等支持 MCP 的 Agent 可直接调用；也带一个命令行工具 `agentveil`。

---

## ⚠️ 先说清楚：它能保证什么，不能保证什么

**没有任何软件能保证"在中国翻墙一定不会被发现"。** AgentVeil 能做到的是：把"浏览器/Agent 这一环"的泄漏全部堵死，并且把这一点用测试证明出来。能否被发现，还取决于隧道协议、你的设备、你的账号和你的行为。

| 风险 | AgentVeil 的处理 | 仍然存在的风险 |
|---|---|---|
| 浏览器绕过 VPN 直连 | 唯一出口是本机 SOCKS5 隧道；代码里没有直连路径；隧道不通即拒绝（fail-closed）。测试验证 Firefox 进程**没有任何**非本机 TCP 连接 | 可选的 Windows 防火墙"断网保护"脚本可再加一层系统级保险 |
| DNS 泄漏（运营商看到你查了哪些域名） | 域名原样交给隧道解析（SOCKS5 DOMAIN），本机从不查询；DoH/DNS 预取/预连接全部关闭。测试用"真实 DNS 中不存在的域名"证明 | — |
| WebRTC 泄漏真实 IP | WebRTC 整体禁用（`RTCPeerConnection` 不存在），UDP 无法经过隔离中继 | — |
| 浏览器指纹追踪 | Firefox resistFingerprinting：统一 UTC 时区、en-US、禁 WebGL/传感器/地理位置/通知/Service Worker；每个页面独立、用完即毁的上下文 | 自动化的 Firefox 可被网站识别为"机器人"（所有 AgentVeil 用户看起来一样，不指向你个人） |
| 跨任务关联 | Tor 下每个身份用随机 SOCKS 凭据 → 独立线路、独立出口 IP；`new_identity` 一键换 | 用 VPS 隧道时出口 IP 固定为你的服务器 |
| 隧道出口节点窃听/篡改 | 默认强制 HTTPS；证书校验失败直接中止 | 明文 HTTP 需显式允许 |
| Agent 被网页"提示注入"操纵 | 隐藏元素、零宽字符、Unicode 标签字符被清除；外部内容用随机标记包裹并标注"不可信"；禁止访问 127.0.0.1/局域网/云元数据地址 | 模型本身仍可能被说服——不要给 Agent 你不愿泄露的权限 |
| Agent 间通信被窃听 | Ed25519 签名 + X25519 封装加密 + 长度填充；中继只看到密文，不知道发件人 | **无前向保密**（长期密钥泄露可解密截获的历史消息） |

**以下是 AgentVeil 管不到、但在中国最常导致暴露的因素：**

1. **隧道本身被识别。** 审查者能看到"你在连一条加密隧道"（目标 IP、流量大小、时长），看不到内容。能否被识别取决于协议：
   - 直连 Tor、默认 obfs4 网桥：基本被封。
   - Snowflake：时通时断。WebTunnel / 私有 obfs4 网桥：相对可用。
   - 自建 VLESS + REALITY（伪装成访问真实网站的 TLS）：目前较难识别，但流量分析（如"TLS 套 TLS"特征、单一境外 IP 的大流量）依然可能暴露，服务器 IP 也可能被封。
2. **实名身份。** 在"翻墙"环境里登录微信/微博/手机号注册的账号、用支付宝购买 VPN，都会把活动和你本人关联起来。
3. **终端设备。** 电脑/手机若装有监控或"安全"软件，或使用会把输入内容上传云端联想的**输入法**，加密隧道毫无意义。
4. **AI 服务商。** 如果 Agent 用的是云端大模型（如 Claude），模型服务商能看到你的提问和 Agent 读到的内容。AgentVeil 让你对**网站和网络**隐身，不是对**模型服务商**隐身。Agent 自身调用 API 的流量也需要走你的隧道。
5. **Agent 自带的联网工具。** 例如 Claude Code 自带的 WebFetch / WebSearch 不经过 AgentVeil，必须禁用（见下文）。
6. **法律。** 中国大陆《计算机信息网络国际联网管理暂行规定》第六条禁止个人"自行建立或者使用其他信道进行国际联网"，第十四条规定可责令停止联网、警告，并可处 15000 元以下罚款。执法通常针对售卖、搭建者，但也有个人被处罚的案例。请自行评估风险。伊朗等地同样有严格管控；朝鲜普通民众基本无法接入国际互联网，本工具不适用。

---

## 架构

```
 Agent（Claude Code / 任意 MCP 客户端）
        │ MCP (stdio)
        ▼
 ┌───────────────────────── AgentVeil ─────────────────────────┐
 │ web_search / web_fetch ─┐                                    │
 │ browser_*（加固 Firefox）┼─► 出口守卫 EgressPolicy             │
 │ msg_*（端到端加密通信） ─┘   · 只允许 http(s)，强制 HTTPS       │
 │                             · 禁止本机/局域网/云元数据地址     │
 │                             · 隧道不通 → 拒绝（fail-closed）   │
 │ Firefox ─► 隔离中继（本机 SOCKS shim：只许 TCP CONNECT，        │
 │            逐连接复查目标，按身份附加 Tor 隔离凭据）             │
 └──────────────────────────────┬───────────────────────────────┘
                                │ SOCKS5（域名不在本机解析）
                                ▼
        本机隧道客户端：Tor(+网桥) ／ sing-box(REALITY) ／ 两者串联
                                │
            审查者只能看到：一条加密隧道（看不到网站与内容）
```

代码结构：

| 文件 | 作用 |
|---|---|
| [agentveil/egress.py](agentveil/egress.py) | 出口守卫：URL 策略、隧道健康检查、唯一的 HTTP 客户端工厂 |
| [agentveil/socks_shim.py](agentveil/socks_shim.py) | Firefox 与隧道之间的隔离中继 |
| [agentveil/browser.py](agentveil/browser.py) | 加固 Firefox（90 余项隐私/安全设置）与页面交互 |
| [agentveil/fetcher.py](agentveil/fetcher.py)、[extract.py](agentveil/extract.py) | 无 JS 抓取、逐跳检查重定向、正文提取与注入清洗 |
| [agentveil/search.py](agentveil/search.py) | DuckDuckGo（Tor 下走 .onion）/ DDG Lite / Mojeek / SearXNG |
| [agentveil/messaging/](agentveil/messaging) | 端到端加密通信：密码学、盲中继、客户端 |
| [agentveil/mcp_server.py](agentveil/mcp_server.py) | MCP 服务器（14 个工具） |
| [agentveil/torconfig.py](agentveil/torconfig.py) | 从 Tor 专家包自动生成带网桥的 torrc |

---

## 快速开始（Windows）

### 1. 安装

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

**在中国大陆安装请看 [INSTALL-CN.md](INSTALL-CN.md)**（国内镜像、离线安装包、Tor 网桥获取）。

### 2. 准备隧道（三选一）

**方案 A：Tor + 网桥**（无需海外服务器；最匿名；较慢）

1. 获取 Tor 专家包（Tor Expert Bundle）。torproject.org 在国内被封，可发邮件到 `gettor@torproject.org` 或用其官方 GitLab/GitHub 镜像获取，并校验签名。解压到无空格、纯英文的路径，如 `C:\tor`。
2. 获取网桥：用 Gmail/Riseup 邮箱发邮件到 `bridges@torproject.org`、Telegram 机器人 `@GetBridgesBot`，或访问 bridges.torproject.org。国内优先用 **webtunnel / obfs4**，保存到 `bridges.txt`（每行一条）。
3. 生成配置并启动：

```powershell
.venv\Scripts\agentveil.exe tor-config --bundle C:\tor --bridge-file bridges.txt
C:\tor\tor\tor.exe -f $HOME\.agentveil\torrc
```

不带 `--bridge-file` 时使用专家包内置的 Snowflake 网桥（`--bridges snowflake|obfs4|meek`）。

**方案 B：自建 VLESS + REALITY（sing-box）**（最快；需境外 VPS；网站看到的是你的 VPS IP，VPS 服务商知道是你）

- 服务端模板：[tunnels/sing-box/server.example.json](tunnels/sing-box/server.example.json)（已拒绝访问 VPS 内网）
- 客户端模板：[tunnels/sing-box/client.example.json](tunnels/sing-box/client.example.json)（本机 `127.0.0.1:1080`，只有一个出站，不存在"直连"出口）
- 密钥：`sing-box generate reality-keypair`、`sing-box generate uuid`、`sing-box generate rand 8 --hex`
- `server` 填 IP（不要填域名，避免本机 DNS 查询）；伪装 SNI 选一个支持 TLS 1.3 的真实大站。
- `agentveil.toml` 中设 `kind = "socks"`、`port = 1080`、`control_port = 0`。

**方案 C：B + Tor 串联（推荐给高风险用户）**

审查者只看到 REALITY；VPS 只看到 Tor 流量；网站只看到 Tor 出口。

```powershell
.venv\Scripts\agentveil.exe tor-config --bundle C:\tor --bridges none --via-socks 127.0.0.1:1080
```

`agentveil.toml` 保持 `kind = "tor"`、`port = 9050`。

### 3. 自检

```powershell
.venv\Scripts\agentveil.exe status --deep
```

会报告：隧道是否可达、Tor 引导进度、网站看到的出口 IP、是否为 Tor 出口，以及浏览器自检（WebRTC、WebGL、时区、浏览器出口 IP）。隧道没开时会显示 `FAIL-CLOSED`——这是正确行为。

### 4. 接入 Agent

安装脚本会在项目目录生成 `.mcp.json`，在该目录启动 Claude Code 时批准 `agentveil` 即可。其他目录可用：

```powershell
claude mcp add agentveil -- "C:\AgentVeil\.venv\Scripts\python.exe" -m agentveil -c "C:\AgentVeil\agentveil.toml" mcp
```

**务必禁用 Agent 自带的联网工具**（它们不经过隧道）。Claude Code 在项目的 `.claude/settings.json` 中加入：

```json
{ "permissions": { "deny": ["WebFetch", "WebSearch"] } }
```

---

## 工具清单

| 工具 | 说明 |
|---|---|
| `web_search` | 匿名搜索（无账号、无 API key），返回标题/链接/摘要 |
| `web_fetch` | 无 JS 抓取网页为干净正文 + 链接，长文分页（`offset`） |
| `browser_open` | 在加固 Firefox 中打开页面，返回 `page_id`、可见文字、带编号的可交互元素 |
| `browser_act` | click / type / press / select / check / hover / scroll / back / forward / reload / goto / wait |
| `browser_read` | 重新读取页面（分页） |
| `browser_screenshot` | 截图 |
| `browser_close` | 关闭页面并销毁其 Cookie/存储 |
| `new_identity` | 新身份：新 Tor 线路（新出口 IP），丢弃所有页面与 Cookie |
| `security_status` | 隧道/出口/策略检查；`deep=true` 时附加浏览器自检 |
| `msg_whoami` | 本 Agent 的通信身份、指纹、可分享的联系卡 |
| `msg_add_contact` | 添加对方联系卡（务必线下核对指纹） |
| `msg_contacts` | 联系人列表 |
| `msg_send` / `msg_receive` | 发送 / 接收端到端加密消息 |

命令行同样可用：`agentveil search ...`、`agentveil fetch URL`、`agentveil open URL --screenshot a.png`、`agentveil new-identity`、`agentveil msg ...`。

---

## Agent 间加密通信

1. **运行中继**（任意一方或第三方均可）：`agentveil relay --port 8787`。中继只在内存保存密文、不写日志、不知道发件人。
2. **发布为洋葱服务**，在 torrc 加入：
   ```
   HiddenServiceDir C:\Users\YOU\.agentveil\relay-onion
   HiddenServicePort 80 127.0.0.1:8787
   ```
   重启 Tor 后，`relay-onion\hostname` 里就是中继地址。这样中继和使用者都不暴露 IP。
3. 双方在 `agentveil.toml` 设 `relay_url = "http://xxxx.onion"`（.onion 本身端到端加密，无需 HTTPS）。
4. 用 `msg_whoami` 取得联系卡（`avc1.` 开头），交换后 `msg_add_contact`，并**通过另一个渠道核对指纹**。
5. `msg_send` / `msg_receive`。收到的消息会标明"已验证联系人"或"未知发件人"，且始终作为不可信数据呈现。

身份私钥保存在 `~/.agentveil/identity.json`。首次使用前设置环境变量 `AGENTVEIL_PASSPHRASE`，私钥将用 Argon2id + XSalsa20-Poly1305 加密保存。

---

## 可选：系统级"断网保护"

[scripts/firewall-killswitch.ps1](scripts/firewall-killswitch.ps1) 用 Windows 防火墙禁止 AgentVeil 的 Python 解释器、Playwright Firefox 和驱动连接任何非本机地址，只有 Tor/sing-box（不同程序）能出网。这样即使程序或 Firefox 有漏洞也无法直连。需管理员 PowerShell 运行；`-Remove` 撤销。

注意：Windows 虚拟环境实际运行的是基础解释器（本机为 `Python313\python.exe`），规则会让**所有**使用该 Python 的程序（包括 pip）失去直连能力。建议给 AgentVeil 单独装一个 Python，或需要 pip 时临时 `-Remove`。

---

## 测试

```powershell
.venv\Scripts\python.exe -m pytest -q
```

测试使用一个"记录型 SOCKS5 代理"冒充隧道，以及只存在于代理映射中的假域名（`site.test`），证明：

- 抓取与浏览器都把**域名原样交给隧道**（本机 DNS 根本解析不了 `site.test`）；
- 隧道断开时**零请求到达目标**，Firefox 甚至不会启动；
- Firefox 全程只请求了测试站点本身——**没有遥测、更新、安全浏览等后台连接**；
- Firefox 及驱动进程在操作系统层面**没有任何非本机 TCP 连接**；
- WebRTC 不存在、WebGL 关闭、时区为 UTC+0、语言 en-US；
- 指向 127.0.0.1 的跟踪像素被拦截、重定向到内网被拦截、环境变量代理被忽略；
- 加密消息防篡改、防伪造、防转发冒充、防重放；他人无法读取或清空你的信箱；
- MCP 服务器经 stdio 端到端可用，失败时返回明确的 `FAIL-CLOSED` / `BLOCKED`。

---

## 已知局限

- 通信无前向保密；长期敏感对话请定期更换身份（删除 `identity.json`）。
- 开启 JavaScript 会扩大攻击面（浏览器漏洞可能导致去匿名化，Tor Browser 同样如此）。对不可信站点用 `javascript=false`，并定期更新：`uv pip install -U playwright` 后 `python -m playwright install firefox`。
- `web_fetch` 的 TLS 指纹是 Python 的，与 Firefox 不同（不指向个人，但可区分工具类型）。
- 搜索引擎常对 Tor 出口弹验证码（Mojeek 目前对所有自动访问都弹）。AgentVeil **不会**破解验证码，只会换引擎或提示 `new_identity`。
- 能同时监视隧道两端的全球性对手可做时间关联分析（Tor 的已知局限）。
- 只保护 AgentVeil 自己的流量；系统和其他程序的流量不在保护范围内。

---

## English summary

AgentVeil is a fail-closed, tunnel-only browser for AI agents, exposed as an MCP server (14 tools: search, fetch, hardened Firefox browsing, identity rotation, self-test, end-to-end encrypted agent-to-agent messaging). All traffic leaves through one local SOCKS5 tunnel (Tor with bridges, or your own sing-box/Xray server); hostnames are resolved inside the tunnel; if the tunnel is down, nothing is sent. WebRTC is disabled, Firefox runs with resistFingerprinting, LAN/loopback targets are blocked, and fetched content is sanitized against hidden prompt injection. No software can guarantee that using a circumvention tunnel goes unnoticed; see the risk table above.
