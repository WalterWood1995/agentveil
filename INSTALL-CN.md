# AgentVeil 中国大陆安装与测试指南

适用于 Windows 10 / 11（64 位）。全程约 20 分钟。**使用前请先读 [README.md](README.md) 中的"能保证什么，不能保证什么"一节**——任何软件都不能保证翻墙不被发现，在大陆使用未经批准的跨境信道违反相关法规，请自行评估风险。

---

## 0. 获取安装包

推荐使用**离线安装包** `AgentVeil-offline-win64.zip`（约 150 MB）。它包含程序本身、全部 Python 依赖、浏览器内核和官方 Tor 专家包，安装过程**不需要访问任何境外网站**。

- 下载地址：本项目 GitHub 页面右侧的 **Releases**（github.com 在国内通常能打开，但可能较慢，可多试几次）。
- 也可以请境外的朋友下载后通过 U 盘或加密渠道转交。**不建议**用微信、QQ、百度网盘传递：这些平台会扫描文件并和你的实名账号关联。
- 校验完整性（在 PowerShell 中执行，结果须与 Release 页面上的 `.sha256` 一致）：

```powershell
Get-FileHash -Algorithm SHA256 .\AgentVeil-offline-win64.zip
```

## 1. 安装 Python 3.13（64 位）

任选一个来源下载 **Windows installer (64-bit)**：

- 官方：https://www.python.org/downloads/windows/ （国内通常可访问）
- 华为云镜像：https://mirrors.huaweicloud.com/python/ （进入 3.13.x 目录，下载 `python-3.13.x-amd64.exe`）

安装时**勾选 "Add python.exe to PATH"**，其余保持默认（会同时安装 `py` 启动器）。

## 2. 解压并安装

1. 把 zip 解压到 **`C:\AgentVeil`**。路径里不要有中文或空格，否则 Tor 无法工作。
2. 打开 PowerShell（开始菜单搜索 "PowerShell"），执行：

```powershell
powershell -ExecutionPolicy Bypass -File C:\AgentVeil\install-offline.ps1
```

看到 `Installed. Next steps:` 就说明安装成功。

> 如果拿不到离线包，也可以直接下载源码在线安装（使用清华 PyPI 镜像和 npmmirror 镜像）：
> `powershell -ExecutionPolicy Bypass -File C:\AgentVeil\scripts\install.ps1 -China`

## 3. 准备隧道

AgentVeil 自己不翻墙，它把所有流量交给本机的隧道客户端。三种方案任选其一：

### 方案 A：Tor + Snowflake（零配置，先试这个）

```powershell
C:\AgentVeil\.venv\Scripts\agentveil.exe tor-config --bundle C:\AgentVeil\tor-bundle --bridges snowflake
C:\AgentVeil\tor-bundle\tor\tor.exe -f $HOME\.agentveil\torrc
```

第二条命令会持续输出日志。看到 `Bootstrapped 100% (done)` 就是连上了，这个窗口要**一直开着**。（作者在境外实测：Snowflake 约 3 分钟到达 100%。）Snowflake 在国内时通时断，如果卡在某个百分比超过 5 分钟，请改用方案 B。

### 方案 B：Tor + 私有网桥（更稳定）

国内无法直接打开网桥申请网站。请**让境外的朋友**帮你获取网桥：打开 https://bridges.torproject.org/ ，类型选 **webtunnel** 或 **obfs4**，把得到的几行文字通过 Signal 等加密渠道发给你。
把这几行保存为 `C:\AgentVeil\bridges.txt`（每行一条），然后：

```powershell
C:\AgentVeil\.venv\Scripts\agentveil.exe tor-config --bundle C:\AgentVeil\tor-bundle --bridge-file C:\AgentVeil\bridges.txt
C:\AgentVeil\tor-bundle\tor\tor.exe -f $HOME\.agentveil\torrc
```

### 方案 C：已有翻墙客户端（Clash / v2rayN / sing-box 等）

用记事本打开 `C:\AgentVeil\agentveil.toml`，在 `[upstream]` 下修改：

```toml
kind = "socks"
port = 7890        # 改成你客户端的本机 SOCKS5 端口（Clash 常见 7890/7891，v2rayN 常见 10808）
control_port = 0
```

注意：你的翻墙客户端必须开启 SOCKS5 端口，且**不要**开"规则分流/直连国内"之类的模式访问 AgentVeil 流量，否则部分请求可能被直连。最好用"全局"模式。

> 想再加一层：在方案 C 的基础上串联 Tor（审查者只看到你的翻墙协议，翻墙服务商只看到 Tor）：
> `agentveil.exe tor-config --bundle C:\AgentVeil\tor-bundle --bridges none --via-socks 127.0.0.1:7890`，`agentveil.toml` 保持 `kind = "tor"`、`port = 9050`。

## 4. 自检

另开一个 PowerShell 窗口：

```powershell
C:\AgentVeil\.venv\Scripts\agentveil.exe status --deep
```

正常结果应包含：

- `Tunnel reachable: yes`
- `Exit IP seen by websites: <一个境外 IP>`，方案 A/B 还应显示 `Tor exit: yes`
- 浏览器自检中 `WebRTC API present: False [OK]`、`WebGL available: False [OK]`

如果显示 `FAIL-CLOSED`，说明隧道没开或端口不对。此时**不会有任何流量发出**，这是正常的保护行为。

## 5. 使用

命令行：

```powershell
C:\AgentVeil\.venv\Scripts\agentveil.exe search 关键词
C:\AgentVeil\.venv\Scripts\agentveil.exe fetch "https://www.torproject.org/"
C:\AgentVeil\.venv\Scripts\agentveil.exe open "https://en.wikipedia.org/wiki/Tor_(network)" --screenshot shot.png
C:\AgentVeil\.venv\Scripts\agentveil.exe new-identity
```

接入 AI Agent：安装脚本已在 `C:\AgentVeil\.mcp.json` 生成 MCP 配置，任何支持 MCP 的客户端都可以使用。

> ⚠️ **重要：Agent 用的大模型能看到所有内容。** 如果把 AgentVeil 接到国内大模型服务（任何境内 AI 应用或 API），你的搜索词和读到的网页内容都会交给该服务商——隧道就白搭了。请使用本地模型（例如 Ollama）或你信任的境外服务，或者只用上面的命令行。

## 6. 测试反馈（给测试者）

请把以下信息发回给项目作者（**发送前去掉任何能识别你身份的内容**）：

1. 使用的方案（A / B / C）以及 Tor 是否到达 100%、用了多久；
2. `agentveil.exe status --deep` 的输出（出口 IP 是境外节点的 IP，可以分享）；
3. 搜索和打开网页是否成功、大概速度；
4. 可选：运行内置测试，把最后一行结果发回：
   ```powershell
   cd C:\AgentVeil; .\.venv\Scripts\python.exe -m pytest -q
   ```

## 7. 常见问题

| 现象 | 处理 |
|---|---|
| `py` 不是可识别的命令 | 重新安装 Python，勾选 "Add python.exe to PATH" |
| 脚本"无法加载，因为在此系统上禁止运行脚本" | 按上文用 `powershell -ExecutionPolicy Bypass -File ...` 运行 |
| `tor-config` 报 "contains spaces or non-ASCII" | 把整个目录移到 `C:\AgentVeil` 后重装 |
| Tor 卡在 `Bootstrapped 10%` 等 | 网桥被封：换方案 B 的新网桥，或改用方案 C |
| `fetch` 返回 403（如维基百科） | 该站拒绝脚本式抓取，改用 `open`（真实浏览器） |
| 搜索返回 "bot challenge / CAPTCHA" | 搜索引擎在拦截 Tor 出口：执行 `new-identity` 后再试 |
| `status` 显示 `Tor exit: no` 但 kind 是 tor | 端口指向了别的程序，检查 `agentveil.toml` 的 `port` |

## 8. 安全习惯

- 不要在 AgentVeil 里登录实名账号（手机号注册的账号、微信/支付宝关联账号等）。
- 不要把真实姓名、手机号、所在地写进搜索词或表单。
- 电脑上若有单位或学校的管理/监控软件，任何隧道都无法保护你。
- 少用云输入法的"云联想"输入敏感内容。
- 用完关闭 Tor 窗口；不相关的任务之间执行 `new-identity`。
