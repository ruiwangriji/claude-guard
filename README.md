# claude-guard：Claude 防直连保护

OpenWrt / ImmortalWrt（firewall4、nftables）插件。可以单独装：路由器上没有任何代理插件时，发往 Claude 的直连一律拦下，不会从本地宽带出去（设备自己开了代理的不受影响）。装了 PassWall 时和它配合：经过路由器访问 Claude 的连接只能走代理；PassWall 停止、重启、崩溃、清规则，或宽带重拨、开机延时期间，这些连接会被拦下。只支持 PassWall，不支持 OpenClash 等其他代理插件。其他网站的分流不变。

在 ImmortalWrt 25.12.1（PassWall 26.10.16）上开发和测试；24.10（opkg）上的安装包也试装过。

## 原理

独立的 nft 表 `inet claude_guard`，不属于 fw4 也不属于 PassWall，两者重载、停止都不碰它。

| 链 | 钩子 | 作用 |
|---|---|---|
| `guard_forward` | forward，优先级 −20 | 局域网设备发往 Claude 地址的转发包一律拒绝。PassWall 代理的连接被 TPROXY 到本机，不经过 forward；走到这里的只能是直连 |
| `guard_output` | output，优先级 +10（在 PassWall 的 nat_output 之后） | 路由器本机发往 Claude 地址的包：带 PassWall 标记（TPROXY）或已被 REDIRECT 改了目的地址的放行，其余拒绝 |
| `guard_audit` | postrouting，优先级 0 | 看实际出接口：除 `lo` 外，任何还要发出去的 Claude 包都丢掉并计数。正常应永远是 0 |

地址集合：静态段 `dst4/dst6`（`/etc/claude-guard/static.list`），网段以外的地址 `dyn4/dyn6`（定期解析发现的或统一列表给的，带过期），豁免源 `ex4/ex6`，自检用金丝雀 `192.0.2.83`、`2001:db8::83`。

## 文件

| 路径 | 内容 |
|---|---|
| `/etc/config/claude_guard` | 配置（UCI） |
| `/etc/claude-guard/static.list` | 静态地址段，一行一段 |
| `/etc/claude-guard/discovered.json` | 发现的段外地址（重启后仍在） |
| `/etc/claude-guard/auto.json` | 自动更新得到的网段和域名、各来源结果（重启后仍在） |
| `/etc/claude-guard/critical.log` | 严重事件（闪存，重启后仍在）。最多 200 行；同类事件 10 分钟内只记一次 |
| `/etc/claude-guard/backup/` | 改 PassWall 前的配置备份 |
| `/etc/init.d/claude-guard` | 开机脚本，START=13（系统日志之后，早于 dnsmasq、firewall 19、network 20）；看护进程 nice −5、OOM 保护 −900 |
| `/etc/hotplug.d/iface/15-claude-guard` | 接口上线后立即复核 |
| `/usr/libexec/claude-guard/guard.lua` | 核心逻辑 |
| `/usr/libexec/claude-guard/ctl` | 命令入口 |
| `/usr/libexec/claude-guard/daemon.sh` | 看护进程（procd 拉起） |
| `/usr/libexec/claude-guard/uninstall.sh` | 卸载 |
| `/www/luci-static/resources/view/claude-guard/` | 管理页（服务 → Claude 防直连） |
| `/lib/upgrade/keep.d/claude-guard` | 升级固件保留配置时一并保留 |
| `/tmp/claude-guard/` | 运行状态、事件、当前规则（内存） |

## 命令

```sh
/usr/libexec/claude-guard/ctl status      # 状态（JSON，不改动任何东西）
/usr/libexec/claude-guard/ctl selftest    # 立即自检 + 出口检测
/usr/libexec/claude-guard/ctl repair      # 重新加载规则，清理残留直连连接
/usr/libexec/claude-guard/ctl apply       # 按配置重新加载（原子替换，无空窗）
/usr/libexec/claude-guard/ctl dry-run     # 只生成规则并做语法检查
/usr/libexec/claude-guard/ctl discover    # 立即解析域名、更新动态地址
/usr/libexec/claude-guard/ctl update      # 立即更新目标列表；update --dry 只看不改
/usr/libexec/claude-guard/ctl trace       # Claude 看到的出口
/usr/libexec/claude-guard/ctl reset-counters  # 拦截计数清零（管理页卡片上也有「清零」）
/usr/libexec/claude-guard/ctl ruleset     # 当前加载的规则原文
/usr/libexec/claude-guard/ctl passwall-test                      # 只读：用 PassWall 生成器（只生成模式）生成配置并 xray 校验
/usr/libexec/claude-guard/ctl passwall-apply <节点ID> [restart]   # 写入 Claude 指定出口（先校验，通过才提交）；节点 ID 写 _default = 跟随默认节点
/usr/libexec/claude-guard/ctl passwall-ensure                    # PassWall 里没有 Claude 规则时补上（看护进程会自动做，这是手动触发）
/usr/libexec/claude-guard/ctl passwall-remove [restart]          # 删除 PassWall 里的 Claude 规则，并关掉自动添加
/usr/libexec/claude-guard/ctl passwall-restart                   # 重启 PassWall，让已写入的出口生效
```

## 启停与恢复

| 要做的事 | 怎么做 |
|---|---|
| 停用保护（卸下规则） | 管理页「停用保护」，或 `ctl disable`，或 `/etc/init.d/claude-guard unload` |
| 重新启用 | 管理页「启用保护」，或 `ctl enable` |
| 规则异常 | 看护进程会自动重装；手动：管理页「立即修复」或 `ctl repair` |
| 紧急拆除 | `nft delete table inet claude_guard`（看护进程实时监听，约 2 秒内装回；要彻底停用请用 `ctl disable`） |
| 卸载 | `sh /usr/libexec/claude-guard/uninstall.sh`；加 `--passwall` 同时删除 PassWall 里的 Claude 规则并重启 PassWall（等它重启完才卸下保护，重启期间 Claude 仍被拦） |
| 恢复 PassWall 原配置 | `cp /etc/claude-guard/backup/passwall.<时间> /etc/config/passwall && /etc/init.d/passwall restart` |

`/etc/init.d/claude-guard stop` 只停看护进程，规则仍在内核中，不会出现空窗。

## 安装

手工安装（软件源上线前用这个）：

```sh
# 在本机：上传到路由器（把 <路由器地址> 换成实际地址）
tar czf - -C claude-guard . | ssh root@<路由器地址> 'rm -rf /tmp/cg-stage && mkdir -p /tmp/cg-stage && tar xzf - -C /tmp/cg-stage'
# 在路由器：安装，300 秒内不确认就自动回滚
sh /tmp/cg-stage/install.sh --deadman 300
/usr/libexec/claude-guard/ctl confirm
```

已有的 `/etc/config/claude_guard` 会保留。

依赖：必须有 `lua`、`luci-lib-nixio`、`luci-lib-jsonc`、`libuci-lua`；建议有 `curl`（更新目标列表、检测出口）和 `conntrack`（清理残留直连）。**不依赖 PassWall。** 这几样在装过 PassWall 的路由器上通常已经有，没装过的（包括官方默认固件）通常没有，安装脚本会自己从软件源装（`apk`，老固件用 `opkg`）；必须的装不上就报出缺哪个并退出，不留下任何文件。

## 打包

`packaging/build.sh` 把插件打成安装包，并生成签名的软件源：25.12 起的固件用 `.apk`（`packages.adb`），24.10 及更早用 `.ipk`（`Packages` + `Packages.sig`）。包名 `luci-app-claude-guard`，不分 CPU，依赖由包管理器从官方源装。在 Alpine 3.24 以上运行（`apk add openssl signify tar`），不需要 OpenWrt SDK，用法见脚本开头。

- 签名私钥不进仓库。
- 包里的脚本：安装时启用并启动；升级后重启看护进程（规则不断）；真卸载才卸下拦截规则。
- 公钥由生成的 `setup.sh` 写到路由器上，不归包管理器管，卸载插件时不删。

## 单独安装（没有代理插件）

- 保护的含义变成「不走本地宽带」：这台路由器下，发往 Claude 地址的连接一律被拦；设备上自己开了代理的，流量发往代理服务器，不受影响。
- 不检测出口（没有代理时从路由器访问 Claude 只会被自己拦下）。
- 不做定期解析（没有代理时路由器的 DNS 结果不可靠）。网段以外的地址只能由统一列表提供。
- 自动更新照常：宽带通了就运行，每天一次。
- 之后装上 PassWall：看护进程会发现它，在它的分流规则里加上 Claude 规则（见「Claude 指定出口」），出口检测和定期解析也随之开始。

## 怎么判断一条连接是直连，什么时候清理

PassWall 转发 TCP 有两种方式：TPROXY 会给连接打标记，REDIRECT 不打标记、把连接转到路由器本机 1041 端口。所以不能只看标记，按连接跟踪里的回程判断：

| 回程情况 | 判定 |
|---|---|
| 回程来源不是原目的地址（被转到本机代理端口） | 走了代理（REDIRECT） |
| 带 PassWall 标记 | 走了代理（TPROXY） |
| 回程目的被改成别的地址（做了地址转换，从宽带口出去） | 直连 |
| 来源是路由器自己的地址 | 路由器本机直连 |
| 其他转发连接 | 装了 PassWall：直连（没有地址转换的 IPv6、旁路由）；没装 PassWall（用别的代理）：判断不了，不算直连 |

PassWall 的标记和直连进程组默认从它自己的脚本里读（`/usr/share/passwall/nftables.sh` 的 `FWMARK`、`utils.sh` 的 `DIRECT_GID`），配置里写 `auto`。

**只在拦截范围刚变大时清理一次已有的直连**（流量卸载会让它们绕过拦截规则）：

- 规则是新装上的（开机、启用、表被删后装回）；
- 加了新网段或新地址：只清到新目标的连接；
- 取消了某台设备的豁免；
- 规则曾被删改（看护进程修复时）。

平时规则一直在，新的直连建立不起来，所以定时检查**只报告、不动连接**（状态页会列出，有「清理这些连接」按钮，命令行是 `ctl flush`）。1.1.0 及以前每 15 秒自动清理，2026-11-10 PassWall 改成 REDIRECT 后把走代理的连接当成直连掐了半小时，1.2.0 起取消。

只读核对：`/usr/libexec/claude-guard/ctl scan`。

## 状态判定

管理页的「保护正常」要求同时满足：拦截表在、三个挂载点正确、规则指纹与加载时一致、静态段齐全、金丝雀探测（以 PassWall 直连进程组身份发出）被拦下且计数增加、连接跟踪表里没有未带 PassWall 标记的 Claude 连接、出网审计计数没有增加。不看进程是否存活。

另外单列：PassWall 是否在运行、Claude 用哪个节点、Claude 看到的出口（PassWall 在运行时每 10 分钟经代理访问 `claude.ai/cdn-cgi/trace`；PassWall 没在运行或没装时不检测）。出口是本地宽带地址或国家为 CN 时告警。

## 自动更新目标列表

每天一次，由看护进程调度，管理页可手动「更新目标列表」。装了 PassWall：等它在运行时才更新（经代理下载），开机后它起来就先跑一次。没装代理插件：宽带通了就更新。自动运行时一个来源都没连上，半小时后重试。

配了统一列表并且这次拿得到，就只用统一列表；没配或拿不到，用下面的公开来源兜底。

| 来源 | 内容 | 用途 |
|---|---|---|
| ARIN `whois.arin.net/rest/org/AP-2440/nets` | 登记在 Anthropic, PBC 名下的全部网段（2026-11-10：`160.79.104.0/21`、`153.61.0.0/16`、`216.73.216.0/22`、`2607:6bc0::/32`） | 按 IP 拦截 |
| RIPEstat `announced-prefixes` AS399358 | Anthropic 自己 ASN 的路由公告 | 按 IP 拦截 |
| 本地 `/usr/share/v2ray/geosite.dat` 的 `anthropic` 类别（PassWall 带来并每周更新，用 geoview 读；路由器上没有就跳过） | Claude / Anthropic 域名 | PassWall 的 Claude 规则 |
| [v2fly/domain-list-community `data/anthropic`](https://github.com/v2fly/domain-list-community/blob/master/data/anthropic) | 同上，社区维护、PR 审核，比 geosite 更新得快 | PassWall 的 Claude 规则 |

规则：

- 公开来源只增不减。某个来源失败、或不再列出某项，已有内容保留，页面标出失败原因。只有统一列表能撤回。
- ARIN 上登记的四个网段已全部写进内置列表（`153.61.0.0/16`、`216.73.216.0/22` 是 2026-11-11 向 ARIN 核对后加的）：没有代理时 ARIN 经常连不上，不能靠在线来源才拿到它们。
- 网段太大（IPv4 短于 /12、IPv6 短于 /19）、保留地址不收；一次新增网段超过 8 个、域名超过 40 个，只报警不加入。
- 已被现有网段覆盖的不重复加。
- 域名只用于 PassWall 的 Claude 规则（按域名精确匹配，不误伤）。规则里只写明确的域名，不引用 `geosite:` 类别：类别一旦在 geosite 数据里不存在，Xray 校验失败、PassWall 整个起不来（虚拟主路由上实测过）。geosite 只当读取域名的来源。CDN、遥测之类第三方主机（如 `servd-anthropic-website.b-cdn.net`、Datadog、Sentry）标为「第三方」，只按域名走 Claude 出口，不按 IP 拦。
- 自有域名解析到 Anthropic 网段以外的地址时只在页面提示，不自动按 IP 拦（可能是共享 CDN），确认后可手动加到「附加网段」。
- 新网段加入后原子重载拦截规则；新域名和网段同步进 PassWall 的 Claude 规则时同样先校验，不重启 PassWall。

### 统一列表

自己维护的一个 JSON 文件，放在一个路由器不用代理也能访问的 https 地址上，在「设置 → 高级 → 统一列表地址」（`central_url`）里填。用途：给所有装了插件的路由器统一下发新地址，也能统一撤回。

```json
{
  "format": "claude-guard-list",
  "version": 1,
  "serial": 2026111101,
  "prefixes": [ { "prefix": "203.0.113.0/24", "note": "说明" } ],
  "hosts":    [ { "ip": "198.51.100.7", "domain": "downloads.claude.ai" } ],
  "domains":  [ { "d": "claude.ai" }, { "d": "x.example-cdn.net", "type": "full", "shared": true } ],
  "revoke":   { "prefixes": [], "hosts": [], "domains": [] }
}
```

| 字段 | 含义 |
|---|---|
| `serial` | 版本序号，每次改动加大。路由器不接受比自己用过的更小的序号 |
| `prefixes` | 整段归 Anthropic 的网段，按 IP 拦 |
| `hosts` | 网段以外、但确认是 Claude 专用的单个地址，按 IP 拦。列表里一直有就一直有效，不再列出后 30 天过期 |
| `domains` | 域名，只写进 PassWall 的 Claude 规则。`type` 是 `suffix`（含子域名，默认）或 `full`；`shared: true` 表示共用 CDN 之类 |
| `revoke` | 要撤回的项。只撤回自动加入的内容，内置列表和手动加的不受影响 |

限制和公开来源相同：网段太大、保留地址不收；一次新增太多只报警不加入。地址只接受 `https://`。

## Claude 指定出口

装了 PassWall 时，看护进程会自动在它的分流规则里放一条 `ClaudeGuard`（显示名「Claude（防直连插件）」），默认跟随默认节点。作用有两个：PassWall 用分流节点时，会把分流规则里的地址段按 IP 强制走代理，不靠 DNS；之后可以在设置页给 Claude 单独选出口。只写配置、不重启 PassWall，等它下次重启时生效；开机头 3 分钟不动，同一个失败原因只记一次日志、每小时重试。在设置页删除这条规则后不再自动添加（「设置 → 高级」里可以重新打开）。PassWall 用单个节点（不是分流节点）时，规则照样放进去备用，但没法单独指定出口。

管理页「设置 → 常用」：选节点后点「写入（PassWall 下次重启时生效）」，或「写入并立即重启 PassWall」（会弹窗确认）。状态页「代理与出口」显示配置里的节点和正在生效的节点，不一致时提示「待生效」。

写入做的事：在 PassWall 加分流规则 `ClaudeGuard`（显示名「Claude（防直连插件）」，`domain:claude.ai`、`claude.com`、`anthropic.com`、`claudeusercontent.com`、`clau.de` 和两个 Anthropic 地址段，TCP+UDP），排在所有分流规则前面；在当前分流节点上把它指向所选节点。

写入前的保护：

1. PassWall 有未提交的修改就不写。
2. 用 PassWall 自己的生成器以只生成模式（`no_run`，不启动进程、不写运行目录）生成一次现有配置，确认和正在运行的规则一致，且 `xray run -test` 通过。
3. 暂存（不提交）改动，再生成一次并校验：Claude 规则指向所选节点、其他规则和顺序不变、xray 校验通过。任何一项不满足就撤销，PassWall 配置不变。
4. 通过才提交，原配置备份到 `/etc/claude-guard/backup/passwall.<时间>`。

只写入不重启时，正在运行的 PassWall 不受影响。LuCI 的「保存并应用」只通知当次改过的配置，不会因为插件改过 PassWall 配置而重启它（实测）。但执行 `/sbin/reload_config` 会全量比对 `/var/run/config.md5`，PassWall 配置和基线不一致就重启它（ucitrack 给 PassWall 注册了触发器，它的 `reload` 就是 `restart`）；所以插件每次提交 PassWall 配置后会把基线里 passwall 这一项更新成当前值。

## 已知限制

- 只支持 PassWall（Xray 分流节点）。没测过 sing-box 类型的节点；不支持 OpenClash。
- 只认得地址：Anthropic 自有段以外的新地址，装了 PassWall 时要等定期发现（默认 6 小时）才加入，没有代理时只能靠统一列表；客户端用加密 DNS 拿到路由器没见过的地址时可能漏掉。
- 拦截表被整张删除：看护进程监听到后先按上次的规则立即装回，虚拟主路由上实测 0.12–0.14 秒；规则被改动、集合被清空走完整复核，约 1 秒。这段空窗里如果 PassWall 也不在，Claude 连接可能直连。监听只接收涉及本插件表的事件（PassWall 重启一次会产生近万行 nft 事件）。
- 第三方服务（Google/Apple 登录、Stripe、Sentry、Datadog、状态页）不在保护范围。
- `ping claude.ai` 永远不通：PassWall 不代理 ICMP，这类包会被当作直连拦下。
- PassWall 停止时，`claude.ai` 的 DNS 查询会发给运营商 DNS；这是查询、不是连接，本插件不拦。
- 不保证代理出口被 Claude 接受。

## 版本

- **1.3.2**（2026-11-11）：管理页重做。状态页以一条线路为主（家里的设备 → 代理节点 → Claude），下面是被拦下的直连和次数；界面本身不上色，颜色只用在线路和「被拦下」上；换节点改成状态页上的弹窗，设置页只留真正的设置项；时间按路由器时区显示。审查方法参考 [unslop](https://github.com/heydamir/unslop)（Damir Sokolovsky，CC BY 4.0）。后台只多了一个时区字段，拦截逻辑没动。
- **1.3.1**（2026-11-11）：停看护进程时不再留下监听进程。原来清理用的是 `pkill`，这类固件的 busybox 没有这个命令，清理悄悄失败，每次重启看护服务（升级、重装）都会多出一对没人管的 `nft monitor` 和 `awk`，1.2.0 起就有。改用 `pgrep` 加 `kill`，看护进程启动时顺手清掉以前留下的；卸载脚本同样处理。
- **1.3.0**（2026-11-11）：可以单独安装。安装脚本自己装依赖；没有 PassWall 时也自动更新目标列表，一个来源都连不上时半小时后重试；内置列表补上 ARIN 登记的另外两段；新增统一列表（可撤回）；代理没在运行时不检测出口；装了 PassWall 自动放 Claude 规则，可选「跟随默认节点」；判断 PassWall 是否安装不再只看启动脚本；带 `--passwall` 卸载时等 PassWall 重启完才卸保护；页面文字按有没有 PassWall 分开。
- **1.2.0**（2026-11-10）：取消定时清理连接，改为只在拦截范围变大时清一次；PassWall 规则不再引用 geosite 类别；提交 PassWall 配置后刷新系统配置基线；严重日志限量限速；PassWall 标记自动读取；看护进程只收本插件的事件，表被删后立即装回；自动更新同步 PassWall 规则时加锁。在虚拟路由器上（真 PassWall、真重启、两种转发方式）测过。
- **1.1.0**（2026-11-10）：目标列表自动更新；开机顺序提前到 13；页面重做；直连判断兼容 REDIRECT。
- **1.0.0**（2026-11-08）：首版。
