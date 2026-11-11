#!/usr/bin/lua
-- Claude 防直连保护 · 核心逻辑（OpenWrt / ImmortalWrt，nftables）
-- 由 /usr/libexec/claude-guard/ctl 调用；所有命令输出一行 JSON。

local nixio = require "nixio"
local nfs = require "nixio.fs"
local jsonc = require "luci.jsonc"
local uci = require "uci"

local VERSION = "1.3.2"
local TABLE = "claude_guard"
local RUN = "/tmp/claude-guard"
local ETC = "/etc/claude-guard"
local CTL = "/usr/libexec/claude-guard/ctl"
local LOCKFILE = "/var/lock/claude-guard.lock"
local CANARY4, CANARY6 = "192.0.2.83", "2001:db8::83"
local DEFAULT_PREFIXES = { "160.79.104.0/21", "2607:6bc0::/32", "153.61.0.0/16", "216.73.216.0/22" }
local DEFAULT_PW_DOMAINS = { "claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com", "clau.de" }
local PW_RULE = "ClaudeGuard"
-- PassWall 生成 Xray 规则时用规则的显示名做 ruleTag（加 " Domains" / " IP"），所以按显示名识别
local PW_REMARKS = "Claude（防直连插件）"

nfs.mkdirr(RUN)
nfs.mkdirr(ETC)

---------------------------------------------------------------- 基础工具

local function q(s)
	return "'" .. (tostring(s):gsub("'", "'\\''")) .. "'"
end

local function run(cmd)
	local p = io.popen("(" .. cmd .. ") 2>&1; echo \"__RC=$?\"")
	local out = p:read("*a") or ""
	p:close()
	local rc = tonumber(out:match("__RC=(%d+)%s*$")) or 255
	out = out:gsub("__RC=%d+%s*$", "")
	return out, rc
end

local function readfile(p)
	local f = io.open(p, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end

local function writefile(p, s)
	local tmp = p .. ".tmp" .. nixio.getpid()
	local f = assert(io.open(tmp, "w"))
	f:write(s)
	f:close()
	assert(os.rename(tmp, p))
end

local function readjson(p)
	local s = readfile(p)
	if not s or s == "" then return nil end
	return jsonc.parse(s)
end

local function writejson(p, v)
	writefile(p, jsonc.stringify(v) or "null")
end

local function trim(s)
	s = (s or ""):gsub("^%s+", "")
	s = s:gsub("%s+$", "")
	return s
end

local function syslog(level, msg)
	os.execute("logger -t claude-guard -p daemon." .. level .. " " .. q(msg))
end

local function event(msg, level)
	level = level or "notice"
	syslog(level, msg)
	local path = RUN .. "/events.log"
	local f = io.open(path, "a")
	if f then
		f:write(os.date("%Y-%m-%d %H:%M:%S") .. " [" .. level .. "] " .. msg .. "\n")
		f:close()
	end
	local s = readfile(path) or ""
	local lines = {}
	for l in s:gmatch("[^\n]+") do lines[#lines + 1] = l end
	if #lines > 300 then
		writefile(path, table.concat(lines, "\n", #lines - 199) .. "\n")
	end
	-- 严重事件另存一份到闪存，重启后还能查。
	-- 限速：同一类事件（数字不同算同类）10 分钟内只写一次；限量：最多保留 200 行。
	-- 整段放在 pcall 里：记日志出错不能影响拦截逻辑。
	if level == "crit" then
		pcall(function()
			local norm = msg:gsub("%d+", "#"):sub(1, 60)
			local h = 5381
			for i = 1, #norm do h = (h * 33 + norm:byte(i)) % 1000000007 end
			local key = "k" .. tostring(h)
			local rl = readjson(RUN .. "/crit_rate.json") or {}
			local now = os.time()
			local e = rl[key]
			if e and now - (tonumber(e.t) or 0) < 600 then
				e.n = (tonumber(e.n) or 0) + 1
				writejson(RUN .. "/crit_rate.json", rl)
				return
			end
			local extra = (e and (tonumber(e.n) or 0) > 0) and ("（此前同类事件另有 " .. e.n .. " 次未逐条记录）") or ""
			rl[key] = { t = now, n = 0 }
			writejson(RUN .. "/crit_rate.json", rl)
			local path2 = ETC .. "/critical.log"
			local keep = {}
			for l in (readfile(path2) or ""):gmatch("[^\n]+") do keep[#keep + 1] = l end
			keep[#keep + 1] = os.date("%Y-%m-%d %H:%M:%S") .. " " .. msg:sub(1, 600) .. extra
			writefile(path2, table.concat(keep, "\n", math.max(1, #keep - 199)) .. "\n")
		end)
	end
end

local lockfd, locked
local function lock(wait)
	if locked then return true end
	nfs.mkdirr("/var/lock")
	lockfd = nixio.open(LOCKFILE, "w")
	if not lockfd then return false end
	local deadline = os.time() + (wait or 30)
	while true do
		if lockfd:lock("tlock") then locked = true; return true end
		if os.time() >= deadline then return false end
		nixio.nanosleep(0, 200000000)
	end
end

---------------------------------------------------------------- 配置

local function list(v)
	if type(v) == "table" then return v end
	if v and v ~= "" then return { v } end
	return {}
end

local function hexnum(s, d)
	if not s then return d end
	s = tostring(s)
	if s:match("^0[xX]") then return tonumber(s:sub(3), 16) or d end
	return tonumber(s) or d
end

-- PassWall 给代理连接打的标记、它的直连进程组：写在 PassWall 自己的脚本里，版本不同可能不同
local function detect_pw()
	local mark, gid
	local s = readfile("/usr/share/passwall/nftables.sh") or ""
	local v = s:match('\nFWMARK="?(0x%x+)"?')
	if v then mark = tonumber(v:sub(3), 16) end
	local u = readfile("/usr/share/passwall/utils.sh") or ""
	gid = tonumber(u:match("\nDIRECT_GID=(%d+)"))
	return mark, gid
end

local function cfg()
	local c = uci.cursor()
	local m = c:get_all("claude_guard", "main") or {}
	local dmark, dgid = detect_pw()
	local function auto(v) return v == nil or v == "" or v == "auto" end
	return {
		enabled = (m.enabled or "1") == "1",
		action = (m.action == "drop") and "drop" or "reject",
		log = (m.log or "1") == "1",
		check_interval = tonumber(m.check_interval) or 15,
		canary_interval = tonumber(m.canary_interval) or 60,
		trace_interval = tonumber(m.trace_interval) or 600,
		discover = (m.discover or "1") == "1",
		discover_interval = tonumber(m.discover_interval) or 21600,
		dyn_ttl = tonumber(m.dyn_ttl) or 2592000,
		max_new = tonumber(m.max_new) or 16,
		pw_mark = auto(m.passwall_mark) and (dmark or 0x50535731) or hexnum(m.passwall_mark, 0x50535731),
		bypass_gid = auto(m.bypass_gid) and (dgid or 9911) or (tonumber(m.bypass_gid) or 9911),
		exempt = list(m.exempt_src),
		extra = list(m.extra_prefix),
		domains = list(m.domain),
		pw_domains = list(m.passwall_domain),
		proxy_node = m.proxy_node,
		auto_update = (m.auto_update or "1") == "1",
		update_interval = tonumber(m.update_interval) or 86400,
		src_geosite = (m.src_geosite or "1") == "1",
		geosite_category = m.geosite_category or "anthropic",
		src_v2fly = (m.src_v2fly or "1") == "1",
		v2fly_url = m.v2fly_url or "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/anthropic",
		src_arin = (m.src_arin or "1") == "1",
		arin_org = m.arin_org or "AP-2440",
		src_ripe = (m.src_ripe or "1") == "1",
		asn = m.asn or "399358",
		max_new_prefix = tonumber(m.max_new_prefix) or 8,
		max_new_domain = tonumber(m.max_new_domain) or 40,
		-- 统一列表：自己维护的一个 JSON 文件的地址（https），空 = 不用
		central_url = trim(m.central_url or ""),
		-- 装了 PassWall 时，自动在它的分流规则里放一条 Claude 规则
		pw_auto_rule = (m.passwall_auto_rule or "1") == "1",
	}
end

---------------------------------------------------------------- IP 地址

local function ip4(s)
	local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	if not a then return nil end
	local t = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
	for i = 1, 4 do if t[i] > 255 then return nil end end
	return t
end

local function ip6(s)
	if not s:find(":", 1, true) then return nil end
	s = s:lower():gsub("%%.*$", "")
	local function split(x)
		local r = {}
		if x == "" then return r end
		for g in (x .. ":"):gmatch("([^:]*):") do r[#r + 1] = g end
		return r
	end
	local head, tail = s:match("^(.-)::(.*)$")
	local h, t
	if head then h, t = split(head), split(tail) else h, t = split(s), {} end
	-- 末尾可能是点分 IPv4（如 ::ffff:1.2.3.4）
	local last = (#t > 0) and t or h
	if #last > 0 and last[#last]:find(".", 1, true) then
		local v4 = ip4(last[#last])
		if not v4 then return nil end
		last[#last] = string.format("%x", v4[1] * 256 + v4[2])
		last[#last + 1] = string.format("%x", v4[3] * 256 + v4[4])
	end
	local n = #h + #t
	if head then
		if n > 7 then return nil end
	elseif n ~= 8 then
		return nil
	end
	local all = {}
	for _, g in ipairs(h) do all[#all + 1] = g end
	if head then for _ = 1, 8 - n do all[#all + 1] = "0" end end
	for _, g in ipairs(t) do all[#all + 1] = g end
	local bytes = {}
	for _, g in ipairs(all) do
		if not g:match("^%x%x?%x?%x?$") then return nil end
		local v = tonumber(g, 16)
		bytes[#bytes + 1] = math.floor(v / 256)
		bytes[#bytes + 1] = v % 256
	end
	return bytes
end

local function parse_ip(s)
	if not s then return nil end
	local b = ip4(s)
	if b then return b, 4 end
	b = ip6(s)
	if b then return b, 6 end
	return nil
end

local function fmt(bytes)
	if #bytes == 4 then return table.concat(bytes, ".") end
	local g = {}
	for i = 1, 16, 2 do g[#g + 1] = string.format("%x", bytes[i] * 256 + bytes[i + 1]) end
	local bs, bl, cs, cl = 0, 0, 0, 0
	for i = 1, 8 do
		if g[i] == "0" then
			if cl == 0 then cs = i end
			cl = cl + 1
			if cl > bl then bs, bl = cs, cl end
		else
			cl = 0
		end
	end
	if bl < 2 then return table.concat(g, ":") end
	return table.concat(g, ":", 1, bs - 1) .. "::" .. table.concat(g, ":", bs + bl, 8)
end

local function masked(bytes, len, fill)
	local r = {}
	for i = 1, #bytes do
		local bits = len - (i - 1) * 8
		if bits >= 8 then
			r[i] = bytes[i]
		elseif bits <= 0 then
			r[i] = fill and 255 or 0
		else
			local div = 2 ^ (8 - bits)
			local base = math.floor(bytes[i] / div) * div
			r[i] = fill and (base + div - 1) or base
		end
	end
	return r
end

local function parse_cidr(s)
	s = trim(s)
	local addr, len = s:match("^([^/]+)/(%d+)$")
	addr = addr or s
	local b, fam = parse_ip(addr)
	if not b then return nil end
	local max = (fam == 4) and 32 or 128
	len = tonumber(len) or max
	if len < 1 or len > max then return nil end
	local net = masked(b, len, false)
	return {
		fam = fam,
		len = len,
		net = net,
		first = fmt(net),
		last = fmt(masked(b, len, true)),
		text = (len == max) and fmt(net) or (fmt(net) .. "/" .. len),
		hostbits = fmt(net) ~= fmt(b),
	}
end

local function in_prefix(b, p)
	if #b ~= #p.net then return false end
	local m = masked(b, p.len, false)
	for i = 1, #m do if m[i] ~= p.net[i] then return false end end
	return true
end

local function covered(b, prefixes)
	for _, p in ipairs(prefixes) do
		if in_prefix(b, p) then return p end
	end
	return nil
end

local RESERVED = {}
for _, s in ipairs({ "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
	"2001:db8::/32", "2001::/32", "2002::/16" }) do
	RESERVED[#RESERVED + 1] = parse_cidr(s)
end
local GLOBAL6 = parse_cidr("2000::/3")

local function public(b)
	if covered(b, RESERVED) then return false end
	if #b == 16 and not in_prefix(b, GLOBAL6) then return false end
	return true
end

---------------------------------------------------------------- 目标

local function read_static()
	local out = {}
	local s = readfile(ETC .. "/static.list") or ""
	for line in s:gmatch("[^\n]+") do
		local l = trim(line)
		if l ~= "" and l:sub(1, 1) ~= "#" then
			local entry = l:match("^(%S+)")
			local note = l:match("#%s*(.-)%s*$")
			out[#out + 1] = { text = entry, note = note }
		end
	end
	return out
end

local AUTO_FILE = ETC .. "/auto.json"
local function load_auto()
	local a = readjson(AUTO_FILE) or {}
	a.prefixes = type(a.prefixes) == "table" and a.prefixes or {}
	a.domains = type(a.domains) == "table" and a.domains or {}
	a.sources = type(a.sources) == "table" and a.sources or {}
	return a
end

local function sorted_keys(t)
	local k = {}
	for x in pairs(t) do k[#k + 1] = x end
	table.sort(k)
	return k
end

-- 返回：全部有效段、IPv4 文本表、IPv6 文本表、无效项、明细
local function targets(c)
	local all, l4, l6, invalid, detail, seen = {}, {}, {}, {}, {}, {}
	local function add(text, source, note)
		local p = parse_cidr(text)
		if not p then
			invalid[#invalid + 1] = { text = text, source = source, error = "格式不对，已跳过" }
			return
		end
		if seen[p.text] then return end
		seen[p.text] = true
		p.source = source
		all[#all + 1] = p
		if p.fam == 4 then l4[#l4 + 1] = p.text else l6[#l6 + 1] = p.text end
		detail[#detail + 1] = { prefix = p.text, source = source, note = note,
			warn = p.hostbits and ("原文 " .. text .. " 含主机位，已按 " .. p.text .. " 处理") or nil }
	end
	for _, e in ipairs(read_static()) do add(e.text, "static", e.note) end
	for _, e in ipairs(c.extra) do add(e, "extra") end
	local auto = load_auto().prefixes
	for _, k in ipairs(sorted_keys(auto)) do
		local e = auto[k]
		add(k, "auto", (e.note and (e.note .. "；") or "") .. "来源 " .. table.concat(e.src or {}, "、"))
	end
	if #all == 0 then
		for _, d in ipairs(DEFAULT_PREFIXES) do add(d, "builtin", "静态列表为空或全部无效，使用内置段") end
	end
	return all, l4, l6, invalid, detail
end

-- 域名检查：只收合法的主机名；共享 CDN、遥测之类第三方主机单独标出来
local SHARED_SUFFIX = { "b-cdn.net", "cloudfront.net", "akamaized.net", "akamaiedge.net", "akamai.net", "fastly.net",
	"fastlylb.net", "azureedge.net", "azurefd.net", "googleapis.com", "googleusercontent.com", "gstatic.com",
	"amazonaws.com", "cloudflare.net", "cloudflare.com", "workers.dev", "pages.dev", "vercel.app", "netlify.app",
	"github.io", "githubusercontent.com", "herokuapp.com", "appspot.com", "sentry.io", "datadoghq.com",
	"usefathom.com", "statuspage.io", "intercom.io", "segment.io", "segment.com", "stripe.com", "jsdelivr.net" }

local function valid_domain(d)
	if type(d) ~= "string" or #d < 4 or #d > 253 then return false end
	if d:find("[^a-z0-9%.%-]") or d:find("..", 1, true) or d:sub(1, 1) == "." or d:sub(-1) == "." then return false end
	local n = 0
	for label in d:gmatch("[^%.]+") do
		if #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" then return false end
		n = n + 1
	end
	return n >= 2 and d:match("%.([a-z][a-z0-9%-]+)$") ~= nil
end

local function under(d, suffix)
	return d == suffix or d:sub(-(#suffix + 1)) == "." .. suffix
end

local function is_shared_host(d)
	for _, s in ipairs(SHARED_SUFFIX) do if under(d, s) then return true end end
	return false
end

local function labels(d)
	local n = 0
	for _ in d:gmatch("[^%.]+") do n = n + 1 end
	return n
end

local function exempts(c)
	local all, e4, e6, invalid = {}, {}, {}, {}
	for _, s in ipairs(c.exempt) do
		local p = parse_cidr(s)
		if p then
			all[#all + 1] = p
			if p.fam == 4 then e4[#e4 + 1] = p.text else e6[#e6 + 1] = p.text end
		else
			invalid[#invalid + 1] = s
		end
	end
	return all, e4, e6, invalid
end

local function load_disc(c)
	local d = readjson(ETC .. "/discovered.json") or {}
	local now, live = os.time(), {}
	for ip, e in pairs(d) do
		if type(e) == "table" and tonumber(e.last) and now - tonumber(e.last) < c.dyn_ttl and parse_ip(ip) then
			live[ip] = e
		end
	end
	return live
end

---------------------------------------------------------------- nft 规则

local function nft_elems(t)
	if #t == 0 then return "" end
	return " elements = { " .. table.concat(t, ", ") .. " }"
end

local function gen(c, l4, l6, d4, d6, e4, e6)
	local L = {}
	local function a(s) L[#L + 1] = s end
	a("table inet " .. TABLE)
	a("delete table inet " .. TABLE)
	a("table inet " .. TABLE .. " {")
	for _, n in ipairs({ "fwd4", "fwd6", "out4", "out6", "audit4", "audit6", "canary" }) do
		a("\tcounter " .. n .. " { }")
	end
	a("\tset dst4 { type ipv4_addr; flags interval; auto-merge;" .. nft_elems(l4) .. " }")
	a("\tset dst6 { type ipv6_addr; flags interval; auto-merge;" .. nft_elems(l6) .. " }")
	a("\tset dyn4 { type ipv4_addr; flags timeout;" .. nft_elems(d4) .. " }")
	a("\tset dyn6 { type ipv6_addr; flags timeout;" .. nft_elems(d6) .. " }")
	a("\tset ex4 { type ipv4_addr; flags interval; auto-merge;" .. nft_elems(e4) .. " }")
	a("\tset ex6 { type ipv6_addr; flags interval; auto-merge;" .. nft_elems(e6) .. " }")
	a("\tset canary4 { type ipv4_addr; elements = { " .. CANARY4 .. " } }")
	a("\tset canary6 { type ipv6_addr; elements = { " .. CANARY6 .. " } }")
	local function blk(name, prefix)
		a("\tchain " .. name .. " {")
		if c.log then
			a("\t\tlimit rate 10/minute burst 20 packets log prefix \"" .. prefix .. "\" level warn")
		end
		if c.action == "reject" then
			a("\t\tmeta l4proto tcp reject with tcp reset")
			a("\t\treject with icmpx admin-prohibited")
		end
		a("\t\tdrop")
		a("\t}")
	end
	blk("block_fwd", "claude-guard FWD ")
	blk("block_out", "claude-guard OUT ")
	-- 自检探测单独一条链：同样拒绝，但不写日志，免得每分钟一条把真正的拦截记录挤掉
	a("\tchain block_canary {")
	a("\t\tmeta l4proto tcp reject with tcp reset")
	a("\t\treject with icmpx admin-prohibited")
	a("\t}")
	a("\tchain block_audit {")
	a("\t\tlimit rate 10/minute burst 20 packets log prefix \"claude-guard AUDIT \" level crit")
	a("\t\tdrop")
	a("\t}")
	-- 局域网设备经路由器转发：PassWall 代理的连接被 TPROXY 到本机，不经过这里；能到这里的只有直连
	a("\tchain guard_forward {")
	a("\t\ttype filter hook forward priority filter - 20; policy accept;")
	a("\t\tip saddr @ex4 return")
	a("\t\tip6 saddr @ex6 return")
	a("\t\tip daddr @dst4 counter name \"fwd4\" jump block_fwd")
	a("\t\tip daddr @dyn4 counter name \"fwd4\" jump block_fwd")
	a("\t\tip6 daddr @dst6 counter name \"fwd6\" jump block_fwd")
	a("\t\tip6 daddr @dyn6 counter name \"fwd6\" jump block_fwd")
	a("\t}")
	-- 路由器本机发出：output 钩子看到的是改道前的出接口，所以按 PassWall 的标记放行要进代理的包；
	-- 这些包是否真的改道进了本机代理，由下面的出网审计（postrouting，看实际出接口）复核
	a("\tchain guard_output {")
	-- 放在地址转换（PassWall 的 nat_output 在 filter - 1）之后：被 REDIRECT 到本机代理的包这里目的地址已经改了
	a("\t\ttype filter hook output priority filter + 10; policy accept;")
	a("\t\toifname \"lo\" return")
	a("\t\tmeta mark " .. string.format("0x%08x", c.pw_mark) .. " return")
	a("\t\tip daddr @canary4 counter name \"canary\" jump block_canary")
	a("\t\tip6 daddr @canary6 counter name \"canary\" jump block_canary")
	a("\t\tip daddr @dst4 counter name \"out4\" jump block_out")
	a("\t\tip daddr @dyn4 counter name \"out4\" jump block_out")
	a("\t\tip6 daddr @dst6 counter name \"out6\" jump block_out")
	a("\t\tip6 daddr @dyn6 counter name \"out6\" jump block_out")
	a("\t}")
	-- 审计：任何还要从网口发出去的 Claude 包都在这里丢掉并计数；正常应永远是 0
	a("\tchain guard_audit {")
	a("\t\ttype filter hook postrouting priority filter; policy accept;")
	a("\t\toifname \"lo\" return")
	a("\t\tip saddr @ex4 return")
	a("\t\tip6 saddr @ex6 return")
	a("\t\tip daddr @dst4 counter name \"audit4\" jump block_audit")
	a("\t\tip daddr @dyn4 counter name \"audit4\" jump block_audit")
	a("\t\tip6 daddr @dst6 counter name \"audit6\" jump block_audit")
	a("\t\tip6 daddr @dyn6 counter name \"audit6\" jump block_audit")
	a("\t}")
	a("}")
	return table.concat(L, "\n") .. "\n"
end

-- 主规则加载失败时的最小规则：只有静态段，直接丢弃
local function gen_min(l4, l6)
	if #l4 == 0 then l4 = { DEFAULT_PREFIXES[1] } end
	if #l6 == 0 then l6 = { DEFAULT_PREFIXES[2] } end
	return table.concat({
		"table inet " .. TABLE,
		"delete table inet " .. TABLE,
		"table inet " .. TABLE .. " {",
		"\tset dst4 { type ipv4_addr; flags interval; auto-merge; elements = { " .. table.concat(l4, ", ") .. " } }",
		"\tset dst6 { type ipv6_addr; flags interval; auto-merge; elements = { " .. table.concat(l6, ", ") .. " } }",
		"\tchain guard_forward { type filter hook forward priority filter - 20; policy accept; ip daddr @dst4 drop; ip6 daddr @dst6 drop; }",
		"\tchain guard_audit { type filter hook postrouting priority filter; policy accept; oifname \"lo\" return; ip daddr @dst4 drop; ip6 daddr @dst6 drop; }",
		"}",
	}, "\n") .. "\n"
end

local function table_exists()
	local _, rc = run("nft list table inet " .. TABLE .. " >/dev/null")
	return rc == 0
end

local function fingerprint()
	local out, rc = run("T=$(mktemp); if nft -s -t list table inet " .. TABLE .. " > $T && " ..
		"for s in dst4 dst6 ex4 ex6 canary4 canary6; do nft -s list set inet " .. TABLE .. " $s >> $T || exit 1; done; " ..
		"then sha256sum < $T; else rm -f $T; exit 1; fi; rm -f $T")
	if rc ~= 0 then return nil end
	return out:match("^(%x+)")
end

local function counters()
	local out, rc = run("nft -j list counters table inet " .. TABLE)
	if rc ~= 0 then return nil end
	local j = jsonc.parse(out)
	local r = {}
	for _, o in ipairs(j and j.nftables or {}) do
		if o.counter and o.counter.table == TABLE then
			r[o.counter.name] = { packets = o.counter.packets or 0, bytes = o.counter.bytes or 0 }
		end
	end
	return r
end

-- 规则重载会把计数清零，所以重载前把当前值累加进 counters_base
local function accumulate()
	local cur = counters()
	if not cur then return end
	local base = readjson(RUN .. "/counters_base.json") or {}
	for k, v in pairs(cur) do
		base[k] = base[k] or { packets = 0, bytes = 0 }
		base[k].packets = base[k].packets + v.packets
		base[k].bytes = base[k].bytes + v.bytes
	end
	writejson(RUN .. "/counters_base.json", base)
end

-- 清零：内核计数和累计值都归零，记下清零时间；规则本身不动
local function reset_counters()
	local out, rc = run("nft reset counters table inet " .. TABLE .. " >/dev/null")
	if rc ~= 0 then return { ok = false, error = "清零失败：" .. trim(out):sub(1, 200) } end
	writejson(RUN .. "/counters_base.json", {})
	writefile(RUN .. "/audit_ack", "0")
	local now = os.time()
	writefile(RUN .. "/counters_since", tostring(now))
	event("拦截计数已清零")
	return { ok = true, since = now }
end

local function counter_totals()
	local cur = counters() or {}
	local base = readjson(RUN .. "/counters_base.json") or {}
	local r = {}
	for _, k in ipairs({ "fwd4", "fwd6", "out4", "out6", "audit4", "audit6", "canary" }) do
		local a, b = cur[k] or {}, base[k] or {}
		r[k] = { packets = (a.packets or 0) + (b.packets or 0), bytes = (a.bytes or 0) + (b.bytes or 0) }
	end
	return r, cur
end

local function chain_hooks()
	local out, rc = run("nft -j list table inet " .. TABLE)
	local r = {}
	if rc ~= 0 then return r end
	local j = jsonc.parse(out)
	for _, o in ipairs(j and j.nftables or {}) do
		local ch = o.chain
		if ch and ch.table == TABLE and ch.hook then
			r[ch.name] = ch.hook .. ":" .. tostring(ch.prio) .. ":" .. tostring(ch.policy)
		end
	end
	return r
end

local EXPECTED_HOOKS = { guard_forward = "forward:-20:accept", guard_output = "output:10:accept", guard_audit = "postrouting:0:accept" }

local function set_has(p)
	local set = (p.fam == 4) and "dst4" or "dst6"
	local _, rc = run("nft get element inet " .. TABLE .. " " .. set .. " { " .. p.first .. ", " .. p.last .. " } >/dev/null")
	return rc == 0
end

---------------------------------------------------------------- 直连连接（conntrack）

-- 路由器自己的全部地址（判断“路由器本机直连”用）
local function router_addrs()
	local r = {}
	for a in run("ip -o addr show"):gmatch("inet6? (%S+)/") do
		local b = parse_ip(a)
		if b then r[fmt(b)] = true end
	end
	return r
end

-- 找出“真的绕开代理、要从网口直接出去”的 Claude 连接。只看 PassWall 的标记不够：
-- TCP 用 REDIRECT 方式时连接被转到路由器本机端口，不打标记。按连接的回程判断：
--   回程来源不是原目的地址      → 被转到本机代理（REDIRECT），算走了代理
--   带 PassWall 标记            → TPROXY，算走了代理
--   否则回程目的被改成别的地址  → 做了地址转换、从宽带口出去，算直连
--   否则来源是路由器自己的地址  → 路由器本机直连
--   其余：装了 PassWall 时，转发的连接既没被转到本机、也没有标记，只可能是直连（没有地址转换的 IPv6、旁路由）；
--         没装 PassWall（用的是别的代理）时判断不了，不算直连
local function scan(c, prefixes, dyn, ex)
	local res = {}
	local f = io.open("/proc/net/nf_conntrack", "r")
	if not f then return nil, "无法读取 /proc/net/nf_conntrack" end
	local mine = router_addrs()
	local pw_known = nfs.access("/etc/init.d/passwall") and true or false
	for line in f:lines() do
		local s1, d1, s2, d2 = line:match(" src=(%S+) dst=(%S+) .- src=(%S+) dst=(%S+)")
		local b = parse_ip(d1)
		if b then
			local key = fmt(b)
			if covered(b, prefixes) or dyn[key] then
				local mark = tonumber(line:match(" mark=(%d+)") or "0") or 0
				local sb, rsb, rdb = parse_ip(s1), parse_ip(s2), parse_ip(d2)
				local redirected = rsb and fmt(rsb) ~= key
				local proxied = redirected or mark == c.pw_mark
				local nat = rdb and sb and fmt(rdb) ~= fmt(sb)
				local own = sb and mine[fmt(sb)]
				if not proxied and (nat or own or pw_known) and not (sb and covered(sb, ex)) then
					res[#res + 1] = {
						family = line:match("^(%S+)"),
						proto = line:match("^%S+%s+%d+%s+(%S+)"),
						src = sb and fmt(sb) or s1,
						dst = key,
						sport = line:match(" sport=(%d+)"),
						dport = line:match(" dport=(%d+)"),
						state = line:match("^%S+%s+%d+%s+%S+%s+%d+%s+%d+%s+(%u[%u_]*)%s"),
						mark = mark,
						via = own and "router" or (nat and "nat" or "forward"),
					}
				end
			end
		end
	end
	f:close()
	return res
end

local function flush_leaks(leaks)
	if #leaks == 0 then return 0 end
	local _, has = run("command -v conntrack >/dev/null")
	if has ~= 0 then return nil, "未安装 conntrack，无法清理" end
	local n = 0
	for _, l in ipairs(leaks) do
		local cmd = "conntrack -D -f " .. (l.family == "ipv6" and "ipv6" or "ipv4") ..
			" -s " .. q(l.src) .. " -d " .. q(l.dst) .. " -p " .. q(l.proto)
		if l.sport and l.dport and (l.proto == "tcp" or l.proto == "udp") then
			cmd = cmd .. " --sport " .. l.sport .. " --dport " .. l.dport
		end
		local _, rc = run(cmd .. " >/dev/null")
		if rc == 0 then n = n + 1 end
	end
	return n
end

local function leak_text(l)
	return string.format("%s %s:%s → %s:%s %s", l.proto or "?", l.src or "?", l.sport or "-",
		l.dst or "?", l.dport or "-", l.state or "")
end

---------------------------------------------------------------- 加载

-- force：规则曾被删除或改动（中间可能放过了直连），加载后把现有的直连连接全清一遍
local function apply(c, force)
	if not c.enabled then
		accumulate()
		run("nft delete table inet " .. TABLE)
		os.remove(RUN .. "/fingerprint")
		os.remove(RUN .. "/applied.json")
		return { ok = true, enabled = false, message = "保护已停用，未加载规则" }
	end
	local had_table = table_exists()
	local all, l4, l6, invalid = targets(c)
	local exall, e4, e6, exbad = exempts(c)
	local disc = load_disc(c)
	local now = os.time()
	local d4, d6, ndyn = {}, {}, 0
	for ip, e in pairs(disc) do
		local b, fam = parse_ip(ip)
		if b and not covered(b, all) then
			local left = math.floor(c.dyn_ttl - (now - tonumber(e.last)))
			if left > 60 then
				local s = fmt(b) .. " timeout " .. left .. "s"
				if fam == 4 then d4[#d4 + 1] = s else d6[#d6 + 1] = s end
				ndyn = ndyn + 1
			end
		end
	end
	local text = gen(c, l4, l6, d4, d6, e4, e6)
	writefile(RUN .. "/ruleset.nft", text)
	accumulate()
	if not nfs.access(RUN .. "/counters_since") then writefile(RUN .. "/counters_since", tostring(os.time())) end
	local res = { ok = true, invalid = invalid, exempt_invalid = exbad }
	local out, rc = run("nft -c -f " .. RUN .. "/ruleset.nft && nft -f " .. RUN .. "/ruleset.nft")
	if rc ~= 0 then
		event("主规则加载失败：" .. trim(out):sub(1, 300) .. "；改用最小规则", "crit")
		writefile(RUN .. "/ruleset-min.nft", gen_min(l4, l6))
		local out2, rc2 = run("nft -f " .. RUN .. "/ruleset-min.nft")
		res.ok = false
		res.fallback = (rc2 == 0)
		res.error = "主规则加载失败：" .. trim(out):sub(1, 300)
		if rc2 ~= 0 then
			event("最小规则也加载失败：" .. trim(out2):sub(1, 300) .. "；Claude 目前没有保护", "crit")
			res.error = res.error .. "；最小规则也失败"
		end
		os.remove(RUN .. "/fingerprint")
		return res
	end
	local fp = fingerprint()
	if fp then writefile(RUN .. "/fingerprint", fp .. "\n") end
	-- 清理已经建立的直连（流量卸载会让它们绕过 forward）。只在拦截范围刚变大时做一次：
	-- 规则是新装上的、加了新网段或地址、取消了某台设备的豁免、或规则曾被删改。
	-- 平时规则一直在，新的直连建立不起来，不需要也不应该反复清理（1.1.0 定时清理曾误掐代理连接）。
	local prev = (had_table and not force) and readjson(RUN .. "/applied.json") or nil
	local cur = { targets = {}, exempt = {} }
	for _, p in ipairs(all) do cur.targets[p.text] = 1 end
	for ip in pairs(disc) do cur.targets[ip] = 1 end
	for _, p in ipairs(exall) do cur.exempt[p.text] = 1 end
	local grew, only_new = (prev == nil), nil
	if prev then
		only_new = {}
		for k in pairs(cur.targets) do
			if not (prev.targets or {})[k] then
				grew = true
				only_new[#only_new + 1] = parse_cidr(k)
			end
		end
		for k in pairs(prev.exempt or {}) do
			if not cur.exempt[k] then grew = true; only_new = nil; break end
		end
	end
	writejson(RUN .. "/applied.json", cur)
	if grew then
		local leaks = {}
		for _, l in ipairs(scan(c, all, disc, exall) or {}) do
			local b = parse_ip(l.dst)
			if not only_new or (b and covered(b, only_new)) then leaks[#leaks + 1] = l end
		end
		if #leaks > 0 then
			local texts = {}
			for i, l in ipairs(leaks) do if i <= 10 then texts[#texts + 1] = leak_text(l) end end
			local n, err = flush_leaks(leaks)
			event("规则加载后清理 " .. #leaks .. " 条已有的直连连接（" ..
				(prev == nil and (force and "规则曾被删改" or "规则新装上") or (only_new and "新增了目标" or "取消了豁免")) ..
				"），" .. (n and ("清掉 " .. n .. " 条") or err) .. "：" .. table.concat(texts, "；"), "crit")
			res.flushed = n
		end
	end
	res.static = #all
	res.dynamic = ndyn
	res.exempt = #exall
	event(string.format("规则已加载：静态 %d 段，动态 %d 个，豁免 %d 个，方式 %s", #all, ndyn, #exall,
		c.action == "reject" and "拒绝" or "丢弃"))
	return res
end

---------------------------------------------------------------- 有没有代理插件

-- PassWall 的防火墙表在不在（在 = 它正在运行）
local function pw_table()
	local _, rc = run("nft list table inet passwall >/dev/null")
	return rc == 0
end

-- 装没装 PassWall：启动脚本和主程序都在才算。只看启动脚本不行——用 apk 卸载 PassWall 时，
-- 被改过的启动脚本会留在路由器上。
local function pw_installed()
	return (nfs.access("/etc/init.d/passwall") and nfs.access("/usr/share/passwall/app.sh")) and true or false
end

-- 路由器有没有默认路由（没有 = 宽带还没起来，这时去下载东西只会失败）
local function net_ready()
	return trim((run("ip -4 route show default 2>/dev/null"))) ~= ""
end

local function uptime()
	return tonumber((readfile("/proc/uptime") or ""):match("^(%d+)")) or 0
end

---------------------------------------------------------------- 自检、出口

local function probe(fam, addr, gid)
	io.stdout:flush()
	local pid = nixio.fork()
	if pid == 0 then
		nixio.setgid(gid)
		local s = nixio.socket(fam == 6 and "inet6" or "inet", "stream")
		if not s then os.exit(20) end
		s:setopt("socket", "sndtimeo", 3)
		local ok, code = s:connect(addr, 443)
		if ok then os.exit(0) end
		if code == 111 then os.exit(11)
		elseif code == 101 then os.exit(12)
		elseif code == 113 then os.exit(13)
		elseif code == 1 or code == 13 then os.exit(15)
		else os.exit(14) end
	end
	if not pid then return 99 end
	local _, _, st = nixio.waitpid(pid)
	return st
end

local function canary(c)
	local res = { time = os.time() }
	for _, t in ipairs({ { 4, CANARY4 }, { 6, CANARY6 } }) do
		local b = (counters() or {}).canary
		local before = b and b.packets or -1
		local code = probe(t[1], t[2], c.bypass_gid)
		local a = (counters() or {}).canary
		local after = a and a.packets or -1
		local r = { code = code }
		if before >= 0 and after > before then
			r.ok = true
r.detail = "模拟直连的探测包被拦下"
		elseif code == 12 then
			r.skip = true
			r.detail = "路由器没有可用的 IPv" .. t[1] .. " 默认路由，跳过"
		elseif before < 0 then
			r.ok = false
			r.detail = "拦截表不存在或没有自检计数"
		else
			r.ok = false
			r.detail = "探测包没有被拦下（结果码 " .. tostring(code) .. "）"
		end
		res["v" .. t[1]] = r
	end
	writejson(RUN .. "/canary.json", res)
	return res
end

local function wan_ips()
	local r = {}
	for _, ifc in ipairs({ "wan", "wan_6", "wan6" }) do
		local out, rc = run("ubus call network.interface." .. ifc .. " status")
		if rc == 0 then
			local j = jsonc.parse(out) or {}
			for _, a in ipairs(j["ipv4-address"] or {}) do r[#r + 1] = a.address end
			for _, a in ipairs(j["ipv6-address"] or {}) do r[#r + 1] = a.address end
		end
	end
	return r
end

local function trace(c)
	local res = { time = os.time() }
	-- 代理没在运行时不探测：这时从路由器访问 Claude 只会被本插件自己拦下，白白多一条拦截记录
	if not pw_table() then
		res.ok = false
		res.skip = true
		res.error = pw_installed() and "PassWall 没在运行，没有检测" or "没有安装代理插件，不检测出口"
		writejson(RUN .. "/trace.json", res)
		writefile(RUN .. "/ts_trace", tostring(res.time))
		return res
	end
	local out, rc = run("curl -s -4 --connect-timeout 5 -m 10 https://claude.ai/cdn-cgi/trace")
	if rc == 0 and out:match("ip=") then
		res.ok = true
		res.ip = out:match("ip=([%x%.:]+)")
		res.loc = out:match("loc=(%u%u)")
		res.colo = out:match("colo=(%u+)")
		for _, w in ipairs(wan_ips()) do
			if w == res.ip then res.alarm = "Claude 看到的是本地宽带地址" end
		end
		if not res.alarm and res.loc == "CN" then res.alarm = "Claude 看到的出口在中国大陆" end
	else
		res.ok = false
		if rc == 7 then
			res.error = "连不上（代理不可用时，这是保护在拦截）"
		elseif rc == 28 then
			res.error = "超时"
		elseif rc == 6 then
			res.error = "域名解析失败"
		else
			res.error = "连接失败（curl 退出码 " .. rc .. "）"
		end
	end
	if res.alarm then event("出口告警：" .. res.alarm .. "（" .. tostring(res.ip) .. "）", "crit") end
	writejson(RUN .. "/trace.json", res)
	writefile(RUN .. "/ts_trace", tostring(res.time))
	return res
end

---------------------------------------------------------------- PassWall



local function pw_procs()
	local names = {}
	for pid in nfs.dir("/proc") do
		if pid:match("^%d+$") then
			local cmd = readfile("/proc/" .. pid .. "/cmdline")
			if cmd and cmd:find("/tmp/etc/passwall/", 1, true) then
				local exe = cmd:match("^([^%z]+)")
				names[#names + 1] = exe and exe:match("([^/]+)$") or "?"
			end
		end
	end
	return names
end

local function pw_global(u)
	local g
	u:foreach("passwall", "global", function(s) if not g then g = s end end)
	return g
end

local function pw_name(u, id)
	if not id or id == "" then return nil end
	if id == "_direct" then return "直连" end
	if id == "_blackhole" then return "屏蔽" end
	if id == "_default" then return "默认节点" end
	return u:get("passwall", id, "remarks") or id
end

-- 正在运行的 PassWall Xray 配置里，Claude 规则指向哪个出口（没有就返回 nil）
local PW_RUNNING = "/tmp/etc/passwall/acl/default/global.json"
local function rule_list(cfgj)
	local r = {}
	for _, x in ipairs(((cfgj or {}).routing or {}).rules or {}) do
		local inb = type(x.inboundTag) == "table" and table.concat(x.inboundTag, ",") or tostring(x.inboundTag or "")
		r[#r + 1] = { tag = x.ruleTag or "", out = x.outboundTag or "", inb = inb }
	end
	return r
end

local function claude_out(rules)
	for _, x in ipairs(rules) do
		if x.tag:sub(1, #PW_REMARKS) == PW_REMARKS then return x.out end
	end
	return nil
end

local function out_name(tag)
	return tag and (tag:match("^[^:]+:(.+)$") or tag) or nil
end

-- 兜底规则（默认节点）的出口：PassWall 把它放在规则表最后一条
local function default_out(rules)
	local last = rules[#rules]
	return last and last.out or nil
end

-- 返回：Claude 规则指向的节点名、有没有运行中的配置、Claude 规则的出口标签、默认出口标签
local function pw_running_claude()
	local j = readjson(PW_RUNNING)
	if not j then return nil, false end
	local rules = rule_list(j)
	local o = claude_out(rules)
	return out_name(o), true, o, default_out(rules)
end

-- 用 PassWall 自己的生成器（no_run：只生成，不启动任何进程、不写运行目录）生成全局 Xray 配置，
-- 再用 xray run -test 校验。只读，不影响正在运行的 PassWall。
local function pw_gen()
	local u = uci.cursor()
	local g = pw_global(u) or {}
	local function first(stype, opt, d)
		local v
		u:foreach("passwall", stype, function(s) if v == nil then v = s[opt] end end)
		if v == nil or v == "" then return d end
		return v
	end
	local mode = g.v2ray_dns_mode or "tcp"
	local var = {
		flag = "global", node = g.node, redir_port = "1041",
		tcp_proxy_way = first("global_forwarding", "tcp_proxy_way", "redirect"),
		run_in_global = "1", no_run = "1", loglevel = g.loglevel or "warning",
		dns_listen_port = "15353", direct_dns_udp_server = "223.5.5.5", direct_dns_port = "53",
		direct_dns_query_strategy = "UseIP", chn_list = g.chn_list or "direct",
		use_proxy_list = "1", use_gfw_list = "1",
	}
	if mode == "doh" then
		var.remote_dns_doh = g.remote_dns_doh or "https://1.1.1.1/dns-query"
	elseif mode == "udp" then
		var.remote_dns_udp_server = g.remote_dns or "1.1.1.1"; var.remote_dns_udp_port = "53"
	else
		var.remote_dns_tcp_server = g.remote_dns or "1.1.1.1"; var.remote_dns_tcp_port = "53"
	end
	local f = RUN .. "/pw-test.json"
	os.remove(f)
	local gout = run("lua /usr/lib/lua/luci/passwall/util_xray.lua gen_config " .. q(jsonc.stringify(var)) .. " > " .. f)
	local cfgj = readjson(f)
	if not cfgj then
		return { ok = false, error = "PassWall 生成器没有输出配置：" .. trim(gout):sub(1, 300) }
	end
	local xray = first("global_app", "xray_file", "/usr/bin/xray")
	local tout, trc = run("XRAY_LOCATION_ASSET=/usr/share/v2ray/ V2RAY_LOCATION_ASSET=/usr/share/v2ray/ " ..
		q(xray) .. " run -test -c " .. f)
	local rules = rule_list(cfgj)
	return { ok = (trc == 0), test = trim(tout):sub(-300), rules = rules, claude_out = claude_out(rules), file = f }
end

-- 属于 Claude 规则的条目：显示名开头的分流规则、指向 ClaudeGuard 出站的规则、Claude 域名的 DNS 入站规则
local function is_claude_rule(r)
	return r.tag:sub(1, #PW_REMARKS) == PW_REMARKS or r.out:sub(1, #PW_RULE + 1) == PW_RULE .. ":" or
		r.inb == "dns-in-" .. PW_RULE
end

-- 比较两组规则（按顺序）；skip=true 时忽略 Claude 规则
local function same_rules(a, b, skip)
	local x, y = {}, {}
	for _, r in ipairs(a) do if not (skip and is_claude_rule(r)) then x[#x + 1] = r.tag .. "|" .. r.out .. "|" .. r.inb end end
	for _, r in ipairs(b) do if not (skip and is_claude_rule(r)) then y[#y + 1] = r.tag .. "|" .. r.out .. "|" .. r.inb end end
	return table.concat(x, "\n") == table.concat(y, "\n")
end

local function pw_test()
	local res = pw_gen()
	local running = readjson(PW_RUNNING)
	if running and res.rules then
		res.matches_running = same_rules(res.rules, rule_list(running))
	end
	res.claude_out_name = out_name(res.claude_out)
	return res
end

local function pw_info()
	local u = uci.cursor()
	local i = { installed = pw_installed() }
	if not i.installed then return i end
	local g = pw_global(u)
	i.enabled = (g and g.enabled == "1") and true or false
	i.table = pw_table()
	i.procs = pw_procs()
	i.running = i.table and #i.procs > 0
	local node = g and g.node
	i.global_node = node
	i.global_node_name = pw_name(u, node)
	i.rule_present = (u:get("passwall", PW_RULE) == "shunt_rules")
	if node and u:get("passwall", node, "protocol") == "_shunt" then
		i.shunt = true
		i.default_node = u:get("passwall", node, "default_node")
		i.default_node_name = pw_name(u, i.default_node)
		i.claude_node = u:get("passwall", node, PW_RULE)
		-- follow：规则在，分流节点里选的是「默认」——Claude 跟随默认节点，但地址仍被 PassWall 按 IP 强制走代理
		i.follow = (i.rule_present and i.claude_node == "_default") and true or false
		if i.rule_present and i.claude_node and i.claude_node ~= "" and i.claude_node ~= "_default" then
			i.pinned = true
			i.effective_id = i.claude_node
		else
			i.pinned = false
			i.effective_id = i.default_node
		end
	else
		i.shunt = false
		i.pinned = false
		i.effective_id = node
	end
	i.effective_name = pw_name(u, i.effective_id)
	-- 配置和正在运行的是否一致：写进配置的出口要等 PassWall 下次重启才生效
	local rname, have, rout, rdef = pw_running_claude()
	i.running_claude_name = rname
	if have and i.running then
		if i.pinned then
			i.pending = (rname ~= i.effective_name)
		elseif i.follow then
			-- 跟随默认节点：运行中的配置里要有 Claude 规则，而且和兜底规则指向同一个出口
			i.pending = not (rout ~= nil and rout == rdef)
		else
			i.pending = (rname ~= nil)
		end
		if i.pending then
			if i.pinned then
				i.pending_note = "已写入「" .. tostring(i.effective_name) .. "」，PassWall 下次重启后生效；现在 Claude 仍按" ..
					(rname and ("「" .. rname .. "」") or ("默认节点「" .. tostring(i.default_node_name) .. "」")) .. "走"
			elseif i.follow then
				i.pending_note = rname and
					("已改为跟随默认节点，PassWall 下次重启后生效；现在仍按「" .. tostring(rname) .. "」走") or
					"已在 PassWall 里加上 Claude 规则（跟随默认节点），PassWall 下次重启后生效"
			else
				i.pending_note = "已删除 Claude 规则，PassWall 下次重启后生效；现在仍按「" .. tostring(rname) .. "」走"
			end
		end
	end
	if i.effective_id == "_direct" then
		i.alarm = "PassWall 把 Claude 设成了直连：这类连接会被本插件拦下，Claude 将无法使用"
	end
	local nodes = {}
	u:foreach("passwall", "nodes", function(s)
		local p = s.protocol or ""
		if s.remarks and p:sub(1, 1) ~= "_" then
			nodes[#nodes + 1] = { id = s[".name"], name = s.remarks, type = s.type }
		end
	end)
	i.nodes = nodes
	return i
end

-- 本地 geosite.dat 里的 Claude 类别（PassWall 每周自动更新这个文件）
local GEOVIEW, GEOSITE = "/usr/bin/geoview", "/usr/share/v2ray/geosite.dat"
local function geosite_list(c)
	if not nfs.access(GEOVIEW) then return nil, "路由器上没有 geoview" end
	if not nfs.access(GEOSITE) then return nil, "路由器上没有 geosite.dat" end
	local out, rc = run(GEOVIEW .. " -type geosite -input " .. GEOSITE .. " -list " .. q(c.geosite_category) .. " -lowmem")
	if rc ~= 0 then return nil, "geoview 出错：" .. trim(out):sub(1, 200) end
	local r = {}
	for l in out:gmatch("[^\n]+") do
		l = trim(l):lower()
		if valid_domain(l) then r[#r + 1] = l end
	end
	if #r == 0 then return nil, "geosite 里没有 " .. c.geosite_category .. " 类别" end
	return r
end

-- 写进 PassWall「Claude」规则的域名：geosite 类别 + 默认 + 自动更新得到的
local function pw_domain_lines(c)
	local lines, seen = {}, {}
	local function add(l) if not seen[l] then seen[l] = true; lines[#lines + 1] = l end end
	-- 只写明确的域名，不引用 geosite 类别：geosite 数据里一旦没有这个类别，Xray 会启动失败
	for _, d in ipairs((#c.pw_domains > 0) and c.pw_domains or DEFAULT_PW_DOMAINS) do add("domain:" .. d) end
	local auto = load_auto().domains
	for _, d in ipairs(sorted_keys(auto)) do
		add((auto[d].type == "full" and "full:" or "domain:") .. d)
	end
	return lines
end

local function prune_backups()
	local list = {}
	for f in nfs.dir(ETC .. "/backup") or function() end do
		if f:match("^passwall%.%d+%-%d+$") then list[#list + 1] = f end
	end
	table.sort(list)
	for i = 1, #list - 20 do os.remove(ETC .. "/backup/" .. list[i]) end
end

-- OpenWrt 在 LuCI「保存并应用」时用 /var/run/config.md5 比对各配置文件，变了就触发对应服务重载；
-- PassWall 的重载就是重启。插件写完 PassWall 配置后把基线里这一项更新成现在的值，
-- 这样写入的内容仍然等 PassWall 下次重启才生效，但不会在用户点别的页面时连带重启 PassWall。
local function refresh_baseline(config)
	local f = "/var/run/config.md5"
	local s = readfile(f)
	if not s then return false end
	local out, rc = run("uci show " .. config .. " 2>/dev/null | md5sum")
	local h = out:match("^(%x+)")
	if rc ~= 0 or not h or #h ~= 32 then return false end
	local path = "/var/run/config.check/" .. config
	local lines, found = {}, false
	for l in s:gmatch("[^\n]+") do
		if l:sub(-(#path + 1)) == " " .. path then
			l = h .. "  " .. path
			found = true
		end
		lines[#lines + 1] = l
	end
	if not found then lines[#lines + 1] = h .. "  " .. path end
	writefile(f, table.concat(lines, "\n") .. "\n")
	return true
end

-- 暂存改动（stage 返回 true 表示暂存成功），用 PassWall 生成器校验后提交。
-- want：校验时 Claude 规则应指向的节点名；{ follow = true } 表示应跟随默认节点；nil 表示应没有 Claude 规则。不重启 PassWall。
local function pw_commit_checked(stage, want)
	if trim(run("uci changes passwall")) ~= "" then
		return false, "PassWall 有还没提交的修改，为免混在一起，本次不改动。请先在 PassWall 页面保存或撤销"
	end
	local base = pw_test()
	if not base.ok then
		return false, "改动前 PassWall 配置校验就不通过：" .. tostring(base.error or base.test)
	end
	nfs.mkdirr(ETC .. "/backup")
	local bk = ETC .. "/backup/passwall." .. os.date("%Y%m%d-%H%M%S")
	nfs.copy("/etc/config/passwall", bk)
	if not stage() then
		run("uci revert passwall")
		return false, "暂存失败，已撤销"
	end
	local t = pw_test()
	local others = base.rules and t.rules and same_rules(base.rules, t.rules, true)
	local why
	if not t.ok then
		why = "xray 校验不通过：" .. tostring(t.error or t.test)
	elseif type(want) == "table" then
		-- want = { follow = true }：Claude 规则要在，并且和兜底规则（默认节点）指向同一个出口
		if not t.claude_out then
			why = "生成的配置里没有 Claude 规则"
		elseif t.claude_out ~= default_out(t.rules or {}) then
			why = "生成的配置里 Claude 没有跟随默认节点，而是指向「" .. tostring(t.claude_out_name) .. "」"
		end
	elseif t.claude_out_name ~= want then
		why = "生成的配置里 Claude 指向「" .. tostring(t.claude_out_name) .. "」，应为「" .. tostring(want) .. "」"
	end
	if not why and not others then
		why = "生成的配置里其他分流规则也变了"
	end
	if why then
		run("uci revert passwall")
		return false, why .. "。已撤销，PassWall 配置没有改动"
	end
	local _, rc = run("uci commit passwall")
	if rc ~= 0 then
		run("uci revert passwall")
		return false, "提交失败，已撤销"
	end
	refresh_baseline("passwall")
	prune_backups()
	return true, bk, base, t
end

local function rule_ips(c)
	local ips = {}
	for _, p in ipairs((targets(c))) do ips[#ips + 1] = p.text end
	return table.concat(ips, "\n")
end

-- 暂存「写 Claude 规则」的命令。规则要排在第一条分流规则前面（PassWall 按配置顺序匹配，要早于“全部 UDP”那条）。
-- gnode、node 都给了，就同时在分流节点里把这条规则指到 node（"_default" = 跟随默认节点）。
local function pw_rule_stage_cmd(c, gnode, node)
	local R = "passwall." .. PW_RULE
	local dl = table.concat(pw_domain_lines(c), "\n")
	local ipl = rule_ips(c)
	local idx, pos = nil, 0
	for line in run("uci show passwall"):gmatch("[^\n]+") do
		local name, typ = line:match("^passwall%.([^.=]+)=(%S+)$")
		if name and name ~= PW_RULE then
			if typ == "shunt_rules" and not idx then idx = pos end
			pos = pos + 1
		end
	end
	return "uci -q delete " .. R .. "; uci set " .. R .. "=shunt_rules" ..
		" && uci set " .. R .. ".remarks=" .. q(PW_REMARKS) ..
		" && uci set " .. R .. ".network=tcp,udp" ..
		" && uci set " .. R .. ".domain_list=" .. q(dl) ..
		" && uci set " .. R .. ".ip_list=" .. q(ipl) ..
		(idx and (" && uci reorder " .. R .. "=" .. idx) or "") ..
		((gnode and node) and (" && uci set passwall." .. gnode .. "." .. PW_RULE .. "=" .. q(node)) or "")
end

-- 给 Claude 指定出口。node 是 PassWall 的节点 ID，或 "_default"（跟随默认节点）。
local function pw_apply(c, node, restart)
	local u = uci.cursor()
	if not pw_installed() then return { ok = false, error = "没有安装 PassWall" } end
	if not node or node == "" then return { ok = false, error = "没有指定节点" } end
	local follow = (node == "_default")
	if not follow then
		if u:get("passwall", node) ~= "nodes" then return { ok = false, error = "PassWall 里没有这个节点：" .. node } end
		local proto = u:get("passwall", node, "protocol") or ""
		if proto:sub(1, 1) == "_" then return { ok = false, error = "请选择具体的代理节点，不能选分流或负载均衡节点" } end
	end
	local g = pw_global(u)
	local gnode = g and g.node
	if not gnode or u:get("passwall", gnode, "protocol") ~= "_shunt" then
		return { ok = false, error = "PassWall 当前的全局节点不是分流节点，没法单独给 Claude 指定出口" }
	end
	local label = follow and "跟随默认节点" or tostring(pw_name(u, node))
	local ok, bk, base, t = pw_commit_checked(function()
		local _, rc = run(pw_rule_stage_cmd(c, gnode, node))
		return rc == 0
	end, follow and { follow = true } or pw_name(u, node))
	if not ok then
		event("写入 Claude 出口未通过：" .. bk, "warn")
		return { ok = false, error = bk }
	end
	run("uci set claude_guard.main.proxy_node=" .. q(follow and "" or node) ..
		" && uci set claude_guard.main.passwall_auto_rule=1 && uci commit claude_guard")
	event("已在 PassWall 写入 Claude 出口「" .. label .. "」（校验通过，" ..
		(restart and "即将重启 PassWall" or "PassWall 下次重启时生效，现在的网络不受影响") .. "）；原配置备份 " .. bk)
	if restart then
		event("应插件请求重启 PassWall（期间 Claude 连接会被拦下）", "warn")
		os.execute("setsid sh -c 'sleep 1; /etc/init.d/passwall restart' >/dev/null 2>&1 </dev/null &")
	end
	return { ok = true, backup = bk, node = label, restarted = restart and true or false,
		baseline_matches_running = base.matches_running, test = t.test }
end

-- PassWall 里 Claude 规则现在的样子；need = 要补（规则不在，或用的是分流节点却没给这条规则选出口）
local function pw_rule_state()
	if not pw_installed() then return nil end
	local u = uci.cursor()
	local g = pw_global(u)
	if not g then return nil end
	local gnode = g.node
	local shunt = (gnode and u:get("passwall", gnode, "protocol") == "_shunt") and true or false
	local present = (u:get("passwall", PW_RULE) == "shunt_rules")
	local assigned = shunt and u:get("passwall", gnode, PW_RULE) or nil
	if assigned == "" then assigned = nil end
	return { gnode = gnode, shunt = shunt, present = present, assigned = assigned,
		need = (not present) or (shunt and not assigned) }
end

-- 装了 PassWall，就在它的分流规则里放一条 Claude 规则（默认跟随默认节点）：
-- PassWall 用分流节点时，会把分流规则里的地址段按 IP 强制走代理（不靠 DNS），并且之后可以在设置页给 Claude 单独选出口。
-- 只写配置，不重启 PassWall，等它下次重启时生效。用户在插件里删掉规则后不再自动加（passwall_auto_rule=0）。
local function pw_ensure(c)
	if not c.pw_auto_rule then return { skip = "已关闭「自动在 PassWall 里放 Claude 规则」" } end
	local s = pw_rule_state()
	if not s then return { skip = "没有安装 PassWall，或它还没有配置" } end
	if not s.need then return { ok = true, unchanged = true } end
	local node, want = nil, nil
	if s.shunt then
		node = s.assigned or "_default"
		want = (node == "_default") and { follow = true } or pw_name(uci.cursor(), node)
	end
	local ok, bk = pw_commit_checked(function()
		local _, rc = run(pw_rule_stage_cmd(c, s.shunt and s.gnode or nil, node))
		return rc == 0
	end, want)
	if not ok then
		-- 同一个原因只记一次日志，之后每小时悄悄重试
		if bk ~= trim(readfile(RUN .. "/pwrule_error") or "") then
			writefile(RUN .. "/pwrule_error", bk)
			event("没能在 PassWall 里自动加上 Claude 规则（PassWall 配置保持原样，稍后再试）：" .. bk, "warn")
		end
		return { ok = false, error = bk }
	end
	os.remove(RUN .. "/pwrule_error")
	event("已在 PassWall 的分流规则里加上「" .. PW_REMARKS .. "」" ..
		(s.shunt and "，跟随默认节点" or "（PassWall 现在用的不是分流节点，这条规则暂时用不上）") ..
		"；PassWall 下次重启时生效，现在的网络不受影响；原配置备份 " .. bk)
	return { ok = true, created = true, shunt = s.shunt, backup = bk }
end

-- 自动更新后，把新的域名和网段同步进 PassWall 的 Claude 规则（不重启，下次重启生效）
local function pw_refresh(c)
	local u = uci.cursor()
	local info = pw_info()
	if not (info.installed and info.rule_present) then
		return { skip = "PassWall 里没有 Claude 规则，不需要同步" }
	end
	local want = nil
	if info.shunt then
		if info.pinned then want = info.effective_name elseif info.follow then want = { follow = true } end
	end
	local dl = table.concat(pw_domain_lines(c), "\n")
	local ipl = rule_ips(c)
	if (u:get("passwall", PW_RULE, "domain_list") or "") == dl and (u:get("passwall", PW_RULE, "ip_list") or "") == ipl then
		return { ok = true, unchanged = true }
	end
	local R = "passwall." .. PW_RULE
	local ok, bk = pw_commit_checked(function()
		local _, rc = run("uci set " .. R .. ".domain_list=" .. q(dl) .. " && uci set " .. R .. ".ip_list=" .. q(ipl))
		return rc == 0
	end, want)
	if not ok then
		event("同步 PassWall 里的 Claude 规则未通过，保留原规则：" .. bk, "warn")
		return { ok = false, error = bk }
	end
	local nd = select(2, dl:gsub("\n", "\n")) + 1
	event("已同步 PassWall 里的 Claude 规则：" .. nd .. " 条域名规则，PassWall 下次重启时生效；原配置备份 " .. bk)
	return { ok = true, changed = true, backup = bk }
end

local function pw_remove(restart)
	if not pw_installed() then return { ok = false, error = "没有安装 PassWall" } end
	local u = uci.cursor()
	local ok, bk = pw_commit_checked(function()
		local cmds = { "uci -q delete passwall." .. PW_RULE }
		u:foreach("passwall", "nodes", function(s)
			if s[PW_RULE] then cmds[#cmds + 1] = "uci -q delete passwall." .. s[".name"] .. "." .. PW_RULE end
		end)
		run(table.concat(cmds, "; "))
		return true
	end, nil)
	if not ok then return { ok = false, error = bk } end
	-- 用户自己删的，之后不再自动加回去（设置页「高级」里可以重新打开）
	run("uci set claude_guard.main.proxy_node='' && uci set claude_guard.main.passwall_auto_rule=0 && uci commit claude_guard")
	event("已从 PassWall 删除 Claude 规则，之后不再自动添加（" .. (restart and "即将重启 PassWall" or "PassWall 下次重启时生效") ..
		"）；原配置备份 " .. bk)
	if restart then
		os.execute("setsid sh -c 'sleep 1; /etc/init.d/passwall restart' >/dev/null 2>&1 </dev/null &")
	end
	return { ok = true, backup = bk, restarted = restart and true or false }
end

local function pw_restart()
	if not pw_installed() then return { ok = false, error = "没有安装 PassWall" } end
	event("应插件请求重启 PassWall（期间 Claude 连接会被拦下）", "warn")
	os.execute("setsid sh -c 'sleep 1; /etc/init.d/passwall restart' >/dev/null 2>&1 </dev/null &")
	return { ok = true }
end

---------------------------------------------------------------- 目标发现

local function resolve(d)
	local out = run("timeout 8 nslookup " .. q(d) .. " 127.0.0.1")
	local ips, ans = {}, false
	for line in out:gmatch("[^\n]+") do
		if line:match("^Name:") then
			ans = true
		elseif ans then
			local a = line:match("^Address:%s*(%S+)")
			if a and parse_ip(a) then ips[#ips + 1] = a end
		end
	end
	return ips
end

local function is_cn(ip, fam)
	local set = (fam == 4) and "psw_chn" or "psw_chn6"
	local _, rc = run("nft get element inet passwall " .. set .. " { " .. ip .. " } >/dev/null")
	return rc == 0
end

local function discover(c, manual)
	local res = { time = os.time(), manual = manual and true or false, added = {}, refreshed = 0,
		covered = 0, skipped = {}, errors = {} }
	writefile(RUN .. "/ts_discover", tostring(res.time))
	if not c.discover and not manual then
		res.skip = "自动发现已关闭"
		writejson(RUN .. "/discover.json", res)
		return res
	end
	if not pw_table() then
		res.skip = pw_installed() and "PassWall 未运行，此时路由器 DNS 结果不可靠，本次不更新" or
			"没有代理时路由器的 DNS 结果不可靠，不做解析；网段以外的地址由统一列表提供"
		writejson(RUN .. "/discover.json", res)
		return res
	end
	local all = targets(c)
	local disc = load_disc(c)
	local now, new, any = os.time(), {}, false
	for _, d in ipairs(c.domains) do
		local ips = resolve(d)
		if #ips == 0 then res.errors[#res.errors + 1] = d .. "：无解析结果" else any = true end
		for _, ip in ipairs(ips) do
			local b, fam = parse_ip(ip)
			local key = fmt(b)
			if covered(b, all) then
				res.covered = res.covered + 1
			elseif not public(b) then
				res.skipped[#res.skipped + 1] = key .. "（" .. d .. "，保留地址）"
			elseif is_cn(key, fam) then
				res.skipped[#res.skipped + 1] = key .. "（" .. d .. "，中国大陆地址，不加入以免误伤）"
			elseif disc[key] then
				disc[key].last = now
				disc[key].domain = d
				res.refreshed = res.refreshed + 1
			elseif not new[key] then
				new[key] = d
			end
		end
	end
	if not any then
		res.ok = false
		res.error = "全部域名都没有解析结果，保留原有列表不变"
		event(res.error, "warn")
		writejson(RUN .. "/discover.json", res)
		return res
	end
	local newlist = {}
	for k, d in pairs(new) do newlist[#newlist + 1] = { ip = k, domain = d } end
	if #newlist > c.max_new then
		res.ok = false
		res.pending = newlist
		res.error = "一次发现 " .. #newlist .. " 个新地址，超过上限 " .. c.max_new .. "，没有加入，请人工确认"
		event(res.error, "warn")
	else
		for _, e in ipairs(newlist) do
			disc[e.ip] = { domain = e.domain, first = now, last = now }
			res.added[#res.added + 1] = e.ip .. "（" .. e.domain .. "）"
		end
		res.ok = true
	end
	writejson(ETC .. "/discovered.json", disc)
	if #res.added > 0 then
		event("发现保护段以外的地址，已加入：" .. table.concat(res.added, "，"), "warn")
	end
	-- 重新加载，让动态集合与文件一致并续期
	if lock(60) then apply(c) end
	writejson(RUN .. "/discover.json", res)
	return res
end

---------------------------------------------------------------- 自动更新目标列表
-- 网段：ARIN 里登记在 Anthropic 名下的网段 + Anthropic 自己 ASN 的路由公告（整段归 Anthropic，按 IP 拦不误伤）
-- 域名：本地 geosite.dat 的类别（PassWall 每周更新）+ v2fly/domain-list-community 在线文件，只用于 PassWall 的 Claude 规则
-- 统一列表（可选）：自己维护的一个 JSON 文件。配了地址并且这次拿到了，就以它为准，不再去问上面的公开来源；
--   拿不到时公开来源兜底。只有统一列表能撤回已经下发的内容。格式见 README「统一列表」。
-- 原则：公开来源只增不减；某个来源失败就保留原有内容；一次新增过多只报警不加入

local function http_get(url, accept)
	local out, rc = run("curl -fsS -m 25 --connect-timeout 10 --max-filesize 524288 " ..
		(accept and ("-H " .. q("Accept: " .. accept) .. " ") or "") .. q(url))
	if rc ~= 0 then return nil, "下载失败（curl " .. rc .. "）" end
	return out
end

local function jget(url)
	local b, e = http_get(url, "application/json")
	if not b then return nil, e end
	local j = jsonc.parse(b)
	if type(j) ~= "table" then return nil, "返回的不是 JSON" end
	return j
end

local function aslist(x)
	if type(x) ~= "table" then return {} end
	if x[1] ~= nil then return x end
	return { x }
end

local function src_arin(c)
	if not c.arin_org:match("^[%w%-]+$") then return nil, "机构号格式不对" end
	local j, err = jget("https://whois.arin.net/rest/org/" .. c.arin_org .. "/nets")
	if not j then return nil, err end
	local refs = aslist(j.nets and j.nets.netRef)
	if #refs == 0 then return nil, "该机构名下没有网段" end
	if #refs > 32 then return nil, "网段数量异常（" .. #refs .. "）" end
	local out = {}
	for _, r in ipairs(refs) do
		local h = r["@handle"]
		if type(h) == "string" and h:match("^[%w%-]+$") then
			local n, e2 = jget("https://whois.arin.net/rest/net/" .. h)
			if not n then return nil, e2 end
			local net = n.net or {}
			if net.orgRef and net.orgRef["@handle"] == c.arin_org then
				local name = type(net.name) == "table" and net.name["$"] or h
				for _, b in ipairs(aslist(net.netBlocks and net.netBlocks.netBlock)) do
					local st = b.startAddress and b.startAddress["$"]
					local len = b.cidrLength and b.cidrLength["$"]
					if st and len then out[#out + 1] = { p = tostring(st) .. "/" .. tostring(len), note = "ARIN " .. name } end
				end
			end
		end
	end
	if #out == 0 then return nil, "没有可用的网段" end
	return out
end

local function src_ripe(c)
	if not tostring(c.asn):match("^%d+$") then return nil, "ASN 格式不对" end
	local j, err = jget("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" .. c.asn)
	if not j then return nil, err end
	local ps = (j.data or {}).prefixes
	if type(ps) ~= "table" then return nil, "返回格式不对" end
	local out = {}
	for _, x in ipairs(ps) do
		if type(x.prefix) == "string" then out[#out + 1] = { p = x.prefix, note = "AS" .. c.asn .. " 公告" } end
	end
	if #out == 0 then return nil, "没有公告的网段" end
	if #out > 64 then return nil, "网段数量异常（" .. #out .. "）" end
	return out
end

local function src_v2fly(c)
	local base = c.v2fly_url:match("^(https://.+/)[^/]+$")
	if not base then return nil, "地址格式不对" end
	local entries, seen, queue, fetched = {}, {}, { c.v2fly_url }, 0
	while #queue > 0 and fetched < 6 do
		local url = table.remove(queue, 1)
		if not seen[url] then
			seen[url] = true
			fetched = fetched + 1
			local body, err = http_get(url)
			if not body then return nil, err end
			local n = 0
			for line in body:gmatch("[^\n]+") do
				n = n + 1
				if n > 2000 then return nil, "文件过大" end
				local l = trim((line:gsub("#.*$", "")))
				if l ~= "" then
					local attrs = {}
					for at in l:gmatch("@([%w_%-!]+)") do attrs[#attrs + 1] = at end
					l = trim((l:gsub("%s*@[%w_%-!]+", "")))
					local kind, val = l:match("^(%a+):(%S+)$")
					if not kind then kind, val = "domain", l end
					val = (val or ""):lower()
					if kind == "include" then
						if val:match("^[%w%-%.]+$") then queue[#queue + 1] = base .. val end
					elseif (kind == "domain" or kind == "full") and valid_domain(val) then
						entries[#entries + 1] = { d = val, type = (kind == "full") and "full" or "suffix", attrs = attrs }
					end
				end
			end
		end
	end
	if #entries == 0 then return nil, "没有解析到域名" end
	return entries
end

local function src_geosite(c)
	local list, err = geosite_list(c)
	if not list then return nil, err end
	local out = {}
	-- geosite 里看不出是“域名及子域名”还是“完整主机名”：两段的当作域名，更长的当作完整主机名
	for _, d in ipairs(list) do out[#out + 1] = { d = d, type = (labels(d) == 2) and "suffix" or "full", attrs = {} } end
	return out
end

local function prefix_ok(p)
	if not p then return false, "格式不对" end
	if p.fam == 4 and p.len < 12 then return false, "范围过大，不收" end
	if p.fam == 6 and p.len < 19 then return false, "范围过大，不收" end
	if not public(p.net) then return false, "保留地址，不收" end
	return true
end

local function inside(p, list)
	for _, x in ipairs(list) do
		if x.fam == p.fam and x.len <= p.len and in_prefix(p.net, x) then return x end
	end
	return nil
end

local function addsrc(e, src)
	e.src = e.src or {}
	for _, s in ipairs(e.src) do if s == src then return end end
	e.src[#e.src + 1] = src
end

local CENTRAL = "统一列表"

-- JSON 数组当列表用；不是表就当空的
local function arr(x)
	return type(x) == "table" and x or {}
end

-- 读统一列表。没配置返回 nil, nil；读不到或格式不对返回 nil, 原因。
local function src_central(c)
	local url = c.central_url
	if url == "" then return nil, nil end
	local body, err
	if url:match("^https://") then
		body, err = http_get(url, "application/json")
	elseif url:match("^file:///") then
		body = readfile(url:sub(8))
		if not body then err = "读不到文件 " .. url:sub(8) end
	else
		return nil, "地址要以 https:// 开头"
	end
	if not body then return nil, err end
	local j = jsonc.parse(body)
	if type(j) ~= "table" or j.format ~= "claude-guard-list" then return nil, "内容不是统一列表的格式" end
	if tonumber(j.version) ~= 1 then return nil, "列表格式版本 " .. tostring(j.version) .. "，这一版插件只认 1" end
	j.serial = tonumber(j.serial)
	if not j.serial then return nil, "缺少 serial（版本序号）" end
	return j
end

local function update_lists(c, manual, dry)
	local a = load_auto()
	local now = os.time()
	local res = { time = now, added_prefixes = {}, added_domains = {}, added_hosts = {}, revoked = {},
		problems = {}, sources = {}, dry = dry or nil }
	if not dry then writefile(RUN .. "/ts_update", tostring(now)) end
	local pw_up = pw_table()

	-- 统一列表
	local central, cerr = src_central(c)
	if central and (tonumber(a.central_serial) or 0) > central.serial then
		cerr = "比本机已经用过的版本旧（" .. central.serial .. " < " .. tostring(a.central_serial) .. "），忽略"
		central = nil
	end
	if c.central_url ~= "" then
		a.sources.central = { ok = central ~= nil, time = now, error = cerr, serial = central and central.serial or nil,
			count = central and (#arr(central.prefixes) + #arr(central.hosts) + #arr(central.domains)) or 0 }
		res.sources.central = a.sources.central
	else
		a.sources.central = nil
	end

	-- 网段
	local have = targets(c)
	local newp, newp_list = {}, {}
	local psrc = {}
	if central then
		psrc[#psrc + 1] = { "central", function()
			local l = {}
			for _, e in ipairs(arr(central.prefixes)) do
				if type(e) == "string" then
					l[#l + 1] = { p = e }
				elseif type(e) == "table" and type(e.prefix) == "string" then
					l[#l + 1] = { p = e.prefix, note = type(e.note) == "string" and e.note or nil }
				end
			end
			return l
		end }
	else
		if c.src_arin then psrc[#psrc + 1] = { "ARIN", src_arin } end
		if c.src_ripe then psrc[#psrc + 1] = { "BGP", src_ripe } end
	end
	for _, s in ipairs(psrc) do
		local list, err = s[2](c)
		local label = (s[1] == "central") and CENTRAL or s[1]
		if s[1] ~= "central" then
			a.sources[s[1]] = { ok = list ~= nil, time = now, count = list and #list or 0, error = err }
			res.sources[s[1]] = a.sources[s[1]]
		end
		for _, it in ipairs(list or {}) do
			local p = parse_cidr(it.p)
			local ok, why = prefix_ok(p)
			if not ok then
				res.problems[#res.problems + 1] = label .. "：" .. it.p .. " " .. why
			elseif a.prefixes[p.text] then
				a.prefixes[p.text].last = now
				addsrc(a.prefixes[p.text], label)
			elseif inside(p, have) then
				-- 已被现有网段覆盖，不用再加
			elseif newp[p.text] then
				addsrc(newp[p.text], label)
			else
				newp[p.text] = { src = { label }, note = it.note }
				newp_list[#newp_list + 1] = p.text
			end
		end
	end
	if #newp_list > c.max_new_prefix then
		res.pending_prefixes = newp_list
		event("自动更新发现 " .. #newp_list .. " 个新网段，超过上限 " .. c.max_new_prefix .. "，没有加入：" ..
			table.concat(newp_list, "、"), "warn")
	else
		for _, k in ipairs(newp_list) do
			a.prefixes[k] = { src = newp[k].src, note = newp[k].note, first = now, last = now }
			res.added_prefixes[#res.added_prefixes + 1] = k
		end
	end

	-- 域名
	local own = {}
	for _, d in ipairs(DEFAULT_PW_DOMAINS) do own[#own + 1] = d end
	local found = {}
	local dsrc = {}
	if central then
		dsrc[#dsrc + 1] = { "central", function()
			local l = {}
			for _, e in ipairs(arr(central.domains)) do
				local d, typ, shared
				if type(e) == "string" then d = e elseif type(e) == "table" then d, typ, shared = e.d or e.domain, e.type, e.shared end
				d = type(d) == "string" and d:lower() or nil
				if d and valid_domain(d) then
					l[#l + 1] = { d = d, type = (typ == "full") and "full" or "suffix", attrs = shared and { "shared" } or {} }
				elseif d then
					res.problems[#res.problems + 1] = CENTRAL .. "：域名 " .. d .. " 格式不对"
				end
			end
			return l
		end }
	else
		-- 本地 geosite 是 PassWall 带来的；路由器上没有就不算一个来源（免得一直显示“部分来源失败”）
		if c.src_geosite and nfs.access(GEOVIEW) and nfs.access(GEOSITE) then
			dsrc[#dsrc + 1] = { "geosite", src_geosite }
		else
			a.sources.geosite = nil
		end
		if c.src_v2fly then dsrc[#dsrc + 1] = { "v2fly", src_v2fly } end
	end
	for _, s in ipairs(dsrc) do
		local list, err = s[2](c)
		local label = (s[1] == "central") and CENTRAL or s[1]
		if s[1] ~= "central" then
			a.sources[s[1]] = { ok = list ~= nil, time = now, count = list and #list or 0, error = err }
			res.sources[s[1]] = a.sources[s[1]]
		end
		for _, e in ipairs(list or {}) do
			local f = found[e.d]
			if not f then
				f = { type = e.type, attrs = e.attrs, src = {} }
				found[e.d] = f
			elseif s[1] == "v2fly" then
				f.type = e.type -- v2fly 写明了类型，以它为准
				if #e.attrs > 0 then f.attrs = e.attrs end
			end
			addsrc(f, label)
			if e.type == "suffix" and #e.attrs == 0 and not is_shared_host(e.d) then own[#own + 1] = e.d end
		end
	end
	local function is_own(d)
		for _, o in ipairs(own) do if under(d, o) then return true end end
		return false
	end
	local newd = {}
	for _, d in ipairs(sorted_keys(found)) do
		local f = found[d]
		local shared = (#(f.attrs or {}) > 0) or is_shared_host(d) or (f.type == "full" and not is_own(d))
		if f.type == "suffix" and is_shared_host(d) then
			res.problems[#res.problems + 1] = "域名 " .. d .. " 是公共托管服务的整个域，不收"
		elseif a.domains[d] then
			local e = a.domains[d]
			e.last, e.type, e.shared = now, f.type, shared
			for _, x in ipairs(f.src) do addsrc(e, x) end
		else
			newd[#newd + 1] = { d = d, type = f.type, shared = shared, src = f.src, attrs = f.attrs }
		end
	end
	if #newd > c.max_new_domain then
		res.pending_domains = #newd
		event("自动更新发现 " .. #newd .. " 个新域名，超过上限 " .. c.max_new_domain .. "，没有加入", "warn")
	else
		for _, e in ipairs(newd) do
			a.domains[e.d] = { type = e.type, shared = e.shared, src = e.src, attrs = e.attrs, first = now, last = now }
			res.added_domains[#res.added_domains + 1] = e.d
		end
	end

	-- 统一列表里的「网段以外的地址」：不在 Anthropic 网段里、但确认是 Claude 专用的地址。
	-- 放进动态集合，和定期解析发现的地址一样：列表里一直有就一直续期，不再列出后 30 天过期。
	local disc, disc_changed = nil, false
	if central then
		disc = readjson(ETC .. "/discovered.json") or {}
		local addlist = {}
		for _, h in ipairs(arr(central.hosts)) do
			local ip = (type(h) == "table") and h.ip or h
			local b = (type(ip) == "string") and parse_ip(ip) or nil
			if not b then
				res.problems[#res.problems + 1] = CENTRAL .. "：地址 " .. tostring(ip) .. " 格式不对"
			elseif not public(b) then
				res.problems[#res.problems + 1] = CENTRAL .. "：地址 " .. ip .. " 是保留地址，不收"
			elseif not covered(b, have) then
				local key = fmt(b)
				if type(disc[key]) == "table" then
					disc[key].last = now
					disc[key].central = true
					disc_changed = true
				else
					addlist[#addlist + 1] = { key = key, domain = (type(h) == "table" and type(h.domain) == "string") and h.domain or nil }
				end
			end
		end
		if #addlist > c.max_new then
			res.pending_hosts = #addlist
			event(CENTRAL .. "一次给出 " .. #addlist .. " 个新地址，超过上限 " .. c.max_new .. "，没有加入，请人工确认", "warn")
		else
			for _, e in ipairs(addlist) do
				disc[e.key] = { domain = e.domain or CENTRAL, first = now, last = now, central = true }
				res.added_hosts[#res.added_hosts + 1] = e.key
				disc_changed = true
			end
		end
		-- 撤回：从自动加入的内容里删掉（内置列表和手动添加的不受影响）
		local rv = (type(central.revoke) == "table") and central.revoke or {}
		for _, x in ipairs(arr(rv.prefixes)) do
			local p = (type(x) == "string") and parse_cidr(x) or nil
			if p and a.prefixes[p.text] then
				a.prefixes[p.text] = nil
				res.revoked[#res.revoked + 1] = p.text
			end
		end
		for _, x in ipairs(arr(rv.hosts)) do
			local b = (type(x) == "string") and parse_ip(x) or nil
			local key = b and fmt(b)
			if key and disc[key] then
				disc[key] = nil
				disc_changed = true
				res.revoked[#res.revoked + 1] = key
			end
		end
		for _, x in ipairs(arr(rv.domains)) do
			if type(x) == "string" and a.domains[x:lower()] then
				a.domains[x:lower()] = nil
				res.revoked[#res.revoked + 1] = x:lower()
			end
		end
	end

	-- 观察：Claude 自己的域名解析到 Anthropic 网段以外的地址，只提示、不自动按 IP 拦（可能是共享 CDN）
	if pw_up then
		local all = targets(c)
		local dnow = load_disc(c)
		local outside = {}
		for _, d in ipairs(sorted_keys(a.domains)) do
			local e = a.domains[d]
			if e.type == "suffix" and not e.shared then
				for _, ip in ipairs(resolve(d)) do
					local b = parse_ip(ip)
					local key = b and fmt(b)
					if b and public(b) and not covered(b, all) and not dnow[key] and not (disc and disc[key]) then
						outside[#outside + 1] = { domain = d, ip = key }
					end
				end
			end
		end
		a.outside = outside
		a.outside_time = now
	end

	local failed, net_total, net_ok = 0, 0, 0
	for k, v in pairs(res.sources) do
		if not v.ok then failed = failed + 1 end
		if k ~= "geosite" then
			net_total = net_total + 1
			if v.ok then net_ok = net_ok + 1 end
		end
	end
	a.last_run = now
	if failed == 0 then a.last_ok = now end
	if central then a.central_serial = central.serial end
	if dry then
		res.outside = a.outside
		res.domains_total = #sorted_keys(a.domains)
		return res
	end
	writejson(AUTO_FILE, a)
	if disc_changed then writejson(ETC .. "/discovered.json", disc) end
	-- 自动运行时一个来源都没连上（多半是网络还没好）：半小时后再试，不等到明天
	if not manual and net_total > 0 and net_ok == 0 then
		writefile(RUN .. "/ts_update", tostring(now - c.update_interval + 1800))
		res.retry_in = 1800
	end

	if #res.added_prefixes > 0 then
		event("自动更新加入新网段：" .. table.concat(res.added_prefixes, "、"), "warn")
	end
	if #res.added_hosts > 0 then
		event(CENTRAL .. "加入网段以外的地址：" .. table.concat(res.added_hosts, "、"), "warn")
	end
	if #res.revoked > 0 then
		event(CENTRAL .. "撤回：" .. table.concat(res.revoked, "、"), "warn")
	end
	-- 有新增、有撤回，或统一列表里有网段以外的地址（要给内核里的条目续期）时重新加载规则
	if #res.added_prefixes > 0 or #res.revoked > 0 or disc_changed then
		if lock(60) then apply(c) end
	end
	if #res.added_domains > 0 then
		event("自动更新加入新域名：" .. table.concat(res.added_domains, "、"))
	end
	if lock(60) then
		res.passwall = pw_refresh(c)
	else
		res.passwall = { ok = false, error = "另一个操作正在进行，本次没有同步 PassWall 规则" }
	end
	local fails = {}
	for k, v in pairs(res.sources) do
		if not v.ok then fails[#fails + 1] = ((k == "central") and CENTRAL or k) .. "（" .. tostring(v.error) .. "）" end
	end
	event(string.format("目标列表更新：网段 +%d，域名 +%d%s%s%s%s%s", #res.added_prefixes, #res.added_domains,
		central and ("，网段以外的地址 +" .. #res.added_hosts) or "",
		#res.revoked > 0 and ("，撤回 " .. #res.revoked .. " 项") or "",
		#fails > 0 and ("；失败的来源保留原有内容：" .. table.concat(fails, "，")) or "",
		res.retry_in and "；半小时后再试" or "",
		manual and "（手动）" or ""), #fails > 0 and "warn" or "notice")
	writejson(RUN .. "/update.json", res)
	return res
end

---------------------------------------------------------------- 状态

local function daemon_running()
	for pid in nfs.dir("/proc") do
		if pid:match("^%d+$") then
			local cmd = readfile("/proc/" .. pid .. "/cmdline")
			if cmd and cmd:find("claude-guard/daemon.sh", 1, true) then return true end
		end
	end
	return false
end

local function since(path)
	local t = tonumber(trim(readfile(path) or ""))
	return t and (os.time() - t) or math.huge
end

local function evaluate(c, live)
	-- tz：路由器的时区（如 +0800）。页面按它显示时间，和日志里的时间一致，不跟着浏览器所在电脑的时区走
	local st = { version = VERSION, time = os.time(), tz = os.date("%z"), enabled = c.enabled, checks = {}, problems = {} }
	local function chk(id, name, ok, detail, extra)
		local e = { id = id, name = name, ok = ok, detail = detail }
		if extra then for k, v in pairs(extra) do e[k] = v end end
		st.checks[#st.checks + 1] = e
		if ok == false then st.problems[#st.problems + 1] = name .. "：" .. detail end
	end
	if not c.enabled then
		st.overall = "disabled"
		st.exists = table_exists()
		return st
	end
	local exists = table_exists()
	chk("table", "拦截表", exists, exists and "inet claude_guard 在内核中" or "拦截表不存在")
	local hooks = exists and chain_hooks() or {}
	local bad = {}
	for name, want in pairs(EXPECTED_HOOKS) do
		if hooks[name] ~= want then bad[#bad + 1] = name end
	end
	table.sort(bad)
	chk("hooks", "挂载点", exists and #bad == 0,
		(exists and #bad == 0) and "转发、本机发出、出网审计三处都已挂上" or ("缺少或不对：" .. table.concat(bad, "、")))
	local fp = exists and fingerprint() or nil
	local want = trim(readfile(RUN .. "/fingerprint") or "")
	local fpok = (fp ~= nil and fp == want)
	chk("fingerprint", "规则完整性", fpok,
		fpok and "与加载时一致" or (want == "" and "没有加载记录（可能是最小规则或刚开机）" or "规则被改动过"))
	local all, _, _, invalid = targets(c)
	local missing = {}
	if exists then
		for _, p in ipairs(all) do if not set_has(p) then missing[#missing + 1] = p.text end end
	end
	chk("targets", "受保护地址段", exists and #missing == 0,
		(exists and #missing == 0) and ("共 " .. #all .. " 段，全部在拦截集合中") or
		(exists and ("缺少：" .. table.concat(missing, "、")) or "拦截表不存在"))
	if #invalid > 0 then st.invalid = invalid end
	local cn = readjson(RUN .. "/canary.json")
	if live or not cn or not cn.time or (os.time() - cn.time) > c.canary_interval * 3 then
		cn = canary(c)
	end
	st.canary = cn
	local v4 = cn.v4 or {}
	if v4.skip then
		chk("canary", "实测拦截（自检）", nil, v4.detail, { time = cn.time })
	else
		chk("canary", "实测拦截（自检）", v4.ok == true, v4.detail or "没有结果", { time = cn.time })
	end
	local exall = exempts(c)
	local leaks, lerr = scan(c, all, load_disc(c), exall)
	st.leaks = leaks or {}
	if leaks then
		chk("leaks", "直连连接", #leaks == 0,
			#leaks == 0 and "没有未经代理的 Claude 连接" or ("发现 " .. #leaks .. " 条疑似未经代理的 Claude 连接（只报告，不自动处理）"))
	else
		chk("leaks", "直连连接", false, lerr)
	end
	local tot = counter_totals()
	local audit = tot.audit4.packets + tot.audit6.packets
	local ack = tonumber(trim(readfile(RUN .. "/audit_ack") or "")) or 0
	chk("audit", "出网审计", audit <= ack,
		audit <= ack and "没有包漏到审计这一层" or ("审计层拦下 " .. (audit - ack) .. " 个包，说明前两道有漏洞，请看日志"))
	st.counters = tot
	st.need_repair = not (exists and #bad == 0 and fpok and #missing == 0)
	st.overall = (#st.problems == 0) and "ok" or "fail"
	return st
end

local function check(c)
	if not c.enabled then return { overall = "disabled" } end
	local st = evaluate(c, false)
	-- 看护进程发现拦截表不见时会先按上次的规则立即装回，并留下这个标记：表缺失期间可能放过了直连，要清一遍
	local restored = nfs.access(RUN .. "/need_flush") and true or false
	if restored then os.remove(RUN .. "/need_flush") end
	if st.need_repair or restored then
		event(restored and "拦截表曾被删除，已立即装回；重新加载并清理期间可能建立的直连" or
			("检查发现问题（" .. table.concat(st.problems, "；") .. "），重新加载规则"), "warn")
		apply(c, true)
		st = evaluate(c, true)
		if st.overall ~= "ok" then event("重新加载后仍有问题：" .. table.concat(st.problems, "；"), "crit") end
	elseif #st.leaks > 0 and since(RUN .. "/ts_leak_report") >= 600 then
		-- 只报告，不动连接（10 分钟最多报一次）
		writefile(RUN .. "/ts_leak_report", tostring(os.time()))
		local texts = {}
		for i, l in ipairs(st.leaks) do if i <= 10 then texts[#texts + 1] = leak_text(l) end end
		event("发现 " .. #st.leaks .. " 条疑似未经代理的 Claude 连接（只报告，没有处理）：" .. table.concat(texts, "；"), "warn")
	end
	if since(RUN .. "/canary.json.ts") >= c.canary_interval then
		canary(c)
		writefile(RUN .. "/canary.json.ts", tostring(os.time()))
	end
	local pw_on
	local function pw_up()
		if pw_on == nil then pw_on = pw_table() end
		return pw_on
	end
	-- 出口检测、定期解析都要经代理才有意义：PassWall 在运行时才做
	if since(RUN .. "/ts_trace") >= c.trace_interval and pw_up() then
		writefile(RUN .. "/ts_trace", tostring(os.time()))
		os.execute("setsid " .. CTL .. " trace >/dev/null 2>&1 </dev/null &")
	end
	if c.discover and since(RUN .. "/ts_discover") >= c.discover_interval and pw_up() then
		writefile(RUN .. "/ts_discover", tostring(os.time()))
		os.execute("setsid " .. CTL .. " discover >/dev/null 2>&1 </dev/null &")
	end
	-- 更新目标列表：装了 PassWall 就等它在运行时做（经代理下载）；没装代理插件时宽带通了就做
	if c.auto_update and since(RUN .. "/ts_update") >= c.update_interval and
		(pw_up() or (not pw_installed() and net_ready())) then
		writefile(RUN .. "/ts_update", tostring(os.time()))
		os.execute("setsid " .. CTL .. " update --auto >/dev/null 2>&1 </dev/null &")
	end
	-- 装了 PassWall 而它的分流规则里还没有 Claude 规则：补上（每小时最多试一次；开机头三分钟不动，让 PassWall 先起来）
	if c.pw_auto_rule and since(RUN .. "/ts_pwrule") >= 3600 and uptime() >= 180 then
		local rs = pw_rule_state()
		if rs and rs.need then
			writefile(RUN .. "/ts_pwrule", tostring(os.time()))
			os.execute("setsid " .. CTL .. " passwall-ensure >/dev/null 2>&1 </dev/null &")
		end
	end
	writejson(RUN .. "/last_check.json", { time = os.time(), overall = st.overall, problems = st.problems })
	return st
end

local MONTHS = { Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6, Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12 }

local function logs()
	local out = run("logread -e 'claude-guard' | tail -n 400")
	local r = {}
	for l in out:gmatch("[^\n]+") do r[#r + 1] = l end
	return r
end

-- 从内核日志里取最近的拦截记录（每分钟最多记 10 条），配上 DHCP 里的设备名
local function blocks(lines, since)
	local names = {}
	for l in (readfile("/tmp/dhcp.leases") or ""):gmatch("[^\n]+") do
		local ip, name = l:match("^%S+%s+%S+%s+(%S+)%s+(%S+)")
		if ip and name and name ~= "*" then names[ip] = name end
	end
	local r = {}
	for i = #lines, 1, -1 do
		local l = lines[i]
		local kind = l:match("claude%-guard (%u+) IN=")
		local d0 = kind and l:match(" DST=(%S+)")
		local d0b = d0 and parse_ip(d0)
		if d0b and (fmt(d0b) == CANARY4 or fmt(d0b) == CANARY6) then kind = nil end
		local mon, day, hms
		if kind then
			mon, day, hms = l:match("^%a+ (%a+)%s+(%d+) (%d+:%d+:%d+)")
			local hh, mi, ss, yy = l:match("^%a+ %a+%s+%d+ (%d+):(%d+):(%d+) (%d+)")
			local ts = (mon and hh) and os.time({ year = tonumber(yy), month = MONTHS[mon] or 1, day = tonumber(day),
				hour = tonumber(hh), min = tonumber(mi), sec = tonumber(ss) }) or nil
			if since and ts and ts < since then kind = nil end
		end
		if kind then
			local src, dst = l:match(" SRC=(%S+)"), l:match(" DST=(%S+)")
			local sb, db = parse_ip(src), parse_ip(dst)
			src, dst = sb and fmt(sb) or src, db and fmt(db) or dst
			r[#r + 1] = {
				time = mon and string.format("%02d-%02d %s", MONTHS[mon] or 0, tonumber(day), hms) or "",
				kind = kind, src = src, host = names[src], dst = dst,
				proto = l:match(" PROTO=(%S+)"), dport = l:match(" DPT=(%d+)"),
				canary = (dst == CANARY4 or dst == CANARY6) or nil,
			}
			if #r >= 30 then break end
		end
	end
	return r
end

local function status(c, live)
	local st = evaluate(c, live)
	local all, _, _, invalid, detail = targets(c)
	local exall, _, _, exbad = exempts(c)
	local disc = load_disc(c)
	local dyn = {}
	for ip, e in pairs(disc) do
		local b = parse_ip(ip)
		if b and not covered(b, all) then
			dyn[#dyn + 1] = { ip = ip, domain = e.domain, first = e.first, last = e.last,
				expires = tonumber(e.last) + c.dyn_ttl }
		end
	end
	table.sort(dyn, function(a, b) return a.ip < b.ip end)
	if not st.counters then st.counters = counter_totals() end
	st.targets = { prefixes = detail, invalid = invalid, dynamic = dyn, domains = c.domains,
		discover = readjson(RUN .. "/discover.json") }
	local ex = {}
	for _, p in ipairs(exall) do ex[#ex + 1] = p.text end
	st.exempt = ex
	st.exempt_invalid = exbad
	st.config = { action = c.action, log = c.log, check_interval = c.check_interval }
	st.passwall = pw_info()
	st.passwall.auto_rule = c.pw_auto_rule
	st.central = { configured = c.central_url ~= "" }
	st.trace = readjson(RUN .. "/trace.json")
	st.wan = wan_ips()
	st.daemon = { running = daemon_running(), last_check = readjson(RUN .. "/last_check.json") }
	st.conntrack_tool = select(2, run("command -v conntrack >/dev/null")) == 0
	local lg = logs()
	st.counters_since = tonumber(trim(readfile(RUN .. "/counters_since") or ""))
	st.blocks = blocks(lg, st.counters_since)
	local plain = {}
	for i = math.max(1, #lg - 59), #lg do plain[#plain + 1] = lg[i] end
	st.logs = plain
	local a = load_auto()
	local dl = {}
	for _, d in ipairs(sorted_keys(a.domains)) do
		local e = a.domains[d]
		dl[#dl + 1] = { d = d, type = e.type, shared = e.shared, src = e.src, first = e.first, last = e.last }
	end
	local pl = {}
	for _, k in ipairs(sorted_keys(a.prefixes)) do
		local e = a.prefixes[k]
		pl[#pl + 1] = { prefix = k, src = e.src, note = e.note, first = e.first, last = e.last }
	end
	st.lists = { auto_update = c.auto_update, interval = c.update_interval, last_run = a.last_run, last_ok = a.last_ok,
		sources = a.sources, domains = dl, prefixes = pl, outside = a.outside, outside_time = a.outside_time,
		last = readjson(RUN .. "/update.json") }
	local ev = {}
	for l in (readfile(RUN .. "/events.log") or ""):gmatch("[^\n]+") do ev[#ev + 1] = l end
	local from = math.max(1, #ev - 39)
	local evs = {}
	for i = #ev, from, -1 do evs[#evs + 1] = ev[i] end
	st.events = evs
	local crit = {}
	for l in (readfile(ETC .. "/critical.log") or ""):gmatch("[^\n]+") do crit[#crit + 1] = l end
	local cf = {}
	for i = #crit, math.max(1, #crit - 19), -1 do cf[#cf + 1] = crit[i] end
	st.critical = cf
	return st
end

---------------------------------------------------------------- 入口

local function out(v)
	io.write((jsonc.stringify(v) or "null") .. "\n")
end

local function set_enabled(v)
	run("uci set claude_guard.main.enabled=" .. v .. " && uci commit claude_guard")
end

local function main()
	local cmd = arg[1] or "status"
	local c = cfg()
	if cmd == "apply" then
		if not lock(60) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		out(apply(c))
	elseif cmd == "check" then
		if not lock(20) then return out({ ok = false, error = "busy" }) end
		local st = check(c)
		out({ ok = true, overall = st.overall, problems = st.problems })
	elseif cmd == "status" then
		out(status(c, false))
	elseif cmd == "selftest" then
		if not lock(30) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		if c.enabled and not table_exists() then apply(c) end
		canary(c)
		trace(c)
		local st = status(c, false)
		event("手动自检：" .. (st.overall == "ok" and "保护正常" or ("有问题：" .. table.concat(st.problems or {}, "；"))))
		out(st)
	elseif cmd == "repair" then
		if not lock(60) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		local r = apply(c)
		canary(c)
		local st = status(c, false)
		st.apply = r
		event("手动修复：" .. (st.overall == "ok" and "完成，保护正常" or ("仍有问题：" .. table.concat(st.problems or {}, "；"))))
		out(st)
	elseif cmd == "enable" then
		if not lock(60) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		set_enabled("1")
		c = cfg()
		local r = apply(c)
		event("保护已启用（手动）")
		out(r)
	elseif cmd == "disable" then
		if not lock(60) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		set_enabled("0")
		c = cfg()
		local r = apply(c)
		event("保护已停用（手动）：Claude 连接在代理不可用时可能直连宽带", "crit")
		out(r)
	elseif cmd == "discover" then
		out(discover(c, true))
	elseif cmd == "trace" then
		out(trace(c))
	elseif cmd == "update" then
		out(update_lists(c, arg[2] ~= "--auto", arg[2] == "--dry"))
	elseif cmd == "flush" then
		if not lock(30) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		local leaks = scan(c, (targets(c)), load_disc(c), (exempts(c))) or {}
		local n, err = flush_leaks(leaks)
		out({ ok = n ~= nil, found = #leaks, flushed = n, error = err })
	elseif cmd == "scan" then
		-- 只读：按当前判断方法列出直连的 Claude 连接，不清理
		local l = scan(c, (targets(c)), load_disc(c), (exempts(c))) or {}
		out({ count = #l, leaks = l })
	elseif cmd == "reset-counters" then
		out(reset_counters())
	elseif cmd == "ack-audit" then
		local tot = counter_totals()
		writefile(RUN .. "/audit_ack", tostring(tot.audit4.packets + tot.audit6.packets))
		event("已确认审计告警")
		out({ ok = true })
	elseif cmd == "passwall-apply" then
		if not lock(30) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		out(pw_apply(c, arg[2], arg[3] == "restart"))
	elseif cmd == "passwall-remove" then
		if not lock(30) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		out(pw_remove(arg[2] == "restart"))
	elseif cmd == "passwall-ensure" then
		if not lock(30) then return out({ ok = false, error = "另一个操作正在进行，请稍后再试" }) end
		out(pw_ensure(c))
	elseif cmd == "passwall-test" then
		local t = pw_test()
		t.rules = nil
		local rname, have = pw_running_claude()
		t.running_claude = rname
		t.running_config = have
		out(t)
	elseif cmd == "passwall-restart" then
		out(pw_restart())
	elseif cmd == "dry-run" then
		-- 只生成规则并让 nft 做语法检查，不加载
		local _, l4, l6, invalid = targets(c)
		local _, e4, e6, exbad = exempts(c)
		local d4, d6 = {}, {}
		local text = gen(c, l4, l6, d4, d6, e4, e6)
		writefile(RUN .. "/ruleset-dry.nft", text)
		local o, rc = run("nft -c -f " .. RUN .. "/ruleset-dry.nft")
		writefile(RUN .. "/ruleset-min-dry.nft", gen_min(l4, l6))
		local o2, rc2 = run("nft -c -f " .. RUN .. "/ruleset-min-dry.nft")
		out({ ok = rc == 0 and rc2 == 0, file = RUN .. "/ruleset-dry.nft", nft = trim(o), nft_min = trim(o2),
			invalid = invalid, exempt_invalid = exbad })
	elseif cmd == "ruleset" then
		io.write(readfile(RUN .. "/ruleset.nft") or "")
	elseif cmd == "version" then
		out({ version = VERSION })
	else
		out({ ok = false, error = "未知命令：" .. cmd,
			usage = "apply|check|status|selftest|repair|enable|disable|discover|trace|flush|ack-audit|reset-counters|update|passwall-test|passwall-apply <节点ID|_default> [restart]|passwall-ensure|passwall-remove [restart]|passwall-restart|ruleset|dry-run|version" })
	end
end

local ok, err = pcall(main)
if not ok then
	io.write((jsonc.stringify({ ok = false, error = "内部错误：" .. tostring(err) }) or "") .. "\n")
	os.exit(1)
end
