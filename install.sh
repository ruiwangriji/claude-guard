#!/bin/sh
# Claude 防直连保护 · 安装（在路由器上运行）
#   sh install.sh                  安装并启用
#   sh install.sh --deadman 180    安装并启用；180 秒内不执行 `ctl confirm` 就自动停用并卸下规则
# 已有的 /etc/config/claude_guard 会保留；static.list 有改动时先备份。

set -e
HERE=$(cd "$(dirname "$0")" && pwd)
DEADMAN=0
[ "$1" = "--deadman" ] && DEADMAN="${2:-180}"

echo "== 检查依赖"
command -v nft >/dev/null || { echo "这台路由器没有 nft（不是 nftables / fw4 固件），本插件装不了"; exit 1; }

# 插件本身只依赖这几样，不依赖 PassWall。没装过 PassWall 的路由器上它们通常不在，这里自己装。
# 必须有：lua 和三个 Lua 库；最好有：curl（更新目标列表、检测出口）、conntrack（清理残留直连）。
missing() {
	local m=""
	if command -v lua >/dev/null 2>&1; then
		lua -e 'require "nixio"; require "nixio.fs"' 2>/dev/null || m="$m luci-lib-nixio"
		lua -e 'require "luci.jsonc"' 2>/dev/null || m="$m luci-lib-jsonc"
		lua -e 'require "uci"' 2>/dev/null || m="$m libuci-lua"
	else
		m="$m lua luci-lib-nixio luci-lib-jsonc libuci-lua"
	fi
	[ "$1" = "all" ] && {
		command -v curl >/dev/null 2>&1 || m="$m curl"
		command -v conntrack >/dev/null 2>&1 || m="$m conntrack"
	}
	echo $m
}
pkg_install() {
	if command -v apk >/dev/null 2>&1; then
		apk update >/dev/null 2>&1 || true
		apk add "$@"
	elif command -v opkg >/dev/null 2>&1; then
		opkg update >/dev/null 2>&1 || true
		opkg install "$@"
	else
		echo "没有找到 apk 或 opkg"; return 127
	fi
}
NEED=$(missing all)
if [ -n "$NEED" ]; then
	echo "缺少：$NEED，正在从软件源安装……"
	pkg_install $NEED >/tmp/claude-guard-deps.log 2>&1 || true
	MUST=$(missing)
	if [ -n "$MUST" ]; then
		echo "装不上必须的软件包：$MUST"
		echo "请确认路由器能上网、软件源可用后重试；安装过程的输出在 /tmp/claude-guard-deps.log"
		exit 1
	fi
	LEFT=$(missing all)
	[ -n "$LEFT" ] && echo "警告：$LEFT 没装上。没有 curl 时不能更新目标列表，没有 conntrack 时不能清理残留的直连连接；拦截本身不受影响" || echo "依赖已装齐"
fi

echo "== 语法检查"
lua -e "assert(loadfile('$HERE/files/usr/libexec/claude-guard/guard.lua'))"
sh -n "$HERE/files/usr/libexec/claude-guard/daemon.sh"
sh -n "$HERE/files/usr/libexec/claude-guard/ctl"
sh -n "$HERE/files/etc/init.d/claude-guard"

echo "== 复制文件"
mkdir -p /etc/claude-guard/backup
TS=$(date +%Y%m%d-%H%M%S)
( cd "$HERE/files" && find . -type f | sed 's#^\./#/#' | sort ) > /tmp/claude-guard-manifest.new
while read -r f; do
	case "$f" in
		/etc/config/claude_guard)
			if [ -f "$f" ]; then echo "保留已有配置 $f"; continue; fi ;;
		/etc/claude-guard/static.list)
			if [ -f "$f" ] && ! cmp -s "$HERE/files$f" "$f"; then
				cp "$f" "/etc/claude-guard/backup/static.list.$TS"
				echo "原 static.list 已备份为 /etc/claude-guard/backup/static.list.$TS"
			fi ;;
	esac
	mkdir -p "$(dirname "$f")"
	cp "$HERE/files$f" "$f"
done < /tmp/claude-guard-manifest.new
mv /tmp/claude-guard-manifest.new /etc/claude-guard/manifest
chmod 755 /etc/init.d/claude-guard /etc/hotplug.d/iface/15-claude-guard \
	/usr/libexec/claude-guard/ctl /usr/libexec/claude-guard/daemon.sh /usr/libexec/claude-guard/uninstall.sh
chmod 644 /usr/libexec/claude-guard/guard.lua /etc/config/claude_guard /etc/claude-guard/static.list

echo "== 启用"
/etc/init.d/claude-guard enable
if [ "$DEADMAN" -gt 0 ]; then
	mkdir -p /tmp/claude-guard
	rm -f /tmp/claude-guard/confirmed
	setsid sh -c "sleep $DEADMAN; if [ ! -f /tmp/claude-guard/confirmed ]; then logger -t claude-guard -p daemon.crit '安装后 $DEADMAN 秒未确认，自动回滚：停用并卸下规则'; /usr/libexec/claude-guard/ctl disable; /etc/init.d/claude-guard stop; /etc/init.d/claude-guard disable; fi" >/dev/null 2>&1 </dev/null &
	echo "已设自动回滚：$DEADMAN 秒内执行 /usr/libexec/claude-guard/ctl confirm 取消"
fi
uci -q get claude_guard.main.enabled >/dev/null || { uci set claude_guard.main.enabled=1; uci commit claude_guard; }
/etc/init.d/claude-guard restart 2>&1 | grep -v "ubus call service delete" || true

rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache
/etc/init.d/rpcd reload

echo "== 当前状态"
/usr/libexec/claude-guard/ctl check
echo "安装完成。管理页：服务 → Claude 防直连"
