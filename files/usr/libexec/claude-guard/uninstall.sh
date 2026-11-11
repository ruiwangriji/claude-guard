#!/bin/sh
# Claude 防直连保护 · 卸载
#   sh /usr/libexec/claude-guard/uninstall.sh              卸下规则、删除插件文件
#   sh /usr/libexec/claude-guard/uninstall.sh --passwall   同时删除 PassWall 里的 Claude 分流规则并重启 PassWall（等它重启完才卸保护）
# PassWall 改动前的原配置备份保留在 /etc/claude-guard/backup/

if [ "$1" = "--passwall" ]; then
	# 先删规则，再在这里同步重启 PassWall，等它重启完才卸保护：
	# 否则 PassWall 重启的那几秒里保护已经不在，Claude 连接会直接走宽带。
	OUT=$(/usr/libexec/claude-guard/ctl passwall-remove)
	echo "$OUT"
	case "$OUT" in
		*'"ok":true'*)
			if nft list table inet passwall >/dev/null 2>&1; then
				echo "重启 PassWall，让删除生效（期间 Claude 连接仍被拦下）……"
				/etc/init.d/passwall restart >/dev/null 2>&1
			fi ;;
	esac
fi

/etc/init.d/claude-guard stop 2>/dev/null
# 后台可能正好有一次自动更新、解析在跑，等它们结束，免得卸载后又写回文件
i=0
while [ $i -lt 10 ] && pgrep -f "claude-guard/guard.lu[a]" >/dev/null 2>&1; do sleep 1; i=$((i + 1)); done
for p in $(pgrep -f "claude-guard/guard.lu[a]" 2>/dev/null); do kill "$p" 2>/dev/null; done
# 旧版（1.3.0 及以前）停看护进程时会留下没人管的监听进程，一并清掉
for p in $(pgrep -x nft 2>/dev/null) $(pgrep -x awk 2>/dev/null); do
	[ "$(awk '{print $4}' /proc/$p/stat 2>/dev/null)" = 1 ] || continue
	case "$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)" in
		"nft monitor "|"awk /inet claude_guard/"*) kill "$p" 2>/dev/null ;;
	esac
done
/usr/libexec/claude-guard/ctl disable >/dev/null 2>&1
nft list table inet claude_guard >/dev/null 2>&1 && nft delete table inet claude_guard
/etc/init.d/claude-guard disable 2>/dev/null

MANIFEST=/etc/claude-guard/manifest
if [ -f "$MANIFEST" ]; then
	while read -r f; do
		case "$f" in
			/etc/claude-guard/*) ;;
			/*) rm -f "$f" ;;
		esac
	done < "$MANIFEST"
fi
rm -f /etc/rc.d/S1[38]claude-guard /etc/rc.d/K99claude-guard
rm -f /etc/claude-guard/static.list /etc/claude-guard/discovered.json /etc/claude-guard/manifest /etc/claude-guard/critical.log /etc/claude-guard/auto.json
rm -f /etc/config/claude_guard
rmdir /usr/libexec/claude-guard /www/luci-static/resources/view/claude-guard 2>/dev/null
rm -rf /tmp/claude-guard /tmp/luci-indexcache* /tmp/luci-modulecache
/etc/init.d/rpcd reload 2>/dev/null
logger -t claude-guard -p daemon.warn "插件已卸载"
# 没有 PassWall 备份时连目录一起删；有备份就留着
rmdir /etc/claude-guard/backup 2>/dev/null
if rmdir /etc/claude-guard 2>/dev/null; then
	echo "已卸载。"
else
	echo "已卸载。PassWall 配置备份留在 /etc/claude-guard/backup/"
fi
