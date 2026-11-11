#!/bin/sh
# Claude 防直连保护 · 看护进程（由 procd 启动并在退出后拉起）
# 1. 每隔 check_interval 秒复核一次；
# 2. 监听 nftables 事件：拦截表被删、规则被改、集合被清空时立刻复核、重装。
# 看护进程本身退出不会影响内核里的拦截规则。

CTL=/usr/libexec/claude-guard/ctl
RUN=/tmp/claude-guard
FIFO=$RUN/monitor.fifo
INTERVAL=$(uci -q get claude_guard.main.check_interval)
[ -n "$INTERVAL" ] || INTERVAL=15

mkdir -p "$RUN"
NFTPID=
# 内存紧张时尽量不杀看护进程（拦截规则在内核里，不依赖这个进程；这里只是让自动修复一直在）
echo -900 > /proc/$$/oom_score_adj 2>/dev/null

start_monitor() {
	rm -f "$FIFO"
	mkfifo "$FIFO" || return 1
	# 只把涉及本插件表的事件送进来。PassWall 重启一次会产生近万行 nft 事件，
	# 不在源头过滤的话，本插件表被删的事件会排在它们后面，反应变慢。
	( nft monitor 2>/dev/null | awk '/inet claude_guard/ { print; fflush() }' ) > "$FIFO" &
	NFTPID=$!
	exec 3<"$FIFO"
}

# 拦截表不见了：不等 Lua，先按上次生成的规则立即装回（几十毫秒），再让复核去清理期间的直连
fast_restore() {
	nft list table inet claude_guard >/dev/null 2>&1 && return 0
	[ "$(uci -q get claude_guard.main.enabled)" = "0" ] && return 0
	[ -s "$RUN/ruleset.nft" ] || return 0
	nft -f "$RUN/ruleset.nft" 2>/dev/null && touch "$RUN/need_flush"
}

# 结束监听子进程和它下面的 nft monitor、awk。
# 不用 pkill：这类固件的 busybox 只带 pgrep，没有 pkill。1.3.0 及以前用的是 pkill，
# 它悄悄失败，每次停看护进程都会留下一对没人管的监听进程。
stop_monitor() {
	local p
	[ -n "$NFTPID" ] || return 0
	for p in $(pgrep -P "$NFTPID" 2>/dev/null); do kill "$p" 2>/dev/null; done
	kill "$NFTPID" 2>/dev/null
	NFTPID=
}

# 清掉以前的看护进程留下的东西：
# 1. 上一个看护主进程被强杀（来不及清理）时留下的监听子进程，连同它下面的 nft monitor、awk；
# 2. 父进程已经不在（变成 1）的 nft monitor 和本插件的过滤 awk。
# 看护进程由 procd 管，同时只有一个；所以除了自己以外、父进程是 1 的 daemon.sh 都是留下来的。
reap_stale() {
	local p c k
	for p in $(pgrep -f "claude-guard/daemon.s[h]" 2>/dev/null); do
		[ "$p" = "$$" ] && continue
		[ "$(awk '{print $4}' /proc/$p/stat 2>/dev/null)" = 1 ] || continue
		for k in $(pgrep -P "$p" 2>/dev/null); do kill "$k" 2>/dev/null; done
		kill "$p" 2>/dev/null
	done
	for p in $(pgrep -x nft 2>/dev/null) $(pgrep -x awk 2>/dev/null); do
		[ "$(awk '{print $4}' /proc/$p/stat 2>/dev/null)" = 1 ] || continue
		c=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
		case "$c" in
			"nft monitor "|"awk /inet claude_guard/"*) kill "$p" 2>/dev/null ;;
		esac
	done
}

cleanup() {
	stop_monitor
	rm -f "$FIFO"
	exit 0
}
trap cleanup TERM INT

reap_stale
start_monitor
last=0
while :; do
	now=$(date +%s)
	if [ $((now - last)) -ge "$INTERVAL" ]; then
		fast_restore
		$CTL check >/dev/null 2>&1
		last=$(date +%s)
	fi
	if [ -n "$NFTPID" ] && kill -0 "$NFTPID" 2>/dev/null; then
		if read -r -t "$INTERVAL" line <&3; then
			# 有事件涉及本插件的表：立刻处理，不等
			fast_restore
			$CTL check >/dev/null 2>&1
			# 自己重装规则也会产生事件：读完这一阵，再复核一次确认
			seen=0
			while read -r -t 1 more <&3; do seen=1; done
			[ "$seen" = 1 ] && { fast_restore; $CTL check >/dev/null 2>&1; }
			last=$(date +%s)
		fi
	else
		# 监听退出了：重新拉起，期间靠定时复核
		exec 3<&-
		stop_monitor
		reap_stale
		start_monitor
		sleep 1
	fi
done
