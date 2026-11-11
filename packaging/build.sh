#!/bin/sh
# Claude 防直连 · 打包并生成签名软件源（原型）
#
# 在 Alpine 3.24 以上（apk-tools 3、openssl、signify、GNU tar、gzip；apk add openssl signify tar）里运行，不需要 OpenWrt SDK。
#   sh build.sh <插件目录> <输出目录> <apk私钥.pem> <ipk私钥（usign/signify 格式）> [包修订号，默认 1] [软件源地址前缀]
# 例：sh build.sh ./claude-guard ./out keys/apk.key keys/ipk.sec 1 https://feed.example.com/claude-guard/stable
#
# 输出：
#   <输出>/apk/luci-app-claude-guard-<版本>-r<修订>.apk + packages.adb（已签名）     ← 25.12 起的固件
#   <输出>/ipk/luci-app-claude-guard_<版本>-r<修订>_all.ipk + Packages(.gz/.sig)     ← 24.10 及更早
#   <输出>/keys/claude-guard.pem、claude-guard-ipk.pub                                 ← 公钥
#   <输出>/setup.sh                                                                     ← 客户路由一次性设置脚本
# 旧版本的包请自己保留在输出目录里再运行（索引会把目录里所有版本都收进去，方便退回）。
#
# 包里的安装、升级、卸载脚本按 OpenWrt 25.12 的 include/package-pack.mk 生成，另加：
#   升级后重启看护进程（apk 升级只执行 start，看护进程不会换成新代码）；
#   真卸载（不是升级）时卸下拦截规则（插件的 stop 不卸规则）；
#   公钥由 setup.sh 写入（不归包管，卸载时不删），公钥路径加进刷固件保留列表。
set -eu

SRC=$1; OUT=$2; APKKEY=$3; IPKKEY=$4; REL=${5:-1}; FEED=${6:-https://feed.example.com/claude-guard/stable}
PKG=luci-app-claude-guard
VER=$(sed -n 's/^local VERSION = "\(.*\)"/\1/p' "$SRC/files/usr/libexec/claude-guard/guard.lua")
[ -n "$VER" ] || { echo "读不到 guard.lua 里的 VERSION"; exit 1; }
FULLVER="$VER-r$REL"
DEPS_APK="lua luci-lib-nixio luci-lib-jsonc libuci-lua curl conntrack firewall4 luci-base"
DEPS_IPK="lua, luci-lib-nixio, luci-lib-jsonc, libuci-lua, curl, conntrack, firewall4, luci-base"
CONFFILES="/etc/config/claude_guard
/etc/claude-guard/static.list"
DESC="Claude 防直连：代理不在时拦下 Claude 直连宽带"

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$OUT/apk" "$OUT/ipk" "$OUT/keys"

# ---- 公钥
openssl ec -in "$APKKEY" -pubout -out "$OUT/keys/claude-guard.pem" 2>/dev/null
IPKPUB="$OUT/keys/claude-guard-ipk.pub"
[ -f "${IPKKEY%.sec}.pub" ] && cp "${IPKKEY%.sec}.pub" "$IPKPUB"
[ -f "$IPKPUB" ] || { echo "找不到 ipk 公钥 ${IPKKEY%.sec}.pub"; exit 1; }
# usign 的指纹 = 公钥里 2 字节算法名之后的 8 字节 key id（十六进制）
FP=$(sed -n 2p "$IPKPUB" | base64 -d | dd bs=1 skip=2 count=8 2>/dev/null | od -An -tx1 | tr -d ' \n')

# ---- 文件树（两种格式共用，只差公钥放的位置）
stage() { # $1=目录 $2=apk|ipk
	local R=$1
	mkdir -p "$R"
	cp -a "$SRC/files/." "$R/"
	find "$R" -name '.DS_Store' -delete
	chmod 755 "$R/etc/init.d/claude-guard" "$R/etc/hotplug.d/iface/15-claude-guard" \
		"$R/usr/libexec/claude-guard/ctl" "$R/usr/libexec/claude-guard/daemon.sh" "$R/usr/libexec/claude-guard/uninstall.sh"
	# 公钥不放进包里：由 setup.sh 写入，卸载插件时留着（源地址也留着），否则只剩源地址没有公钥，
	# 这台路由器以后所有 apk 操作都会因为「源不可用」被拒。只把公钥路径加进刷固件保留列表。
	if [ "$2" = apk ]; then
		echo /etc/apk/keys/claude-guard.pem >> "$R/lib/upgrade/keep.d/claude-guard"
	else
		echo "/etc/opkg/keys/$FP" >> "$R/lib/upgrade/keep.d/claude-guard"
	fi
}

# ---- 脚本
HEAD='[ -s "${IPKG_INSTROOT}/lib/functions.sh" ] || exit 0
. "${IPKG_INSTROOT}/lib/functions.sh"
export root="${IPKG_INSTROOT}"
export pkgname="'$PKG'"'
cat > "$T/postinst" <<EOF
#!/bin/sh
[ "\${IPKG_NO_SCRIPT}" = "1" ] && exit 0
$HEAD
if [ -n "\${IPKG_INSTROOT}" ]; then default_postinst; exit 0; fi
mkdir -p /etc/claude-guard/backup
uci -q get claude_guard.main.enabled >/dev/null || { uci -q set claude_guard.main.enabled=1; uci -q commit claude_guard; }
default_postinst
# 升级：换上新的看护进程（stop 不卸规则，restart 时保护不断）
[ "\${PKG_UPGRADE}" = "1" ] && /etc/init.d/claude-guard restart >/dev/null 2>&1
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache
[ -x /etc/init.d/rpcd ] && /etc/init.d/rpcd reload >/dev/null 2>&1
exit 0
EOF
cat > "$T/prerm" <<EOF
#!/bin/sh
$HEAD
default_prerm
[ -n "\${IPKG_INSTROOT}" ] && exit 0
# 真卸载才卸规则；升级时（PKG_UPGRADE=1，opkg 升级也会走到这里）保留
if [ "\${PKG_UPGRADE}" != "1" ]; then
	i=0; while [ \$i -lt 10 ] && pgrep -f "claude-guard/guard.lu[a]" >/dev/null 2>&1; do sleep 1; i=\$((i + 1)); done
	# 这类固件的 busybox 没有 pkill（插件 1.3.1 起同样改用 pgrep + kill）
	for p in \$(pgrep -f "claude-guard/guard.lu[a]" 2>/dev/null); do kill "\$p" 2>/dev/null; done
	nft list table inet claude_guard >/dev/null 2>&1 && nft delete table inet claude_guard
	logger -t claude-guard -p daemon.warn "插件已卸载，拦截规则已卸下"
fi
exit 0
EOF
cat > "$T/postrm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
[ "${PKG_UPGRADE}" = "1" ] && exit 0
rm -f /etc/claude-guard/discovered.json /etc/claude-guard/auto.json /etc/claude-guard/critical.log /etc/claude-guard/manifest
rmdir /etc/claude-guard/backup /etc/claude-guard 2>/dev/null
rm -rf /tmp/claude-guard /tmp/luci-indexcache* /tmp/luci-modulecache
[ -x /etc/init.d/rpcd ] && /etc/init.d/rpcd reload >/dev/null 2>&1
exit 0
EOF
{ echo '#!/bin/sh'; echo 'export PKG_UPGRADE=1'; sed 1d "$T/postinst"; } > "$T/post-upgrade"

# ---- apk
R=$T/apkroot; stage "$R" apk
mkdir -p "$R/lib/apk/packages"
echo "$CONFFILES" > "$R/lib/apk/packages/$PKG.conffiles"
echo "$CONFFILES" | while read -r f; do echo "$f $(sha256sum "$R$f" | cut -d' ' -f1)"; done > "$R/lib/apk/packages/$PKG.conffiles_static"
( cd "$R" && find . -type f -o -type l | sed 's#^\.##' | sort ) > "$T/list"; mv "$T/list" "$R/lib/apk/packages/$PKG.list"
apk mkpkg --compat 3.0.5 \
	--info "name:$PKG" --info "version:$FULLVER" --info "arch:noarch" \
	--info "description:$DESC" --info "license:GPL-3.0-or-later" --info "origin:$PKG" \
	--info "depends:$DEPS_APK" \
	--script "post-install:$T/postinst" --script "post-upgrade:$T/post-upgrade" \
	--script "pre-deinstall:$T/prerm" --script "post-deinstall:$T/postrm" \
	--files "$R" --output "$OUT/apk/$PKG-$FULLVER.apk"
( cd "$OUT/apk" && apk mkndx --allow-untrusted --sign-key "$APKKEY" --output packages.adb *.apk )

# ---- ipk
R=$T/ipkroot; stage "$R" ipk
C=$T/control; mkdir -p "$C"
cat > "$C/control" <<EOF
Package: $PKG
Version: $FULLVER
Depends: $DEPS_IPK
Source: $PKG
License: GPL-3.0-or-later
Section: luci
Architecture: all
Installed-Size: $(du -sk "$R" | cut -f1)000
Description: $DESC
EOF
echo "$CONFFILES" > "$C/conffiles"
cp "$T/postinst" "$C/postinst"; cp "$T/prerm" "$C/prerm"; cp "$T/postrm" "$C/postrm"
chmod 755 "$C/postinst" "$C/prerm" "$C/postrm"
echo 2.0 > "$T/debian-binary"
( cd "$R" && tar --owner=0 --group=0 --numeric-owner -czf "$T/data.tar.gz" . )
( cd "$C" && tar --owner=0 --group=0 --numeric-owner -czf "$T/control.tar.gz" . )
( cd "$T" && tar --owner=0 --group=0 --numeric-owner -czf "$OUT/ipk/${PKG}_${FULLVER}_all.ipk" ./debian-binary ./data.tar.gz ./control.tar.gz )
: > "$OUT/ipk/Packages"
for p in "$OUT"/ipk/*.ipk; do
	tar xzf "$p" -O ./control.tar.gz | tar xzf - -O ./control >> "$OUT/ipk/Packages"
	printf "Filename: %s\nSize: %s\nSHA256sum: %s\n\n" "$(basename "$p")" "$(stat -c %s "$p")" "$(sha256sum "$p" | cut -d' ' -f1)" >> "$OUT/ipk/Packages"
done
gzip -9nc "$OUT/ipk/Packages" > "$OUT/ipk/Packages.gz"
rm -f "$OUT/ipk/Packages.sig"
signify -S -s "$IPKKEY" -m "$OUT/ipk/Packages" -x "$OUT/ipk/Packages.sig"

# ---- 客户路由一次性设置脚本（公钥直接写在脚本里，不用另外下载）
cat > "$OUT/setup.sh" <<EOF
#!/bin/sh
# Claude 防直连：添加软件源并安装（路由器上以 root 运行一次）
FEED="$FEED"
PKG=$PKG
set -e
if command -v apk >/dev/null 2>&1; then
	mkdir -p /etc/apk/keys /etc/apk/repositories.d
	cat > /etc/apk/keys/claude-guard.pem <<'KEY'
$(cat "$OUT/keys/claude-guard.pem")
KEY
	L=/etc/apk/repositories.d/customfeeds.list
	grep -qxF "\$FEED/apk/packages.adb" "\$L" 2>/dev/null || echo "\$FEED/apk/packages.adb" >> "\$L"
	apk update || true
	apk add "\$PKG"
elif command -v opkg >/dev/null 2>&1; then
	mkdir -p /etc/opkg/keys
	cat > /etc/opkg/keys/$FP <<'KEY'
$(cat "$IPKPUB")
KEY
	L=/etc/opkg/customfeeds.conf
	grep -q "^src/gz claude_guard " "\$L" 2>/dev/null || echo "src/gz claude_guard \$FEED/ipk" >> "\$L"
	opkg update || true
	opkg install "\$PKG"
else
	echo "这台路由器没有 apk 也没有 opkg"; exit 1
fi
echo "装好了。管理页：服务 → Claude 防直连"
EOF

echo "版本 $FULLVER"
ls -l "$OUT/apk" "$OUT/ipk"
