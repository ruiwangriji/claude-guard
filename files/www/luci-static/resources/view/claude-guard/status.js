'use strict';
'require view';
'require fs';
'require ui';
'require poll';
'require dom';

/* 版式参考了 unslop（Damir Sokolovsky，@heydamir，CC BY 4.0，https://github.com/heydamir/unslop）的审查方法：
   界面本身不上色，颜色只留给线路和「被拦下」这两处。 */

var CTL = '/usr/libexec/claude-guard/ctl';
var EASE = 'cubic-bezier(.22,1,.36,1)';
var MONO = 'ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace';

var CSS = [
	/* 底色、分隔线和三档文字都从当前文字颜色按比例取，所以跟着路由器主题走（浅色、深色都行） */
	'.cg{max-width:1120px;font-size:14px;line-height:20px;--ok:#16a34a;--bad:#dc2626;--warn:#b45309;--line:rgba(128,128,128,.24);--raise:rgba(128,128,128,.08);--t2:inherit;--t3:inherit;--bg:#fff}',
	'@supports (color:color-mix(in srgb,red 50%,blue)){.cg{--line:color-mix(in srgb,currentColor 11%,transparent);--raise:color-mix(in srgb,currentColor 5%,transparent);--t2:color-mix(in srgb,currentColor 72%,transparent);--t3:color-mix(in srgb,currentColor 56%,transparent)}}',
	'.cg *{box-sizing:border-box}',
	'.cg-card{padding:24px;margin:0 0 16px}',
	'.cg-i{display:inline-flex;width:16px;height:16px;flex:none}.cg-i svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}',
	'.cg-mono{font-family:' + MONO + ';font-variant-numeric:tabular-nums;font-size:12px}',
	'.cg-2{color:var(--t2)}.cg-3{color:var(--t3)}',
	/* 顶部：状态一句话 */
	'.cg-top{display:flex;align-items:flex-start;gap:16px}',
	'.cg-head{flex:1;min-width:0}',
	'.cg-state{display:flex;align-items:center;gap:12px;font-size:20px;line-height:28px;font-weight:500}',
	'.cg-dot{width:10px;height:10px;border-radius:50%;background:var(--t3);flex:none}',
	'.cg-ok .cg-dot{background:var(--ok)}.cg-warn .cg-dot{background:var(--warn)}.cg-bad .cg-dot{background:var(--bad)}',
	'.cg-desc{margin:4px 0 0 22px;color:var(--t2);max-width:640px}',
	'.cg-acts{display:flex;gap:8px;flex:none;position:relative}',
	'.cg-b{display:inline-flex;align-items:center;gap:4px;height:32px;padding:0 12px;margin:0;border-radius:8px;border:1px solid var(--line);background:transparent;color:inherit;font-size:13px;line-height:20px;font-weight:400;white-space:nowrap;cursor:pointer;box-shadow:none;text-transform:none;min-height:0;transition:background-color .15s ' + EASE + '}',
	'.cg-b:hover{background:var(--raise)}.cg-b:focus-visible{outline:2px solid var(--t3);outline-offset:2px}',
	'.cg-b.sm{height:28px;padding:0 8px;font-size:12px}',
	'.cg-b.pri{background:var(--ok);border-color:var(--ok);color:#fff}.cg-b.pri:hover{background:var(--ok);opacity:.92}',
	'details.cg-menu{position:relative}details.cg-menu>summary{list-style:none}details.cg-menu>summary::-webkit-details-marker{display:none}',
	'.cg-items{position:absolute;right:0;top:36px;z-index:20;min-width:176px;padding:4px;border-radius:12px;border:1px solid var(--line);background:var(--bg);box-shadow:0 8px 24px rgba(0,0,0,.08)}',
	'.cg-items button{display:block;width:100%;height:32px;padding:0 8px;margin:0;text-align:left;border:none;border-radius:8px;background:none;color:inherit;font-size:13px;font-weight:400;cursor:pointer;box-shadow:none;text-transform:none;min-height:0}',
	'.cg-items button:hover{background:var(--raise)}.cg-items button.cg-dg{color:var(--bad)}',
	/* 线路：设备 → 代理 → Claude。整页只有这里和「被拦下」有颜色 */
	'.cg-route{display:grid;grid-template-columns:repeat(3,1fr);margin-top:32px}',
	'.cg-route.two{grid-template-columns:repeat(2,1fr)}',
	'.cg-st{position:relative;padding:24px 24px 0 0;min-width:0}',
	'.cg-st:before{content:"";position:absolute;left:14px;right:4px;top:4px;height:2px;background:var(--ok)}',
	'.cg-st:last-child:before{display:none}',
	'.cg-st:after{content:"";position:absolute;left:0;top:0;width:10px;height:10px;border-radius:50%;background:var(--ok)}',
	'.cg-route.idle .cg-st:before{background:repeating-linear-gradient(90deg,var(--t3) 0 4px,transparent 4px 8px)}',
	'.cg-route.idle .cg-st:after,.cg-route.cut .cg-st:after{background:var(--bg);border:2px solid var(--t3)}',
	'.cg-route.cut .cg-st:before{background:repeating-linear-gradient(90deg,var(--bad) 0 4px,transparent 4px 8px)}',
	'.cg-cut{position:absolute;top:-3px;left:50%;margin-left:-8px;color:var(--bad);background:var(--bg)}',
	'.cg-k{font-size:12px;line-height:16px;color:var(--t3)}',
	'.cg-v{font-size:16px;line-height:24px;font-weight:500;margin-top:4px;overflow-wrap:anywhere}',
	'.cg-n{font-size:13px;line-height:20px;color:var(--t2);margin-top:4px}',
	'.cg-n .cg-b{margin-top:4px}',
	'.cg-branch{display:flex;align-items:flex-start;gap:12px;margin-top:24px;padding-top:20px;border-top:1px solid var(--line)}',
	'.cg-branch>.cg-i{margin-top:2px;color:var(--bad)}.cg-branch.open>.cg-i{color:var(--warn)}',
	'.cg-grow{flex:1;min-width:0}',
	'.cg-fig{text-align:right;flex:none}',
	'.cg-num{font-family:' + MONO + ';font-variant-numeric:tabular-nums;font-size:28px;line-height:32px;font-weight:500}',
	'.cg-pend{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin-top:20px;padding:12px 16px;border-radius:8px;background:var(--raise)}',
	'.cg-pend .cg-dot{background:var(--warn)}',
	/* 提醒 */
	'.cg-alerts{margin:0 0 16px;padding:16px 24px}',
	'.cg-al{display:flex;gap:12px;align-items:flex-start;padding:4px 0}.cg-al .cg-dot{background:var(--warn);margin-top:5px}',
	/* 详细内容：一张列表，细线分隔 */
	'.cg-list{padding:4px 24px;margin:0 0 16px}',
	'details.cg-row{border-top:1px solid var(--line)}details.cg-row:first-child{border-top:none}',
	'details.cg-row>summary{display:flex;align-items:center;gap:12px;min-height:48px;cursor:pointer;list-style:none}',
	'details.cg-row>summary::-webkit-details-marker{display:none}',
	'details.cg-row>summary>.cg-i{color:var(--t3);transition:transform .15s ' + EASE + '}',
	'details.cg-row[open]>summary>.cg-i{transform:rotate(90deg)}',
	'.cg-sum{margin-left:auto;color:var(--t3);text-align:right;font-size:13px}',
	'.cg-body{padding:0 0 20px 28px}',
	'.cg-body h5{margin:20px 0 8px;font-size:13px;line-height:20px;font-weight:500}',
	'.cg-body h5:first-child{margin-top:0}',
	'.cg-body p{margin:8px 0 0;font-size:13px;color:var(--t2)}',
	'.cg-s{display:inline-flex;align-items:center;gap:8px;white-space:nowrap}.cg-s i{width:8px;height:8px;border-radius:50%;background:var(--t3)}',
	'.cg-s.ok i{background:var(--ok)}.cg-s.bad i{background:var(--bad)}',
	'.cg-chips{display:flex;flex-wrap:wrap;gap:4px}',
	'.cg-chip{font-family:' + MONO + ';font-size:12px;line-height:20px;padding:0 8px;border:1px solid var(--line);border-radius:4px}',
	'.cg-chip.sh{color:var(--t3)}',
	'.cg-rec{display:flex;gap:16px;padding:8px 0;border-top:1px solid var(--line)}.cg-rec:first-child{border-top:none;padding-top:0}',
	'.cg-rec .t{flex:0 0 120px;color:var(--t3)}',
	'.cg-pre{white-space:pre-wrap;word-break:break-all;font-family:' + MONO + ';font-size:12px;line-height:16px;max-height:320px;overflow:auto;margin:0;padding:12px;border-radius:8px;background:var(--raise)}',
	'.cg table.table td,.cg table.table th{padding:8px;font-size:13px}',
	'.cg-form select{width:100%;margin:8px 0 4px}.cg-form p.s{font-size:13px;opacity:.75}',
	'@media (max-width:720px){.cg-card{padding:20px 16px}.cg-list{padding:4px 16px}.cg-top{flex-wrap:wrap}.cg-head{flex:1 1 100%}.cg-acts{margin-left:22px}.cg-route,.cg-route.two{grid-template-columns:1fr}.cg-st{padding:0 0 24px 24px}.cg-st:last-child{padding-bottom:0}.cg-st:before{left:4px;right:auto;top:14px;bottom:4px;width:2px;height:auto}.cg-route.idle .cg-st:before{background:repeating-linear-gradient(180deg,var(--t3) 0 4px,transparent 4px 8px)}.cg-route.cut .cg-st:before{background:repeating-linear-gradient(180deg,var(--bad) 0 4px,transparent 4px 8px)}.cg-st:after{top:5px}.cg-cut{left:-3px;top:50%;margin:-8px 0 0}.cg-body{padding-left:0}.cg-rec{flex-direction:column;gap:0}.cg-rec .t{flex:none}}'
].join('\n');

/* 一套线条图标，同一大小、同一线宽（路径取自 lucide，ISC 许可） */
var ICONS = {
	right: '<path d="m9 18 6-6-6-6"/>',
	down: '<path d="m6 9 6 6 6-6"/>',
	ban: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
	x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>'
};
function icon(name, cls) {
	var s = E('span', { 'class': 'cg-i ' + (cls || '') });
	s.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true">' + ICONS[name] + '</svg>';
	return s;
}

function ctl(args) {
	return fs.exec(CTL, args).then(function(res) {
		var out = (res.stdout || '').trim();
		if (!out) throw new Error((res.stderr || '').trim() || ('命令退出码 ' + res.code));
		var lines = out.split('\n');
		return JSON.parse(lines[lines.length - 1]);
	});
}

function pad(n) { return (n < 10 ? '0' : '') + n; }
var TZ = null;   // 路由器时区相对 UTC 的分钟数；拿不到时退回浏览器本地时间
function setTz(z) {
	var m = /^([+-])(\d\d)(\d\d)$/.exec(z || '');
	TZ = m ? (m[1] === '-' ? -1 : 1) * (parseInt(m[2], 10) * 60 + parseInt(m[3], 10)) : null;
}
function fmtTime(ts) {
	if (!ts) return '—';
	if (TZ === null) {
		var l = new Date(ts * 1000);
		return (l.getMonth() + 1) + '-' + pad(l.getDate()) + ' ' + pad(l.getHours()) + ':' + pad(l.getMinutes());
	}
	var d = new Date((ts + TZ * 60) * 1000);
	return (d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
}
function ago(ts, now) {
	if (!ts) return '从未';
	var s = Math.max(0, (now || Math.floor(Date.now() / 1000)) - ts);
	if (s < 60) return '刚刚';
	if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
	if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
	return Math.floor(s / 86400) + ' 天前';
}
function num(n) { return String(n || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
function mark(state, text) {
	return E('span', { 'class': 'cg-s ' + (state === true ? 'ok' : state === false ? 'bad' : '') }, [E('i'), text]);
}
function mono(t) { return E('span', { 'class': 'cg-mono' }, t); }
function tbl(head, rows, empty) {
	var t = E('table', { 'class': 'table' });
	t.appendChild(E('tr', { 'class': 'tr table-titles' }, head.map(function(h) { return E('th', { 'class': 'th left' }, h); })));
	if (!rows.length)
		t.appendChild(E('tr', { 'class': 'tr' }, E('td', { 'class': 'td left', 'colspan': head.length }, E('em', {}, empty || '无'))));
	rows.forEach(function(r) {
		t.appendChild(E('tr', { 'class': 'tr' }, r.map(function(c) { return E('td', { 'class': 'td left' }, c); })));
	});
	return t;
}
function cnt(c, k) { return ((c || {})[k] || {}).packets || 0; }
function who(b) { return b.kind === 'OUT' ? '路由器自己' : (b.host || b.src || ''); }
function station(k, v, notes, extra) {
	return E('div', { 'class': 'cg-st' }, [extra || '', E('div', { 'class': 'cg-k' }, k), E('div', { 'class': 'cg-v' }, v)].concat(
		(notes || []).filter(Boolean).map(function(n) { return E('div', { 'class': 'cg-n' }, n); })));
}

var SRC = { 'static': '内置', 'extra': '手动添加', 'builtin': '内置', 'auto': '自动更新' };
var SOURCE_NAME = { central: '统一列表', ARIN: 'ARIN 登记网段', BGP: 'AS399358 路由公告', geosite: '本地 geosite', v2fly: 'v2fly 在线列表' };
var KIND = { FWD: '家里的设备', OUT: '路由器自己', AUDIT: '出网审计' };
var COUNTRY = { US: '美国', JP: '日本', SG: '新加坡', HK: '香港', TW: '台湾', KR: '韩国', GB: '英国', DE: '德国', FR: '法国', NL: '荷兰',
	CA: '加拿大', AU: '澳大利亚', IN: '印度', CN: '中国大陆' };
function place(tr) {
	var c = COUNTRY[tr.loc] || tr.loc || '未知地区';
	return tr.colo ? (c + '（' + tr.colo + '）') : c;
}

return view.extend({
	open: {},

	load: function() {
		return ctl(['status']).catch(function(e) { return { overall: 'error', error: e.message }; });
	},

	act: function(args, busy, done) {
		ui.showModal('请稍候', [E('p', { 'class': 'spinning' }, busy)]);
		this.open.menu = false;
		return ctl(args).then(L.bind(function(r) {
			ui.hideModal();
			if (r && r.ok === false && r.error)
				ui.addNotification(null, E('p', {}, '没有成功：' + r.error), 'danger');
			else
				ui.addNotification(null, E('p', {}, typeof done === 'function' ? done(r) : done), 'info');
			return this.refresh();
		}, this)).catch(L.bind(function(e) {
			ui.hideModal();
			ui.addNotification(null, E('p', {}, '执行出错：' + e.message), 'danger');
			return this.refresh();
		}, this));
	},

	/* 现在是哪种情况：off 停用、bad 异常、solo 没装代理、down 代理没在运行、ok 正常 */
	mode: function(st) {
		var pw = st.passwall || {};
		if (st.overall === 'disabled') return 'off';
		if (st.overall !== 'ok') return 'bad';
		if (!pw.installed) return 'solo';
		if (!pw.running) return 'down';
		return 'ok';
	},

	confirmDisable: function() {
		ui.showModal('停用保护', [
			E('p', {}, this.hasProxy ?
				'停用后不再拦截。PassWall 停止、重启或宽带重拨的那段时间，Claude 的连接可能直接从家里宽带出去。' :
				'停用后不再拦截。这台路由器上没有代理，停用期间设备可以直接从家里宽带访问 Claude。'),
			E('p', {}, '只在排查问题时停用。停用后不会自己恢复，用完要手动启用。'),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, '取消'), ' ',
				E('button', { 'class': 'btn cbi-button-negative', 'click': L.bind(function() {
					return this.act(['disable'], '正在停用', '保护已停用');
				}, this) }, '停用')
			])
		]);
	},

	confirmRestart: function() {
		ui.showModal('重启 PassWall', [
			E('p', {}, '重启约半分钟。这段时间所有走代理的网站会断，正在进行的 Claude 任务会断线；Claude 的连接仍被拦下，不会走家里宽带。'),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, '取消'), ' ',
				E('button', { 'class': 'btn cbi-button-negative', 'click': L.bind(function() {
					return this.act(['passwall-restart'], '正在重启 PassWall', 'PassWall 正在重启，约半分钟后恢复');
				}, this) }, '现在重启')
			])
		]);
	},

	/* 给 Claude 换出口节点 */
	changeNode: function(st) {
		var pw = st.passwall || {}, self = this;
		var sel = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': '_default' }, '跟随默认节点（' + (pw.default_node_name || '—') + '）')
		].concat((pw.nodes || []).map(function(n) { return E('option', { 'value': n.id }, n.name); })));
		sel.value = pw.pinned ? pw.claude_node : '_default';
		var go = function(restart) {
			var id = sel.value;
			var name = sel.options[sel.selectedIndex].textContent;
			return self.act(restart ? ['passwall-apply', id, 'restart'] : ['passwall-apply', id],
				restart ? '正在校验、保存并重启 PassWall' : '正在校验并保存',
				function(r) {
					return restart ? ('已改成「' + (r.node || name) + '」，PassWall 正在重启，约半分钟后生效') :
						('已改成「' + (r.node || name) + '」，PassWall 下次重启后生效');
				});
		};
		ui.showModal('Claude 走哪个节点', [
			E('div', { 'class': 'cg-form' }, [
				sel,
				E('p', { 'class': 's' }, '只改 Claude，其他网站不受影响。保存前会校验 PassWall 配置并自动备份，校验不过就不改。'),
				E('p', { 'class': 's' }, '「保存」不重启 PassWall，等它下次重启才换过去。「保存并重启」马上换，但会断网约半分钟。')
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, '取消'), ' ',
				E('button', { 'class': 'btn cbi-button-negative', 'click': function() { return go(true); } }, '保存并重启'), ' ',
				E('button', { 'class': 'btn cbi-button-action important', 'click': function() { return go(false); } }, '保存')
			])
		]);
	},

	top: function(st, m) {
		var self = this, cls, title, desc;
		if (m === 'ok') {
			cls = 'cg-ok'; title = '保护正常';
			desc = 'Claude 只走代理。代理断开时连接会被拦下，不会从家里宽带出去；代理恢复后自动恢复。';
		} else if (m === 'solo') {
			cls = 'cg-ok'; title = '保护正常';
			desc = '这台路由器没有装代理，发往 Claude 的连接一律拦下。设备自己开了代理的不受影响。';
		} else if (m === 'down') {
			cls = 'cg-warn'; title = '代理没在运行';
			desc = 'Claude 暂时用不了：连接都被拦下了，没有走家里宽带。PassWall 恢复后自动恢复。';
		} else if (m === 'off') {
			cls = 'cg-off'; title = '保护已停用';
			desc = this.hasProxy ? '现在没有拦截。代理不可用时，Claude 的连接会直接从家里宽带出去。' : '现在没有拦截，设备可以直接从家里宽带访问 Claude。';
		} else {
			cls = 'cg-bad'; title = '保护异常';
			desc = (st.problems || []).join('；') + '。正在自动修复，也可以手动修复。';
		}
		var acts = [];
		if (m === 'off') {
			acts.push(E('button', { 'class': 'cg-b pri', 'click': function() { return self.act(['enable'], '正在启用', '保护已启用'); } }, '启用保护'));
		} else {
			if (m === 'bad')
				acts.push(E('button', { 'class': 'cg-b pri', 'click': function() { return self.act(['repair'], '正在重新加载规则', '已重新加载规则'); } }, '立即修复'));
			else
				acts.push(E('button', { 'class': 'cg-b', 'click': function() { return self.act(['selftest'], '正在自检', '自检完成'); } }, '自检'));
			var menu = E('details', { 'class': 'cg-menu' }, [
				E('summary', { 'class': 'cg-b' }, ['更多', icon('down')]),
				E('div', { 'class': 'cg-items' }, [
					E('button', { 'click': function() {
						return self.act(['update'], '正在更新地址列表，约半分钟', function(r) {
							return '更新完成：网段 +' + (r.added_prefixes || []).length + '，域名 +' + (r.added_domains || []).length;
						});
					} }, '更新地址列表'),
					E('button', { 'click': function() { return self.act(['repair'], '正在重新加载规则', '已重新加载规则'); } }, '重新加载规则'),
					E('button', { 'click': function() { return self.act(['reset-counters'], '正在清零', '拦截计数已清零'); } }, '拦截计数清零'),
					E('button', { 'class': 'cg-dg', 'click': function() { self.open.menu = false; self.confirmDisable(); } }, '停用保护')
				])
			]);
			if (this.open.menu) menu.setAttribute('open', '');
			menu.addEventListener('toggle', function() { self.open.menu = menu.open; });
			acts.push(menu);
		}
		return [cls, E('div', { 'class': 'cg-top' }, [
			E('div', { 'class': 'cg-head' }, [
				E('div', { 'class': 'cg-state' }, [E('span', { 'class': 'cg-dot' }), title]),
				E('div', { 'class': 'cg-desc' }, desc)
			]),
			E('div', { 'class': 'cg-acts' }, acts)
		])];
	},

	/* 线路：设备 → 代理 → Claude；下面是被拦下的直连 */
	route: function(st, m) {
		var self = this, pw = st.passwall || {}, tr = st.trace || {}, c = st.counters || {};
		var lan = cnt(c, 'fwd4') + cnt(c, 'fwd6'), own = cnt(c, 'out4') + cnt(c, 'out6'), audit = cnt(c, 'audit4') + cnt(c, 'audit6');
		var total = lan + own;
		var last = (st.blocks || []).filter(function(x) { return !x.canary; })[0];
		var nEx = (st.exempt || []).length;
		var since = '自 ' + (st.counters_since ? fmtTime(st.counters_since) : '插件加载') + ' 起';
		var out = [];
		var dev = station('从', '家里的设备', [nEx ? (nEx + ' 台设了允许直连') : '']);

		if (!pw.installed) {
			var blocked = (m !== 'off');
			out.push(E('div', { 'class': 'cg-route two ' + (blocked ? 'cut' : 'idle') }, [
				station('从', '家里的设备', [nEx ? (nEx + ' 台设了允许直连') : '', blocked ? '直连家里宽带：拦下' : '直连家里宽带：没有拦'],
					blocked ? icon('x', 'cg-cut') : ''),
				station('到', 'Claude', [blocked ? '在这台路由器下连不上' : '可以直接连上'])
			]));
			out.push(E('div', { 'class': 'cg-branch' + (blocked ? '' : ' open') }, [
				icon('ban'),
				E('div', { 'class': 'cg-grow' }, [
					E('div', {}, blocked ? '已拦下的直连' : '直连现在没有拦'),
					E('div', { 'class': 'cg-n' }, blocked ?
						((last ? ('最近 ' + (last.time || '').slice(0, 11) + ' · ' + who(last) + ' · ') : '') + since) :
						'启用保护后才会拦')
				]),
				blocked ? E('div', { 'class': 'cg-fig' }, [E('div', { 'class': 'cg-num' }, num(total)), E('div', { 'class': 'cg-k' }, '次')]) : ''
			]));
			out.push(E('div', { 'class': 'cg-n', 'style': 'margin-top:16px' },
				'设备上自己开了代理的，连接发往代理服务器，不走这条线。装上 PassWall 后，线路上会多出代理这一站，可以给 Claude 选节点。'));
			return out;
		}

		var live = pw.running && m !== 'bad';
		var how = pw.pinned ? '给 Claude 单独指定' : (pw.shunt ? '跟随默认节点' : '跟随全局节点');
		var pn = [];
		if (pw.running) pn.push(how + (pw.shunt ? '' : '，单节点没法单独指定'));
		if (pw.shunt) pn.push(E('button', { 'class': 'cg-b sm', 'click': function() { self.changeNode(st); } }, '换节点'));
		var cn = [];
		if (!pw.running) cn.push('代理恢复后自动恢复');
		else if (!tr.time || tr.skip) cn.push('出口还没检测');
		else if (tr.ok) {
			cn.push(tr.alarm ? E('span', { 'style': 'color:var(--bad)' }, tr.alarm) : ('出口在' + place(tr)));
			cn.push([mono(tr.ip), E('span', { 'class': 'cg-3' }, ' · ' + ago(tr.time, st.time) + '检测')]);
		} else cn.push('出口检测没连上：' + (tr.error || '') + '，' + ago(tr.time, st.time));

		out.push(E('div', { 'class': 'cg-route ' + (live ? '' : 'idle') }, [
			dev,
			station('经过 PassWall', pw.running ? (pw.effective_name || '—') : '没在运行', pn),
			station('到', pw.running ? 'Claude' : 'Claude 连不上', cn)
		]));
		if (pw.pending)
			out.push(E('div', { 'class': 'cg-pend' }, [
				E('span', { 'class': 'cg-dot' }),
				E('div', { 'class': 'cg-grow' }, '还没生效：' + (pw.pending_note || 'PassWall 下次重启后生效')),
				E('button', { 'class': 'cg-b sm', 'click': function() { self.confirmRestart(); } }, '重启 PassWall')
			]));
		else if (!pw.rule_present)
			out.push(E('div', { 'class': 'cg-n', 'style': 'margin-top:16px' },
				pw.auto_rule ? 'PassWall 里还没有 Claude 规则，稍后自动加上，不会重启 PassWall' : 'PassWall 里没有 Claude 规则，自动添加已在设置里关掉'));

		var open = (m === 'off');
		var info = [];
		if (last) info.push('最近 ' + (last.time || '').slice(0, 11) + ' · ' + who(last));
		if (own && lan) info.push('其中路由器自己 ' + num(own) + ' 次');
		info.push(since);
		out.push(E('div', { 'class': 'cg-branch' + (open ? ' open' : '') }, [
			icon('ban'),
			E('div', { 'class': 'cg-grow' }, [
				E('div', {}, open ? '不经代理、直连家里宽带：现在没有拦' : '不经代理、直连家里宽带：拦下'),
				E('div', { 'class': 'cg-n' }, open ? '启用保护后才会拦' : info.join(' · '))
			]),
			open ? '' : E('div', { 'class': 'cg-fig' }, [E('div', { 'class': 'cg-num' }, num(total)), E('div', { 'class': 'cg-k' }, '次已拦下')])
		]));
		if (audit)
			out.push(E('div', { 'class': 'cg-n', 'style': 'margin-top:12px;color:var(--bad)' }, '最后一道检查拦下了 ' + num(audit) + ' 个包，说明前面有漏洞，看日志'));
		return out;
	},

	alerts: function(st) {
		var list = [], pw = st.passwall || {}, li = st.lists || {};
		if (pw.alarm) list.push(pw.alarm);
		if (st.daemon && !st.daemon.running && st.overall !== 'disabled')
			list.push('看护进程没有运行：拦截规则仍在，但被删除后不会自动恢复（/etc/init.d/claude-guard start）');
		if (st.conntrack_tool === false) list.push('没有安装 conntrack，残留的直连连接无法自动清理');
		if ((st.targets && st.targets.invalid || []).length)
			list.push('地址列表里有格式错误的行，已跳过：' + st.targets.invalid.map(function(i) { return i.text; }).join('、'));
		if ((li.outside || []).length)
			list.push(li.outside.length + ' 个 Claude 域名解析到 Anthropic 网段以外的地址，可能是共用的 CDN，没有按 IP 拦');
		var u = li.last || {};
		if (u.pending_prefixes) list.push('自动更新一次发现太多新网段，暂未加入：' + u.pending_prefixes.join('、'));
		if (u.pending_domains) list.push('自动更新一次发现 ' + u.pending_domains + ' 个新域名，超过上限，暂未加入');
		if (!list.length) return '';
		return E('div', { 'class': 'cbi-section cg-alerts' }, list.map(function(t) {
			return E('div', { 'class': 'cg-al' }, [E('span', { 'class': 'cg-dot' }), E('div', {}, t)]);
		}));
	},

	row: function(id, title, sum, body, forceOpen) {
		var self = this;
		var isOpen = (id in this.open) ? this.open[id] : !!forceOpen;
		var d = E('details', { 'class': 'cg-row', 'id': 'cg-sec-' + id }, [
			E('summary', {}, [icon('right'), E('span', {}, title), E('span', { 'class': 'cg-sum' }, sum || '')]),
			E('div', { 'class': 'cg-body' }, body)
		]);
		if (isOpen) d.setAttribute('open', '');
		d.addEventListener('toggle', function() { self.open[id] = d.open; });
		return d;
	},

	rowBlocks: function(st) {
		var all = (st.blocks || []).filter(function(x) { return !x.canary; });
		var b = all.slice(0, 10);
		var leaks = st.leaks || [];
		var body = [b.length ? E('div', {}, b.map(function(x) {
			return E('div', { 'class': 'cg-rec' }, [
				E('span', { 'class': 't cg-mono' }, x.time),
				E('span', {}, (x.kind === 'OUT' ? ['路由器自己'] : [x.host ? (x.host + ' ') : '', mono(x.src || '')]).concat(
					[' 想直连 ', mono((x.dst || '') + (x.dport ? ':' + x.dport : '')), '，拦下']))
			]);
		})) : E('p', { 'style': 'margin:0' }, '没有拦截记录')];
		if (all.length) body.push(E('p', {}, '最近 ' + b.length + ' 条，共 ' + all.length + ' 条，从计数清零算起。每分钟最多记 10 条，自检用的探测不算'));
		if (leaks.length)
			body.unshift(E('div', { 'class': 'cg-pend', 'style': 'margin:0 0 16px' }, [
				E('span', { 'class': 'cg-dot' }),
				E('div', { 'class': 'cg-grow' }, leaks.length + ' 条连接疑似没走代理，只报告不处理：' +
					leaks.slice(0, 8).map(function(l) { return l.src + ' → ' + l.dst + ':' + (l.dport || ''); }).join('；')),
				E('button', { 'class': 'cg-b sm', 'click': L.bind(function() {
					return this.act(['flush'], '正在清理', function(r) { return '清理了 ' + (r.flushed || 0) + ' 条'; });
				}, this) }, '清理这些连接')
			]));
		return this.row('blocks', '拦截记录', all.length ? all.length + ' 条' : '无', body, leaks.length > 0);
	},

	rowChecks: function(st) {
		var checks = st.checks || [];
		var bad = checks.filter(function(c) { return c.ok === false; }).length;
		var pass = checks.filter(function(c) { return c.ok === true; }).length;
		var lc = (st.daemon || {}).last_check || {};
		var sum = st.overall === 'disabled' ? '已停用' : (bad ? bad + ' 项不通过' : pass + '/' + checks.length + ' 通过');
		var body = st.overall === 'disabled' ? [E('p', { 'style': 'margin:0' }, '保护已停用，不做检查')] : [
			tbl(['检查项', '结果', '说明'], checks.map(function(c) {
				return [c.name, mark(c.ok, c.ok === true ? '通过' : c.ok === false ? '不通过' : '跳过'),
					(c.detail || '') + (c.time ? '，' + ago(c.time, st.time) : '')];
			})),
			E('p', {}, '每 ' + ((st.config || {}).check_interval || 15) + ' 秒查一次' + (lc.time ? ('，上次' + ago(lc.time, st.time)) : '') +
				'。每一项都通过才算正常。其中「实测拦截」会真的发一个探测包，确认它被拦下。')
		];
		return this.row('checks', '保护检查', sum, body, bad > 0);
	},

	rowTargets: function(st) {
		var t = st.targets || {}, li = st.lists || {};
		var hasPw = !!(st.passwall && st.passwall.installed);
		var nP = (t.prefixes || []).length, nD = (t.dynamic || []).length;
		var upd;
		if (!li.auto_update) upd = '自动更新已关';
		else if (!li.last_run) upd = '还没更新过';
		else upd = ago(li.last_run, st.time) + '更新' + (li.last_ok === li.last_run ? '' : '，有来源没连上');
		var body = [];
		body.push(E('h5', {}, '按 IP 拦的网段'));
		body.push(tbl(['网段', '来源', '说明'], (t.prefixes || []).map(function(p) {
			return [mono(p.prefix), SRC[p.source] || p.source, p.note || ''];
		})));
		if (nD) {
			body.push(E('h5', {}, '网段以外的单独地址'));
			body.push(tbl(['地址', '来自', '过期'], t.dynamic.map(function(d) {
				return [mono(d.ip), d.domain || '', mono(fmtTime(d.expires))];
			})));
		}
		var doms = li.domains || [];
		body.push(E('h5', {}, hasPw ? ('写进 PassWall 规则的域名，' + doms.length + ' 个') : ('域名，' + doms.length + ' 个，装了 PassWall 才用得上')));
		body.push(E('div', { 'class': 'cg-chips' }, doms.length ? doms.map(function(d) {
			return E('span', { 'class': 'cg-chip' + (d.shared ? ' sh' : ''), 'title': (d.shared ? '第三方共用地址，只按域名走 Claude 出口，不按 IP 拦；' : '') + '来源 ' + (d.src || []).join('、') },
				(d.type === 'full' ? '' : '*.') + d.d);
		}) : [E('span', { 'class': 'cg-3' }, '还没有，等自动更新')]));
		body.push(E('p', {}, '「*.」含所有子域名。颜色浅的是 CDN、遥测之类第三方地址，只按域名走 Claude 出口，不按 IP 拦，免得误伤共用这些地址的网站。'));
		if ((li.outside || []).length) {
			body.push(E('h5', {}, '解析到 Anthropic 网段以外的地址，' + ago(li.outside_time, st.time)));
			body.push(tbl(['域名', '地址'], li.outside.map(function(o) { return [o.domain, mono(o.ip)]; })));
			body.push(E('p', {}, '这些地址没有按 IP 拦，它们可能是很多网站共用的 CDN。确认是 Anthropic 专用的，可以在「设置 → 高级 → 附加网段」里加上。'));
		}
		body.push(E('h5', {}, '列表从哪里更新'));
		var srcs = li.sources || {};
		body.push(tbl(['来源', '状态', '时间', '说明'], Object.keys(SOURCE_NAME).filter(function(k) { return srcs[k]; }).map(function(k) {
			var s = srcs[k];
			return [SOURCE_NAME[k], mark(!!s.ok, s.ok ? '成功' : '没连上'), ago(s.time, st.time), s.ok ? (s.count + ' 条') : (s.error || '') + '，保留原有内容'];
		}), '还没更新过'));
		body.push(E('p', {}, '来源没连上或不再列出某项时，已有内容保留' +
			((st.central || {}).configured ? '，只有统一列表能撤回。' : '。') + '允许直连的设备：' +
			((st.exempt || []).length ? st.exempt.join('、') : '无') + '。'));
		return this.row('targets', '拦的地址', nP + ' 个网段' + (nD ? ' + ' + nD + ' 个地址' : '') + ' · ' + upd, body, false);
	},

	rowLogs: function(st) {
		var lines = [];
		(st.critical || []).forEach(function(l) { lines.push('[严重] ' + l); });
		return this.row('logs', '日志', '版本 ' + (st.version || ''), [
			E('h5', {}, '插件事件，新的在上'),
			E('pre', { 'class': 'cg-pre' }, (lines.length ? lines.join('\n') + '\n\n' : '') + ((st.events || []).join('\n') || '无')),
			E('h5', {}, '系统日志'),
			E('pre', { 'class': 'cg-pre' }, (st.logs || []).slice().reverse().join('\n') || '无')
		], false);
	},

	refresh: function() {
		return ctl(['status']).then(L.bind(this.update, this)).catch(L.bind(function(e) {
			this.update({ overall: 'error', error: e.message });
		}, this));
	},

	/* 卡片的底色跟主题走：读出来给站点圆点和弹出菜单用 */
	syncBg: function() {
		var el = this.root && this.root.querySelector('.cbi-section');
		while (el && el !== document.documentElement) {
			var b = window.getComputedStyle(el).backgroundColor;
			if (b && b !== 'transparent' && !/rgba\(\s*\d+,\s*\d+,\s*\d+,\s*0\s*\)/.test(b)) {
				this.page.style.setProperty('--bg', b);
				return;
			}
			el = el.parentElement;
		}
	},

	update: function(st) {
		if (!this.root) return;
		if (st.overall === 'error') {
			dom.content(this.root, E('div', { 'class': 'cbi-section cg-card cg-bad' }, E('div', { 'class': 'cg-top' }, E('div', { 'class': 'cg-head' }, [
				E('div', { 'class': 'cg-state' }, [E('span', { 'class': 'cg-dot' }), '读不到状态']),
				E('div', { 'class': 'cg-desc' }, (st.error || '') + '。可以在路由器上执行 /usr/libexec/claude-guard/ctl status 看原因。')
			]))));
			return;
		}
		this.last = st;
		setTz(st.tz);
		this.hasProxy = !!(st.passwall && st.passwall.installed);
		var m = this.mode(st);
		var top = this.top(st, m);
		dom.content(this.root, [
			E('div', { 'class': 'cbi-section cg-card ' + top[0] }, [top[1]].concat(this.route(st, m))),
			this.alerts(st),
			E('div', { 'class': 'cbi-section cg-list' }, [
				this.rowBlocks(st),
				this.rowChecks(st),
				this.rowTargets(st),
				this.rowLogs(st)
			])
		]);
		this.syncBg();
	},

	render: function(st) {
		this.root = E('div', {});
		this.page = E('div', { 'class': 'cg' }, [E('style', {}, CSS), E('h2', {}, 'Claude 防直连'), this.root]);
		this.update(st);
		window.setTimeout(L.bind(this.syncBg, this), 0);
		poll.add(L.bind(this.refresh, this), 10);
		return this.page;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
