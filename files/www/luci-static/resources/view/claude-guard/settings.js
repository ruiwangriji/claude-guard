'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';

var CTL = '/usr/libexec/claude-guard/ctl';

function ctl(args) {
	return fs.exec(CTL, args).then(function(res) {
		var out = (res.stdout || '').trim();
		if (!out) throw new Error((res.stderr || '').trim() || ('命令退出码 ' + res.code));
		var lines = out.split('\n');
		return JSON.parse(lines[lines.length - 1]);
	});
}

var CSS = '.cg-box{padding:10px 14px;border-radius:10px;background:rgba(128,128,128,.1);line-height:1.8}';

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('claude_guard'),
			ctl(['status']).catch(function() { return {}; })
		]);
	},

	run: function(args, busy, done) {
		ui.showModal('请稍候', [E('p', { 'class': 'spinning' }, busy)]);
		return ctl(args).then(function(r) {
			ui.hideModal();
			if (r.ok === false) {
				ui.addNotification(null, E('p', {}, '没有改动：' + r.error), 'danger');
			} else {
				ui.addNotification(null, E('p', {}, done(r)), 'info');
				window.setTimeout(function() { location.reload(); }, 2500);
			}
		}).catch(function(e) {
			ui.hideModal();
			ui.addNotification(null, E('p', {}, '执行出错：' + e.message), 'danger');
		});
	},

	render: function(data) {
		var self = this;
		var st = (data && data[1]) || {};
		var pw = st.passwall || {};
		var statusUrl = L.url('admin/services/claude_guard/status');
		var m, s, o;

		m = new form.Map('claude_guard', 'Claude 防直连 · 设置',
			'平时不用改这里。给 Claude 换出口节点、运行自检、更新地址列表都在「状态」页。');
		s = m.section(form.NamedSection, 'main', 'main');
		s.anonymous = true;
		s.addremove = false;
		s.tab('common', '常用');
		s.tab('advanced', '高级');

		// ---------------- 常用
		o = s.taboption('common', form.DummyValue, '_exit', 'Claude 出口');
		o.rawhtml = true;
		o.cfgvalue = function() {
			if (!pw.installed)
				return '<div class="cg-box">这台路由器没有安装 PassWall，现在只做拦截。装上 PassWall 后可以给 Claude 选出口节点。</div>';
			if (!pw.shunt)
				return '<div class="cg-box">PassWall 用的是单个节点，Claude 跟着它走，没法单独指定。要单独指定，先在 PassWall 里把节点换成分流节点。</div>';
			return '<div class="cg-box">在 <a href="' + statusUrl + '">状态页</a> 的「Claude 的连接现在怎么走」里，点「换一个节点」。</div>';
		};

		o = s.taboption('common', form.Flag, 'auto_update', '自动更新地址列表',
			'每天一次，更新要拦的 Claude 地址。更新失败时保留原来的内容，不影响拦截。');
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('common', form.DynamicList, 'exempt_src', '允许直连 Claude 的设备',
			'填设备的 IP。默认不填，所有设备都受保护。填进来的设备访问 Claude 时不拦，Claude 会看到家里宽带的地址。');
		o.datatype = 'ipaddr';

		// ---------------- 高级
		o = s.taboption('advanced', form.ListValue, 'action', '拦截方式');
		o.value('reject', '立即拒绝（推荐）');
		o.value('drop', '静默丢弃');
		o.default = 'reject';

		o = s.taboption('advanced', form.Flag, 'log', '记录拦截日志', '每分钟最多 10 条。');
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'check_interval', '复核间隔（秒）', '规则被删时另有实时监听，不用等这个间隔。');
		o.datatype = 'range(5,300)';
		o.default = '15';

		o = s.taboption('advanced', form.DynamicList, 'extra_prefix', '附加网段', '在内置和自动更新的网段之外再加。只加整段属于 Anthropic 的地址。');
		o.datatype = 'cidr';

		o = s.taboption('advanced', form.Value, 'central_url', '统一列表地址',
			'自己维护的地址列表（一个 JSON 文件）的网址，以 https:// 开头。填了并且拿得到，就以它为准，下面几个公开来源只在拿不到时兜底；只有它能撤回已经加入的内容。留空 = 不用。');
		o.placeholder = 'https://';
		o.validate = function(sid, v) {
			return (!v || /^https:\/\/\S+$/.test(v) || /^file:\/\/\/\S+$/.test(v)) ? true : '要以 https:// 开头';
		};

		o = s.taboption('advanced', form.Value, 'update_interval', '自动更新间隔（秒）');
		o.datatype = 'range(3600,604800)';
		o.default = '86400';

		o = s.taboption('advanced', form.Flag, 'src_arin', '公开来源：ARIN 登记网段');
		o.default = '1'; o.rmempty = false;
		o = s.taboption('advanced', form.Flag, 'src_ripe', '公开来源：AS399358 路由公告');
		o.default = '1'; o.rmempty = false;
		o = s.taboption('advanced', form.Flag, 'src_geosite', '公开来源：本地 geosite', 'PassWall 带来的域名库，路由器上没有就跳过。');
		o.default = '1'; o.rmempty = false;
		o = s.taboption('advanced', form.Flag, 'src_v2fly', '公开来源：v2fly 在线列表');
		o.default = '1'; o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'max_new_prefix', '一次最多新增网段', '自动更新一次发现的新网段超过这个数，只报警不加入。');
		o.datatype = 'range(1,64)';
		o.default = '8';
		o = s.taboption('advanced', form.Value, 'max_new_domain', '一次最多新增域名');
		o.datatype = 'range(1,500)';
		o.default = '40';

		o = s.taboption('advanced', form.DynamicList, 'domain', '定期解析的主机名',
			'PassWall 运行时每 6 小时解析一次，结果不在已知网段里的地址按 IP 拦（30 天没再解析到就过期）。只放 Anthropic 自己的主机名。没有代理时不解析，这类地址由统一列表提供。');
		o.datatype = 'hostname';

		o = s.taboption('advanced', form.Flag, 'passwall_auto_rule', '自动在 PassWall 里放 Claude 规则',
			'装了 PassWall 时，插件在它的分流规则里加一条「Claude（防直连插件）」。有了它，PassWall 会按 IP 强制 Claude 走代理，也才能给 Claude 单独选出口。只写配置，不重启 PassWall。关掉后不再自动添加。');
		o.default = '1';
		o.rmempty = false;

		if (pw.installed && pw.rule_present) {
			o = s.taboption('advanced', form.Button, '_remove', '删除 PassWall 里的 Claude 规则');
			o.inputtitle = '从 PassWall 删除 Claude 规则';
			o.inputstyle = 'remove';
			o.description = '只想让 Claude 改回跟随默认节点，在状态页「换一个节点」里选「跟随默认节点」就行，不用删。删除后插件不再自动添加，PassWall 也不再按 IP 强制 Claude 走代理。不重启 PassWall，下次重启时生效。';
			o.onclick = function() {
				return self.run(['passwall-remove'], '正在校验并删除……', function() { return '已删除，PassWall 下次重启时生效。'; });
			};
		}

		return m.render().then(function(node) {
			node.insertBefore(E('style', {}, CSS), node.firstChild);
			return node;
		});
	}
});
