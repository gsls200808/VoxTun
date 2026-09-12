// VoxTun 服务端面板前端逻辑（petite-vue）
(function () {
  'use strict';

  var POLL_MS = 3000;

  // describeCheck 把 /api/ipfilter/check 的返回翻译成一句结论
  function describeCheck(d) {
    if (!d.enabled) return 'IP 过滤当前未启用，该地址会被放行。';
    if (d.allowed) {
      if (d.rule) return '会被放行：命中白名单规则 ' + d.rule + '。';
      return '会被放行：未命中黑名单，且白名单为空。';
    }
    if (d.rule) return '会被拦截：命中黑名单规则 ' + d.rule + '。';
    return '会被拦截：白名单非空，且该地址未命中任何白名单规则。';
  }

  // 注意：mount() 的返回值是 petite-vue 内部对象，不含这里定义的方法，
  // 因此初始化由 index.html 上的 @vue:mounted="boot" 触发，不在此处手动调用。
  PetiteVue.createApp({
    // 登录表单
    user: '',
    pass: '',
    loginErr: '',

    // 会话
    ready: false,   // 首次 overview 是否已返回
    logged: false,

    // 数据
    server: { version: '', startAt: 0, uptime: 0, bindAddr: '', bindPort: 0, publicAddr: '', proxyCount: 0, clientCount: 0, bytesIn: 0, bytesOut: 0 },
    proxies: [],
    clients: [],
    ipf: { enable: false, allowList: [], denyList: [] },

    // IP 检测 / 黑白名单操作
    checkIP: '',
    checkResult: null,
    addMask: '0',

    // 交互
    busy: '',
    toast: '',
    toastTimer: null,

    // boot 首次加载：拉一次数据决定展示登录还是面板，然后开始轮询
    boot: function () {
      document.getElementById('app').style.display = '';
      var self = this;
      this.refresh().then(function () {
        self.ready = true;
        setInterval(function () {
          if (self.logged) self.refresh();
        }, POLL_MS);
      });
    },

    refresh: function () {
      var self = this;
      return fetch('/api/overview', { cache: 'no-store' })
        .then(function (r) {
          if (r.status === 401) {
            self.logged = false;
            self.proxies = [];
            self.clients = [];
            return null;
          }
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (d) {
          if (!d) return null;
          self.server = d.server || self.server;
          self.proxies = d.proxies || [];
          self.clients = d.clients || [];
          self.logged = true;
          // 操作进行中不覆盖表单区数据，避免刚提交的改动被回显成旧值
          if (self.busy) return null;
          return self.loadIPFilter();
        })
        .catch(function (e) {
          if (self.ready) self.notify('刷新失败: ' + e.message);
        });
    },

    loadIPFilter: function () {
      var self = this;
      return fetch('/api/ipfilter', { cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { if (d) self.ipf = d; })
        .catch(function () {});
    },

    login: function () {
      var self = this;
      this.loginErr = '';
      fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: this.user, password: this.pass })
      })
        .then(function (r) {
          return r.json().catch(function () { return {}; }).then(function (d) {
            if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
            return d;
          });
        })
        .then(function () {
          self.pass = '';
          self.logged = true;
          return self.refresh();
        })
        .catch(function (e) {
          self.loginErr = e.message;
        });
    },

    logout: function () {
      var self = this;
      fetch('/api/logout', { method: 'POST' }).catch(function () {}).then(function () {
        self.logged = false;
        self.proxies = [];
        self.clients = [];
        self.ipf = { enable: false, allowList: [], denyList: [] };
        self.checkResult = null;
      });
    },

    closeProxy: function (name) {
      var self = this;
      if (!confirm('确定关闭代理「' + name + '」？\n\n服务端会立即释放该公网端口；'
        + '如果客户端重连，它会重新注册这个代理。')) return;
      this.post('/api/proxy/close', { name: name }, 'proxy:' + name, '代理「' + name + '」已关闭');
    },

    kickClient: function (addr) {
      if (!confirm('确定断开客户端 ' + addr + '？\n\n如果客户端配置了自动重连，它会立即重新连上。')) return;
      this.post('/api/client/close', { addr: addr }, 'client:' + addr, '已断开 ' + addr);
    },

    // ---- IP 黑白名单 ----

    checkIPFilter: function () {
      var self = this;
      var ip = (this.checkIP || '').trim();
      if (!ip) { this.notify('请先填写要检测的 IP 地址'); return; }
      fetch('/api/ipfilter/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
      })
        .then(function (r) {
          return r.json().catch(function () { return {}; }).then(function (d) {
            if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
            return d;
          });
        })
        .then(function (d) {
          self.checkResult = { allowed: !!d.allowed, text: describeCheck(d) };
        })
        .catch(function (e) {
          self.checkResult = null;
          self.notify('检测失败: ' + e.message);
        });
    },

    addIPFilter: function (list) {
      var ip = (this.checkIP || '').trim();
      if (!ip) { this.notify('请先填写要添加的 IP 地址'); return; }
      var mask = Number(this.addMask) || 0;
      var name = list === 'allow' ? '白名单' : '黑名单';
      var label = mask ? (ip + '/' + mask) : ip;
      this.post('/api/ipfilter/add', { list: list, ip: ip, mask: mask },
        'ipf:add', '已加入' + name + '：' + label);
    },

    removeIPFilter: function (list, value) {
      var name = list === 'allow' ? '白名单' : '黑名单';
      if (!confirm('确定从' + name + '中删除 ' + value + '？')) return;
      this.post('/api/ipfilter/remove', { list: list, value: value },
        'ipf:rm', '已从' + name + '删除 ' + value);
    },

    toggleIPFilter: function (enable) {
      this.post('/api/ipfilter/toggle', { enable: !!enable },
        'ipf:toggle', enable ? 'IP 过滤已启用' : 'IP 过滤已关闭');
    },

    post: function (url, body, busyKey, okMsg) {
      var self = this;
      this.busy = busyKey;
      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })
        .then(function (r) {
          return r.json().catch(function () { return {}; }).then(function (d) {
            self.notify(r.ok ? okMsg : ('操作失败: ' + (d.error || ('HTTP ' + r.status))));
          });
        })
        .catch(function (e) { self.notify('操作失败: ' + e.message); })
        .then(function () {
          self.busy = '';
          return self.refresh();
        });
    },

    notify: function (msg) {
      var self = this;
      this.toast = msg;
      if (this.toastTimer) clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(function () { self.toast = ''; }, 3000);
    },

    // ---- 展示格式化 ----

    fmtBytes: function (n) {
      n = Number(n) || 0;
      if (n < 1024) return n + ' B';
      var units = ['KB', 'MB', 'GB', 'TB', 'PB'];
      var i = -1;
      do { n = n / 1024; i++; } while (n >= 1024 && i < units.length - 1);
      return (n >= 100 ? n.toFixed(0) : n.toFixed(2)) + ' ' + units[i];
    },

    fmtDuration: function (sec) {
      sec = Math.floor(Number(sec) || 0);
      var d = Math.floor(sec / 86400);
      var h = Math.floor((sec % 86400) / 3600);
      var m = Math.floor((sec % 3600) / 60);
      var s = sec % 60;
      if (d) return d + ' 天 ' + h + ' 小时';
      if (h) return h + ' 小时 ' + m + ' 分';
      if (m) return m + ' 分 ' + s + ' 秒';
      return s + ' 秒';
    },

    fmtTime: function (unix) {
      if (!unix) return '-';
      var d = new Date(unix * 1000);
      var p = function (n) { return String(n).padStart(2, '0'); };
      return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' '
        + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    },

    fmtAgo: function (unix) {
      if (!unix) return '-';
      var s = Math.floor(Date.now() / 1000) - unix;
      if (s < 5) return '刚刚';
      if (s < 60) return s + ' 秒前';
      if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
      return Math.floor(s / 3600) + ' 小时前';
    }
  }).mount('#app');
})();
