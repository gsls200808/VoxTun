// VoxTun 服务端面板前端逻辑（petite-vue）
(function () {
  'use strict';

  var POLL_MS = 3000;

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
          if (!d) return;
          self.server = d.server || self.server;
          self.proxies = d.proxies || [];
          self.clients = d.clients || [];
          self.logged = true;
        })
        .catch(function (e) {
          if (self.ready) self.notify('刷新失败: ' + e.message);
        });
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
