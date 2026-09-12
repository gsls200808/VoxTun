# VoxTun

VoxTun 是一个面向 **SIP / IAX 语音信令** 的内网穿透工具，架构参考 [frp](https://github.com/fatedier/frp) 与 [nps](https://github.com/ehang-io/nps)。

它将内网中的 PBX / SIP 服务器 / IAX 服务暴露到公网，使外部终端能够在内网无公网 IP 的情况下完成信令交互；内置 SIP SDP / 路由头改写与 **RTP 媒体中继**，解决信令与媒体双向的 NAT 问题。

## 特性

- **SIP 信令穿透**：支持 UDP 5060，改写 SDP（`c=` / `o=` / `m=`）与 Contact / Record-Route 中的内网地址
- **SIP over TCP 穿透**：`sip-tcp` 类型在 TCP 上传送 SIP，按 `Content-Length` 分帧并复用同一套 SDP 改写与 RTP 中继
- **SIP over TLS 穿透**：`sip-tls` 类型由服务端原生终止 TLS（无需外部 stunnel），话机到公网走 TLS，隧道与内网仍为明文，并复用同一套 SDP 改写与 RTP 中继；同一端口可同时接受 TLS 与明文 SIP/TCP（按连接首字节自动分流）
- **IAX 信令穿透**：支持 UDP 4569，单端口承载信令与媒体
- **RTP 媒体中继**：按 SDP 协商的媒体条目动态分配公网端口并双向转发，媒体不再依赖对端直连
- **通用 TCP / UDP 代理**：可作为通用内网穿透工具使用
- **同端口多协议**：同一端口号的 UDP 与 TCP 代理可共存（如 SIP 5060）
- **Token 认证**：客户端连接需携带服务端配置的 token
- **端口白名单**：服务端可限制允许暴露的端口范围
- **IP 黑白名单**：基于 IP / CIDR 过滤所有外部对端，被拒来源记录日志便于排查
- **管理面板**：服务端内置 Web 控制台（petite-vue 实现，静态资源随二进制分发），可查看服务端状态、代理 / 客户端列表与实时流量，可关闭代理、断开客户端，并可在线管理 IP 黑白名单（含 IP 拦截检测，改动即时生效并回写配置文件）
- **心跳保活**：Ping/Pong 机制，服务端超时自动回收会话

## 工作原理

VoxTun 采用经典的「客户端主动外联 + 服务端端口监听」模型：

```
公网侧                                           内网侧
┌─────────────┐      控制连接(外联)      ┌──────────────┐
│  外部终端    │                          │   客户端       │
│ (SIP话机等)  │                          │   voxcli      │
└──────┬──────┘                          └──────┬───────┘
       │                                        │
       │  ① SIP/IAX 信令 (UDP 5060/4569)         │  转发
       │  ② RTP 媒体     (UDP 10000+，动态分配)   │
       ▼                                        ▼
┌─────────────┐    UDPPacket / NewRTPRelay  ┌──────────────┐
│   服务端      │◄──────────────────────────►│  内网 SIP/    │
│   voxsrv      │      (控制连接中继)         │  IAX 服务     │
└─────────────┘                            └──────────────┘
```

1. 客户端 `voxcli` 主动连接服务端 `voxsrv` 的控制端口（默认 7000），通过 token 认证
2. 客户端为每个代理发送 `NewProxy` 请求，声明服务类型、内网地址、公网端口
3. 服务端在对应公网端口创建监听（TCP `net.Listener` 或 UDP `net.UDPConn`）
4. **TCP 代理**：外部连入时，服务端通过控制连接通知客户端新建 work 连接，客户端连接本地服务并与外部连接桥接
5. **UDP 代理（SIP / IAX）**：服务端收到 UDP 包后封装为 `UDPPacket` 消息经控制连接发往客户端，客户端转发给本地服务并将响应原路回传
6. **RTP 媒体中继**：服务端解析到 SDP 中的媒体条目后，从端口池分配公网端口并发 `NewRTPRelay` 通知客户端为该媒体端口建立中继，之后双向转发 RTP
7. **SIP 改写**：SIP 消息经服务端回传外部对端时，将 SDP 与 Contact / Record-Route 中的内网地址替换为服务端公网地址

## 项目结构

```
VoxTun/
├── cmd/
│   ├── voxsrv/                # 服务端入口
│   │   └── main.go
│   └── voxcli/                # 客户端入口
│       └── main.go
├── configs/
│   ├── voxsrv.yaml            # 服务端配置
│   └── voxcli.yaml            # 客户端配置
└── internal/app/
    ├── common/
    │   ├── consts/            # 常量（消息类型、默认端口、心跳参数）
    │   ├── config/            # YAML 配置加载
    │   ├── ipfilter/          # IP 黑白名单过滤
    │   ├── protocol/          # 控制协议消息定义与编解码
    │   └── util/              # 连接工具、日志（zap）
    ├── protocol/
    │   ├── sip/               # SIP 消息解析 + SDP / 路由头重写
    │   └── iax/               # IAX 帧解析
    ├── server/                # 服务端：控制连接、代理监听、work连接、RTP 中继、管理面板
    │   └── web/               # 管理面板前端资源（index.html / app.js / style.css / petite-vue），go:embed 打包
    └── client/                # 客户端：控制连接、work连接、UDP/RTP 中继
```

## 编译

```bash
go build -o voxsrv ./cmd/voxsrv
go build -o voxcli ./cmd/voxcli

# 交叉编译 Linux amd64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o voxsrv ./cmd/voxsrv
```

## 快速开始

### 1. 启动服务端

编辑 `configs/voxsrv.yaml`：

```yaml
bindAddr: "0.0.0.0"
bindPort: 7000
publicAddr: "your.public.ip"   # 用于 SDP 重写的公网地址
token: "voxTun_secret"
logLevel: "info"
allowPorts:
  - start: 5060
    end: 5061
  - start: 4569
    end: 4569
  - start: 10000     # RTP 中继从 >=10000 的段中分配
    end: 20000
```

启动：

```bash
./voxsrv -c configs/voxsrv.yaml
```

### 2. 启动客户端

编辑 `configs/voxcli.yaml`：

```yaml
serverAddr: "your.public.ip"
serverPort: 7000
token: "voxTun_secret"
proxies:
  - name: "sip-udp"
    type: "sip"
    localIP: "127.0.0.1"
    localPort: 5060
    remotePort: 5060
    rewriteSDP: true

  - name: "iax-udp"
    type: "iax"
    localIP: "127.0.0.1"
    localPort: 4569
    remotePort: 4569
```

启动：

```bash
./voxcli -c configs/voxcli.yaml
```

启动后，外部终端即可通过 `your.public.ip:5060` 访问内网 SIP 服务，通过 `your.public.ip:4569` 访问 IAX 服务，RTP 媒体则通过服务端动态分配的公网端口转发。

## 配置说明

### 服务端（voxsrv.yaml）

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| bindAddr | string | 0.0.0.0 | 控制连接监听地址 |
| bindPort | int | 7000 | 控制连接监听端口；需确保该端口未被占用 |
| publicAddr | string | 空 | 公网 IP 或域名，用于 SIP SDP 重写；留空则使用 bindAddr。填域名时启动阶段会解析为 IP（SDP 的 `c=` 行不接受域名） |
| token | string | 空 | 客户端认证 token，留空则不校验 |
| logLevel | string | info | 日志级别：debug / info / warn / error |
| maxPoolCount | int | 5 | 预留连接池大小（当前版本未使用） |
| udpPacketSize | int | 1500 | 预留的 UDP 包缓冲大小（当前版本未使用） |
| tlsCertFile | string | 空 | `sip-tls` 代理使用的 TLS 证书（PEM），与 `tlsKeyFile` 必须同时配置 |
| tlsKeyFile | string | 空 | `sip-tls` 代理使用的 TLS 私钥（PEM） |
| allowPorts | list | 不限制 | 允许暴露的端口范围，同时决定 RTP 中继的可用端口段（只取 end ≥ 10000 的段） |
| ipFilter | object | 关闭 | IP 黑白名单过滤，见下文 |
| webServer | object | 关闭 | 管理面板，见下文「管理面板」；`port` 为 0 时不启动 |

### 客户端（voxcli.yaml）

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| serverAddr | string | 服务端地址 |
| serverPort | int | 服务端控制端口 |
| token | string | 认证 token，需与服务端一致 |
| logLevel | string | 日志级别 |
| proxies | list | 代理列表 |

单个代理项：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| name | string | 代理名称，需唯一 |
| type | string | 代理类型：tcp / udp / sip / iax / sip-tcp / sip-tls（sip / iax 内部走 UDP 中继；sip-tcp / sip-tls 内部走 TCP 中继并做 SDP 改写与 RTP 中继，sip-tls 的监听端口同时接受 TLS 与明文 SIP/TCP） |
| localIP | string | 内网服务地址 |
| localPort | int | 内网服务端口 |
| remotePort | int | 公网暴露端口 |
| rewriteSDP | bool | sip / sip-tcp / sip-tls 类型生效。开启后服务端才会改写 SDP / Contact / Record-Route 并启用 RTP 中继；关闭则 SIP 消息原样透传 |

## RTP 媒体中继

信令穿透成功后，媒体流仍需要一条可达的通道。VoxTun 的做法是：服务端解析 SIP 消息里的 SDP 媒体条目（`m=audio <port>` 与对应的 `c=` 地址），为每条媒体分配一个公网端口并中继 RTP。

> 该能力由 `sip` / `sip-tls` 类型代理的 `rewriteSDP: true` 开启。关闭时服务端不做任何改写，也就不会建立 RTP 中继。

- **端口分配**：从 `allowPorts` 中 `end >= 10000` 的段顺序分配（未配置时默认 10000-20000），避免与信令端口冲突
- **按呼叫复用**：以 `Call-ID#<媒体序号>` 为键，同一呼叫内多条 SDP（如 183 / 200 OK）复用同一个中继
- **对端地址学习**：外部对端首次发出 RTP 时记录其地址，之后客户端回传的媒体包发往该地址
- **回收时机**：检测到任一方发送 `BYE` 时立即释放；或超时 60 秒无包自动回收（每 15 秒检查一次）
- **连接断开**：控制连接断开时会一并销毁该客户端的所有中继

## SIP over TCP（sip-tcp）

`sip-tcp` 用于话机走**明文 TCP**（而非 UDP）传输 SIP 的场景：

```
话机 --TCP--> voxsrv:remotePort --隧道--> voxcli --明文 TCP--> Asterisk
```

- **与 `sip` 一致的能力**：服务端按 SIP over TCP 的 `Content-Length` 分帧，`内网 -> 外部` 方向做 SDP / Contact / Record-Route 改写并分配 RTP 中继，`外部 -> 内网` 方向透传并检测 `BYE` 释放中继；媒体仍为 UDP
- **与 `tcp` 的区别**：`tcp` 类型是纯字节双向转发（不做任何 SIP 解析）；`sip-tcp` 会解析 SIP 消息，因此**必须**配合 `rewriteSDP: true` 才能让通话媒体可达
- **内网要求**：内网 SIP 服务（Asterisk 等）需启用 **TCP** 传输并监听 `localPort`

## SIP over TLS（sip-tls）

`sip-tls` 用于话机侧必须走 TLS 的场景（例如运营商封锁 UDP 5060、或要求加密信令）。TLS 由**服务端原生终止**，无需额外的 stunnel：

```
话机 --TLS--> voxsrv:remotePort（终止 TLS）--隧道明文--> voxcli --明文 TCP--> Asterisk
```

- **证书配置**：服务端 `tlsCertFile` / `tlsKeyFile` 配置 PEM 证书与私钥，最低 TLS 1.2；话机需信任该证书（自签时需手动导入或关闭校验）
- **内网要求**：内网 SIP 服务（Asterisk 等）需启用 **TCP** 传输并监听 `localPort`
- **同端口共存**：`remotePort` 可同时接受 TLS 与明文 SIP/TCP——监听器读取连接首字节，`0x16`（TLS 握手记录）走 TLS 终止，其余按明文处理。因此可把 TLS 话机与明文 TCP 话机合并到同一端口（如 5060），**不要再为同一端口单独配置 `sip-tcp` / `tcp` 代理**，否则同端口重复绑定会失败
- **协议处理**：无论 TLS 还是明文连接，服务端都按 SIP over TCP 的 `Content-Length` 分帧，`内网 -> 外部` 方向复用与 `sip` 类型相同的 SDP / 路由头重写与 RTP 中继，`外部 -> 内网` 方向透传；媒体仍为 UDP
- **媒体**：RTP 走服务端动态分配的公网端口，与 `sip` 类型一致
- **握手保护**：首字节嗅探与 TLS 握手在建立 work 连接前完成（10 秒超时），非 TLS 扫描流量不会触发隧道连接
- **加密边界**：仅 `话机 <-> 公网服务端` 一跳加密，隧道内与内网均为明文

## IP 黑白名单

`ipFilter` 对**控制连接、TCP 代理、UDP 代理、RTP 中继**的所有外部对端生效，支持单个 IP 与 CIDR：

```yaml
ipFilter:
  enable: true
  allowList:          # 非空时仅放行名单内的地址
    - "10.0.0.0/8"
    - "203.0.113.0/24" # 客户端与话机的公网出口
  denyList:           # 优先级高于白名单
    - "1.2.3.4"
```

匹配规则：

1. 命中 `denyList` → 拒绝
2. `allowList` 非空 → 仅放行名单内的地址
3. `allowList` 为空 → 放行全部（此时 `denyList` 相当于纯黑名单）

注意事项：

- 白名单模式下**必须同时包含客户端（voxcli）与外部终端的地址**，否则会把隧道自身挡掉
- 移动网络下终端的公网出口 IP 会漂移，建议按运营商网段预留余量（例如用 `/20` 覆盖 16 个连续 `/24`）
- 被拒绝的来源以 **INFO** 级别记录，同一 IP **5 分钟内只记一次**，避免扫描流量刷屏；可据此发现 IP 漂移：

  ```bash
  grep -a 'ip rejected by filter' voxsrv.log | tail -20
  ```

## 管理面板

服务端内置 Web 控制台，交互参考 frp 的 dashboard，前端用 [petite-vue](https://github.com/vuejs/petite-vue) 实现。页面与 petite-vue 运行时通过 `go:embed` 打进 `voxsrv`，**不依赖外部 CDN**，离线环境同样可用。

### 启用

```yaml
webServer:
  addr: "0.0.0.0"   # 监听地址；设为 127.0.0.1 则只能通过 SSH 隧道访问
  port: 7500        # 0 表示不启动面板
  user: "admin"
  password: "请改为强密码"
```

配置 `port` 后重启服务端，浏览器访问 `http://<服务器>:7500` 即可。若 `port` 非 0 但 `user` / `password` 为空，服务端会记录错误并**跳过面板**（不影响隧道功能）。

### 功能

| 区域 | 内容 |
| --- | --- |
| 服务端概览 | 版本、启动时间、运行时长、控制端口、公网地址、代理/客户端数量、累计流量 |
| 代理列表 | 名称、类型（`sip` / `sip-tcp` / `sip-tls` / `iax` / `tcp` / `udp`）、内网地址、公网端口、所属客户端、连接数、入/出流量、启动时间 |
| 客户端列表 | 地址、认证状态、代理数量、连接时间、最后心跳时间 |
| 分机号分析 | 分机号、协议、来源地址、最后注册、最后通话、通话号码、通话次数、累计通话、入/出流量（详见下文） |
| IP 黑白名单 | 启用开关、白名单 / 黑名单条目增删、IP 拦截检测（详见下文） |
| 操作 | **关闭代理**（停止公网监听并注销）、**断开客户端**（关闭控制连接） |

页面每 3 秒自动轮询一次 `GET /api/overview`、`GET /api/ipfilter` 与 `GET /api/extensions`。

### IP 黑白名单管理

面板可直接读写配置里的 `ipFilter`，**改动立即生效，并回写到服务端启动时 `-c` 指定的配置文件**。回写只重写 `ipFilter` 段落，文件其余内容与注释保持不变。

| 操作 | 说明 |
| --- | --- |
| 启用 / 关闭 | 对应 `ipFilter.enable`；关闭时所有来源一律放行 |
| 检测 | 输入一个 IP，按当前配置给出「会被放行 / 会被拦截」的结论，并指出命中的具体规则 |
| 加入白名单 / 加入黑名单 | 把输入框中的 IP 加入对应名单，支持两种粒度：**按 IP**（单个地址）与**按掩码**（`/24`、`/16` 等，按掩码取网络号后写入，如 `10.20.30.40` + `/24` → `10.20.30.0/24`） |
| 删除 | 从名单中移除指定条目 |

判定顺序与运行时完全一致：**黑名单优先**；白名单非空时仅放行白名单内的地址。因此维护白名单时需确保客户端（voxcli）与外部话机的 IP 都在其中，否则会被一并拦截。

> 回写依赖配置文件路径可写。若配置文件所在目录只读，面板会返回错误并**放弃本次修改**（运行中的名单与磁盘配置保持一致）。

### 流量与连接数统计口径

- **入流量 / 出流量**：以服务端视角计，入 = 外部 → 内网，出 = 内网 → 外部，从进程启动或代理建立时开始累计，**不落盘**（重启清零）
- **SIP 代理的流量包含 RTP 媒体流量**：RTP 中继由某个 SIP 代理的 SDP 触发后，媒体字节数计入该代理
- **连接数**：TCP 代理为当前活动外部连接数；UDP 代理为已见到的外部对端数
- 计数在转发路径上用原子操作累加，不引入锁开销

### 分机号分析

服务端在转发的信令路径上**旁路解析**经过隧道的 SIP / IAX 报文，按分机号汇总下表指标，通过 `GET /api/extensions` 提供给面板。**只统计注册过的分机**：统计记录只在 SIP `REGISTER` / IAX `REGREQ` 时建立，从未注册的号码（外呼的外线被叫、中继号等）不会出现在列表中。

| 指标 | 口径 |
| --- | --- |
| 最后注册 | SIP `REGISTER`（取其 `200 OK`）、IAX `REGREQ` 的时刻；分机号取 `To`，取不到再回退 `From` |
| 最后通话 | 呼叫**接通**的时刻：SIP `200 OK`(INVITE) 或 `ACK`，IAX `ACCEPT` |
| 通话号码 | 最后一次接通通话的**对方号码**：外呼时为外线被叫、来电时为主叫；对方号码无需注册过，无法从报文识别时为空 |
| 通话次数 | 累计**接通**次数；振铃未接听、失败（SIP `>=300`、IAX `REJECT`）都不计 |
| 累计通话 | 每次从接通累计到 `BYE` / `CANCEL`（SIP）或 `HANGUP`（IAX）的时长之和 |
| 入 / 出流量 | 服务端视角：入 = 外部 → 内网，出 = 内网 → 外部，含该分机的信令与所属媒体 |

口径与限制：

- **只统计注册过的分机**：呼叫（INVITE / NEW）中出现但此前没注册过的号码直接忽略，既不建记录也不分摊通话与媒体字节；通话指标只归因给参与呼叫的已注册分机（因此一通已注册分机 ↔ 外线的呼叫，媒体字节只计入该分机，不会重复记到外线号码上）
- **只统计经过本服务端的流量**，不经隧道的注册与通话看不到
- 解析失败一律静默忽略，**只读报文、不改写、不影响转发**；数据保存在内存，**服务重启后重新学习**
- 分机号从注册报文推断（SIP 取 `From` / `To` 的 URI user，IAX 取 `CALLED NUMBER` IE），**不查询 PBX**；只接受 `0-9` `*` `#` 且长度 ≤ 8 的 user 部分，E.164 外线号、中继号会被过滤
- 同一分机号用 SIP 与 IAX 注册会**分别统计**（列表按「协议 / 分机号」分行）；IAX 收发两个方向的呼叫编号各自独立，因此按对端地址归因
- SIP 媒体（RTP 中继）按 `Call-ID` 归因到通话中已注册的分机；无法对加密媒体做内容分析

> 统计仅在内存中维护，条目有上限：对端地址索引 4096、呼叫表 1024，超出后按时间淘汰。

### 认证与安全

- 登录成功后下发 `HttpOnly` 会话 Cookie（有效期 24 小时），密码用恒定时间比较，避免从响应耗时推断
- 面板**不受 `ipFilter` 约束**，否则管理员 IP 不在白名单时会被锁在门外。因此建议：
  - 用**云安全组 / 防火墙**把面板端口限制到管理来源 IP，或
  - 把 `addr` 设为 `127.0.0.1`，通过 SSH 隧道访问：

    ```bash
    ssh -L 7500:127.0.0.1:7500 root@<服务器>
    # 随后本地浏览器打开 http://127.0.0.1:7500
    ```

### 操作语义

- **关闭代理**：只停止服务端的公网监听并注销该代理。客户端侧的 runner 不会收到通知，**客户端重连（或重启）后会重新注册这个代理**。若需永久下线，请修改客户端 `voxcli.yaml` 的 `proxies` 后重启客户端。
- **断开客户端**：直接关闭控制连接。客户端 `voxcli` 的 `voxcli.service` 配置了 `Restart=on-failure`，通常会**立即自动重连**。

## 控制协议

控制连接使用自定义长度帧协议，消息格式为 `[4字节长度][1字节类型][JSON载荷]`：

| 消息类型 | 值 | 方向 | 说明 |
| --- | --- | --- | --- |
| NewProxy | 0x01 | C→S | 请求新建代理 |
| NewProxyResp | 0x02 | S→C | 新建代理响应 |
| NewWorkConn | 0x03 | S→C | 服务端请求新建 work 连接 |
| StartWorkConn | 0x04 | C→S | 客户端启动 work 连接 |
| ProxyClosed | 0x05 | C→S | 代理关闭通知 |
| Ping | 0x06 | C→S | 心跳 |
| Pong | 0x07 | S→C | 心跳响应 |
| UDPPacket | 0x08 | 双向 | UDP 数据包中继 |
| Auth | 0x09 | C→S | 客户端认证请求 |
| AuthResp | 0x0A | S→C | 认证响应 |
| NewRTPRelay | 0x0B | S→C | 请求客户端为 RTP 端口建立中继 |
| NewRTPRelayResp | 0x0C | C→S | 中继建立结果 |
| CloseRTPRelay | 0x0D | S→C | 释放 RTP 中继 |

心跳参数（`internal/app/common/consts`）：客户端每 **30 秒** 发送一次 Ping，服务端超过 **90 秒** 未收到任何 Ping 则关闭该会话并回收其代理与中继。

## 服务端防火墙与安全组

服务端需要同时打通**两层**入方向限制，缺任何一层都会导致外部异常：

1. **云主机安全组**（厂商侧）：在云厂商控制台 / API 中配置，作用于实例的网络入口，**独立于系统内防火墙**。多数厂商默认拒绝所有入方向流量。
2. **系统防火墙**（主机侧）：`firewalld`、`ufw` 或 `iptables`，运行在操作系统内部。

两层都放行后才真正可达。只配了一层时的典型现象是「服务器上 `telnet` 自己的端口通，外部却连不上」。

### 需要放行的端口

| 用途 | 协议 | 端口 | 建议来源 | 说明 |
| --- | --- | --- | --- | --- |
| 控制连接 | **TCP** | `bindPort`（默认 7000） | 仅客户端出口 IP | 客户端主动外联的目标端口；建议按来源 IP 收敛 |
| 管理面板 | **TCP** | `webServer.port`（如 7500） | 仅管理来源 IP | 未配置 `webServer.port` 时无需放行 |
| SIP 信令 | **UDP** | 代理的 `remotePort`（如 5060） | 外部终端 | `sip` 类型代理 |
| SIP over TLS / 明文 SIP-TCP | **TCP** | 代理的 `remotePort`（如 5060、5061） | 外部终端 | `sip-tls` / `sip-tcp` 类型代理；`sip-tls` 同一端口自动分流 TLS 与明文 |
| IAX 信令与媒体 | **UDP** | 代理的 `remotePort`（如 4569） | 外部终端 | `iax` 类型代理；单端口承载信令与媒体 |
| RTP 媒体 | **UDP** | `allowPorts` 中 `end >= 10000` 的段（默认 10000-20000） | 外部终端 | 通话时动态分配 |
| 通用代理 | TCP 或 UDP | 代理的 `remotePort` | 按业务需要 | `tcp` / `udp` 类型代理 |

两个容易踩的坑：

- **SIP / IAX / RTP 全部走 UDP**（IAX 的媒体也复用 4569 的 UDP）。安全组里误配成 TCP 是最常见的配置错误，表现为端口「已放行」但完全收不到包。
- **UDP 无连接**：被安全组或防火墙丢弃时不会返回任何错误，客户端只会「一直没响应」。话机侧通常表现为注册超时（而非 4xx 拒绝），排查时容易误判为服务端故障。

### 云安全组配置要点

- 入方向规则需按上表逐条添加，出方向一般默认全放行（客户端是主动外联，客户端所在网络无需额外配置）
- 部分厂商的安全组规则条数有限制，若 RTP 段过大（如 `10000-20000` 共 10001 个端口），建议缩小 `allowPorts` 中的媒体段以降低规则数量
- 控制端口不宜对全网开放，可只放行客户端出口网段；若客户端出口 IP 会漂移，按运营商网段预留余量
- 云厂商的**网络 ACL / 子网防火墙**（若使用）位于安全组之外，同样需要放行

### 系统防火墙示例

**firewalld**（CentOS / RHEL / Rocky）

```bash
# 控制端口：仅放行客户端出口网段
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="203.0.113.0/24" port port="7000" protocol="tcp" accept'
# SIP / IAX 信令
firewall-cmd --permanent --add-port=5060/udp
firewall-cmd --permanent --add-port=4569/udp
# RTP 媒体段
firewall-cmd --permanent --add-port=10000-20000/udp
firewall-cmd --reload
```

**ufw**（Ubuntu / Debian）

```bash
ufw allow from 203.0.113.0/24 to any port 7000 proto tcp
ufw allow 5060/udp
ufw allow 4569/udp
ufw allow 10000:20000/udp
ufw reload
```

**iptables**

```bash
iptables -A INPUT -p tcp --dport 7000 -s 203.0.113.0/24 -j ACCEPT
iptables -A INPUT -p udp --dport 5060 -j ACCEPT
iptables -A INPUT -p udp --dport 4569 -j ACCEPT
iptables -A INPUT -p udp --dport 10000:20000 -j ACCEPT
```

> 若直接手写 iptables 规则，注意云镜像可能预置了 `fail2ban` 等自定义链。这类链会按来源 IP 做全协议封禁（`protocol=all`），一旦把隧道客户端的出口 IP 拉黑，会同时切断控制连接、SIP、IAX 与 RTP，且表现为「连接被拒绝」。排查命令：
>
> ```bash
> iptables -L -n --line-numbers | grep -i -E 'fail2ban|DROP|REJECT'
> fail2ban-client status                      # 查看各 jail 及其封禁列表
> fail2ban-client set <jail> unbanip <IP>     # 解封
> ```

### 按现象排查

| 现象 | 优先排查 |
| --- | --- |
| `voxcli` 报连接超时 / 被拒绝，服务端看不到 `client authenticated` | 控制端口未放行，或客户端出口 IP 不在白名单 |
| 话机注册无响应（超时，不是 4xx） | 信令端口 UDP 未放行，或被 `ipFilter` / fail2ban 拦截 |
| 能振铃并接通，但听不到声音；或通话约 30 秒后自动挂断 | RTP 端口段未放行（媒体被丢），或 PBX 侧 `rtp_timeout` 到期挂断 |
| 服务器本机 `telnet` 通、外部不通 | 只配了系统防火墙，云安全组漏配 |

## 部署提示

- 客户端**不内置断线重连**，`Run()` 出错即退出。生产环境建议用 systemd 等守护进程拉起（`Restart=on-failure`），并确保控制端口可达，配置方法见「开机自启（systemd）」
- 服务端端口放行清单见上一节「服务端防火墙与安全组」
- 对外暴露 SIP / IAX 端口会持续收到互联网扫描流量，建议配合 `ipFilter` 收敛来源，并在 PBX 侧配置 fail2ban 白名单，避免隧道出口 IP 被误封

## 开机自启（systemd）

服务端与客户端都**不内置守护逻辑**（进程退出即结束），生产环境用 systemd 托管：既能开机自启，也能在异常退出时自动拉起。

### 服务端（voxsrv）

创建 `/etc/systemd/system/voxsrv.service`：

```ini
[Unit]
Description=VoxTun Server (voxsrv)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/voxtun
ExecStart=/opt/voxtun/voxsrv -c /opt/voxtun/voxsrv.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
StandardOutput=append:/opt/voxtun/voxsrv.log
StandardError=append:/opt/voxtun/voxsrv.log

[Install]
WantedBy=multi-user.target
```

### 客户端（voxcli）

创建 `/etc/systemd/system/voxcli.service`：

```ini
[Unit]
Description=VoxTun Client (voxcli)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/voxtun
ExecStart=/opt/voxtun/voxcli -c /opt/voxtun/voxcli.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 启用

```bash
# 重载 unit 并设为开机自启 + 立即启动
systemctl daemon-reload
systemctl enable --now voxsrv     # 客户端主机执行 systemctl enable --now voxcli
```

### 常用操作

```bash
systemctl status voxsrv           # 查看运行状态
systemctl restart voxsrv          # 重启（更换二进制或改配置后）
systemctl stop voxsrv             # 停止
systemctl disable --now voxsrv    # 取消开机自启并停止
journalctl -u voxsrv -f           # 实时日志（客户端为 -u voxcli）
```

### 部署要点

- **路径**：`WorkingDirectory`、`ExecStart` 中的二进制与配置路径需与实际一致；本文档统一使用 `/opt/voxtun/`（生产配置存放位置）
- **`After=network-online.target`**：确保开机时网络就绪后再启动，避免客户端因控制端口暂不可达而反复失败
- **`Restart=on-failure` + `RestartSec=5`**：客户端不内置断线重连，靠 systemd 兜底；服务端异常退出同样会自动拉起
- **`LimitNOFILE=65535`**：SIP / RTP 会占用较多文件描述符与端口，建议放开
- **日志**：服务端用 `StandardOutput/StandardError` 追加到 `/opt/voxtun/voxsrv.log`；客户端未重定向，用 `journalctl -u voxcli` 查看
- **替换二进制**：`systemctl stop` 后再覆盖文件（`chmod +x` 保留执行位），然后 `systemctl start`；直接覆盖运行中的文件可能报 `Text file busy`
- **证书续期无需重启**：`sip-tls` 使用的证书由服务端按文件 `ModTime` 自动重载，acme.sh / certbot 续期后不用重启 `voxsrv`，隧道不会中断

## 后续可扩展

- 控制连接 TLS 加密
- Web 管理面板：实时查看在线客户端与代理状态
- 多客户端隔离：按 token / 客户端 ID 隔离代理与端口

## License

MIT
