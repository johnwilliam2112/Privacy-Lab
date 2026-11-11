# ◈ Privacy Lab — 浏览器隐私与指纹实验室

[English](README.md) · [فارسی](README.fa.md) · **中文**

一个单文件的 Cloudflare Worker，包含 40 个工具页面，展示网站能了解到你的浏览器和网络的哪些信息：IP 与请求元数据、指纹识别面（Canvas、WebGL、音频、字体等）、隐私信号和安全标头。无依赖、无数据库，不保存任何数据。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/johnwilliam2112/privacy-lab-worker)


## 功能

- **40 个工具**，每个一页；打开页面即自动运行并显示结果。
- **3 种语言**：English、فارسی（从右到左布局）、中文。按钮、提示和消息均已翻译。
- **本地优先**：浏览器测试在你的浏览器中运行；只有 IP/请求页面使用 Cloudflare 的请求数据。
- **如实说明限制**：TLS、HTTP/2、QUIC 和 TCP/IP 测试会说明 Worker 无法看到原始握手，而不是伪造指纹。
- 无 Cookie、无统计分析、无第三方脚本。

| 分组 | 工具 |
|---|---|
| 网络 / 服务器 | IP、TLS、HTTP/2、QUIC、TCP/IP、连接信息 |
| 浏览器指纹 | JavaScript、WebRTC、Canvas、WebGL、字体、音频、语音、屏幕、ClientRects、Client Hints、指纹汇总、CSS 媒体查询、功能检测、传感器、媒体设备 |
| 隐私 | 地理位置、权限、存储与 Cookie、跟踪器拦截、第三方脚本、请勿跟踪、内容过滤器、扩展 |
| 安全 | HTTPS 与标头、CSP、CORS、Referrer 策略、Permissions-Policy、凭据、WebAuthn、混合内容、跨源隔离、WebGPU、JS 引擎与 Intl |

## 部署

### 1. 一键部署
将本仓库推送到 GitHub（公开），把仓库地址填入上方按钮链接，然后点击按钮。Cloudflare 会在你的账户上构建并部署。

### 2. Cloudflare 控制台（复制粘贴）
1. 进入 **Workers & Pages → Create → Create Worker**。
2. 打开代码编辑器，用 [`worker.js`](worker.js) 的内容替换全部代码，然后点击 **Deploy**。

### 3. Wrangler 命令行
```bash
npm install
npx wrangler login
npm run deploy
```

本地预览：`npm run dev`（然后打开 http://localhost:8787）。

## 选择语言

在任意网址后加上 `?lang=en`、`?lang=fa` 或 `?lang=zh`，或使用页眉中的语言切换器。否则会使用浏览器的 `Accept-Language`，再回退到英文。不会设置 Cookie，站内链接会保留 `?lang=` 参数。

## API

| 路径 | 说明 |
|---|---|
| `/api/request` | JSON：Worker 看到的请求头和 Cloudflare 元数据 |
| `/api/ip` | JSON：观察到的 IP、国家/地区、城市、ASN |

## 限制

Cloudflare 在其边缘终止访问者的 TCP/TLS/HTTP/QUIC 连接，因此 Worker 无法读取原始数据包、TLS ClientHello（JA3/JA4）、HTTP/2 帧或 QUIC 握手。IP 定位只是近似值。检测类测试（跟踪器、扩展、内容过滤器）为尽力而为，并标注为结果不确定。

## 自定义

- **添加语言**：把它加入 `LANGS`，并在 `worker.js` 末尾添加 `I.<code> = { ... }` 词典。缺失的键会回退到英文。
- **添加工具**：把 id 加入 `TOOLS`，在 `pages` 中添加页面，并在各词典中添加对应文案（`<id>.t`、`<id>.d` 等）。

## 负责任地使用

请用它了解自己的信息暴露情况，而不是用来跟踪或识别他人。

## 许可证

MIT — 见 [LICENSE](LICENSE)。
