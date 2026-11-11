# ◈ Privacy Lab — Browser Privacy & Fingerprint Lab

**English** · [فارسی](README.fa.md) · [中文](README.zh-CN.md)

A single-file Cloudflare Worker with 40 tool pages that show what a website can learn about your browser and network: IP and request metadata, fingerprinting surfaces (canvas, WebGL, audio, fonts…), privacy signals, and security headers. No dependencies, no database, nothing is stored.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/YOUR_USERNAME/privacy-lab-worker)

> Replace `YOUR_USERNAME/privacy-lab-worker` in the button link with your own **public** GitHub repository.

## Features

- **40 tools**, one page each, results run automatically when a page opens.
- **3 languages**: English, فارسی (right-to-left layout), 中文. Buttons, notices and messages are translated.
- **Local-first**: browser tests run in your browser; only the IP/request page uses Cloudflare's request data.
- **Honest limits**: TLS, HTTP/2, QUIC and TCP/IP tests explain that a Worker cannot see raw handshakes instead of inventing fingerprints.
- No cookies, no analytics, no third-party scripts.

| Group | Tools |
|---|---|
| Network / server | IP, TLS, HTTP/2, QUIC, TCP/IP, Connection info |
| Browser fingerprint | JavaScript, WebRTC, Canvas, WebGL, Fonts, Audio, Voices, Screen, ClientRects, Client Hints, Fingerprint summary, CSS media, Features, Sensors, Media devices |
| Privacy | Geolocation, Permissions, Storage & cookies, Tracker blocking, Third-party scripts, Do Not Track, Content filters, Extensions |
| Security | HTTPS & headers, CSP, CORS, Referrer policy, Permissions-Policy, Credentials, WebAuthn, Mixed content, Cross-origin isolation, WebGPU, JS engine & Intl |

## Deploy

### 1. One click
Push this repository to GitHub (public), put its URL into the button above, and click it. Cloudflare builds and deploys it on your account.

### 2. Cloudflare dashboard (copy & paste)
1. **Workers & Pages → Create → Create Worker**.
2. Open the code editor, replace everything with the contents of [`worker.js`](worker.js), then **Deploy**.

### 3. Wrangler CLI
```bash
npm install
npx wrangler login
npm run deploy
```

Local preview: `npm run dev` (then open http://localhost:8787).

## Choosing the language

Add `?lang=en`, `?lang=fa` or `?lang=zh` to any URL, or use the switcher in the header. Without it, the browser's `Accept-Language` is used, then English. No cookie is set; links keep the `?lang=` parameter.

## API

| Route | Description |
|---|---|
| `/api/request` | JSON: request headers and Cloudflare metadata seen by the Worker |
| `/api/ip` | JSON: observed IP, country, city, ASN |

## Limitations

Cloudflare ends the visitor's TCP/TLS/HTTP/QUIC connection at its edge, so a Worker cannot read raw packets, the TLS ClientHello (JA3/JA4), HTTP/2 frames or QUIC handshakes. IP geolocation is approximate. Detection tests (trackers, extensions, content filters) are best-effort and marked inconclusive.

## Customize

- **Add a language**: add it to `LANGS` and add an `I.<code> = { ... }` dictionary at the bottom of `worker.js`. Missing keys fall back to English.
- **Add a tool**: add its id to `TOOLS`, a page to `pages`, and its strings (`<id>.t`, `<id>.d`, …) to the dictionaries.

## Responsible use

Use this to understand your own exposure, not to track or identify other people.

## License

MIT — see [LICENSE](LICENSE).
