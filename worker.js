/**
 * Browser Privacy & Fingerprint Lab — single-file Cloudflare Worker (v4)
 * Languages: English · فارسی (RTL) · 中文.  Deploy as worker.js. No npm dependencies.
 *
 * IMPORTANT LIMITATIONS:
 * Cloudflare terminates the visitor's TCP/TLS/HTTP connection at its edge.
 * A Worker cannot inspect the visitor's original TCP packets, TLS ClientHello,
 * HTTP/2 frames, or QUIC handshake. Pages for those tests explain this and
 * provide browser-visible checks instead of inventing fingerprints.
 * Browser fingerprint tests run locally in the visitor's browser. Geolocation
 * requires permission. No browser fingerprint data is intentionally stored.
 *
 * LANGUAGE: ?lang=en|fa|zh  (otherwise Accept-Language, otherwise English). No cookie is set.
 * To add a language: add it to LANGS and add an I.<code> dictionary at the bottom of this file
 * (missing keys fall back to English).
 */

const LANGS = {
  en: { label: "English", html: "en", dir: "ltr" },
  fa: { label: "فارسی", html: "fa", dir: "rtl" },
  zh: { label: "中文", html: "zh-CN", dir: "ltr" }
};

const TOOLS = ["ip","tls","http2","quic","tcpip","connection","javascript","webrtc","canvas","webgl","fonts","audio","voices","screen","clientrects","client-hints","fingerprint","css-media","features","sensors","media-devices","geolocation","permissions","storage","trackers","third-party","dnt","content-filters","extensions","https-audit","csp","cors","referrer","permissions-policy","credential","webauthn","mixed-content","isolation","webgpu","js-engine"];

const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const json = (data, status = 200) => new Response(JSON.stringify(data, null, 2), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" } });
const getIP = (req, na = "Unavailable") => req.headers.get("CF-Connecting-IP") || req.headers.get("x-real-ip") || na;

const pickLang = (url, req) => {
  const q = (url.searchParams.get("lang") || "").toLowerCase();
  if (hasOwn(LANGS, q)) return q;
  for (const part of (req.headers.get("accept-language") || "").split(",")) {
    const base = part.trim().split(";")[0].split("-")[0].toLowerCase();
    if (hasOwn(LANGS, base)) return base;
  }
  return "en";
};

const translator = L => (k, vars) => {
  let s = (I[L] && I[L][k]) ?? I.en[k] ?? k;
  if (vars) for (const v in vars) s = s.split("{" + v + "}").join(vars[v]);
  return s;
};

// Strings handed to the browser-side script of one page: its own keys ("<id>.x" -> x) plus common "c." keys.
const strsFor = (L, id) => {
  const out = { c: {} }, pre = id + ".";
  for (const k of Object.keys(I.en)) {
    const v = (I[L] && I[L][k]) ?? I.en[k];
    if (k.startsWith(pre)) out[k.slice(pre.length)] = v;
    else if (k.startsWith("c.")) out.c[k.slice(2)] = v;
  }
  return out;
};

// Reverse-DNS (PTR) name for an IPv4/IPv6 address, or null.
const ptrName = ip => {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split(".").reverse().join(".") + ".in-addr.arpa";
  if (ip.includes(":") && !ip.includes(".")) {
    const parts = ip.split("::");
    if (parts.length > 2) return null;
    const hs = parts[0] ? parts[0].split(":") : [];
    const ts = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
    const full = parts.length === 1 ? hs : [...hs, ...Array(Math.max(8 - hs.length - ts.length, 0)).fill("0"), ...ts];
    if (full.length !== 8 || !full.every(g => /^[0-9a-f]{1,4}$/i.test(g))) return null;
    return full.map(g => g.padStart(4, "0")).join("").split("").reverse().join(".") + ".ip6.arpa";
  }
  return null;
};

const reqInfo = (req, t = translator("en")) => {
  const h = req.headers, cf = req.cf || {}, na = t("rq.na");
  return {
    [t("rq.ip")]: getIP(req, na),
    [t("rq.country")]: cf.country || h.get("cf-ipcountry") || na,
    [t("rq.region")]: cf.region || na,
    [t("rq.city")]: cf.city || na,
    [t("rq.tz")]: cf.timezone || na,
    "ASN": cf.asn || na,
    [t("rq.isp")]: cf.asOrganization || na,
    [t("rq.proto")]: cf.httpProtocol || (h.get("cf-visitor") || "").slice(0, 100) || na,
    "User-Agent": h.get("user-agent") || na,
    "Accept-Language": h.get("accept-language") || na,
    "Referer": h.get("referer") || na,
    "DNT header": h.get("dnt") || t("rq.ns"),
    "Sec-GPC header": h.get("sec-gpc") || t("rq.ns"),
    [t("rq.ray")]: h.get("cf-ray") || na
  };
};

const CSS = `
:root{
  color-scheme:dark;
  --bg:#070b18;--bg2:#0a0f22;--panel:#101830;--panel2:#152046;--panel-soft:#0d142a;
  --text:#eef3ff;--muted:#9aa8c8;--line:#22305a;--line-strong:#334680;
  --accent:#22d3ee;--accent2:#a78bfa;--accent3:#f472b6;--good:#34d399;--warn:#fbbf24;--bad:#f87171;
}
*{box-sizing:border-box}
html,body{margin:0}
body{
  margin:0;min-height:100vh;
  background:
    radial-gradient(1000px 600px at 15% -10%, rgba(34,211,238,.14), transparent 60%),
    radial-gradient(900px 600px at 95% 0%, rgba(167,139,250,.16), transparent 55%),
    radial-gradient(700px 500px at 50% 110%, rgba(244,114,182,.10), transparent 60%),
    linear-gradient(180deg,#070b18,#050814 60%,#070b18);
  color:var(--text);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",Tahoma,Vazirmatn,"PingFang SC","Microsoft YaHei","Noto Sans SC","Noto Sans Arabic",sans-serif;
}
body::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:linear-gradient(rgba(255,255,255,.028) 1px, transparent 1px),linear-gradient(90deg, rgba(255,255,255,.028) 1px, transparent 1px);
  background-size:44px 44px;
  -webkit-mask-image:radial-gradient(ellipse at center, #000 40%, transparent 85%);
  mask-image:radial-gradient(ellipse at center, #000 40%, transparent 85%);
}
a{color:#7dd3fc}
a:hover{color:#a5f3fc}
header{
  padding:14px max(18px,calc((100% - 1240px)/2));
  border-bottom:1px solid var(--line);
  background:rgba(7,11,24,.72);
  position:sticky;top:0;z-index:5;
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
}
header .bar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
header .brand{
  font-size:20px;font-weight:800;letter-spacing:.3px;
  background:linear-gradient(90deg,var(--accent),var(--accent2) 60%,var(--accent3));
  -webkit-background-clip:text;background-clip:text;color:transparent;display:inline-block;
}
header small{display:block;color:var(--muted);margin-top:2px}
.langs{display:flex;gap:6px;flex-wrap:wrap}
.lang{padding:5px 12px;border:1px solid var(--line);border-radius:999px;color:var(--muted);text-decoration:none;font-size:13px}
.lang:hover{color:var(--text);border-color:var(--line-strong)}
.lang.active{color:#04121f;background:linear-gradient(90deg,var(--accent),#4cc9f0);border-color:transparent;font-weight:700}
.layout{max-width:1240px;margin:auto;padding:22px 16px;display:grid;grid-template-columns:250px minmax(0,1fr);gap:22px;position:relative;z-index:1}
.sidebar,.panel,.hero{background:linear-gradient(180deg,rgba(16,24,48,.95),rgba(11,17,36,.95));border:1px solid var(--line);border-radius:16px}
.sidebar{padding:10px;align-self:start;position:sticky;top:84px;max-height:calc(100vh - 100px);overflow:auto}
.sidebar::-webkit-scrollbar{width:8px}
.sidebar::-webkit-scrollbar-thumb{background:var(--line-strong);border-radius:8px}
.navlink{display:block;text-decoration:none;padding:8px 11px;border-radius:9px;color:var(--muted);font-size:13px;transition:background .15s,color .15s}
.navlink:hover{background:var(--panel2);color:var(--text)}
.navlink.active{background:linear-gradient(90deg,rgba(34,211,238,.20),rgba(167,139,250,.20));color:#e6f8ff;box-shadow:inset 0 0 0 1px rgba(34,211,238,.35)}
main{min-width:0}
.hero{
  padding:26px;margin-bottom:16px;
  background:radial-gradient(600px 200px at 0% 0%, rgba(34,211,238,.18), transparent 60%),radial-gradient(600px 200px at 100% 100%, rgba(167,139,250,.18), transparent 60%),linear-gradient(135deg,#121b3a,#0d142a);
  position:relative;overflow:hidden;
}
h1{font-size:clamp(24px,4vw,34px);line-height:1.2;margin:0 0 10px;letter-spacing:-.01em}
h2{font-size:17px;margin:0 0 12px;color:#dbe6ff}
p{color:var(--muted);margin:8px 0}
.panel{padding:18px;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:12px}
.toolcard{
  display:block;padding:16px;text-decoration:none;color:var(--text);
  background:linear-gradient(180deg,rgba(16,24,48,.9),rgba(11,17,36,.9));
  border:1px solid var(--line);border-radius:14px;
  transition:transform .15s ease, border-color .15s ease, box-shadow .15s ease;position:relative;overflow:hidden;
}
.toolcard::after{content:"";position:absolute;inset:-1px;border-radius:14px;pointer-events:none;background:linear-gradient(120deg,rgba(34,211,238,.0),rgba(167,139,250,.0));transition:background .2s ease}
.toolcard:hover{transform:translateY(-2px);border-color:var(--line-strong);box-shadow:0 8px 30px rgba(34,211,238,.08)}
.toolcard:hover::after{background:linear-gradient(120deg,rgba(34,211,238,.18),rgba(167,139,250,.18))}
.toolcard strong{display:block;margin-bottom:6px;color:#e6f0ff}
.toolcard span{color:var(--muted);font-size:13px}
.btn{
  border:0;border-radius:10px;padding:10px 16px;font:inherit;font-weight:700;cursor:pointer;
  background:linear-gradient(90deg,var(--accent),#4cc9f0);color:#04121f;margin:5px 0;margin-inline-end:8px;
  transition:transform .1s ease, box-shadow .15s ease, filter .15s ease;box-shadow:0 6px 20px rgba(34,211,238,.22);
}
.btn:hover{filter:brightness(1.06);transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn.secondary{background:linear-gradient(180deg,var(--panel2),var(--panel-soft));color:var(--text);border:1px solid var(--line-strong);box-shadow:none}
.btn.secondary:hover{filter:none;background:var(--panel2)}
.btn:focus-visible,.navlink:focus-visible,.lang:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
pre,code{overflow-wrap:anywhere;white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{direction:ltr;text-align:left;background:#050a18;border:1px solid var(--line);border-radius:12px;padding:13px;color:#cfdaff;max-height:460px;overflow:auto}
.kv{display:grid;grid-template-columns:minmax(120px,190px) minmax(0,1fr);gap:8px 14px}
.kv>div{display:contents}
.kv span{color:var(--muted)}
.kv code{color:var(--text);direction:ltr;unicode-bidi:plaintext}
.status{padding:11px 13px;border-radius:10px;margin:10px 0;overflow-wrap:anywhere;background:var(--panel-soft);border:1px solid var(--line);display:inline-block;font-weight:600}
.status.good{color:var(--good);border-color:rgba(52,211,153,.35);background:rgba(52,211,153,.08)}
.status.warn{color:var(--warn);border-color:rgba(251,191,36,.35);background:rgba(251,191,36,.08)}
.status.bad{color:var(--bad);border-color:rgba(248,113,113,.35);background:rgba(248,113,113,.08)}
.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.muted{color:var(--muted)}
input,textarea,select{background:#050a18;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:10px;max-width:100%}
footer{max-width:1240px;padding:0 16px 28px;margin:auto;color:var(--muted);font-size:12px;position:relative;z-index:1}
.notice{border-inline-start:3px solid var(--accent);padding:10px 13px;margin:14px 0;background:linear-gradient(90deg,rgba(34,211,238,.10),rgba(34,211,238,.02));border-radius:6px;color:#cdeaff}
.notice.warn{border-inline-start-color:var(--warn);background:linear-gradient(90deg,rgba(251,191,36,.10),rgba(251,191,36,.02));color:#ffe7b3}
canvas{max-width:100%;border:1px solid var(--line);border-radius:10px;background:white}
@media(max-width:820px){
  .layout{grid-template-columns:1fr;padding:12px}
  .sidebar{position:static;max-height:none;display:flex;gap:4px;overflow-x:auto;white-space:nowrap}
  .navlink{flex:0 0 auto}
  header{position:static;padding:14px 16px}
  .kv{grid-template-columns:1fr;gap:2px}
  .kv>div{display:block;margin-bottom:9px}
  .kv span{display:block;font-size:12px}
  .hero,.panel{padding:15px}
}
`;

const CH_HINTS = "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model";

const buildCSP = id => [
  "default-src 'self' 'unsafe-inline' data: blob:",
  "connect-src 'self' https: stun:",
  "img-src 'self' data: blob: https: http:",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'unsafe-inline'" + (id === "extensions" ? " chrome-extension:" : ""),
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'"
].join("; ");

// One header set for every HTML response, so the "HTTPS & Security Headers" audit is consistent on every page.
const htmlHeaders = id => {
  const h = {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": id === "media-devices" ? "geolocation=(), camera=(self), microphone=(self)" : "geolocation=(self), camera=(), microphone=()",
    "content-security-policy": buildCSP(id),
    "vary": "Accept-Language"
  };
  if (id === "client-hints") h["accept-ch"] = CH_HINTS;
  return h;
};

const page = (L, t, current, path, title, description, body) => {
  const nav = TOOLS.map(id => `<a class="navlink ${current === id ? "active" : ""}" href="/${id}?lang=${L}">${esc(t(id + ".t"))}</a>`).join("");
  const langs = Object.keys(LANGS).map(k => `<a class="lang ${k === L ? "active" : ""}" lang="${LANGS[k].html}" hreflang="${LANGS[k].html}" href="${path}?lang=${k}">${esc(LANGS[k].label)}</a>`).join("");
  return `<!doctype html><html lang="${LANGS[L].html}" dir="${LANGS[L].dir}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>${esc(title)} · Privacy Lab</title><style>${CSS}</style></head><body>
<header><div class="bar"><div><div class="brand">◈ Privacy Lab</div><small>${esc(t("ui.sub"))}</small></div><nav class="langs" aria-label="${esc(t("ui.langs"))}">${langs}</nav></div></header>
<div class="layout">
  <aside class="sidebar"><a class="navlink ${current === "home" ? "active" : ""}" href="/?lang=${L}">${esc(t("ui.overview"))}</a>${nav}</aside>
  <main>
    <section class="hero"><h1>${esc(title)}</h1><p>${esc(description)}</p></section>
    ${body}
  </main>
</div>
<footer>${esc(t("ui.footer"))}</footer>
</body></html>`;
};

const outputBox = t => `<section class="panel"><h2>${esc(t("ui.results"))}</h2><div id="result" class="status">${esc(t("c.running"))}</div><pre id="details">…</pre></section>`;

// Standard page body: optional notice, a "run" button (+ extras), results box.
const B = (id, o = {}) => t =>
  (o.w ? `<div class="notice${o.w === "warn" ? " warn" : ""}">${esc(t(id + ".w"))}</div>` : "") +
  `<section class="panel">${o.pre ? o.pre(t) : ""}<button class="btn" id="run">${esc(t(o.b ? id + ".b" : "c.run"))}</button>${o.extra ? o.extra(t) : ""}</section>` +
  outputBox(t);

// Browser-side helpers shared by every page script (no backticks / ${ } allowed in page scripts).
const basic = `
const $=id=>document.getElementById(id);
const show=v=>{$('details').textContent=typeof v==='string'?v:JSON.stringify(v,null,2)};
const st=(s,c)=>{const e=$('result');e.textContent=s;e.className='status '+(c||'')};
const fmt=(s,o)=>{for(const k in o)s=s.split('{'+k+'}').join(o[k]);return s};
const hex=b=>Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));
const getJSON=async u=>(await fetch(u,{cache:'no-store'})).json();
const wire=f=>{$('run').onclick=async()=>{st(T.c.running,'warn');try{await f()}catch(e){show(String((e&&e.message)||e));st(T.c.failed,'bad')}}};
`;

const runPage = (L, t, id, bodyFn, script) => {
  const T = JSON.stringify(strsFor(L, id)).replace(/</g, "\\u003c");
  const js = `(function(){const T=${T};${basic}${script}})();`;
  const html = page(L, t, id, "/" + id, t(id + ".t"), t(id + ".d"),
    bodyFn(t) + `<script>${js}</script><script>if(!window.__noAuto){var r=document.getElementById('run');if(r)r.click()}</script>`);
  return new Response(html, { headers: htmlHeaders(id) });
};

const pages = {

// ---------- Network / server ----------

"tls": [B("tls", { w: "warn", b: true }), `
wire(async()=>{
  const d=await getJSON('/api/request');
  const algs=[];
  for(const name of ['SHA-1','SHA-256','SHA-384','SHA-512']){try{await crypto.subtle.digest(name,new Uint8Array(1));algs.push({name,available:true})}catch(e){algs.push({name,available:false})}}
  show({workerObservation:d,clientSecureContext:window.isSecureContext,locationProtocol:location.protocol,cryptoSubtle:!!(window.crypto&&crypto.subtle),webCryptoDigests:algs,limitations:T.lim});
  st(T.ok,'good');
});`],

"http2": [B("http2", { w: "warn", b: true }), `
wire(async()=>{
  const d={browserNavigation:performance.getEntriesByType('navigation').map(n=>({nextHopProtocol:n.nextHopProtocol})),note:T.note};
  try{d.edge=await getJSON('/api/request')}catch(e){d.error=e.message}
  show(d);st(T.ok,'warn');
});`],

"quic": [B("quic", { w: "warn", b: true }), `
wire(async()=>{
  const d={secureContext:isSecureContext,https:location.protocol==='https:',fetchAvailable:!!window.fetch,performanceNavigation:performance.getEntriesByType('navigation').map(x=>({nextHopProtocol:x.nextHopProtocol,transferSize:x.transferSize,encodedBodySize:x.encodedBodySize})),note:T.note};
  try{d.edgeMetadata=await getJSON('/api/request')}catch(e){d.edgeMetadataError=e.message}
  show(d);st(T.ok,'good');
});`],

"tcpip": [B("tcpip", { w: "warn", b: true }), `
wire(async()=>{
  show({edgeVisible:await getJSON('/api/request'),rawTCPHeaders:T.na,clientMTU:T.na,hopCount:T.na,JA4T:T.ja4t});
  st(T.ok,'good');
});`],

"connection": [B("connection"), `
wire(()=>{
  const c=navigator.connection||navigator.mozConnection||navigator.webkitConnection;
  const o={available:!!c};
  if(c){o.effectiveType=c.effectiveType;o.rtt=c.rtt;o.downlink=c.downlink;o.downlinkMax=c.downlinkMax;o.saveData=c.saveData;o.type=c.type}
  try{const n=performance.getEntriesByType('navigation')[0];if(n)o.nextHopProtocol=n.nextHopProtocol}catch(e){}
  o.note=T.note;show(o);st(T.ok,'good');
});`],

// ---------- Browser fingerprint ----------

"javascript": [B("javascript"), `
wire(async()=>{
  const n=navigator,s=screen;
  const d={userAgent:n.userAgent,platform:n.platform,language:n.language,languages:n.languages,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,localTime:new Date().toString(),
    screen:{width:s.width,height:s.height,availWidth:s.availWidth,availHeight:s.availHeight,colorDepth:s.colorDepth,pixelDepth:s.pixelDepth},
    viewport:{width:innerWidth,height:innerHeight,devicePixelRatio:devicePixelRatio},
    hardwareConcurrency:n.hardwareConcurrency??'Not exposed',deviceMemoryGB:n.deviceMemory??'Not exposed',maxTouchPoints:n.maxTouchPoints,cookieEnabled:n.cookieEnabled,online:n.onLine,
    pdfViewerEnabled:n.pdfViewerEnabled??'Not exposed',webdriver:n.webdriver??'Not exposed',plugins:Array.from(n.plugins||[]).map(p=>p.name),permissionsAPI:!!n.permissions,serviceWorker:!!n.serviceWorker};
  try{d.storageEstimate=n.storage&&n.storage.estimate?await n.storage.estimate():'Not exposed'}catch(e){d.storageEstimate='Not exposed'}
  try{if(n.getBattery){const b=await n.getBattery();d.battery={charging:b.charging,level:b.level,chargingTime:b.chargingTime,dischargingTime:b.dischargingTime}}else d.battery='Not exposed'}catch(e){d.battery='Not exposed'}
  show(d);st(T.ok,'good');
});`],

"webrtc": [B("webrtc", { w: "warn" }), `
wire(async()=>{
  if(!window.RTCPeerConnection){st(T.na,'bad');show('RTCPeerConnection is not supported.');return}
  const items=[];let timer;
  const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
  try{
    pc.createDataChannel('privacy-check');
    const gathered=new Promise(res=>{
      timer=setTimeout(()=>res('timeout'),8000);
      pc.onicecandidate=e=>{if(e.candidate){items.push({candidate:e.candidate.candidate,type:e.candidate.type||'unknown',address:e.candidate.address||'hidden',protocol:e.candidate.protocol||'unknown'});show({candidates:items,note:T.note})}else res('done')};
    });
    await pc.setLocalDescription(await pc.createOffer());
    st(T.gather,'warn');
    const r=await gathered;
    show({candidates:items,note:T.note});
    if(r==='done')st(items.length?T.done:T.none,items.length?'warn':'good');else st(T.timeout,'warn');
  }finally{clearTimeout(timer);pc.close()}
});`],

"canvas": [B("canvas", { extra: () => '<div id="canvasout"></div>' }), `
wire(async()=>{
  const c=document.createElement('canvas');c.width=320;c.height=90;const x=c.getContext('2d');
  x.textBaseline='top';x.font='16px Arial';x.fillStyle='#f60';x.fillRect(8,8,90,35);
  x.fillStyle='#069';x.fillText('Privacy Lab canvas ✓',12,14);
  x.fillStyle='rgba(90,20,180,.7)';x.beginPath();x.arc(160,48,25,0,Math.PI*2);x.fill();
  $('canvasout').replaceChildren(c);
  const url=c.toDataURL();
  show({sha256:await sha(url),dataURLLength:url.length,note:T.note});
  st(T.ok,'good');
});`],

"webgl": [B("webgl"), `
wire(()=>{
  const c=document.createElement('canvas'),gl=c.getContext('webgl')||c.getContext('experimental-webgl');
  if(!gl){st(T.none,'warn');show('No WebGL context.');return}
  const ext=gl.getExtension('WEBGL_debug_renderer_info');
  show({version:gl.getParameter(gl.VERSION),shadingLanguageVersion:gl.getParameter(gl.SHADING_LANGUAGE_VERSION),vendor:gl.getParameter(gl.VENDOR),renderer:gl.getParameter(gl.RENDERER),
    unmaskedVendor:ext?gl.getParameter(ext.UNMASKED_VENDOR_WEBGL):'Masked/not exposed',unmaskedRenderer:ext?gl.getParameter(ext.UNMASKED_RENDERER_WEBGL):'Masked/not exposed',
    maxTextureSize:gl.getParameter(gl.MAX_TEXTURE_SIZE),maxRenderbufferSize:gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),maxVertexAttribs:gl.getParameter(gl.MAX_VERTEX_ATTRIBS),extensions:gl.getSupportedExtensions()});
  st(T.ok,'good');
});`],

"fonts": [B("fonts"), `
wire(()=>{
  const fonts=['Arial','Arial Black','Calibri','Cambria','Comic Sans MS','Consolas','Courier New','Georgia','Helvetica','Impact','Menlo','Roboto','Times New Roman','Trebuchet MS','Verdana','Segoe UI','Tahoma','Ubuntu','Fira Sans','Cantarell','Noto Sans','Vazirmatn','Noto Naskh Arabic','Microsoft YaHei','PingFang SC','SimSun'];
  const bases=['monospace','sans-serif','serif'];
  const x=document.createElement('canvas').getContext('2d'),sample='mmmmmmmmmmlli 0123456789';
  const base={};
  bases.forEach(b=>{x.font='72px '+b;base[b]=x.measureText(sample).width});
  const results=fonts.map(f=>{
    const deltas=bases.map(b=>{x.font='72px "'+f+'",'+b;return +(x.measureText(sample).width-base[b]).toFixed(3)});
    return {font:f,detected:deltas.some(d=>d!==0),deltas};
  });
  show({baselineWidths:base,detectedCount:results.filter(r=>r.detected).length,results,note:T.note});
  st(T.ok,'good');
});`],

"audio": [B("audio", { w: "info" }), `
wire(async()=>{
  const Ctx=window.OfflineAudioContext||window.webkitOfflineAudioContext;
  if(!Ctx){st(T.none,'warn');show('No OfflineAudioContext.');return}
  const ctx=new Ctx(1,44100,44100);
  const osc=ctx.createOscillator();osc.type='triangle';osc.frequency.value=10000;
  const comp=ctx.createDynamicsCompressor();
  comp.threshold.value=-50;comp.knee.value=40;comp.ratio.value=12;comp.attack.value=0;comp.release.value=.25;
  osc.connect(comp);comp.connect(ctx.destination);osc.start(0);
  const buf=await ctx.startRendering();
  const ch=buf.getChannelData(0);
  let sum=0;for(let i=4500;i<5000;i++)sum+=Math.abs(ch[i]);
  const hash=hex(await crypto.subtle.digest('SHA-256',new Uint8Array(ch.buffer,ch.byteOffset,Math.min(ch.byteLength,20000))));
  show({sha256:hash,sum_4500_5000:+sum.toFixed(6),sampleRate:buf.sampleRate,length:buf.length,note:T.note});
  st(T.ok,'good');
});`],

"voices": [B("voices", { w: "warn", b: true }), `
wire(async()=>{
  if(!window.speechSynthesis){st(T.none,'bad');show('No speechSynthesis API.');return}
  let v=speechSynthesis.getVoices();
  if(!v.length){await new Promise(r=>{speechSynthesis.onvoiceschanged=()=>{speechSynthesis.onvoiceschanged=null;r()};setTimeout(r,1200)});v=speechSynthesis.getVoices()}
  show({count:v.length,voices:v.map(x=>({name:x.name,lang:x.lang,localService:x.localService,default:x.default,voiceURI:x.voiceURI}))});
  st(v.length?fmt(T.ok,{n:v.length}):T.zero,v.length?'good':'warn');
});`],

"screen": [B("screen"), `
wire(()=>{
  const s=screen;
  show({screen:{width:s.width,height:s.height,availWidth:s.availWidth,availHeight:s.availHeight,colorDepth:s.colorDepth,pixelDepth:s.pixelDepth,orientation:s.orientation?{type:s.orientation.type,angle:s.orientation.angle}:'Unavailable',isExtended:(typeof s.isExtended!=='undefined'?s.isExtended:'Not exposed')},
    window:{innerWidth,innerHeight,outerWidth,outerHeight,devicePixelRatio,screenX,screenY,screenLeft,screenTop},
    matchMedia:{'color-gamut srgb':matchMedia('(color-gamut: srgb)').matches,'color-gamut p3':matchMedia('(color-gamut: p3)').matches,'color-gamut rec2020':matchMedia('(color-gamut: rec2020)').matches,'dynamic-range high':matchMedia('(dynamic-range: high)').matches,'prefers-reduced-motion':matchMedia('(prefers-reduced-motion: reduce)').matches,'pointer fine':matchMedia('(pointer: fine)').matches,'pointer coarse':matchMedia('(pointer: coarse)').matches,'hover hover':matchMedia('(hover: hover)').matches},
    note:T.note});
  st(T.ok,'good');
});`],

"clientrects": [B("clientrects", { pre: () => '<div id="sample" dir="ltr" style="display:inline-block;font:17px Arial;padding:7px;border:2px solid #789;transform:rotate(.2deg)">ClientRects test — 0123456789</div><br>' }), `
wire(async()=>{
  const el=$('sample'),r=el.getBoundingClientRect(),range=document.createRange();
  range.selectNodeContents(el);
  const rects=[...range.getClientRects()].map(x=>({x:x.x,y:x.y,width:x.width,height:x.height,top:x.top,right:x.right,bottom:x.bottom,left:x.left}));
  const d={element:{x:r.x,y:r.y,width:r.width,height:r.height,top:r.top,right:r.right,bottom:r.bottom,left:r.left},textRects:rects,devicePixelRatio,viewport:{width:innerWidth,height:innerHeight},note:T.note};
  d.localDiagnosticHash=await sha(JSON.stringify(d));
  show(d);st(T.ok,'good');
});`],

"client-hints": [B("client-hints", { b: true }), `
wire(async()=>{
  const u=navigator.userAgentData;
  const d={javascript:{userAgent:navigator.userAgent,platform:(u&&u.platform)||'Unavailable',mobile:u?u.mobile:'Unavailable',brands:(u&&u.brands)||'Unavailable',highEntropy:'not requested'}};
  try{if(u&&u.getHighEntropyValues)d.javascript.highEntropy=await u.getHighEntropyValues(['architecture','bitness','model','platformVersion','fullVersionList','wow64'])}catch(e){d.javascript.highEntropy='Error: '+e.message}
  try{d.serverHeaders=await getJSON('/api/request')}catch(e){d.serverHeaders='Error: '+e.message}
  d.note=T.note;show(d);st(T.ok,'good');
});`],

"fingerprint": [B("fingerprint", { w: "warn", b: true }), `
wire(async()=>{
  const p={};
  p.ua=navigator.userAgent;p.platform=navigator.platform;p.languages=navigator.languages;
  p.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
  p.screen=[screen.width,screen.height,screen.colorDepth,devicePixelRatio].join('x');
  p.hc=navigator.hardwareConcurrency??null;p.mem=navigator.deviceMemory??null;
  try{const c=document.createElement('canvas');c.width=200;c.height=60;const x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(5,5,50,20);x.fillStyle='#069';x.fillText('PL fp ✓',8,10);p.canvasHash=(await sha(c.toDataURL())).slice(0,24)}catch(e){p.canvasHash='error'}
  try{const c=document.createElement('canvas'),gl=c.getContext('webgl');const ext=gl&&gl.getExtension('WEBGL_debug_renderer_info');p.gl=gl?(ext?gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)+' | '+gl.getParameter(ext.UNMASKED_RENDERER_WEBGL):'masked'):'none'}catch(e){p.gl='error'}
  try{const Ctx=window.OfflineAudioContext||window.webkitOfflineAudioContext;if(Ctx){const ctx=new Ctx(1,8000,8000);const o=ctx.createOscillator();o.type='triangle';o.frequency.value=8000;const k=ctx.createDynamicsCompressor();k.threshold.value=-50;k.knee.value=40;k.ratio.value=12;o.connect(k);k.connect(ctx.destination);o.start(0);const b=await ctx.startRendering();const ch=b.getChannelData(0);let s=0;for(let i=2000;i<2200;i++)s+=Math.abs(ch[i]);p.audioSum=+s.toFixed(6)}else p.audioSum='n/a'}catch(e){p.audioSum='error'}
  p.voices=(window.speechSynthesis&&speechSynthesis.getVoices().length)||0;
  p.touch=navigator.maxTouchPoints;p.pdf=navigator.pdfViewerEnabled;
  show({parts:p,compositeHash:await sha(JSON.stringify(p)),note:T.note});
  st(T.ok,'good');
});`],

"css-media": [B("css-media"), `
wire(()=>{
  const qs={'prefers-color-scheme: dark':'(prefers-color-scheme: dark)','prefers-color-scheme: light':'(prefers-color-scheme: light)','reduced motion':'(prefers-reduced-motion: reduce)','forced colors':'(forced-colors: active)','high contrast':'(prefers-contrast: more)','hover available':'(hover: hover)','fine pointer':'(pointer: fine)','coarse pointer':'(pointer: coarse)','portrait':'(orientation: portrait)','landscape':'(orientation: landscape)','wide viewport':'(min-width: 1024px)','small viewport':'(max-width: 600px)','HDR':'(dynamic-range: high)','color gamut P3':'(color-gamut: p3)','inverted colors':'(inverted-colors: inverted)','transparency reduced':'(prefers-reduced-transparency: reduce)','scripting none':'(scripting: none)'};
  const o={};for(const [k,q] of Object.entries(qs))o[k]={query:q,matches:matchMedia(q).matches};
  show(o);st(T.ok,'good');
});`],

"features": [B("features"), `
wire(()=>{
  const tests={'Fetch':()=>!!window.fetch,'WebSocket':()=>!!window.WebSocket,'WebRTC':()=>!!window.RTCPeerConnection,'WebGL':()=>!!document.createElement('canvas').getContext('webgl'),'WebGL2':()=>!!document.createElement('canvas').getContext('webgl2'),'WebGPU':()=>!!navigator.gpu,'WebAssembly':()=>!!window.WebAssembly,
    'Wasm SIMD':()=>{try{return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11]))}catch(e){return false}},
    'Service Worker':()=>!!navigator.serviceWorker,'IndexedDB':()=>!!window.indexedDB,
    'Local Storage':()=>{try{localStorage.setItem('__pl','1');localStorage.removeItem('__pl');return true}catch(e){return false}},
    'Cookies enabled':()=>navigator.cookieEnabled,'Clipboard API':()=>!!navigator.clipboard,'Geolocation':()=>!!navigator.geolocation,'MediaDevices':()=>!!navigator.mediaDevices,'Notifications':()=>!!window.Notification,'Permissions API':()=>!!navigator.permissions,'ResizeObserver':()=>!!window.ResizeObserver,'IntersectionObserver':()=>!!window.IntersectionObserver,'OffscreenCanvas':()=>!!window.OffscreenCanvas,'Web Crypto':()=>!!(window.crypto&&crypto.subtle),'SharedArrayBuffer':()=>!!window.SharedArrayBuffer,'Web Animations':()=>!!Element.prototype.animate,
    'CSS container queries':()=>CSS.supports('container-type:inline-size'),'CSS :has()':()=>CSS.supports('selector(:has(*))'),'CSS grid':()=>CSS.supports('display:grid'),
    'AVIF export (canvas)':()=>{const c=document.createElement('canvas');return c.toDataURL('image/avif').startsWith('data:image/avif')},
    'Touch events':()=>('ontouchstart' in window),'File System Access':()=>!!window.showOpenFilePicker,'BroadcastChannel':()=>!!window.BroadcastChannel,'Web Locks':()=>!!navigator.locks,'Idle Detection':()=>!!window.IdleDetector,'Compression Streams':()=>!!window.CompressionStream,'Background Fetch':()=>!!window.BackgroundFetchManager,'Push Manager':()=>!!window.PushManager,'Payment Request':()=>!!window.PaymentRequest,'WebAuthn':()=>!!window.PublicKeyCredential,'WebOTP':()=>!!window.OTPCredential,'Shape Detection':()=>!!window.BarcodeDetector,'EyeDropper':()=>!!window.EyeDropper,'Serial':()=>!!navigator.serial,'USB':()=>!!navigator.usb,'Bluetooth':()=>!!navigator.bluetooth,'HID':()=>!!navigator.hid,'NFC':()=>('NDEFReader' in window)};
  const o={};for(const [k,f] of Object.entries(tests)){try{o[k]=f()?'Supported':'Not detected'}catch(e){o[k]='Error: '+e.message}}
  show(o);st(T.ok,'good');
});`],

"sensors": [B("sensors"), `
wire(()=>{
  const r={'Accelerometer':!!window.Accelerometer,'Gyroscope':!!window.Gyroscope,'Magnetometer':!!window.Magnetometer,'LinearAccelerationSensor':!!window.LinearAccelerationSensor,'GravitySensor':!!window.GravitySensor,'AmbientLightSensor':!!window.AmbientLightSensor,'ProximitySensor':!!window.ProximitySensor,'DeviceOrientationEvent':!!window.DeviceOrientationEvent,'DeviceMotionEvent':!!window.DeviceMotionEvent,'USB':!!navigator.usb,'Serial':!!navigator.serial,'HID':!!navigator.hid,'Bluetooth':!!navigator.bluetooth,'NFC':('NDEFReader' in window),'WakeLock':!!navigator.wakeLock,'IdleDetector':!!window.IdleDetector,'ContactsManager':!!navigator.contacts,'Presentation':!!navigator.presentation,'Vibration':!!navigator.vibrate,'Battery':!!navigator.getBattery};
  r.note=T.note;show(r);st(T.ok,'good');
});`],

"media-devices": [B("media-devices", { w: "warn", b: true, extra: t => ` <button class="btn secondary" id="ask">${esc(t("media-devices.b2"))}</button>` }), `
window.__noAuto=true;
const enumerate=async()=>{
  const out={devices:[]};
  try{
    const l=await navigator.mediaDevices.enumerateDevices();
    out.devices=l.map(d=>({kind:d.kind,label:d.label||'(hidden)',deviceId:(d.deviceId||'').slice(0,10)+'…',groupId:(d.groupId||'').slice(0,10)+'…'}));
    out.note=T.note;st(fmt(T.ok,{n:out.devices.length}),'good');
  }catch(e){out.error=e.message;st(T.fail,'bad')}
  show(out);
};
wire(enumerate);
$('ask').onclick=async()=>{try{const s=await navigator.mediaDevices.getUserMedia({audio:true,video:true});s.getTracks().forEach(x=>x.stop());await enumerate()}catch(e){st(fmt(T.denied,{e:e.message}),'warn')}};
enumerate();`],

// ---------- Privacy ----------

"geolocation": [B("geolocation", { b: true }), `
window.__noAuto=true;
const perm=async()=>{const o={supported:!!navigator.geolocation,permission:'unknown'};try{if(navigator.permissions&&navigator.permissions.query){o.permission=(await navigator.permissions.query({name:'geolocation'})).state}}catch(e){o.permission='Permission query unavailable'}return o};
const ask=async()=>{
  const o=await perm();
  if(!navigator.geolocation){show(o);st(T.unsupported,'warn');return}
  if(o.permission==='denied'){show(o);st(T.denied,'warn');return}
  st(T.waiting,'warn');
  navigator.geolocation.getCurrentPosition(p=>{show({...o,latitude:p.coords.latitude,longitude:p.coords.longitude,accuracyMeters:p.coords.accuracy,altitude:p.coords.altitude,heading:p.coords.heading,speed:p.coords.speed,timestamp:new Date(p.timestamp).toISOString()});st(T.ok,'good')},e=>{show({...o,error:e.message,code:e.code});st(T.fail,'warn')},{enableHighAccuracy:false,timeout:12000,maximumAge:0});
};
$('run').onclick=ask;
(async()=>{const o=await perm();show(o);if(o.permission==='granted')ask();else st(fmt(T.state,{s:o.permission}),'warn')})();`],

"permissions": [B("permissions", { w: "warn", b: true }), `
wire(async()=>{
  const names=['geolocation','notifications','push','midi','camera','microphone','speaker-selection','device-info','background-sync','bluetooth','persistent-storage','ambient-light-sensor','accelerometer','gyroscope','magnetometer','clipboard-read','clipboard-write','payment-handler','idle-detection','periodic-background-sync','system-wake-lock','storage-access','window-management','local-fonts','screen-wake-lock','display-capture','window-placement','top-level-storage-access'];
  const out={};
  for(const name of names){try{if(!(navigator.permissions&&navigator.permissions.query)){out[name]='Permissions API unsupported';continue}out[name]=(await navigator.permissions.query({name})).state}catch(e){out[name]='Not supported: '+e.message}}
  show(out);st(T.ok,'good');
});`],

"storage": [B("storage"), `
wire(async()=>{
  const o={};
  try{document.cookie='__pl_test=1;path=/;SameSite=Lax';o.cookieEnabled=document.cookie.includes('__pl_test=1');document.cookie='__pl_test=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/'}catch(e){o.cookieError=e.message}
  try{localStorage.setItem('__pl_ls','1');o.localStorage=localStorage.getItem('__pl_ls')==='1';localStorage.removeItem('__pl_ls')}catch(e){o.localStorage='Error: '+e.message}
  try{sessionStorage.setItem('__pl_ss','1');o.sessionStorage=sessionStorage.getItem('__pl_ss')==='1';sessionStorage.removeItem('__pl_ss')}catch(e){o.sessionStorage='Error: '+e.message}
  try{o.indexedDB=!!window.indexedDB}catch(e){o.indexedDB='Error: '+e.message}
  try{if(navigator.storage&&navigator.storage.estimate)o.estimate=await navigator.storage.estimate()}catch(e){o.estimate='Error: '+e.message}
  try{if(navigator.storage&&navigator.storage.persisted)o.persisted=await navigator.storage.persisted()}catch(e){o.persisted='Error: '+e.message}
  try{if(navigator.storage&&navigator.storage.persist)o.canPersist='persist() available'}catch(e){}
  show(o);st(T.ok,'good');
});`],

"trackers": [B("trackers", { w: "warn", b: true }), `
wire(async()=>{
  const targets=[
    {name:'Google Analytics',url:'https://www.google-analytics.com/analytics.js'},
    {name:'Google Tag Manager',url:'https://www.googletagmanager.com/gtm.js'},
    {name:'Facebook Pixel',url:'https://connect.facebook.net/en_US/fbevents.js'},
    {name:'DoubleClick',url:'https://stats.g.doubleclick.net/dc.js'},
    {name:'Amazon Ads',url:'https://c.amazon-adsystem.com/aax2/apstag.js'},
    {name:'Scorecard Research',url:'https://sb.scorecardresearch.com/beacon.js'},
    {name:'Mixpanel',url:'https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js'},
    {name:'Hotjar',url:'https://static.hotjar.com/c/hotjar-0.js'},
    {name:'Sentry',url:'https://browser.sentry-cdn.com/7.0.0/bundle.min.js'}
  ];
  const results=await Promise.all(targets.map(async t=>{
    const host=new URL(t.url).host,start=performance.now(),ac=new AbortController(),timer=setTimeout(()=>ac.abort(),4000);
    let r;
    try{await fetch(t.url,{method:'HEAD',mode:'no-cors',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',signal:ac.signal});r={result:'reachable'}}
    catch(e){r={result:(e&&e.name==='AbortError')?'timeout':'failed or blocked'}}
    clearTimeout(timer);
    return {target:t.name,host,...r,ms:Math.round(performance.now()-start)};
  }));
  show({results,note:T.note});
  const failed=results.filter(r=>r.result!=='reachable').length;
  st(fmt(T.ok,{b:failed,n:results.length}),'warn');
});`],

"third-party": [B("third-party", { w: "warn", b: true }), `
wire(()=>{
  const hints={'Google Analytics (gtag/ga)':!!(window.gtag||window.ga||window.dataLayer),'Google Tag Manager':!!window.dataLayer,'Facebook Pixel (fbq)':!!window.fbq,'Hotjar (hj)':!!window.hj,'Matomo (_paq)':!!window._paq,'Mixpanel':!!window.mixpanel,'Heap':!!window.heap,'Segment':!!(window.analytics&&window.analytics._integrations),'Intercom':!!window.Intercom,'Sentry':!!window.Sentry,'Rollbar':!!window.Rollbar,'New Relic':!!window.NREUM,'Datadog RUM':!!(window.DD_RUM||window.DD_LOGS),'Amplitude':!!window.amplitude,'Plausible':!!window.plausible,'Umami':!!window.umami,'PostHog':!!window.posthog,'Criteo':!!window.criteo_q,'Twitter Pixel (twq)':!!window.twq,'LinkedIn Insight (lintrk)':!!window.lintrk,'TikTok Pixel (ttq)':!!window.ttq,'Pinterest Tag (pintrk)':!!window.pintrk};
  const scripts=[...document.scripts].map(s=>s.src).filter(Boolean).slice(0,30);
  show({globals:hints,scriptSrcs:scripts,note:T.note});st(T.ok,'good');
});`],

"dnt": [B("dnt", { b: true }), `
wire(async()=>{
  const client={doNotTrack:navigator.doNotTrack??'Not exposed',windowDoNotTrack:window.doNotTrack??'Not exposed',globalPrivacyControl:navigator.globalPrivacyControl??'Not exposed',secureContext:isSecureContext,note:T.note};
  let server=null;try{server=await getJSON('/api/request')}catch(e){server={error:e.message}}
  show({client,server});st(T.ok,'good');
});`],

"content-filters": [B("content-filters"), `
wire(async()=>{
  const out={webdriver:navigator.webdriver??'Not exposed',doNotTrack:navigator.doNotTrack??'Not exposed',globalPrivacyControl:navigator.globalPrivacyControl??'Not exposed',thirdPartyCookieBehavior:'Not tested (varies by browser)'};
  const bait=document.createElement('div');
  bait.className='adsbox ad-banner ad_unit pub_300x250 text-ad';
  bait.style.cssText='position:absolute;left:-9999px;width:10px;height:10px';
  bait.textContent=' ';document.body.appendChild(bait);
  await new Promise(r=>setTimeout(r,150));
  const cs=getComputedStyle(bait);
  out.cosmeticBait=(!bait.offsetHeight||cs.display==='none'||cs.visibility==='hidden')?'hidden (a cosmetic filter may be active)':'visible (no cosmetic filter detected)';
  bait.remove();
  out.note=T.note;show(out);st(T.ok,'warn');
});`],

"extensions": [B("extensions", { w: "info", b: true }), `
wire(async()=>{
  const ids=[['uBlock Origin','cjpalhdlnbpafiamejdnhcphjbkeiagm'],['Google Translate','aapbdbdomjkkjkaonfhkkikfgjllcleb'],['Grammarly','kbfnbcaeplbcioakkpcpgfkobkghlhen'],['Bitwarden','nngceckbapebfimnlniiiahkandclblb'],['Dark Reader','eimadpbcbfnmbkopoojfekhnkhdbieeh']];
  const out=[];
  for(const [name,id] of ids){
    const result=await new Promise(res=>{
      const s=document.createElement('script');
      const t=setTimeout(()=>{s.remove();res('no response (not detectable)')},1500);
      s.onload=()=>{clearTimeout(t);s.remove();res('resource loaded (not conclusive)')};
      s.onerror=()=>{clearTimeout(t);s.remove();res('not detectable (does not mean absent)')};
      s.src='chrome-extension://'+id+'/manifest.json';document.head.appendChild(s);
    });
    out.push({name,result});
  }
  show({results:out,note:T.note});st(T.ok,'warn');
});`],

// ---------- Security ----------

"https-audit": [B("https-audit", { w: "info", b: true }), `
wire(async()=>{
  const o={isSecureContext,protocol:location.protocol,host:location.host};
  const hd={};
  try{const r=await fetch(location.pathname+location.search,{cache:'no-store'});r.headers.forEach((v,k)=>{hd[k]=v});o.responseHeaders=hd}catch(e){o.error=e.message}
  const has=n=>hd[n]?'present':'missing';
  o.checks={'HTTPS':location.protocol==='https:','Secure Context':isSecureContext,'CSP header (this Worker)':has('content-security-policy'),'X-Content-Type-Options':has('x-content-type-options'),'Referrer-Policy':has('referrer-policy'),'Permissions-Policy':has('permissions-policy'),
    'Strict-Transport-Security':hd['strict-transport-security']?'present':'not set by Worker (may be set by platform)','Cross-Origin-Opener-Policy':has('cross-origin-opener-policy'),'Cross-Origin-Embedder-Policy':has('cross-origin-embedder-policy'),'Cross-Origin-Resource-Policy':has('cross-origin-resource-policy'),'X-Frame-Options':has('x-frame-options')};
  show(o);st(T.ok,'good');
});`],

"csp": [B("csp", { w: "warn", b: true }), `
wire(async()=>{
  const out={inlineScript:'allowed (this script is inline)'};
  try{eval('1+1');out.eval='allowed'}catch(e){out.eval='blocked: '+e.message}
  try{const f=new Function('return 1');f();out.newFunction='allowed'}catch(e){out.newFunction='blocked: '+e.message}
  try{new WebAssembly.Module(new Uint8Array([0,97,115,109,1,0,0,0]));out.wasmCompile='allowed'}catch(e){out.wasmCompile='blocked: '+e.message}
  out.blobWorker=await new Promise(res=>{
    try{
      const w=new Worker(URL.createObjectURL(new Blob(['postMessage(1)'],{type:'text/javascript'})));
      const t=setTimeout(()=>{w.terminate();res('no response (likely blocked)')},800);
      w.onmessage=()=>{clearTimeout(t);w.terminate();res('allowed')};
      w.onerror=()=>{clearTimeout(t);w.terminate();res('blocked')};
    }catch(e){res('blocked: '+e.message)}
  });
  try{const img=new Image();await new Promise((ok,no)=>{img.onload=ok;img.onerror=no;img.src='data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'});out.dataURLImage='allowed'}catch(e){out.dataURLImage='blocked'}
  try{if(navigator.serviceWorker&&navigator.serviceWorker.register){out.serviceWorkerRegistration='API available (registration may still be blocked)'}}catch(e){}
  show(out);st(T.ok,'good');
});`],

"cors": [B("cors", { b: true }), `
wire(async()=>{
  const out={};
  try{const r=await fetch('/api/request',{cache:'no-store'});out.sameOrigin={ok:r.ok,status:r.status,type:r.type}}catch(e){out.sameOrigin={error:e.message}}
  try{const r=await fetch('/api/request',{cache:'no-store',mode:'no-cors'});out.noCors={ok:r.ok,status:r.status,type:r.type,note:'opaque response'}}catch(e){out.noCors={error:e.message}}
  try{await fetch('https://example.com/',{mode:'cors',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});out.crossOrigin='allowed (server sent CORS headers)'}catch(e){out.crossOrigin='failed (blocked by CORS, or a network error): '+e.message}
  out.note=T.note;show(out);st(T.ok,'good');
});`],

"referrer": [B("referrer", { b: true }), `
wire(async()=>{
  const meta=[...document.querySelectorAll('meta[name="referrer"]')].map(m=>m.content);
  const o={documentReferrerPolicy:document.referrerPolicy||'(not set)',metaReferrer:meta.length?meta:'(none)',documentReferrer:document.referrer||'(none)'};
  const seen=async p=>{const d=await (await fetch('/api/request',{cache:'no-store',referrerPolicy:p})).json();return d.observed['Referer']};
  o.workerSawReferer={defaultPolicy:await (async()=>{const d=await getJSON('/api/request');return d.observed['Referer']})(),unsafeUrl:await seen('unsafe-url'),noReferrer:await seen('no-referrer')};
  o.note=T.note;show(o);st(T.ok,'good');
});`],

"permissions-policy": [B("permissions-policy", { b: true }), `
wire(async()=>{
  const o={};
  const pp=document.permissionsPolicy||document.featurePolicy;
  try{if(pp){if(pp.allowedFeatures)o.allowedFeatures=pp.allowedFeatures();if(pp.features)o.knownFeatures=pp.features()}else o.api='Not exposed'}catch(e){o.error=e.message}
  try{const r=await fetch(location.pathname+location.search,{cache:'no-store'});o.responseHeader=r.headers.get('permissions-policy')}catch(e){o.responseHeaderError=e.message}
  o.note=T.note;show(o);st(T.ok,'good');
});`],

"credential": [B("credential", { b: true }), `
wire(()=>{
  const c=navigator.credentials;
  show({available:!!c,methods:c?{get:typeof c.get,store:typeof c.store,create:typeof c.create,preventSilentAccess:typeof c.preventSilentAccess}:null,passwordCredential:!!window.PasswordCredential,federatedCredential:!!window.FederatedCredential,identityCredential:!!window.IdentityCredential,publicKeyCredential:!!window.PublicKeyCredential,note:T.note});
  st(T.ok,'good');
});`],

"webauthn": [B("webauthn", { b: true }), `
wire(async()=>{
  const o={publicKeyCredential:!!window.PublicKeyCredential};
  try{if(window.PublicKeyCredential&&PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable)o.platformAuthenticator=await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()}catch(e){o.platformAuthenticator='error: '+e.message}
  try{if(window.PublicKeyCredential&&PublicKeyCredential.isConditionalMediationAvailable)o.conditionalMediation=await PublicKeyCredential.isConditionalMediationAvailable()}catch(e){o.conditionalMediation='error: '+e.message}
  o.note=T.note;show(o);st(T.ok,'good');
});`],

"mixed-content": [B("mixed-content", { w: "warn", b: true }), `
wire(async()=>{
  const out={secureContext:isSecureContext,https:location.protocol==='https:'};
  out.insecureImage=await new Promise(res=>{
    const img=new Image();let done=false;
    const t=setTimeout(()=>{if(!done){done=true;res('timeout')}},4000);
    img.onload=()=>{if(!done){done=true;clearTimeout(t);res('loaded (possibly upgraded to https by the browser)')}};
    img.onerror=()=>{if(!done){done=true;clearTimeout(t);res('error (likely blocked)')}};
    img.src='http://www.cloudflare.com/favicon.ico?_='+Math.random();
  });
  out.note=T.note;show(out);st(T.ok,'warn');
});`],

"isolation": [B("isolation", { b: true }), `
wire(async()=>{
  let min=Infinity,last=performance.now();
  for(let i=0;i<20000;i++){const n=performance.now(),d=n-last;if(d>0&&d<min)min=d;last=n}
  const o={crossOriginIsolated:window.crossOriginIsolated??'not exposed',sharedArrayBuffer:typeof SharedArrayBuffer!=='undefined',atomics:typeof Atomics!=='undefined',smallestTimerStepMs:min===Infinity?'not measurable':+min.toFixed(4),note:T.note};
  try{const r=await fetch(location.pathname+location.search,{cache:'no-store'});o.coop=r.headers.get('cross-origin-opener-policy');o.coep=r.headers.get('cross-origin-embedder-policy')}catch(e){o.error=e.message}
  show(o);st(T.ok,'good');
});`],

"webgpu": [B("webgpu", { b: true }), `
wire(async()=>{
  if(!navigator.gpu){show({supported:false,note:T.none});st(T.notdet,'warn');return}
  try{
    const a=await navigator.gpu.requestAdapter();
    const info=a&&a.info?{vendor:a.info.vendor,architecture:a.info.architecture,device:a.info.device,description:a.info.description}:'Adapter information not exposed';
    show({supported:true,adapterAvailable:!!a,info,features:a?[...a.features]:[],limits:a?{maxTextureDimension2D:a.limits.maxTextureDimension2D,maxBufferSize:a.limits.maxBufferSize}:null});
    st(T.ok,'good');
  }catch(e){show({supported:true,error:e.message});st(T.rejected,'bad')}
});`],

"js-engine": [B("js-engine"), `
wire(()=>{
  const o={};
  o.bigInt=typeof BigInt==='function';
  o.intl=typeof Intl!=='undefined'?{resolvedOptions:Intl.DateTimeFormat().resolvedOptions(),locale:Intl.DateTimeFormat().resolvedOptions().locale}:null;
  try{o.dateFormat=new Intl.DateTimeFormat('en-US',{dateStyle:'full',timeStyle:'long'}).format(new Date(0))}catch(e){o.dateFormat='error'}
  try{o.numberFormat=new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(1234.567)}catch(e){o.numberFormat='error'}
  try{o.relativeTime=new Intl.RelativeTimeFormat('en',{numeric:'auto'}).format(-3,'day')}catch(e){o.relativeTime='error'}
  try{o.pluralRules=new Intl.PluralRules('en').select(2)}catch(e){o.pluralRules='error'}
  try{o.listFormat=new Intl.ListFormat('en').format(['a','b','c'])}catch(e){o.listFormat='error'}
  o.note=T.note;show(o);st(T.ok,'good');
});`]
};

// ---------- Router ----------

export default {
  async fetch(request) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405, headers: { allow: "GET, HEAD" } });
    }
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+$/, "") || "/";

    if (p === "/favicon.ico") return new Response(null, { status: 204 });

    if (p === "/api/request") {
      const clientHintHeaders = {};
      for (const [k, v] of request.headers) if (k.startsWith("sec-ch-")) clientHintHeaders[k] = v;
      return json({
        observed: reqInfo(request),
        clientHintHeaders,
        cf: {
          country: request.cf?.country || null,
          region: request.cf?.region || null,
          city: request.cf?.city || null,
          timezone: request.cf?.timezone || null,
          asn: request.cf?.asn || null,
          asOrganization: request.cf?.asOrganization || null,
          httpProtocol: request.cf?.httpProtocol || null
        },
        timestamp: new Date().toISOString()
      });
    }

    if (p === "/api/ip") return json({
      ip: getIP(request),
      country: request.cf?.country || null,
      city: request.cf?.city || null,
      region: request.cf?.region || null,
      timezone: request.cf?.timezone || null,
      asn: request.cf?.asn || null,
      organization: request.cf?.asOrganization || null
    });

    const L = pickLang(url, request), t = translator(L);
    const html = (body, id = "", status = 200) => new Response(body, { status, headers: htmlHeaders(id) });

    if (p === "/ip") {
      const rawIP = request.headers.get("CF-Connecting-IP") || request.headers.get("x-real-ip") || "";
      const ptr = ptrName(rawIP);
      const kv = Object.entries(reqInfo(request, t)).map(([k, v]) => `<div><span>${esc(k)}</span><code>${esc(v)}</code></div>`).join("");
      const links = rawIP ? `<p><a href="https://ipinfo.io/${encodeURIComponent(rawIP)}" target="_blank" rel="noopener noreferrer">${esc(t("ip.lookup"))}</a> · <a href="https://who.is/whois-ip/ip-address/${encodeURIComponent(rawIP)}" target="_blank" rel="noopener noreferrer">${esc(t("ip.whois"))}</a>${ptr ? ` · <a href="https://dns.google/resolve?name=${encodeURIComponent(ptr)}&type=PTR" target="_blank" rel="noopener noreferrer">${esc(t("ip.rdns"))}</a>` : ""}</p>` : "";
      const body = `<section class="panel"><h2>${esc(t("ip.h1"))}</h2><div dir="ltr" style="font-size:clamp(25px,5vw,42px);font-weight:850;overflow-wrap:anywhere">${esc(getIP(request, t("rq.na")))}</div><p>${esc(t("ip.p1"))}</p>${links}</section><section class="panel"><h2>${esc(t("ip.h2"))}</h2><div class="kv">${kv}</div></section><section class="panel"><h2>${esc(t("ip.h3"))}</h2><p>${esc(t("ip.lim"))}</p><p>${esc(t("ip.v6"))} <a href="https://test-ipv6.com/" target="_blank" rel="noopener noreferrer">${esc(t("ip.v6link"))}</a></p></section>`;
      return html(page(L, t, "ip", "/ip", t("ip.t"), t("ip.d"), body), "ip");
    }

    if (p === "/") {
      const cards = TOOLS.map(id => `<a class="toolcard" href="/${id}?lang=${L}"><strong>${esc(t(id + ".t"))} ↗</strong><span>${esc(t(id + ".d"))}</span></a>`).join("");
      const body = `<section class="panel"><h2>${esc(t("ui.allTools"))}</h2><p>${esc(t("ui.homeP"))}</p><div class="grid">${cards}</div></section><section class="panel"><h2>${esc(t("ui.notesT"))}</h2><p>${esc(t("ui.notes1"))}</p><p>${esc(t("ui.notes2"))}</p></section>`;
      return html(page(L, t, "home", "/", t("ui.homeT"), t("ui.homeD"), body), "home");
    }

    const key = p.slice(1);
    if (hasOwn(pages, key)) {
      const [bodyFn, script] = pages[key];
      return runPage(L, t, key, bodyFn, script);
    }

    return html(page(L, t, "", "/", t("ui.nfT"), t("ui.nfD"), `<section class="panel"><p>${esc(t("ui.nfP"))}</p><a class="btn" href="/?lang=${L}" style="display:inline-block;text-decoration:none">${esc(t("ui.back"))}</a></section>`), "", 404);
  }
};

// ===================== TRANSLATIONS =====================
const I = {};

I.en = {
  "ui.sub": "Browser diagnostics · local-first where possible",
  "ui.langs": "Language",
  "ui.overview": "Overview",
  "ui.results": "Results",
  "ui.footer": "Privacy note: browser tests run in your browser. This demo does not intentionally save test results. IP and request details are processed by Cloudflare to serve the request. Some tests are approximate; see each page's limitations. The language comes from the ?lang= link parameter; no cookie is set.",
  "ui.homeT": "Browser Privacy & Fingerprint Lab",
  "ui.homeD": "A multi-page toolbox for inspecting browser-exposed privacy signals, network metadata and fingerprinting surfaces.",
  "ui.allTools": "All tools",
  "ui.homeP": "Each tool has its own page. Browser-only tests run on your device; server details come from the Cloudflare request context.",
  "ui.notesT": "Important privacy and technical notes",
  "ui.notes1": "Fingerprinting can be used for tracking. Use these diagnostics to understand what a website can observe, not to identify or track other people.",
  "ui.notes2": "Cloudflare Workers do not receive raw visitor TCP packets or the original TLS/HTTP2/QUIC handshakes. Tests that need those details are clearly marked as limited instead of showing fabricated results.",
  "ui.nfT": "Page not found",
  "ui.nfD": "This tool page does not exist.",
  "ui.nfP": "That route was not found.",
  "ui.back": "Back to all tools",

  "c.running": "Running test…",
  "c.failed": "The test failed.",
  "c.run": "Run again",

  "rq.ip": "Observed IP", "rq.country": "Country", "rq.region": "Region / state", "rq.city": "City", "rq.tz": "Timezone",
  "rq.isp": "ISP / organization", "rq.proto": "HTTP protocol", "rq.ray": "Request ID", "rq.na": "Unavailable", "rq.ns": "Not sent",

  "ip.t": "IP Address",
  "ip.d": "Server-observed IP, request headers, approximate location, ASN/ISP, reverse DNS and lookup links.",
  "ip.h1": "Your observed IP",
  "ip.p1": "As observed by this Cloudflare Worker; VPN/proxy routing may affect the value.",
  "ip.lookup": "IP information lookup",
  "ip.whois": "WHOIS lookup",
  "ip.rdns": "Reverse DNS (PTR) query",
  "ip.h2": "Request headers and approximate network data",
  "ip.h3": "Limitations",
  "ip.lim": "City and region are approximate IP geolocation, not GPS. ISP/organization and ASN are provided only when Cloudflare exposes them. This Worker cannot run raw TCP/IP OS fingerprinting, scan ports or identify a person by IP.",
  "ip.v6": "IPv6 check:",
  "ip.v6link": "Open external IPv6 test",

  "tls.t": "TLS Client Test",
  "tls.d": "Explains edge-termination limits and shows request/connection metadata available to this Worker.",
  "tls.w": "A Cloudflare Worker cannot see your original TLS ClientHello, cipher list, ECH negotiation or JA3/JA4 fingerprint, because TLS ends at Cloudflare's edge. This is not a raw handshake test; the results must not be read as a JA3/JA4 fingerprint.",
  "tls.b": "Refresh edge-visible metadata",
  "tls.ok": "Edge-visible request metadata loaded.",
  "tls.lim": "No access to the original ClientHello, ciphers, TLS extensions, ECH status or JA3/JA4 from this Worker.",

  "http2.t": "HTTP/2 Fingerprinting",
  "http2.d": "Shows protocol metadata exposed by Cloudflare, without claiming access to raw HTTP/2 frames.",
  "http2.w": "A Worker cannot read raw HTTP/2 frames or build an Akamai fingerprint of your original connection; Cloudflare terminates and may transform it.",
  "http2.b": "Inspect available protocol metadata",
  "http2.ok": "Available protocol metadata shown; no Akamai fingerprint generated.",
  "http2.note": "Akamai HTTP/2 fingerprints need the raw frame order and settings of the original connection, which Workers cannot see.",

  "quic.t": "QUIC Client Test",
  "quic.d": "Explains QUIC visibility limits and checks browser-visible HTTP/3 hints.",
  "quic.w": "Raw QUIC handshake and HTTP/3 fingerprinting are not available to a Worker; Cloudflare terminates the client connection first.",
  "quic.b": "Check browser-visible capabilities",
  "quic.ok": "Browser and edge-visible protocol details collected.",
  "quic.note": "nextHopProtocol may show h2 or h3 if the browser exposes it; it is not a QUIC fingerprint.",

  "tcpip.t": "TCP/IP Fingerprinting",
  "tcpip.d": "Shows server-observed request metadata and explains why raw TCP/MTU/hop fingerprints are unavailable.",
  "tcpip.w": "Cloudflare proxies the connection, so this Worker cannot read original TCP headers, TTL, MTU, hop count, packet windows or JA4T. Only edge-visible metadata is shown.",
  "tcpip.b": "Load edge metadata",
  "tcpip.ok": "Metadata loaded.",
  "tcpip.na": "Not accessible",
  "tcpip.ja4t": "Cannot be computed accurately in this Worker",

  "connection.t": "Connection Info",
  "connection.d": "Reports NetworkInformation: effective type, RTT, downlink, save-data and nextHopProtocol.",
  "connection.ok": "Connection information collected.",
  "connection.note": "NetworkInformation values are estimates; privacy browsers may round or hide them.",

  "javascript.t": "JavaScript",
  "javascript.d": "Inspects browser APIs, language, time zone, screen, CPU, memory, battery and network hints.",
  "javascript.ok": "Browser information collected locally.",

  "webrtc.t": "WebRTC Leak Test",
  "webrtc.d": "Checks whether WebRTC is available and whether ICE candidates reveal addresses.",
  "webrtc.w": "Browser policies may hide local addresses (mDNS) or block STUN; this is not a guarantee of VPN anonymity. No candidates does not prove there is no leak.",
  "webrtc.na": "WebRTC API is unavailable.",
  "webrtc.gather": "Gathering ICE candidates…",
  "webrtc.done": "ICE gathering finished. Review the candidates below.",
  "webrtc.none": "ICE gathering ended without visible candidates.",
  "webrtc.timeout": "Stopped after timeout. Any candidates received are shown.",
  "webrtc.note": "Candidate visibility varies by browser. No candidate does not prove no leak.",

  "canvas.t": "Canvas Fingerprinting",
  "canvas.d": "Renders a small test pattern and hashes its pixels locally (diagnostic only).",
  "canvas.ok": "Canvas rendered and hashed locally.",
  "canvas.note": "Local test pattern; do not treat it as a unique or stable identifier.",

  "webgl.t": "WebGL Report",
  "webgl.d": "Inspects WebGL renderer, vendor, extensions and capabilities. Browsers may mask details.",
  "webgl.none": "WebGL is unavailable or blocked.",
  "webgl.ok": "WebGL information read locally.",

  "fonts.t": "Font Fingerprinting",
  "fonts.d": "Compares text metrics for a practical, non-exhaustive list of common fonts.",
  "fonts.ok": "Font metrics measured locally.",
  "fonts.note": "A width difference suggests a font is present; it is not proof, and anti-fingerprinting protections can distort it.",

  "audio.t": "Audio Fingerprinting",
  "audio.d": "Renders a short OfflineAudioContext buffer and hashes it locally; no sound is played.",
  "audio.w": "Audio fingerprinting exploits subtle differences in audio stacks. This page hashes a locally rendered buffer and plays no sound.",
  "audio.none": "OfflineAudioContext is unavailable.",
  "audio.ok": "Audio fingerprint computed locally.",
  "audio.note": "Local diagnostic only; not a persistent identifier.",

  "voices.t": "SpeechSynthesis Voices",
  "voices.d": "Lists text-to-speech voices (a known entropy source).",
  "voices.w": "The voice list may take a moment to appear, and some browsers need a user gesture first.",
  "voices.b": "Load voices",
  "voices.none": "SpeechSynthesis is unavailable.",
  "voices.ok": "Loaded {n} voices.",
  "voices.zero": "No voices exposed.",

  "screen.t": "Screen & Display",
  "screen.d": "Screen size, orientation, color gamut, HDR, pixel ratio and window details.",
  "screen.ok": "Screen data collected locally.",
  "screen.note": "Privacy-preserving browsers may report rounded or quantized values.",

  "clientrects.t": "ClientRects Fingerprinting",
  "clientrects.d": "Measures rendered element rectangles and builds a local diagnostic hash.",
  "clientrects.ok": "Element geometry measured locally.",
  "clientrects.note": "Values change with viewport, zoom, font rendering and layout.",

  "client-hints.t": "Client Hints Test",
  "client-hints.d": "Compares JavaScript UA data with request headers sent to this Worker.",
  "client-hints.b": "Compare client hints",
  "client-hints.ok": "Client hints comparison complete.",
  "client-hints.note": "Chromium browsers send low-entropy hints by default; high-entropy hints appear only after the server asks for them (this page does, via Accept-CH). Firefox and Safari do not support UA client hints.",

  "fingerprint.t": "Fingerprint Summary",
  "fingerprint.d": "Combines several weak signals into one local diagnostic hash (not a stable identity).",
  "fingerprint.w": "Composite fingerprinting is a well-known technique. Use this to see what your browser exposes, not to identify yourself or others.",
  "fingerprint.b": "Compute summary",
  "fingerprint.ok": "Composite fingerprint computed locally.",
  "fingerprint.note": "Diagnostic only. Not a stable or unique identifier.",

  "css-media.t": "CSS Media Queries",
  "css-media.d": "Evaluates common CSS media queries in the browser.",
  "css-media.ok": "Media queries evaluated.",

  "features.t": "Features Detection",
  "features.d": "Checks a broad set of browser APIs and HTML features.",
  "features.ok": "Feature checks complete.",

  "sensors.t": "Sensors & Device APIs",
  "sensors.d": "Checks availability of motion, orientation, USB, Bluetooth, Serial, HID, NFC and related APIs.",
  "sensors.ok": "Sensor API availability collected.",
  "sensors.note": "Presence does not mean access: most of these APIs need a user gesture or permission.",

  "media-devices.t": "Media Devices",
  "media-devices.d": "Lists audio/video devices visible to this page (labels may be hidden).",
  "media-devices.w": "If labels are hidden, press “Request permissions” to prompt for camera/microphone. Only grant it if you trust this page. Nothing is recorded or sent.",
  "media-devices.b": "Enumerate",
  "media-devices.b2": "Request permissions",
  "media-devices.ok": "Enumerated {n} devices.",
  "media-devices.fail": "Enumeration failed.",
  "media-devices.denied": "Permission denied or unavailable: {e}",
  "media-devices.note": "Labels stay hidden until permission is granted. Counts and IDs remain a fingerprint surface.",

  "geolocation.t": "Geolocation API",
  "geolocation.d": "Tests geolocation permission and optionally requests the device location.",
  "geolocation.b": "Request my location",
  "geolocation.unsupported": "Geolocation is unsupported.",
  "geolocation.denied": "Permission denied; enable it in browser settings if you want to test.",
  "geolocation.waiting": "Waiting for location permission…",
  "geolocation.ok": "Location returned. This page does not send it to a server.",
  "geolocation.fail": "Location not returned. Permission may be denied or location unavailable.",
  "geolocation.state": "Permission state: {s}. Press “Request my location” to ask the browser.",

  "permissions.t": "Permissions Report",
  "permissions.d": "Queries current permission states for common capabilities.",
  "permissions.w": "Some entries may say “prompt” even after an OS-level denial; that state is not exposed. This page triggers no prompts.",
  "permissions.b": "Query permissions",
  "permissions.ok": "Permission states collected.",

  "storage.t": "Storage & Cookies",
  "storage.d": "Inspects cookies, local/session storage, IndexedDB and quota behavior.",
  "storage.ok": "Storage capabilities checked.",

  "trackers.t": "Tracker Blocking Probe",
  "trackers.d": "Tries to reach common tracker hosts and reports whether they were blocked (inconclusive).",
  "trackers.w": "This probe does not bypass any filter. Failures can also come from timeouts or network errors, and nothing is rendered.",
  "trackers.b": "Run probe",
  "trackers.ok": "{b} of {n} targets failed to load (may be blocked or unreachable).",
  "trackers.note": "A failure is not proof of blocking. For stronger evidence use the browser devtools Network panel.",

  "third-party.t": "Third-Party Scripts",
  "third-party.d": "Looks for well-known analytics/marketing globals already present on the page.",
  "third-party.w": "This demo Worker intentionally loads no third-party scripts, so absence here says nothing about other sites.",
  "third-party.b": "Scan current page",
  "third-party.ok": "Third-party hints scanned.",
  "third-party.note": "Best-effort detection; many loaders do not expose globals.",

  "dnt.t": "Do Not Track",
  "dnt.d": "Checks Do Not Track and Global Privacy Control signals (client + server).",
  "dnt.b": "Check privacy signals",
  "dnt.ok": "Privacy signals checked (client + request headers).",
  "dnt.note": "DNT and GPC are preference signals; website compliance varies.",

  "content-filters.t": "Content Filters",
  "content-filters.d": "Runs simple local checks for common content-blocking behavior.",
  "content-filters.ok": "Local filter checks complete; findings are inconclusive.",
  "content-filters.note": "A hidden bait element suggests cosmetic filtering. This page does not try to detect Tor conclusively or bypass filters.",

  "extensions.t": "Chrome Extension Detection",
  "extensions.d": "Checks a few public web-accessible resource URLs; results are inconclusive.",
  "extensions.w": "Not an exhaustive scan; no private extension data is accessed. Browsers usually hide extension resources from web pages, so both outcomes are inconclusive.",
  "extensions.b": "Check sample extension resources",
  "extensions.ok": "Sample checks complete; no extension inventory is available.",
  "extensions.note": "Browsers usually block extension-origin requests from ordinary pages. Results are inconclusive.",

  "https-audit.t": "HTTPS & Security Headers",
  "https-audit.d": "Secure context, CSP presence, COOP/COEP hints and mixed-content status.",
  "https-audit.w": "Header checks reflect this Worker's response for the current page, not your original connection or earlier sessions.",
  "https-audit.b": "Audit page",
  "https-audit.ok": "HTTPS and header audit complete.",

  "csp.t": "CSP / Sandbox Probe",
  "csp.d": "Checks whether inline scripts, eval, Wasm compile and blob workers are permitted here.",
  "csp.w": "Blocked-vs-allowed detection is best-effort. A thrown error strongly suggests a block, but not every block throws.",
  "csp.b": "Probe",
  "csp.ok": "CSP/sandbox probes complete.",

  "cors.t": "CORS & Same-Origin Probe",
  "cors.d": "Observes same-origin, no-cors and cross-origin request behavior.",
  "cors.b": "Run CORS probe",
  "cors.ok": "CORS probe complete.",
  "cors.note": "This Worker cannot observe another origin's CORS policy beyond whether the browser allowed the request.",

  "referrer.t": "Referrer Policy",
  "referrer.d": "Reports effective referrer policy hints from the document and meta tags.",
  "referrer.b": "Check referrer behavior",
  "referrer.ok": "Referrer policy hints collected.",
  "referrer.note": "The Worker sees the Referer header per request policy: default, unsafe-url (full URL) and no-referrer.",

  "permissions-policy.t": "Permissions-Policy",
  "permissions-policy.d": "Shows which browser features are delegated or blocked on this page.",
  "permissions-policy.b": "Read policy hints",
  "permissions-policy.ok": "Permissions-Policy hints collected.",
  "permissions-policy.note": "Permissions-Policy only restricts features; it never grants permissions.",

  "credential.t": "Credential Management API",
  "credential.d": "Checks availability of the credentials container and mediation modes.",
  "credential.b": "Check availability",
  "credential.ok": "Credential Management availability checked.",
  "credential.note": "No credential request is made; only API availability is reported.",

  "webauthn.t": "WebAuthn / Passkeys",
  "webauthn.d": "Checks PublicKeyCredential and platform authenticator availability.",
  "webauthn.b": "Check WebAuthn",
  "webauthn.ok": "WebAuthn availability checked.",
  "webauthn.note": "No credential prompt is created by this page.",

  "mixed-content.t": "Mixed Content Probe",
  "mixed-content.d": "Tries to load an insecure subresource from this HTTPS page.",
  "mixed-content.w": "This probes the browser's mixed-content handling. The Worker cannot change whether a browser blocks insecure subresources.",
  "mixed-content.b": "Probe mixed content",
  "mixed-content.ok": "Mixed content probe complete.",
  "mixed-content.note": "Behavior varies: modern browsers may upgrade or block http:// images on HTTPS pages.",

  "isolation.t": "Cross-Origin Isolation",
  "isolation.d": "Reports crossOriginIsolated, SharedArrayBuffer, timer precision and Atomics.",
  "isolation.b": "Check isolation",
  "isolation.ok": "Cross-origin isolation state checked.",
  "isolation.note": "Reduced timer precision is a side effect of isolation; the measurement is best-effort.",

  "webgpu.t": "WebGPU Browser Report",
  "webgpu.d": "Checks WebGPU availability and requests an adapter if supported.",
  "webgpu.b": "Request WebGPU adapter",
  "webgpu.none": "WebGPU is unavailable, disabled or blocked.",
  "webgpu.notdet": "WebGPU not detected.",
  "webgpu.ok": "WebGPU adapter query complete.",
  "webgpu.rejected": "WebGPU request was rejected or blocked.",

  "js-engine.t": "JS Engine & Intl",
  "js-engine.d": "Reports Intl locales, number/date formatting, timer precision and BigInt support.",
  "js-engine.ok": "JS engine and Intl details collected.",
  "js-engine.note": "Engine-level output varies by ICU version and browser build; a weak fingerprint signal."
};

I.fa = {
  "ui.sub": "عیب‌یابی مرورگر · تا حد ممکن محلی",
  "ui.langs": "زبان",
  "ui.overview": "نمای کلی",
  "ui.results": "نتایج",
  "ui.footer": "نکته حریم خصوصی: آزمون‌های مرورگر درون مرورگر شما اجرا می‌شوند. این نمونه عمداً نتایج آزمون را ذخیره نمی‌کند. نشانی IP و جزئیات درخواست برای پاسخ‌دهی توسط Cloudflare پردازش می‌شود. برخی آزمون‌ها تقریبی هستند؛ محدودیت‌های هر صفحه را ببینید. زبان از پارامتر ?lang= در پیوند گرفته می‌شود و هیچ کوکی‌ای تنظیم نمی‌شود.",
  "ui.homeT": "آزمایشگاه حریم خصوصی و اثرانگشت مرورگر",
  "ui.homeD": "جعبه‌ابزاری چندصفحه‌ای برای بررسی سیگنال‌های حریم خصوصی، فراداده‌های شبکه و سطوح اثرانگشت‌گیری که مرورگر در معرض دید قرار می‌دهد.",
  "ui.allTools": "همه ابزارها",
  "ui.homeP": "هر ابزار صفحه جداگانه‌ای دارد. آزمون‌های مرورگری روی دستگاه شما اجرا می‌شوند؛ جزئیات سمت سرور از زمینه درخواست Cloudflare می‌آید.",
  "ui.notesT": "نکات مهم حریم خصوصی و فنی",
  "ui.notes1": "اثرانگشت‌گیری می‌تواند برای ردیابی به کار رود. از این ابزارها برای فهمیدن اینکه یک وب‌سایت چه چیزی را می‌بیند استفاده کنید، نه برای شناسایی یا ردیابی دیگران.",
  "ui.notes2": "Cloudflare Workers بسته‌های خام TCP بازدیدکننده و دست‌دهی‌های اصلی TLS/HTTP2/QUIC را دریافت نمی‌کنند. آزمون‌هایی که به این جزئیات نیاز دارند به‌صراحت «محدود» علامت‌گذاری شده‌اند و نتیجه ساختگی نشان داده نمی‌شود.",
  "ui.nfT": "صفحه پیدا نشد",
  "ui.nfD": "این صفحه ابزار وجود ندارد.",
  "ui.nfP": "این مسیر پیدا نشد.",
  "ui.back": "بازگشت به همه ابزارها",

  "c.running": "در حال اجرای آزمون…",
  "c.failed": "آزمون ناموفق بود.",
  "c.run": "اجرای دوباره",

  "rq.ip": "IP مشاهده‌شده", "rq.country": "کشور", "rq.region": "منطقه / استان", "rq.city": "شهر", "rq.tz": "منطقه زمانی",
  "rq.isp": "ISP / سازمان", "rq.proto": "پروتکل HTTP", "rq.ray": "شناسه درخواست", "rq.na": "در دسترس نیست", "rq.ns": "ارسال نشده",

  "ip.t": "آدرس IP",
  "ip.d": "IP مشاهده‌شده توسط سرور، سرآیندهای درخواست، موقعیت تقریبی، ASN/ISP، DNS معکوس و پیوندهای جستجو.",
  "ip.h1": "IP مشاهده‌شده شما",
  "ip.p1": "همان‌طور که این Cloudflare Worker می‌بیند؛ مسیریابی VPN/پروکسی می‌تواند مقدار را تغییر دهد.",
  "ip.lookup": "جستجوی اطلاعات IP",
  "ip.whois": "جستجوی WHOIS",
  "ip.rdns": "پرس‌وجوی DNS معکوس (PTR)",
  "ip.h2": "سرآیندهای درخواست و داده‌های تقریبی شبکه",
  "ip.h3": "محدودیت‌ها",
  "ip.lim": "شهر و منطقه موقعیت‌یابی تقریبی بر پایه IP هستند، نه GPS. ISP/سازمان و ASN فقط وقتی نمایش داده می‌شوند که Cloudflare آن‌ها را در اختیار بگذارد. این Worker نمی‌تواند اثرانگشت خام TCP/IP سیستم‌عامل را بگیرد، پورت‌ها را اسکن کند یا فردی را از روی IP شناسایی کند.",
  "ip.v6": "بررسی IPv6:",
  "ip.v6link": "باز کردن آزمون IPv6 خارجی",

  "tls.t": "آزمون کلاینت TLS",
  "tls.d": "محدودیت‌های پایان‌دادن اتصال در لبه را توضیح می‌دهد و فراداده‌های اتصال/درخواست در دسترس این Worker را نشان می‌دهد.",
  "tls.w": "Cloudflare Worker نمی‌تواند ClientHello اصلی TLS، فهرست رمزها، مذاکره ECH یا اثرانگشت JA3/JA4 را ببیند، چون TLS در لبه Cloudflare پایان می‌یابد. این یک آزمون دست‌دهی خام نیست و نتایج را نباید اثرانگشت JA3/JA4 دانست.",
  "tls.b": "تازه‌سازی فراداده‌های قابل‌مشاهده در لبه",
  "tls.ok": "فراداده‌های درخواست قابل‌مشاهده در لبه بارگذاری شد.",
  "tls.lim": "این Worker به ClientHello اصلی، رمزها، افزونه‌های TLS، وضعیت ECH یا JA3/JA4 دسترسی ندارد.",

  "http2.t": "اثرانگشت HTTP/2",
  "http2.d": "فراداده‌های پروتکل را که Cloudflare در اختیار می‌گذارد نشان می‌دهد، بدون ادعای دسترسی به فریم‌های خام HTTP/2.",
  "http2.w": "Worker نمی‌تواند فریم‌های خام HTTP/2 را بخواند یا اثرانگشت Akamai اتصال اصلی شما را بسازد؛ Cloudflare اتصال را پایان می‌دهد و ممکن است آن را تغییر دهد.",
  "http2.b": "بررسی فراداده‌های پروتکل موجود",
  "http2.ok": "فراداده‌های پروتکل موجود نمایش داده شد؛ هیچ اثرانگشت Akamai ساخته نشد.",
  "http2.note": "اثرانگشت‌های HTTP/2 شرکت Akamai به ترتیب فریم‌ها و تنظیمات خام اتصال اصلی نیاز دارند که Workers نمی‌بینند.",

  "quic.t": "آزمون کلاینت QUIC",
  "quic.d": "محدودیت‌های دید نسبت به QUIC را توضیح می‌دهد و نشانه‌های HTTP/3 قابل‌مشاهده در مرورگر را بررسی می‌کند.",
  "quic.w": "دست‌دهی خام QUIC و اثرانگشت HTTP/3 برای Worker در دسترس نیست؛ Cloudflare ابتدا اتصال کلاینت را پایان می‌دهد.",
  "quic.b": "بررسی قابلیت‌های قابل‌مشاهده در مرورگر",
  "quic.ok": "جزئیات پروتکل قابل‌مشاهده در مرورگر و لبه جمع‌آوری شد.",
  "quic.note": "اگر مرورگر نمایش دهد، nextHopProtocol می‌تواند h2 یا h3 باشد؛ این اثرانگشت QUIC نیست.",

  "tcpip.t": "اثرانگشت TCP/IP",
  "tcpip.d": "فراداده‌های درخواست مشاهده‌شده توسط سرور را نشان می‌دهد و توضیح می‌دهد چرا اثرانگشت‌های خام TCP/MTU/hop در دسترس نیستند.",
  "tcpip.w": "Cloudflare اتصال را پروکسی می‌کند، بنابراین این Worker نمی‌تواند سرآیندهای اصلی TCP، TTL، MTU، تعداد hop، پنجره بسته‌ها یا JA4T را بخواند. فقط فراداده‌های قابل‌مشاهده در لبه نمایش داده می‌شود.",
  "tcpip.b": "بارگذاری فراداده‌های لبه",
  "tcpip.ok": "فراداده بارگذاری شد.",
  "tcpip.na": "غیرقابل‌دسترس",
  "tcpip.ja4t": "در این Worker نمی‌توان آن را دقیق محاسبه کرد",

  "connection.t": "اطلاعات اتصال",
  "connection.d": "NetworkInformation را گزارش می‌دهد: نوع مؤثر، RTT، سرعت دانلود، حالت صرفه‌جویی داده و nextHopProtocol.",
  "connection.ok": "اطلاعات اتصال جمع‌آوری شد.",
  "connection.note": "مقادیر NetworkInformation تخمینی هستند؛ مرورگرهای حافظ حریم خصوصی ممکن است آن‌ها را گرد یا پنهان کنند.",

  "javascript.t": "جاوااسکریپت",
  "javascript.d": "APIهای مرورگر، زبان، منطقه زمانی، صفحه‌نمایش، CPU، حافظه، باتری و نشانه‌های شبکه را بررسی می‌کند.",
  "javascript.ok": "اطلاعات مرورگر به‌صورت محلی جمع‌آوری شد.",

  "webrtc.t": "آزمون نشت WebRTC",
  "webrtc.d": "بررسی می‌کند WebRTC در دسترس است یا نه و آیا کاندیدهای ICE آدرس‌ها را فاش می‌کنند.",
  "webrtc.w": "سیاست‌های مرورگر ممکن است آدرس‌های محلی (mDNS) را پنهان یا STUN را مسدود کنند؛ این تضمینی برای ناشناس‌ماندن با VPN نیست. نبودن کاندید ثابت نمی‌کند نشتی وجود ندارد.",
  "webrtc.na": "API مربوط به WebRTC در دسترس نیست.",
  "webrtc.gather": "در حال جمع‌آوری کاندیدهای ICE…",
  "webrtc.done": "جمع‌آوری ICE تمام شد. کاندیدهای زیر را بررسی کنید.",
  "webrtc.none": "جمع‌آوری ICE بدون کاندید قابل‌مشاهده پایان یافت.",
  "webrtc.timeout": "پس از اتمام مهلت متوقف شد. کاندیدهای دریافت‌شده نمایش داده می‌شوند.",
  "webrtc.note": "قابلیت مشاهده کاندیدها بسته به مرورگر فرق می‌کند. نبودن کاندید ثابت نمی‌کند نشتی وجود ندارد.",

  "canvas.t": "اثرانگشت Canvas",
  "canvas.d": "یک الگوی آزمایشی کوچک رسم می‌کند و پیکسل‌های آن را به‌صورت محلی هش می‌کند (فقط برای عیب‌یابی).",
  "canvas.ok": "Canvas رسم و به‌صورت محلی هش شد.",
  "canvas.note": "الگوی آزمایشی محلی؛ آن را شناسه یکتا یا پایدار فرض نکنید.",

  "webgl.t": "گزارش WebGL",
  "webgl.d": "رندرر، سازنده، افزونه‌ها و قابلیت‌های WebGL را بررسی می‌کند. مرورگرها ممکن است جزئیات را پنهان کنند.",
  "webgl.none": "WebGL در دسترس نیست یا مسدود شده است.",
  "webgl.ok": "اطلاعات WebGL به‌صورت محلی خوانده شد.",

  "fonts.t": "اثرانگشت فونت‌ها",
  "fonts.d": "اندازه‌گیری‌های متن را برای فهرستی کاربردی و غیرکامل از فونت‌های رایج مقایسه می‌کند.",
  "fonts.ok": "معیارهای فونت به‌صورت محلی اندازه‌گیری شد.",
  "fonts.note": "تفاوت عرض نشان می‌دهد فونت احتمالاً وجود دارد؛ این اثبات نیست و محافظت‌های ضد اثرانگشت می‌توانند نتیجه را مخدوش کنند.",

  "audio.t": "اثرانگشت صدا",
  "audio.d": "یک بافر کوتاه OfflineAudioContext را رندر و به‌صورت محلی هش می‌کند؛ هیچ صدایی پخش نمی‌شود.",
  "audio.w": "اثرانگشت صدا از تفاوت‌های ظریف پشته‌های صوتی بهره می‌برد. این صفحه یک بافر رندرشده محلی را هش می‌کند و صدایی پخش نمی‌کند.",
  "audio.none": "OfflineAudioContext در دسترس نیست.",
  "audio.ok": "اثرانگشت صدا به‌صورت محلی محاسبه شد.",
  "audio.note": "فقط برای عیب‌یابی محلی؛ شناسه پایدار نیست.",

  "voices.t": "صداهای SpeechSynthesis",
  "voices.d": "صداهای تبدیل متن به گفتار را فهرست می‌کند (منبعی شناخته‌شده از آنتروپی).",
  "voices.w": "ممکن است فهرست صداها کمی دیر ظاهر شود و برخی مرورگرها ابتدا به یک تعامل کاربر نیاز دارند.",
  "voices.b": "بارگذاری صداها",
  "voices.none": "SpeechSynthesis در دسترس نیست.",
  "voices.ok": "{n} صدا بارگذاری شد.",
  "voices.zero": "هیچ صدایی در دسترس قرار نگرفت.",

  "screen.t": "صفحه‌نمایش و نمایشگر",
  "screen.d": "اندازه صفحه، جهت، گستره رنگ، HDR، نسبت پیکسل و جزئیات پنجره.",
  "screen.ok": "داده‌های صفحه‌نمایش به‌صورت محلی جمع‌آوری شد.",
  "screen.note": "مرورگرهای حافظ حریم خصوصی ممکن است مقادیر گرد یا کوانتیزه‌شده گزارش کنند.",

  "clientrects.t": "اثرانگشت ClientRects",
  "clientrects.d": "مستطیل‌های رندرشده عناصر را اندازه می‌گیرد و یک هش تشخیصی محلی می‌سازد.",
  "clientrects.ok": "هندسه عنصر به‌صورت محلی اندازه‌گیری شد.",
  "clientrects.note": "مقادیر با اندازه نمای‌پورت، زوم، رندر فونت و چیدمان تغییر می‌کنند.",

  "client-hints.t": "آزمون Client Hints",
  "client-hints.d": "داده‌های UA در جاوااسکریپت را با سرآیندهای درخواست ارسالی به این Worker مقایسه می‌کند.",
  "client-hints.b": "مقایسه Client Hints",
  "client-hints.ok": "مقایسه Client Hints انجام شد.",
  "client-hints.note": "مرورگرهای Chromium به‌طور پیش‌فرض راهنماهای کم‌آنتروپی می‌فرستند؛ راهنماهای پرآنتروپی فقط پس از درخواست سرور ظاهر می‌شوند (این صفحه از طریق Accept-CH درخواست می‌کند). Firefox و Safari از Client Hints پشتیبانی نمی‌کنند.",

  "fingerprint.t": "خلاصه اثرانگشت",
  "fingerprint.d": "چند سیگنال ضعیف را در یک هش تشخیصی محلی ترکیب می‌کند (هویت پایدار نیست).",
  "fingerprint.w": "اثرانگشت‌گیری ترکیبی روشی شناخته‌شده است. از این ابزار برای دیدن آنچه مرورگرتان فاش می‌کند استفاده کنید، نه برای شناسایی خود یا دیگران.",
  "fingerprint.b": "محاسبه خلاصه",
  "fingerprint.ok": "اثرانگشت ترکیبی به‌صورت محلی محاسبه شد.",
  "fingerprint.note": "فقط برای عیب‌یابی. شناسه پایدار یا یکتا نیست.",

  "css-media.t": "کوئری‌های رسانه CSS",
  "css-media.d": "کوئری‌های رسانه رایج CSS را در مرورگر ارزیابی می‌کند.",
  "css-media.ok": "کوئری‌های رسانه ارزیابی شد.",

  "features.t": "تشخیص قابلیت‌ها",
  "features.d": "مجموعه گسترده‌ای از APIهای مرورگر و ویژگی‌های HTML را بررسی می‌کند.",
  "features.ok": "بررسی قابلیت‌ها کامل شد.",

  "sensors.t": "حسگرها و APIهای دستگاه",
  "sensors.d": "در دسترس بودن حرکت، جهت‌یابی، USB، بلوتوث، Serial، HID، NFC و APIهای مرتبط را بررسی می‌کند.",
  "sensors.ok": "وضعیت در دسترس بودن APIهای حسگر جمع‌آوری شد.",
  "sensors.note": "وجود API به معنای دسترسی نیست: بیشتر این APIها به تعامل کاربر یا مجوز نیاز دارند.",

  "media-devices.t": "دستگاه‌های رسانه",
  "media-devices.d": "دستگاه‌های صوتی/تصویری قابل‌مشاهده برای این صفحه را فهرست می‌کند (برچسب‌ها ممکن است پنهان باشند).",
  "media-devices.w": "اگر برچسب‌ها پنهان است، برای درخواست دسترسی به دوربین/میکروفون «درخواست مجوز» را بزنید. فقط اگر به این صفحه اعتماد دارید اجازه دهید. چیزی ضبط یا ارسال نمی‌شود.",
  "media-devices.b": "فهرست‌کردن",
  "media-devices.b2": "درخواست مجوز",
  "media-devices.ok": "{n} دستگاه فهرست شد.",
  "media-devices.fail": "فهرست‌کردن ناموفق بود.",
  "media-devices.denied": "مجوز رد شد یا در دسترس نیست: {e}",
  "media-devices.note": "تا زمانی که مجوز داده نشود برچسب‌ها پنهان می‌مانند. تعداد و شناسه دستگاه‌ها همچنان سطحی برای اثرانگشت‌گیری است.",

  "geolocation.t": "API مکان‌یابی",
  "geolocation.d": "مجوز مکان‌یابی را آزمایش می‌کند و در صورت تمایل موقعیت دستگاه را درخواست می‌کند.",
  "geolocation.b": "درخواست موقعیت من",
  "geolocation.unsupported": "مکان‌یابی پشتیبانی نمی‌شود.",
  "geolocation.denied": "مجوز رد شده است؛ اگر می‌خواهید آزمایش کنید آن را در تنظیمات مرورگر فعال کنید.",
  "geolocation.waiting": "در انتظار مجوز مکان‌یابی…",
  "geolocation.ok": "موقعیت دریافت شد. این صفحه آن را به سرور ارسال نمی‌کند.",
  "geolocation.fail": "موقعیت دریافت نشد. شاید مجوز رد شده یا موقعیت در دسترس نیست.",
  "geolocation.state": "وضعیت مجوز: {s}. برای پرسیدن از مرورگر «درخواست موقعیت من» را بزنید.",

  "permissions.t": "گزارش مجوزها",
  "permissions.d": "وضعیت فعلی مجوزها را برای قابلیت‌های رایج پرس‌وجو می‌کند.",
  "permissions.w": "حتی پس از رد در سطح سیستم‌عامل، برخی موارد ممکن است «prompt» نشان دهند؛ این وضعیت قابل‌مشاهده نیست. این صفحه هیچ درخواست مجوزی نمایش نمی‌دهد.",
  "permissions.b": "پرس‌وجوی مجوزها",
  "permissions.ok": "وضعیت مجوزها جمع‌آوری شد.",

  "storage.t": "حافظه و کوکی‌ها",
  "storage.d": "کوکی‌ها، حافظه محلی/نشست، IndexedDB و رفتار سهمیه را بررسی می‌کند.",
  "storage.ok": "قابلیت‌های ذخیره‌سازی بررسی شد.",

  "trackers.t": "بررسی مسدودسازی ردیاب‌ها",
  "trackers.d": "تلاش می‌کند به میزبان‌های ردیاب رایج برسد و گزارش می‌دهد مسدود شده‌اند یا نه (نتیجه قطعی نیست).",
  "trackers.w": "این بررسی هیچ فیلتری را دور نمی‌زند. شکست می‌تواند ناشی از اتمام مهلت یا خطای شبکه هم باشد و چیزی نمایش داده نمی‌شود.",
  "trackers.b": "اجرای بررسی",
  "trackers.ok": "{b} از {n} هدف بارگذاری نشد (ممکن است مسدود یا غیرقابل‌دسترس باشند).",
  "trackers.note": "شکست در بارگذاری اثبات مسدودسازی نیست. برای شواهد قوی‌تر از پنل Network در ابزار توسعه‌دهنده مرورگر استفاده کنید.",

  "third-party.t": "اسکریپت‌های شخص ثالث",
  "third-party.d": "به دنبال متغیرهای سراسری شناخته‌شده تحلیل/بازاریابی می‌گردد که از قبل در صفحه هستند.",
  "third-party.w": "این Worker نمایشی عمداً هیچ اسکریپت شخص ثالثی بارگذاری نمی‌کند، پس نبودن آن‌ها اینجا درباره سایت‌های دیگر چیزی نمی‌گوید.",
  "third-party.b": "اسکن صفحه فعلی",
  "third-party.ok": "نشانه‌های شخص ثالث اسکن شد.",
  "third-party.note": "تشخیص در حد تلاش است؛ بسیاری از بارگذارها متغیر سراسری ایجاد نمی‌کنند.",

  "dnt.t": "عدم ردیابی (DNT)",
  "dnt.d": "سیگنال‌های Do Not Track و Global Privacy Control را (سمت کلاینت و سرور) بررسی می‌کند.",
  "dnt.b": "بررسی سیگنال‌های حریم خصوصی",
  "dnt.ok": "سیگنال‌های حریم خصوصی بررسی شد (کلاینت + سرآیندهای درخواست).",
  "dnt.note": "DNT و GPC فقط سیگنال ترجیح هستند؛ رعایت آن‌ها توسط وب‌سایت‌ها متفاوت است.",

  "content-filters.t": "فیلترهای محتوا",
  "content-filters.d": "بررسی‌های محلی ساده برای رفتارهای رایج مسدودسازی محتوا انجام می‌دهد.",
  "content-filters.ok": "بررسی‌های محلی فیلتر کامل شد؛ یافته‌ها قطعی نیستند.",
  "content-filters.note": "پنهان‌شدن عنصر طعمه نشان‌دهنده فیلتر ظاهری است. این صفحه تلاشی برای تشخیص قطعی Tor یا دور زدن فیلترها نمی‌کند.",

  "extensions.t": "تشخیص افزونه کروم",
  "extensions.d": "چند نشانی منبع عمومی در دسترس وب را بررسی می‌کند؛ نتایج قطعی نیستند.",
  "extensions.w": "اسکن کامل نیست و به داده خصوصی افزونه‌ها دسترسی ندارد. مرورگرها معمولاً منابع افزونه را از صفحات وب پنهان می‌کنند، پس هر دو نتیجه قطعی نیست.",
  "extensions.b": "بررسی منابع نمونه افزونه‌ها",
  "extensions.ok": "بررسی نمونه‌ها کامل شد؛ فهرستی از افزونه‌ها در دسترس نیست.",
  "extensions.note": "مرورگرها معمولاً درخواست‌های مبدأ افزونه را از صفحات عادی مسدود می‌کنند. نتایج قطعی نیستند.",

  "https-audit.t": "HTTPS و هدرهای امنیتی",
  "https-audit.d": "زمینه امن، وجود CSP، نشانه‌های COOP/COEP و وضعیت محتوای ترکیبی.",
  "https-audit.w": "بررسی هدرها پاسخ این Worker برای همین صفحه را نشان می‌دهد، نه اتصال اصلی یا نشست‌های قبلی شما را.",
  "https-audit.b": "ممیزی صفحه",
  "https-audit.ok": "ممیزی HTTPS و هدرها کامل شد.",

  "csp.t": "بررسی CSP / Sandbox",
  "csp.d": "بررسی می‌کند اسکریپت درون‌خطی، eval، کامپایل Wasm و workerهای blob اینجا مجازند یا نه.",
  "csp.w": "تشخیص مسدود یا مجاز بودن در حد تلاش است. بروز خطا قویاً نشانه مسدودسازی است، اما هر مسدودسازی خطا نمی‌دهد.",
  "csp.b": "بررسی",
  "csp.ok": "بررسی‌های CSP/sandbox کامل شد.",

  "cors.t": "بررسی CORS و هم‌مبدأ",
  "cors.d": "رفتار درخواست‌های هم‌مبدأ، no-cors و میان‌مبدأ را مشاهده می‌کند.",
  "cors.b": "اجرای بررسی CORS",
  "cors.ok": "بررسی CORS کامل شد.",
  "cors.note": "این Worker فراتر از اینکه مرورگر درخواست را اجازه داد یا نه، سیاست CORS مبدأ دیگر را نمی‌بیند.",

  "referrer.t": "سیاست Referrer",
  "referrer.d": "نشانه‌های سیاست مؤثر referrer را از سند و تگ‌های meta گزارش می‌دهد.",
  "referrer.b": "بررسی رفتار referrer",
  "referrer.ok": "نشانه‌های سیاست referrer جمع‌آوری شد.",
  "referrer.note": "Worker سرآیند Referer را برای هر سیاست درخواست می‌بیند: پیش‌فرض، unsafe-url (نشانی کامل) و no-referrer.",

  "permissions-policy.t": "Permissions-Policy",
  "permissions-policy.d": "نشان می‌دهد کدام قابلیت‌های مرورگر در این صفحه واگذار یا مسدود شده‌اند.",
  "permissions-policy.b": "خواندن نشانه‌های سیاست",
  "permissions-policy.ok": "نشانه‌های Permissions-Policy جمع‌آوری شد.",
  "permissions-policy.note": "Permissions-Policy فقط قابلیت‌ها را محدود می‌کند و هرگز مجوزی نمی‌دهد.",

  "credential.t": "Credential Management API",
  "credential.d": "در دسترس بودن ظرف اعتبارنامه‌ها و حالت‌های میانجی‌گری را بررسی می‌کند.",
  "credential.b": "بررسی دسترس‌پذیری",
  "credential.ok": "دسترس‌پذیری Credential Management بررسی شد.",
  "credential.note": "هیچ درخواست اعتبارنامه‌ای ارسال نمی‌شود؛ فقط در دسترس بودن API گزارش می‌شود.",

  "webauthn.t": "WebAuthn / پس‌کی (Passkey)",
  "webauthn.d": "در دسترس بودن PublicKeyCredential و احراز‌هویت‌کننده پلتفرم را بررسی می‌کند.",
  "webauthn.b": "بررسی WebAuthn",
  "webauthn.ok": "دسترس‌پذیری WebAuthn بررسی شد.",
  "webauthn.note": "این صفحه هیچ پنجره درخواست اعتبارنامه‌ای ایجاد نمی‌کند.",

  "mixed-content.t": "بررسی محتوای ترکیبی",
  "mixed-content.d": "تلاش می‌کند از این صفحه HTTPS یک زیرمنبع ناامن بارگذاری کند.",
  "mixed-content.w": "این بررسی نحوه مدیریت محتوای ترکیبی در مرورگر را می‌سنجد. Worker نمی‌تواند تعیین کند مرورگر زیرمنابع ناامن را مسدود کند یا نه.",
  "mixed-content.b": "بررسی محتوای ترکیبی",
  "mixed-content.ok": "بررسی محتوای ترکیبی کامل شد.",
  "mixed-content.note": "رفتار متفاوت است: مرورگرهای مدرن ممکن است تصاویر http:// را در صفحات HTTPS ارتقا دهند یا مسدود کنند.",

  "isolation.t": "ایزوله‌سازی میان‌مبدأ",
  "isolation.d": "crossOriginIsolated، SharedArrayBuffer، دقت تایمر و Atomics را گزارش می‌دهد.",
  "isolation.b": "بررسی ایزوله‌سازی",
  "isolation.ok": "وضعیت ایزوله‌سازی میان‌مبدأ بررسی شد.",
  "isolation.note": "کاهش دقت تایمر اثر جانبی ایزوله‌سازی است؛ اندازه‌گیری در حد تلاش است.",

  "webgpu.t": "گزارش WebGPU مرورگر",
  "webgpu.d": "در دسترس بودن WebGPU را بررسی می‌کند و در صورت پشتیبانی یک آداپتور درخواست می‌کند.",
  "webgpu.b": "درخواست آداپتور WebGPU",
  "webgpu.none": "WebGPU در دسترس نیست، غیرفعال یا مسدود است.",
  "webgpu.notdet": "WebGPU شناسایی نشد.",
  "webgpu.ok": "پرس‌وجوی آداپتور WebGPU کامل شد.",
  "webgpu.rejected": "درخواست WebGPU رد یا مسدود شد.",

  "js-engine.t": "موتور JS و Intl",
  "js-engine.d": "زبان‌های Intl، قالب‌بندی عدد/تاریخ، دقت تایمر و پشتیبانی BigInt را گزارش می‌دهد.",
  "js-engine.ok": "جزئیات موتور JS و Intl جمع‌آوری شد.",
  "js-engine.note": "خروجی سطح موتور بسته به نسخه ICU و ساخت مرورگر فرق می‌کند؛ سیگنالی ضعیف برای اثرانگشت است."
};

I.zh = {
  "ui.sub": "浏览器诊断 · 尽可能在本地完成",
  "ui.langs": "语言",
  "ui.overview": "概览",
  "ui.results": "结果",
  "ui.footer": "隐私说明：浏览器测试在你的浏览器中运行。本演示不会有意保存测试结果。IP 和请求详情由 Cloudflare 处理以响应请求。部分测试结果仅为近似值，请查看各页面的限制说明。语言由链接中的 ?lang= 参数决定，不会设置任何 Cookie。",
  "ui.homeT": "浏览器隐私与指纹实验室",
  "ui.homeD": "一个多页面工具箱，用于检查浏览器暴露的隐私信号、网络元数据和指纹识别面。",
  "ui.allTools": "全部工具",
  "ui.homeP": "每个工具都有独立页面。仅限浏览器的测试在你的设备上运行；服务器端详情来自 Cloudflare 请求上下文。",
  "ui.notesT": "重要的隐私与技术说明",
  "ui.notes1": "指纹识别可被用于跟踪。请用这些诊断来了解网站能观察到什么，而不是用来识别或跟踪他人。",
  "ui.notes2": "Cloudflare Workers 无法获得访问者原始的 TCP 数据包，也无法获得原始的 TLS/HTTP2/QUIC 握手。需要这些细节的测试会明确标注为受限，而不会显示伪造的结果。",
  "ui.nfT": "页面未找到",
  "ui.nfD": "该工具页面不存在。",
  "ui.nfP": "未找到该路径。",
  "ui.back": "返回全部工具",

  "c.running": "正在运行测试…",
  "c.failed": "测试失败。",
  "c.run": "重新运行",

  "rq.ip": "观察到的 IP", "rq.country": "国家/地区", "rq.region": "地区 / 省州", "rq.city": "城市", "rq.tz": "时区",
  "rq.isp": "ISP / 组织", "rq.proto": "HTTP 协议", "rq.ray": "请求 ID", "rq.na": "不可用", "rq.ns": "未发送",

  "ip.t": "IP 地址",
  "ip.d": "服务器观察到的 IP、请求头、大致位置、ASN/ISP、反向 DNS 和查询链接。",
  "ip.h1": "你的 IP（服务器观察到的）",
  "ip.p1": "此为该 Cloudflare Worker 观察到的值；VPN/代理路由可能影响该值。",
  "ip.lookup": "IP 信息查询",
  "ip.whois": "WHOIS 查询",
  "ip.rdns": "反向 DNS（PTR）查询",
  "ip.h2": "请求头与大致网络数据",
  "ip.h3": "限制",
  "ip.lim": "城市和地区是基于 IP 的大致定位，并非 GPS。仅当 Cloudflare 提供时才会显示 ISP/组织和 ASN。此 Worker 无法进行原始 TCP/IP 操作系统指纹识别、扫描端口，也无法通过 IP 识别个人。",
  "ip.v6": "IPv6 检测：",
  "ip.v6link": "打开外部 IPv6 测试",

  "tls.t": "TLS 客户端测试",
  "tls.d": "说明边缘终止的限制，并显示此 Worker 可获得的请求/连接元数据。",
  "tls.w": "由于 TLS 在 Cloudflare 边缘终止，Cloudflare Worker 看不到你原始的 TLS ClientHello、密码套件列表、ECH 协商或 JA3/JA4 指纹。这不是原始握手测试，结果不能当作 JA3/JA4 指纹。",
  "tls.b": "刷新边缘可见元数据",
  "tls.ok": "已加载边缘可见的请求元数据。",
  "tls.lim": "此 Worker 无法获取原始 ClientHello、密码套件、TLS 扩展、ECH 状态或 JA3/JA4。",

  "http2.t": "HTTP/2 指纹",
  "http2.d": "显示 Cloudflare 提供的协议元数据，不声称能访问原始 HTTP/2 帧。",
  "http2.w": "Worker 无法读取原始 HTTP/2 帧，也无法为你的原始连接生成 Akamai 指纹；Cloudflare 会终止并可能转换该连接。",
  "http2.b": "查看可用的协议元数据",
  "http2.ok": "已显示可用的协议元数据；未生成 Akamai 指纹。",
  "http2.note": "Akamai HTTP/2 指纹需要原始连接的帧顺序和设置，而 Workers 看不到这些。",

  "quic.t": "QUIC 客户端测试",
  "quic.d": "说明 QUIC 可见性的限制，并检查浏览器可见的 HTTP/3 线索。",
  "quic.w": "Worker 无法获得原始 QUIC 握手和 HTTP/3 指纹；Cloudflare 会先终止客户端连接。",
  "quic.b": "检查浏览器可见的能力",
  "quic.ok": "已收集浏览器和边缘可见的协议详情。",
  "quic.note": "若浏览器暴露，nextHopProtocol 可能显示 h2 或 h3；它不是 QUIC 指纹。",

  "tcpip.t": "TCP/IP 指纹",
  "tcpip.d": "显示服务器观察到的请求元数据，并说明为何无法获得原始 TCP/MTU/跳数指纹。",
  "tcpip.w": "Cloudflare 代理了连接，因此此 Worker 无法读取原始 TCP 头、TTL、MTU、跳数、数据包窗口或 JA4T。仅显示边缘可见的元数据。",
  "tcpip.b": "加载边缘元数据",
  "tcpip.ok": "元数据已加载。",
  "tcpip.na": "无法访问",
  "tcpip.ja4t": "无法在此 Worker 中准确计算",

  "connection.t": "连接信息",
  "connection.d": "报告 NetworkInformation：有效类型、RTT、下行速度、节省流量模式和 nextHopProtocol。",
  "connection.ok": "已收集连接信息。",
  "connection.note": "NetworkInformation 的值只是估算；注重隐私的浏览器可能会取整或隐藏它们。",

  "javascript.t": "JavaScript",
  "javascript.d": "检查浏览器 API、语言、时区、屏幕、CPU、内存、电池和网络线索。",
  "javascript.ok": "已在本地收集浏览器信息。",

  "webrtc.t": "WebRTC 泄漏测试",
  "webrtc.d": "检查 WebRTC 是否可用，以及 ICE 候选是否暴露地址。",
  "webrtc.w": "浏览器策略可能隐藏本地地址（mDNS）或阻止 STUN；这并不保证使用 VPN 时的匿名性。没有候选并不能证明没有泄漏。",
  "webrtc.na": "WebRTC API 不可用。",
  "webrtc.gather": "正在收集 ICE 候选…",
  "webrtc.done": "ICE 收集已完成。请查看下方候选。",
  "webrtc.none": "ICE 收集结束，没有可见的候选。",
  "webrtc.timeout": "超时后已停止。已收到的候选会显示出来。",
  "webrtc.note": "候选的可见性因浏览器而异。没有候选并不能证明没有泄漏。",

  "canvas.t": "Canvas 指纹",
  "canvas.d": "渲染一个小型测试图案并在本地对其像素做哈希（仅供诊断）。",
  "canvas.ok": "Canvas 已渲染并在本地完成哈希。",
  "canvas.note": "这是本地测试图案；请勿将其视为唯一或稳定的标识符。",

  "webgl.t": "WebGL 报告",
  "webgl.d": "检查 WebGL 渲染器、厂商、扩展和能力。浏览器可能会屏蔽部分细节。",
  "webgl.none": "WebGL 不可用或已被阻止。",
  "webgl.ok": "已在本地读取 WebGL 信息。",

  "fonts.t": "字体指纹",
  "fonts.d": "针对一份实用但不完整的常见字体列表，比较文本度量。",
  "fonts.ok": "已在本地测量字体度量。",
  "fonts.note": "宽度差异表明字体可能存在，但这不是证明，反指纹保护也可能扭曲结果。",

  "audio.t": "音频指纹",
  "audio.d": "渲染一小段 OfflineAudioContext 缓冲并在本地做哈希；不会播放任何声音。",
  "audio.w": "音频指纹利用音频栈的细微差异。本页只对本地渲染的缓冲做哈希，不会播放声音。",
  "audio.none": "OfflineAudioContext 不可用。",
  "audio.ok": "已在本地计算音频指纹。",
  "audio.note": "仅为本地诊断；不是持久标识符。",

  "voices.t": "语音合成声音",
  "voices.d": "列出文本转语音的声音（已知的熵来源）。",
  "voices.w": "声音列表可能需要片刻才会出现，部分浏览器需要先有用户操作。",
  "voices.b": "加载声音",
  "voices.none": "SpeechSynthesis 不可用。",
  "voices.ok": "已加载 {n} 个声音。",
  "voices.zero": "未暴露任何声音。",

  "screen.t": "屏幕与显示",
  "screen.d": "屏幕尺寸、方向、色域、HDR、像素比和窗口详情。",
  "screen.ok": "已在本地收集屏幕数据。",
  "screen.note": "注重隐私的浏览器可能会报告取整或量化后的值。",

  "clientrects.t": "ClientRects 指纹",
  "clientrects.d": "测量已渲染元素的矩形，并生成本地诊断哈希。",
  "clientrects.ok": "已在本地测量元素几何信息。",
  "clientrects.note": "这些值会随视口、缩放、字体渲染和布局而变化。",

  "client-hints.t": "Client Hints 测试",
  "client-hints.d": "将 JavaScript 中的 UA 数据与发送到此 Worker 的请求头进行比较。",
  "client-hints.b": "比较 Client Hints",
  "client-hints.ok": "Client Hints 比较完成。",
  "client-hints.note": "Chromium 系浏览器默认发送低熵提示；高熵提示只有在服务器请求后才会出现（本页通过 Accept-CH 请求）。Firefox 和 Safari 不支持 UA Client Hints。",

  "fingerprint.t": "指纹汇总",
  "fingerprint.d": "将多个弱信号合并为一个本地诊断哈希（不是稳定身份）。",
  "fingerprint.w": "组合指纹识别是一种广为人知的技术。请用它查看浏览器暴露了什么，而不是用来识别你自己或他人。",
  "fingerprint.b": "计算汇总",
  "fingerprint.ok": "已在本地计算组合指纹。",
  "fingerprint.note": "仅供诊断。不是稳定或唯一的标识符。",

  "css-media.t": "CSS 媒体查询",
  "css-media.d": "在浏览器中评估常见的 CSS 媒体查询。",
  "css-media.ok": "媒体查询已评估。",

  "features.t": "功能检测",
  "features.d": "检查大量浏览器 API 和 HTML 功能。",
  "features.ok": "功能检查完成。",

  "sensors.t": "传感器与设备 API",
  "sensors.d": "检查运动、方向、USB、蓝牙、串口、HID、NFC 及相关 API 是否可用。",
  "sensors.ok": "已收集传感器 API 的可用性。",
  "sensors.note": "存在不代表可访问：这些 API 大多需要用户操作或权限。",

  "media-devices.t": "媒体设备",
  "media-devices.d": "列出此页面可见的音频/视频设备（标签可能被隐藏）。",
  "media-devices.w": "如果标签被隐藏，请点击“请求权限”以弹出摄像头/麦克风授权提示。仅在信任本页时才授权。不会录制或发送任何内容。",
  "media-devices.b": "枚举设备",
  "media-devices.b2": "请求权限",
  "media-devices.ok": "已枚举 {n} 个设备。",
  "media-devices.fail": "枚举失败。",
  "media-devices.denied": "权限被拒绝或不可用：{e}",
  "media-devices.note": "在授予权限之前，标签会保持隐藏。设备数量和 ID 仍然是一种指纹面。",

  "geolocation.t": "地理位置 API",
  "geolocation.d": "测试地理位置权限，并可选择请求设备位置。",
  "geolocation.b": "请求我的位置",
  "geolocation.unsupported": "不支持地理位置。",
  "geolocation.denied": "权限已被拒绝；如需测试，请在浏览器设置中启用。",
  "geolocation.waiting": "正在等待位置权限…",
  "geolocation.ok": "已返回位置。本页不会将其发送到服务器。",
  "geolocation.fail": "未返回位置。可能是权限被拒绝或位置不可用。",
  "geolocation.state": "权限状态：{s}。点击“请求我的位置”以询问浏览器。",

  "permissions.t": "权限报告",
  "permissions.d": "查询常见能力当前的权限状态。",
  "permissions.w": "即使在操作系统层面已被拒绝，部分条目仍可能显示“prompt”；该状态不会暴露。本页不会触发任何授权提示。",
  "permissions.b": "查询权限",
  "permissions.ok": "已收集权限状态。",

  "storage.t": "存储与 Cookie",
  "storage.d": "检查 Cookie、本地/会话存储、IndexedDB 和配额行为。",
  "storage.ok": "已检查存储能力。",

  "trackers.t": "跟踪器拦截探测",
  "trackers.d": "尝试访问常见的跟踪器主机，并报告它们是否被拦截（结果不确定）。",
  "trackers.w": "此探测不会绕过任何过滤器。失败也可能源于超时或网络错误，且不会渲染任何内容。",
  "trackers.b": "运行探测",
  "trackers.ok": "{n} 个目标中有 {b} 个加载失败（可能被拦截或无法访问）。",
  "trackers.note": "加载失败并不证明被拦截。如需更有力的证据，请使用浏览器开发者工具的“网络”面板。",

  "third-party.t": "第三方脚本",
  "third-party.d": "查找页面上已存在的知名分析/营销全局变量。",
  "third-party.w": "此演示 Worker 有意不加载任何第三方脚本，因此这里检测不到并不代表其他网站没有。",
  "third-party.b": "扫描当前页面",
  "third-party.ok": "已扫描第三方线索。",
  "third-party.note": "尽力检测；许多加载器不会暴露全局变量。",

  "dnt.t": "请勿跟踪 (DNT)",
  "dnt.d": "检查“请勿跟踪”和全球隐私控制信号（客户端 + 服务器）。",
  "dnt.b": "检查隐私信号",
  "dnt.ok": "已检查隐私信号（客户端 + 请求头）。",
  "dnt.note": "DNT 和 GPC 只是偏好信号；网站是否遵守各不相同。",

  "content-filters.t": "内容过滤器",
  "content-filters.d": "对常见的内容拦截行为做简单的本地检查。",
  "content-filters.ok": "本地过滤器检查完成；结果不确定。",
  "content-filters.note": "诱饵元素被隐藏说明可能存在外观过滤。本页不会尝试确切检测 Tor，也不会绕过过滤器。",

  "extensions.t": "Chrome 扩展检测",
  "extensions.d": "检查少量可通过网页访问的公开资源 URL；结果不确定。",
  "extensions.w": "这不是详尽扫描，也不会访问扩展的私有数据。浏览器通常不会向网页暴露扩展资源，因此无论结果如何都不确定。",
  "extensions.b": "检查示例扩展资源",
  "extensions.ok": "示例检查完成；无法获得扩展清单。",
  "extensions.note": "浏览器通常会阻止普通页面请求扩展来源。结果不确定。",

  "https-audit.t": "HTTPS 与安全标头",
  "https-audit.d": "安全上下文、CSP 是否存在、COOP/COEP 线索和混合内容状态。",
  "https-audit.w": "标头检查反映的是此 Worker 对当前页面的响应，而不是你原始的连接或之前的会话。",
  "https-audit.b": "审计页面",
  "https-audit.ok": "HTTPS 与标头审计完成。",

  "csp.t": "CSP / 沙箱探测",
  "csp.d": "检查此处是否允许内联脚本、eval、Wasm 编译和 blob Worker。",
  "csp.w": "是否被阻止的检测只是尽力而为。抛出错误强烈暗示被阻止，但并非每次阻止都会抛出错误。",
  "csp.b": "探测",
  "csp.ok": "CSP/沙箱探测完成。",

  "cors.t": "CORS 与同源探测",
  "cors.d": "观察同源、no-cors 和跨源请求的行为。",
  "cors.b": "运行 CORS 探测",
  "cors.ok": "CORS 探测完成。",
  "cors.note": "除了浏览器是否允许该请求之外，此 Worker 无法观察其他来源的 CORS 策略。",

  "referrer.t": "Referrer 策略",
  "referrer.d": "报告来自文档和 meta 标签的有效 Referrer 策略线索。",
  "referrer.b": "检查 Referrer 行为",
  "referrer.ok": "已收集 Referrer 策略线索。",
  "referrer.note": "Worker 会按请求策略查看 Referer 头：默认、unsafe-url（完整 URL）和 no-referrer。",

  "permissions-policy.t": "Permissions-Policy",
  "permissions-policy.d": "显示此页面上哪些浏览器功能被委托或被阻止。",
  "permissions-policy.b": "读取策略线索",
  "permissions-policy.ok": "已收集 Permissions-Policy 线索。",
  "permissions-policy.note": "Permissions-Policy 只会限制功能，从不授予权限。",

  "credential.t": "凭据管理 API",
  "credential.d": "检查凭据容器和中介模式是否可用。",
  "credential.b": "检查可用性",
  "credential.ok": "已检查凭据管理的可用性。",
  "credential.note": "不会发起任何凭据请求；仅报告 API 是否可用。",

  "webauthn.t": "WebAuthn / 通行密钥",
  "webauthn.d": "检查 PublicKeyCredential 和平台认证器是否可用。",
  "webauthn.b": "检查 WebAuthn",
  "webauthn.ok": "已检查 WebAuthn 的可用性。",
  "webauthn.note": "本页不会弹出任何凭据提示。",

  "mixed-content.t": "混合内容探测",
  "mixed-content.d": "尝试从此 HTTPS 页面加载一个不安全的子资源。",
  "mixed-content.w": "这是在探测浏览器对混合内容的处理方式。Worker 无法改变浏览器是否阻止不安全的子资源。",
  "mixed-content.b": "探测混合内容",
  "mixed-content.ok": "混合内容探测完成。",
  "mixed-content.note": "行为因浏览器而异：现代浏览器可能会升级或阻止 HTTPS 页面中的 http:// 图片。",

  "isolation.t": "跨源隔离",
  "isolation.d": "报告 crossOriginIsolated、SharedArrayBuffer、计时器精度和 Atomics。",
  "isolation.b": "检查隔离状态",
  "isolation.ok": "已检查跨源隔离状态。",
  "isolation.note": "计时器精度降低是隔离的副作用；该测量只是尽力而为。",

  "webgpu.t": "WebGPU 浏览器报告",
  "webgpu.d": "检查 WebGPU 是否可用，并在支持时请求适配器。",
  "webgpu.b": "请求 WebGPU 适配器",
  "webgpu.none": "WebGPU 不可用、已禁用或已被阻止。",
  "webgpu.notdet": "未检测到 WebGPU。",
  "webgpu.ok": "WebGPU 适配器查询完成。",
  "webgpu.rejected": "WebGPU 请求被拒绝或被阻止。",

  "js-engine.t": "JS 引擎与 Intl",
  "js-engine.d": "报告 Intl 区域设置、数字/日期格式化、计时器精度和 BigInt 支持。",
  "js-engine.ok": "已收集 JS 引擎和 Intl 详情。",
  "js-engine.note": "引擎层面的输出因 ICU 版本和浏览器构建而异；是一个较弱的指纹信号。"
};
