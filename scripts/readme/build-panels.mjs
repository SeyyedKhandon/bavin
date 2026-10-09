// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
// Generates the README panels (docs/assets/*-light.svg and *-dark.svg).  Run:  node scripts/readme/build-panels.mjs
// Pure Node, no dependencies. Each panel is an SVG that wraps an HTML card in <foreignObject> (the same technique
// as the profile README), with Inter embedded as a base64 subset so it looks identical everywhere.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const out = join(root, 'docs', 'assets');
mkdirSync(out, { recursive: true });
const FONT = readFileSync(join(out, 'fonts', 'Inter-subset.woff2')).toString('base64');

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// ── design tokens (same palette family as the profile README) ──
const THEMES = {
  light: { bg: '#f5f5f3', surface: '#ffffff', surface2: '#f1f1ef', border: '#e7e7e3', text: '#0e0e0d', muted: '#6b6b66', link: '#2563c9', accent: '#0e0e0d', ok: '#276b1a',
    blue: '#2563c9', green: '#276b1a', purple: '#7c3fc4', amber: '#a86400', teal: '#0b7f70', slate: '#5b6b82', red: '#b8341b', shadow: '0 1px 2px rgba(15,15,12,.04), 0 6px 24px rgba(15,15,12,.06)', scheme: 'light' },
  dark: { bg: '#0b0b0a', surface: '#151514', surface2: '#1e1e1d', border: '#272726', text: '#f4f4f1', muted: '#8b8b85', link: '#7fa9f2', accent: '#f4f4f1', ok: '#7fcf5f',
    blue: '#8fb4f5', green: '#8bd76b', purple: '#c7a4f0', amber: '#f0b24a', teal: '#3cc7b4', slate: '#94a3b8', red: '#f29a82', shadow: 'none', scheme: 'dark' },
};

const css = (t) => `
@font-face { font-family: 'Inter Variable'; font-weight: 100 900; src: url(data:font/woff2;base64,${FONT}) format('woff2'); }
.panel { box-sizing: border-box; --surface:${t.surface}; --surface-2:${t.surface2}; --border:${t.border}; --text:${t.text}; --muted:${t.muted}; --link:${t.link}; --accent:${t.accent}; --ok:${t.ok};
  --blue:${t.blue}; --green:${t.green}; --purple:${t.purple}; --amber:${t.amber}; --teal:${t.teal}; --slate:${t.slate}; --red:${t.red}; --shadow:${t.shadow}; color-scheme:${t.scheme};
  width: 900px; padding: 4px 6px; font: 14px/1.5 'Inter Variable', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; color: var(--text); }
.panel * { box-sizing: border-box; margin: 0; }
.mono { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; }
.muted { color: var(--muted); }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 20px; padding: 20px; box-shadow: var(--shadow); }
.eyebrow { color: var(--link); font-weight: 700; font-size: 12px; text-transform: uppercase; letter-spacing: .09em; margin-bottom: 6px; }
h1 { font-size: 46px; line-height: 1.04; letter-spacing: -.035em; font-weight: 800; margin: 12px 0; }
h2 { font-size: 28px; line-height: 1.12; letter-spacing: -.03em; font-weight: 800; margin-bottom: 6px; }
h3 { font-size: 15px; letter-spacing: -.01em; font-weight: 700; }
.sub { color: var(--muted); font-size: 14.5px; margin-bottom: 16px; }
.grad { background: linear-gradient(100deg, var(--blue), var(--green) 60%, var(--purple)); -webkit-background-clip: text; background-clip: text; color: transparent; }
.grid { display: grid; gap: 14px; } .c2 { grid-template-columns: repeat(2, 1fr); } .c3 { grid-template-columns: repeat(3, 1fr); }
.tag { display: inline-block; padding: 1px 9px; border-radius: 99px; background: var(--surface-2); color: var(--muted); font-size: 11.5px; font-weight: 600; }
.t-link { --c: var(--slate); } .t-network { --c: var(--teal); } .t-transport { --c: var(--amber); } .t-app { --c: var(--purple); }
@keyframes rise { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
@keyframes blink { 50% { opacity: 0; } }
@keyframes flow { from { transform: translateX(0); opacity: 0; } 15% { opacity: 1; } 85% { opacity: 1; } to { transform: translateX(var(--dist, 120px)); opacity: 0; } }
@keyframes pulse { 50% { opacity: .45; } }
.rise { animation: rise 600ms cubic-bezier(.2,.7,.2,1) both; animation-delay: calc(var(--i, 0) * 70ms); }
@media (prefers-reduced-motion: reduce) { .panel * { animation: none !important; } }
`;

const wrap = (t, w, h, label, extraCss, body) => `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(label)}">
<foreignObject width="${w}" height="${h}"><div xmlns="http://www.w3.org/1999/xhtml" class="panel"><style>${css(t)}${extraCss}</style>
${body}
</div></foreignObject>
</svg>
`;

const chip = (name, tier, extra = '') => `<span class="chip t-${tier}">${esc(name)}${extra}</span>`;
const CHIP_CSS = `.chip { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; border-radius: 8px; font-size: 12.5px; font-weight: 600; background: color-mix(in srgb, var(--c) 14%, transparent); border: 1px solid color-mix(in srgb, var(--c) 38%, transparent); }
.chip::before { content: ''; width: 7px; height: 7px; border-radius: 2px; background: var(--c); }`;

// ───────────────────────── panels ─────────────────────────
const panels = {};

panels.hero = (t) => wrap(t, 900, 324, 'Bavin: see what is inside every packet. A packet analyzer that unwraps traffic layer by layer, from Ethernet to HTTP, now in your browser.', `
.hero { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 26px; align-items: center; padding: 16px 8px; }
.prompt { font-size: 13px; color: var(--muted); } .prompt b { color: var(--ok); font-weight: 600; }
.type { display: block; width: 41ch; overflow: hidden; white-space: nowrap; font-size: 13.5px; color: var(--muted); border-right: 2px solid var(--accent); animation: typing 2s steps(41) 600ms both, blink 900ms step-end 2.6s infinite; }
@keyframes typing { from { width: 0; } }
.stats { display: grid; grid-template-columns: repeat(4, auto); justify-content: start; gap: 6px 26px; margin-top: 22px; }
.stats b { display: block; font-size: 24px; font-weight: 800; letter-spacing: -.03em; line-height: 1.1; } .stats span { color: var(--muted); font-size: 12px; }
.stack { display: grid; gap: 7px; padding: 14px; border-radius: 22px; }
.layer { --c: var(--slate); display: grid; grid-template-columns: 4px 1fr auto; gap: 10px; align-items: center; padding: 7px 10px 7px 0; border-radius: 10px; background: color-mix(in srgb, var(--c) 9%, var(--surface)); border: 1px solid color-mix(in srgb, var(--c) 28%, transparent); overflow: hidden; }
.layer i { align-self: stretch; background: var(--c); } .layer b { font-size: 12.5px; display: block; line-height: 1.25; } .layer small { font-size: 11px; color: var(--muted); display: block; line-height: 1.25; }
.layer em { font-style: normal; font-size: 10px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: var(--c); }
.bytes { margin-top: 2px; padding: 8px 10px; border-radius: 10px; background: var(--surface-2); font-size: 10.5px; line-height: 1.6; white-space: normal; overflow: hidden; }
.bytes s { text-decoration: none; padding: 0 1.5px; border-radius: 3px; } .b-link { color: var(--slate); } .b-net { color: var(--teal); } .b-tr { color: var(--amber); } .b-app { color: var(--purple); }
`, `<div class="hero">
  <div>
    <p class="prompt mono rise"><b>bavin</b> ~ $ open capture.pcap</p>
    <h1 class="rise" style="--i:1">See what is inside<br/><span class="grad">every packet.</span></h1>
    <p class="type mono">Read TCP/IP the way the RFCs describe it.</p>
    <div class="stats"><div class="rise" style="--i:6"><b>15</b><span>protocols</span></div><div class="rise" style="--i:7"><b>0 B</b><span>uploaded</span></div><div class="rise" style="--i:8"><b>1 click</b><span>to install</span></div><div class="rise" style="--i:9"><b>MIT</b><span>licensed</span></div></div>
  </div>
  <div class="card stack" aria-hidden="true">
    <div class="layer t-app rise" style="--i:3"><i></i><div><b>HTTP</b><small class="mono">GET / HTTP/1.1</small></div><em>App</em></div>
    <div class="layer t-transport rise" style="--i:4"><i></i><div><b>TCP</b><small class="mono">49722 → 80 [PSH, ACK]</small></div><em>Transport</em></div>
    <div class="layer t-network rise" style="--i:5"><i></i><div><b>IPv4</b><small class="mono">192.168.1.105 → 93.184.216.34</small></div><em>Network</em></div>
    <div class="layer t-link rise" style="--i:6"><i></i><div><b>Ethernet II</b><small class="mono">3c:22:fb:7a → 84:16:f9:0c</small></div><em>Link</em></div>
    <div class="bytes mono rise" style="--i:7"><s class="b-link">fb 7a 10 5e 08 00</s> <s class="b-net">45 00 00 9b 1a 30 …</s> <s class="b-tr">c2 3a 00 50 5a 10 …</s> <s class="b-app">47 45 54 20 2f …</s></div>
  </div>
</div>`);

const ROW = (k, v, good = true) => `<div class="row"><span class="k">${esc(k)}</span><span class="v">${good ? '<u>✓</u>' : '<u class="no">–</u>'}${esc(v)}</span></div>`;
panels.compare = (t) => wrap(t, 900, 520, 'Two generations of Bavin: the original Windows desktop app in C#, and the new web version that runs in any browser.', `
${CHIP_CSS}
.wrap { padding: 12px 8px 8px; } .sub { max-width: 64ch; }
.col { padding: 18px 20px 16px; } .col.new { border-color: color-mix(in srgb, var(--blue) 45%, var(--border)); box-shadow: 0 0 0 3px color-mix(in srgb, var(--blue) 10%, transparent); }
.col h3 { font-size: 17px; margin: 8px 0 12px; display: flex; align-items: center; gap: 8px; }
.row { display: grid; grid-template-columns: 82px 1fr; gap: 8px; padding: 7px 0; border-top: 1px solid var(--border); font-size: 13px; } .row .k { color: var(--muted); font-weight: 600; font-size: 12px; padding-top: 1px; }
.row .v u { text-decoration: none; display: inline-block; width: 16px; color: var(--green); font-weight: 800; } .row .v u.no { color: var(--muted); }
`, `<div class="wrap">
  <p class="eyebrow rise">Two generations</p>
  <h2 class="rise" style="--i:1">From a Windows sniffer<br/><span class="grad">to a web app.</span></h2>
  <p class="sub rise" style="--i:2">Same idea — show every packet as a readable protocol stack — rebuilt for the browser.</p>
  <div class="grid c2">
    <div class="card col rise" style="--i:3">
      <span class="tag mono">C# · WinForms · WinPcap</span>
      <h3>Desktop <span class="muted" style="font-weight:600;font-size:13px">the original</span></h3>
      ${ROW('Platform', 'Windows only')}${ROW('Install', '.NET 4 + WinPcap driver')}${ROW('Capture', 'live, straight from a network card')}${ROW('Protocols', '15, shown as stacked tabs')}${ROW('View', 'packet list, header fields, live graphs')}${ROW('Share', 'nothing to link to — install & run', false)}
    </div>
    <div class="card col new rise" style="--i:4">
      <span class="tag mono">JavaScript · PWA · no build step</span>
      <h3>Web <span class="grad" style="font-weight:800;font-size:13px">new</span></h3>
      ${ROW('Platform', 'any browser, any OS, phones too')}${ROW('Install', 'open a link — or one-click install')}${ROW('Capture', 'open .pcap files, or live via a local agent')}${ROW('Protocols', '15 + VLAN, IPv6 ext., mDNS, TLS/SNI')}${ROW('View', 'layer cards, linked hex dump, filters, overview')}${ROW('Share', 'a URL; works offline; nothing uploaded')}
    </div>
  </div>
</div>`);

const FEAT = (i, tier, glyph, title, text, visual) => `<div class="card feat t-${tier} rise" style="--i:${i}"><div class="ico">${glyph}</div><h3>${esc(title)}</h3><p class="muted">${text}</p><div class="viz">${visual}</div></div>`;
const FEAT_CSS = `.feat { padding: 18px; display: grid; gap: 6px; align-content: start; } .feat p { font-size: 12.5px; line-height: 1.5; min-height: 56px; }
.ico { width: 30px; height: 30px; border-radius: 9px; display: grid; place-items: center; font-size: 15px; font-weight: 800; color: var(--c); background: color-mix(in srgb, var(--c) 15%, transparent); margin-bottom: 4px; }
.viz { margin-top: 6px; padding: 9px 10px; border-radius: 10px; background: var(--surface-2); font-size: 11px; line-height: 1.55; min-height: 64px; }
.viz .bar { display: block; height: 8px; border-radius: 3px; margin: 3px 0; background: color-mix(in srgb, var(--c) 55%, transparent); }
.viz code { color: var(--text); }`;

panels.features1 = (t) => wrap(t, 900, 284, 'Features: stacked protocol view, a hex dump linked to fields, and Wireshark-style filters.', `${FEAT_CSS}
.wrap { padding: 8px 8px; }`, `<div class="wrap"><div class="grid c3">
${FEAT(0, 'app', '≡', 'Stacked protocol view', 'Every packet unwrapped layer by layer, with a plain-language note on what each layer is for.',
  '<span class="bar" style="width:90%;background:color-mix(in srgb,var(--purple) 55%,transparent)"></span><span class="bar" style="width:74%;background:color-mix(in srgb,var(--amber) 55%,transparent)"></span><span class="bar" style="width:58%;background:color-mix(in srgb,var(--teal) 55%,transparent)"></span><span class="bar" style="width:42%;background:color-mix(in srgb,var(--slate) 55%,transparent)"></span>')}
${FEAT(1, 'transport', '▸', 'Bytes you can point at', 'Hover a field to light up its bytes; hover a byte to see which field owns it. Click to pin.',
  '<div class="mono"><span style="color:var(--amber)">c2 3a 00 50</span> <span style="background:color-mix(in srgb,var(--amber) 35%,transparent);padding:0 2px;border-radius:3px">5a 10 c3 e1</span> <span style="color:var(--amber)">80 18</span><br/><span class="muted">Sequence number · bytes 38–41</span></div>')}
${FEAT(2, 'network', '⌕', 'Wireshark-style filters', 'tcp, dns or dhcp, !arp, ip.addr == 10.0.0.0/8 — what you learn here carries over.',
  '<div class="mono"><code>tcp &amp;&amp; port == 443</code><br/><code>ip.addr == 192.168.1.0/24</code><br/><code>info contains "GET"</code></div>')}
</div></div>`);

panels.features2 = (t) => wrap(t, 900, 284, 'Features: safe live capture through a local agent, installable and offline, and private by design.', `${FEAT_CSS}
.wrap { padding: 8px 8px; } .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--red); animation: pulse 1.2s ease-in-out infinite; margin-right: 6px; }`, `<div class="wrap"><div class="grid c3">
${FEAT(0, 'link', '●', 'Live capture, safely', 'A tiny local agent captures with tcpdump and streams to the page. Loopback only, token-protected.',
  '<div class="mono"><span class="dot"></span>Capturing on en0<br/><span class="muted">1,284 packets · 212/s</span></div>')}
${FEAT(1, 'network', '⇩', 'Install it, use it offline', 'One-click install as an app. The whole analyzer works with no network at all.',
  '<div class="mono">Install&#160;→&#160;<span style="color:var(--green)">✓</span> works offline<br/><span class="muted">opens .pcap / .pcapng files</span></div>')}
${FEAT(2, 'app', '✓', 'Private by design', 'Captures stay in your tab. A strict CSP only allows connections to your own computer.',
  '<div class="mono"><span class="muted">connect-src</span><br/>ws://127.0.0.1:*<br/><span class="muted">uploads:</span> <span style="color:var(--green)">none</span></div>')}
</div></div>`);

panels.architecture = (t) => wrap(t, 900, 318, 'How live capture works: the browser page connects over a WebSocket on 127.0.0.1 to a small local agent, which runs tcpdump on your network card.', `${CHIP_CSS}
.wrap { padding: 12px 8px 6px; }
.flow { display: grid; grid-template-columns: 1fr 74px 1fr 74px 1fr 74px 1fr; align-items: center; margin-top: 8px; }
.node { text-align: center; padding: 14px 8px; min-height: 92px; display: grid; align-content: center; gap: 3px; } .node b { font-size: 14px; } .node small { color: var(--muted); font-size: 11.5px; line-height: 1.35; }
.link { position: relative; height: 2px; background: var(--border); margin: 0 4px; } .link::after { content: ''; position: absolute; right: -1px; top: -4px; border: 5px solid transparent; border-left: 7px solid var(--muted); border-right: 0; }
.link i { position: absolute; top: -3px; left: 0; width: 8px; height: 8px; border-radius: 50%; background: var(--blue); --dist: 56px; animation: flow 1.6s linear infinite; animation-delay: calc(var(--d, 0) * 0.5s); }
.lbl { text-align: center; font-size: 11px; color: var(--muted); margin-top: 8px; font-weight: 600; }
.notes { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 16px; } .notes div { font-size: 12px; color: var(--muted); padding: 10px 12px; border-radius: 12px; background: var(--surface); border: 1px solid var(--border); } .notes b { color: var(--text); display: block; font-size: 12.5px; margin-bottom: 1px; }
`, `<div class="wrap">
  <p class="eyebrow rise">Live capture</p>
  <h2 class="rise" style="--i:1">A browser can’t sniff.<br/><span class="grad">So a tiny helper does.</span></h2>
  <div class="flow">
    <div class="card node t-app rise" style="--i:2"><b>Bavin page</b><small>online, installed,<br/>or local</small></div>
    <div><div class="link"><i style="--d:0"></i><i style="--d:1"></i><i style="--d:2"></i></div><div class="lbl mono">ws://</div></div>
    <div class="card node t-transport rise" style="--i:3"><b>Bavin agent</b><small>Node · 127.0.0.1 only<br/>one small file</small></div>
    <div><div class="link"><i style="--d:0.4"></i><i style="--d:1.4"></i></div><div class="lbl mono">pcap</div></div>
    <div class="card node t-network rise" style="--i:4"><b>tcpdump</b><small>or Wireshark’s<br/>dumpcap</small></div>
    <div><div class="link"><i style="--d:0.8"></i><i style="--d:1.8"></i></div><div class="lbl mono">sudo</div></div>
    <div class="card node t-link rise" style="--i:5"><b>Network card</b><small>Wi-Fi · Ethernet<br/>loopback</small></div>
  </div>
  <div class="notes rise" style="--i:6">
    <div><b>Private token</b>Passed in the URL fragment — never sent to any server.</div>
    <div><b>Host &amp; Origin checks</b>Other sites and DNS-rebinding tricks are refused.</div>
    <div><b>Pair a hosted copy</b><span class="mono">--origin https://you.github.io/bavin/</span></div>
  </div>
</div>`);

const GROUPS = [
  ['Link', 'link', [['Ethernet', 1], ['802.1Q VLAN', 0]]],
  ['Network', 'network', [['IPv4', 1], ['IPv6', 1], ['IPv6 ext. headers', 0], ['ARP', 1], ['ICMP', 1], ['ICMPv6', 1], ['IGMP', 1]]],
  ['Transport', 'transport', [['TCP', 1], ['UDP', 1]]],
  ['Application', 'app', [['HTTP', 1], ['DNS', 1], ['DHCP', 1], ['NBNS', 1], ['LLMNR', 1], ['SSDP', 1], ['mDNS', 0], ['TLS · SNI', 0]]],
];
panels.protocols = (t) => wrap(t, 900, 386, 'Supported protocols: Ethernet, 802.1Q VLAN, IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP, TCP, UDP, HTTP, DNS, DHCP, NBNS, LLMNR, SSDP, mDNS and TLS.', `${CHIP_CSS}
.wrap { padding: 12px 8px 6px; } .tiers { display: grid; gap: 10px; margin-top: 12px; }
.tier { display: grid; grid-template-columns: 96px 1fr; gap: 10px; align-items: center; padding: 10px 14px; } .tier > b { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--c); }
.chips { display: flex; flex-wrap: wrap; gap: 6px; } .chip.new { border-style: dashed; } .legend { font-size: 12px; color: var(--muted); margin-top: 10px; }
.legend span { display: inline-block; width: 22px; height: 11px; border-radius: 4px; vertical-align: -1px; margin-right: 5px; border: 1px solid var(--muted); } .legend .d { border-style: dashed; margin-left: 14px; }
`, `<div class="wrap">
  <p class="eyebrow rise">Protocols</p>
  <h2 class="rise" style="--i:1">Fifteen from the original.<br/><span class="grad">A few more in the web version.</span></h2>
  <div class="tiers">
  ${GROUPS.map(([label, tier, items], i) => `<div class="card tier t-${tier} rise" style="--i:${2 + i}"><b>${label}</b><div class="chips">${items.map(([n, orig]) => `<span class="chip t-${tier}${orig ? '' : ' new'}">${esc(n)}</span>`).join('')}</div></div>`).join('')}
  </div>
  <p class="legend rise" style="--i:7"><span></span>in the original desktop app <span class="d"></span>added in the web version</p>
</div>`);

for (const [name, make] of Object.entries(panels)) {
  for (const mode of ['light', 'dark']) {
    const svg = make(THEMES[mode]);
    // SVG is strict XML: only the five predefined entities (and numeric ones) exist. Catch &nbsp; & co. at build time.
    const bad = svg.match(/&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-f]+;)[a-z]+;/gi);
    if (bad) throw new Error(`${name}-${mode}: HTML-only entity in SVG: ${[...new Set(bad)].join(' ')} — use a numeric reference like &#160;`);
    writeFileSync(join(out, `${name}-${mode}.svg`), svg);
    console.log(`${name}-${mode}.svg`.padEnd(26), (svg.length / 1024).toFixed(1) + ' KB');
  }
}
