#!/usr/bin/env node
// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin capture agent — gives the web UI live capture.
 *
 * Browsers cannot open a network interface, so this small program runs on YOUR computer, captures with
 * tcpdump (or Wireshark's dumpcap), serves the Bavin web UI, and streams packets to it over a WebSocket.
 *
 *   sudo node web/agent/bavin-agent.js            # then open the printed URL
 *   node web/agent/bavin-agent.js --replay x.pcap # no privileges: replays a capture file as if it were live
 *   sudo node bavin-agent.js --origin https://you.github.io/bavin/   # pair with a hosted copy of the web UI
 *
 * Security model (read before changing anything):
 *   - listens on 127.0.0.1 only, never on a public interface
 *   - the WebSocket needs a random token that is printed once at startup
 *   - Host and Origin are checked, so other websites (and DNS-rebinding tricks) cannot talk to it.
 *     Only this agent's own page is trusted, plus any site you explicitly pass with --origin
 *   - the capture command is spawned without a shell; the interface must be one the tool listed;
 *     the capture filter is a single validated argument
 *   - static files are served only from web/ (not agent/ or test/)
 * No dependencies; Node 18+.
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');

const VERSION = 1;
const WEB_ROOT = path.resolve(__dirname, '..');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.pcap': 'application/vnd.tcpdump.pcap' };

// ───────────────────────────── CLI ─────────────────────────────
function parseArgs(argv) {
  const o = { port: 8765, replay: null, speed: 1, loop: false, open: false, help: false, origins: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) fail('Missing value for ' + a); return argv[++i]; };
    if (a === '--port' || a === '-p') o.port = Number(val());
    else if (a === '--replay') o.replay = val();
    else if (a === '--speed') o.speed = Number(val());
    else if (a === '--loop') o.loop = true;
    else if (a === '--open') o.open = true;
    else if (a === '--origin') o.origins.push(parseOrigin(val()));
    else if (a === '--help' || a === '-h') o.help = true;
    else fail('Unknown option ' + a + ' (try --help)');
  }
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) fail('--port must be 0-65535');
  if (!(o.speed > 0)) fail('--speed must be positive');
  return o;
}
// A hosted copy of the UI that may pair with this agent. Returns { origin, url } (origin = what browsers send in
// the Origin header; url = the page address to print). Only https sites or local dev hosts are accepted.
function parseOrigin(text) {
  let u;
  try { u = new URL(text); } catch (_) { fail('--origin needs a full URL such as https://you.github.io/bavin/'); }
  const local = u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
  if (u.protocol !== 'https:' && !local) fail('--origin must be https:// (or http://localhost for development), got ' + u.protocol + '//');
  if (u.username || u.password) fail('--origin must not contain credentials');
  return { origin: u.origin.toLowerCase(), url: u.origin + (u.pathname === '/' ? '/' : u.pathname) };
}
function fail(msg) { console.error('bavin-agent: ' + msg); process.exit(2); }
const HELP = `Bavin capture agent v${VERSION}

Usage: node bavin-agent.js [options]
  --port N        port to listen on (default 8765, 0 = pick a free one)
  --replay FILE   stream a .pcap/.pcapng file as if it were live (needs no privileges)
  --speed X       replay speed multiplier (default 1)
  --loop          repeat the replay forever
  --origin URL    also trust this hosted copy of the web UI (repeatable), e.g. https://you.github.io/bavin/
  --open          open the page in your browser
  -h, --help      this text

Live capture needs privileges:
  macOS   sudo node bavin-agent.js      (or install Wireshark's ChmodBPF helper and run without sudo)
  Linux   sudo node bavin-agent.js      (or: sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump))
  Windows install Wireshark (provides dumpcap + Npcap) and run from an Administrator terminal
`;

// ───────────────────────────── capture tool discovery ─────────────────────────────
function findTool() {
  const candidates = process.platform === 'win32'
    ? ['dumpcap.exe', 'C:\\Program Files\\Wireshark\\dumpcap.exe', 'tcpdump.exe']
    : ['tcpdump', '/usr/sbin/tcpdump', '/usr/bin/tcpdump', 'dumpcap', '/usr/local/bin/dumpcap', '/Applications/Wireshark.app/Contents/MacOS/dumpcap'];
  return new Promise((resolve) => {
    let i = 0;
    const next = () => {
      if (i >= candidates.length) return resolve(null);
      const bin = candidates[i++];
      execFile(bin, ['-h'], { timeout: 4000, windowsHide: true }, (err, so, se) => {
        const out = String(so || '') + String(se || '');
        if (err && err.code === 'ENOENT') return next();
        if (!/tcpdump|dumpcap|libpcap|Usage/i.test(out)) return next();
        resolve({ bin, kind: /dumpcap/i.test(path.basename(bin)) ? 'dumpcap' : 'tcpdump' });
      });
    };
    next();
  });
}

function listInterfaces(tool) {
  return new Promise((resolve, reject) => {
    execFile(tool.bin, ['-D'], { timeout: 6000, windowsHide: true }, (err, so, se) => {
      const text = String(so || '') + (err ? String(se || '') : '');
      const out = [];
      for (const line of text.split(/\r?\n/)) {
        const m = /^(\d+)\.\s*(\S+)\s*(.*)$/.exec(line.trim());
        if (m) out.push({ id: m[2], index: m[1], desc: m[3].replace(/^[([]|[)\]]$/g, '') });
      }
      if (!out.length && err) return reject(new Error('Could not list interfaces: ' + (String(se).trim() || err.message)));
      resolve(out);
    });
  });
}

// BPF filter text: allow only what real filters use, one argv element, never starting with "-".
const FILTER_OK = /^[\w .:/\-[\]()&|!<>=,*%]*$/; // plain space only: no tabs or newlines
function validateFilter(f) {
  if (f == null || f === '') return '';
  if (typeof f !== 'string' || f.length > 300 || !FILTER_OK.test(f)) throw new Error('That capture filter contains characters that are not allowed.');
  const t = f.trim();
  if (t.startsWith('-')) throw new Error('A capture filter cannot start with "-".');
  return t;
}

// ───────────────────────────── minimal WebSocket (RFC 6455) ─────────────────────────────
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function frame(op, payload) {
  const n = payload.length;
  let head;
  if (n < 126) head = Buffer.from([0x80 | op, n]);
  else if (n < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | op; head[1] = 126; head.writeUInt16BE(n, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | op; head[1] = 127; head.writeBigUInt64BE(BigInt(n), 2); }
  return Buffer.concat([head, payload]);
}
class WsConn {
  constructor(socket, onMessage, onClose) {
    this.socket = socket; this.buf = Buffer.alloc(0); this.closed = false;
    socket.on('data', (d) => this.onData(d));
    // HTTP-server sockets are half-open: a browser's FIN arrives as 'end' and 'close' never follows on its own.
    socket.on('end', () => { this.finish(); socket.destroy(); });
    socket.on('close', () => this.finish());
    socket.on('error', () => this.finish());
    this.onMessage = onMessage; this.onClose = onClose;
  }
  finish() { if (!this.closed) { this.closed = true; this.onClose(); } }
  sendJson(obj) { return this.write(frame(0x1, Buffer.from(JSON.stringify(obj)))); }
  sendBinary(buf) { return this.write(frame(0x2, buf)); }
  write(b) { return !this.closed && this.socket.write(b); }
  close(code, reason) {
    if (this.closed) return;
    const p = Buffer.alloc(2 + Buffer.byteLength(reason || ''));
    p.writeUInt16BE(code || 1000, 0); p.write(reason || '', 2);
    this.socket.end(frame(0x8, p));
  }
  onData(d) {
    this.buf = Buffer.concat([this.buf, d]);
    for (;;) {
      const b = this.buf;
      if (b.length < 2) return;
      const fin = (b[0] & 0x80) !== 0, op = b[0] & 0x0f, masked = (b[1] & 0x80) !== 0;
      let len = b[1] & 0x7f, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; const big = b.readBigUInt64BE(2); if (big > 1048576n) return this.close(1009, 'too big'); len = Number(big); off = 10; }
      if (len > 1048576) return this.close(1009, 'too big');
      if (!masked) return this.close(1002, 'client frames must be masked');
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4);
      const data = Buffer.from(b.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
      this.buf = b.subarray(off + 4 + len);
      if (!fin || op === 0) return this.close(1003, 'fragmented messages are not supported');
      if (op === 0x8) { this.close(1000); return; }
      if (op === 0x9) this.write(frame(0xa, data));
      else if (op === 0x1) this.onMessage(data.toString('utf8'));
    }
  }
}

// ───────────────────────────── replay source ─────────────────────────────
function loadReplay(file) {
  let pcap;
  try { require('../js/util.js'); pcap = require('../js/pcap.js'); } catch (_) { fail('--replay needs the web/js files next to the agent (run it from a checkout of the repository).'); }
  const raw = fs.readFileSync(file);
  const parsed = pcap.parse(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
  const lt = parsed.packets[0] ? parsed.packets[0].linktype : 1;
  return { packets: parsed.packets, linktype: lt, header: Buffer.from(pcap.write([], lt)), pcap };
}

// ───────────────────────────── server ─────────────────────────────
async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { process.stdout.write(HELP); return; }
  const token = crypto.randomBytes(18).toString('base64url');
  const tokenBuf = Buffer.from(token);
  const replay = opts.replay ? loadReplay(opts.replay) : null;
  const tool = replay ? null : await findTool();
  const trustedOrigins = new Set(opts.origins.map((o) => o.origin));
  let allowedHosts = new Set();
  let client = null; // one browser at a time
  const hostOk = (h) => allowedHosts.has(String(h || '').toLowerCase());

  const server = http.createServer((req, res) => {
    const sec = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' };
    if (!hostOk(req.headers.host)) { res.writeHead(403, sec); return res.end('Forbidden host'); }
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, sec); return res.end('Method not allowed'); }
    let rel;
    try { rel = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch (_) { res.writeHead(400, sec); return res.end('Bad request'); }
    if (rel.endsWith('/')) rel += 'index.html';
    const file = path.resolve(WEB_ROOT, '.' + path.sep + rel);
    const within = path.relative(WEB_ROOT, file);
    const top = within.split(path.sep)[0];
    if (within.startsWith('..') || path.isAbsolute(within) || top === 'agent' || top === 'test' || within.split(path.sep).some((s) => s.startsWith('.')) || rel.includes('\0')) {
      res.writeHead(404, sec); return res.end('Not found');
    }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404, sec); return res.end('Not found'); }
      res.writeHead(200, Object.assign({ 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' }, sec));
      res.end(req.method === 'HEAD' ? undefined : data);
    });
  });

  server.on('upgrade', (req, socket) => {
    const reject = (code, why) => { socket.end('HTTP/1.1 ' + code + ' ' + why + '\r\nConnection: close\r\n\r\n'); };
    let u;
    try { u = new URL(req.url, 'http://x'); } catch (_) { return reject(400, 'Bad Request'); }
    const origin = req.headers.origin;
    const given = Buffer.from(u.searchParams.get('token') || '');
    if (u.pathname !== '/ws') return reject(404, 'Not Found');
    if (!hostOk(req.headers.host)) return reject(403, 'Forbidden');
    const o = String(origin || '').toLowerCase();
    if (!origin || (o !== 'http://' + String(req.headers.host).toLowerCase() && !trustedOrigins.has(o))) return reject(403, 'Forbidden');
    if (given.length !== tokenBuf.length || !crypto.timingSafeEqual(given, tokenBuf)) return reject(401, 'Unauthorized');
    if (String(req.headers.upgrade).toLowerCase() !== 'websocket' || !req.headers['sec-websocket-key']) return reject(400, 'Bad Request');
    if (client) return reject(409, 'Conflict'); // another tab is already connected
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + WS_GUID).digest('base64');
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
    handleClient(socket);
  });

  function handleClient(socket) {
    let capture = null; // { stop() }
    let ifaces = null;
    const ws = new WsConn(socket, onMessage, () => { stopCapture('client left'); client = null; });
    client = ws;
    ws.sendJson({ type: 'hello', version: VERSION, tool: replay ? 'replay' : tool ? tool.kind : null, platform: process.platform });

    function stopCapture(why) { if (capture) { const c = capture; capture = null; c.stop(why); } }

    async function onMessage(text) {
      let m;
      try { m = JSON.parse(text); } catch (_) { return ws.sendJson({ type: 'error', message: 'Bad message' }); }
      try {
        if (m.type === 'list') {
          if (replay) ifaces = [{ id: 'replay', index: '1', desc: path.basename(opts.replay) + ' (replay)' }];
          else if (!tool) return ws.sendJson({ type: 'error', message: 'No capture tool found. Install tcpdump (macOS/Linux) or Wireshark (Windows) — or start the agent with --replay FILE.' });
          else ifaces = await listInterfaces(tool);
          ws.sendJson({ type: 'interfaces', interfaces: ifaces });
        } else if (m.type === 'start') {
          if (capture) return ws.sendJson({ type: 'error', message: 'A capture is already running.' });
          if (!ifaces) return ws.sendJson({ type: 'error', message: 'Ask for the interface list first.' });
          const chosen = ifaces.find((i) => i.id === m.iface || i.index === String(m.iface));
          if (!chosen) return ws.sendJson({ type: 'error', message: 'Unknown interface.' });
          const filter = validateFilter(m.filter);
          const done = () => { capture = null; };
          // 'started' must reach the browser before any capture bytes: it creates its pcap parser on this message.
          ws.sendJson({ type: 'started', iface: chosen.id, filter });
          capture = replay ? startReplay(ws, replay, opts, done) : startTool(ws, tool, chosen, filter, done);
        } else if (m.type === 'stop') stopCapture('stopped');
      } catch (e) { ws.sendJson({ type: 'error', message: e.message }); }
    }
  }

  function startTool(ws, tool, iface, filter, done) {
    const args = tool.kind === 'dumpcap'
      ? ['-q', '-P', '-i', iface.id, '-w', '-'].concat(filter ? ['-f', filter] : [])
      : ['-i', iface.id, '-U', '-s', '0', '-n', '-w', '-'].concat(filter ? ['--', filter] : []);
    const child = spawn(tool.bin, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); // no shell
    let errTail = '', sent = 0, stopping = false;
    child.stderr.on('data', (d) => { errTail = (errTail + d).slice(-1500); });
    child.stdout.on('data', (d) => {
      sent += d.length;
      if (!ws.sendBinary(d)) { child.stdout.pause(); ws.socket.once('drain', () => child.stdout.resume()); }
    });
    child.on('error', (e) => { stopping = true; done(); ws.sendJson({ type: 'error', message: 'Could not start ' + tool.bin + ': ' + e.message }); ws.sendJson({ type: 'stopped', reason: 'error' }); });
    child.on('close', (code) => {
      done();
      if (stopping) return ws.sendJson({ type: 'stopped', reason: 'stopped' });
      const denied = /permission|denied|not permitted|bpf|access/i.test(errTail);
      let message = errTail.split('\n').filter((l) => l && !/^(tcpdump: )?(verbose output|listening on|\d+ packets)/i.test(l)).join(' ').trim();
      if (denied) message += ' — capturing needs elevated privileges. Restart the agent with sudo (macOS/Linux) or from an Administrator terminal (Windows).';
      if (code !== 0 || sent === 0) ws.sendJson({ type: 'error', message: message || 'The capture tool exited with code ' + code + '.' });
      ws.sendJson({ type: 'stopped', reason: code === 0 ? 'ended' : 'error' });
    });
    return { stop: () => { stopping = true; child.kill('SIGINT'); setTimeout(() => child.kill('SIGKILL'), 1500).unref(); } };
  }

  // Replays a file on a virtual clock: every packet that is "due" goes out together in one frame (so dense
  // captures are not limited by timer resolution), gaps are clamped to 2 s, and a slow reader pauses us.
  function startReplay(ws, rp, o, done) {
    let timer = null, idx = 0, dead = false, startAt = Date.now(), due = 0;
    const gap = (p, next) => Math.max(0, Math.min(2, next.ts - p.ts)) * 1000 / o.speed;
    ws.sendBinary(rp.header);
    const step = () => {
      timer = null;
      if (dead) return;
      const elapsed = Date.now() - startAt;
      const batch = [];
      while (idx < rp.packets.length && due <= elapsed && batch.length < 1000) {
        const p = rp.packets[idx++];
        batch.push(p);
        const next = rp.packets[idx];
        if (next) due += gap(p, next);
      }
      let wrote = true;
      if (batch.length) wrote = ws.sendBinary(Buffer.from(rp.pcap.write(batch, rp.linktype)).subarray(24)); // header stripped
      if (idx >= rp.packets.length) {
        if (o.loop) { idx = 0; due = 0; startAt = Date.now() + 500; } else { done(); ws.sendJson({ type: 'stopped', reason: 'ended' }); return; }
      }
      const resume = () => { if (!dead && !timer) timer = batch.length >= 1000 ? setImmediate(step) : setTimeout(step, Math.max(1, due - (Date.now() - startAt))); };
      if (!wrote) ws.socket.once('drain', resume); else resume();
    };
    timer = setTimeout(step, 100);
    return { stop: () => { dead = true; clearTimeout(timer); ws.sendJson({ type: 'stopped', reason: 'stopped' }); } };
  }

  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(opts.port, '127.0.0.1', resolve); });
  const port = server.address().port;
  allowedHosts = new Set(['127.0.0.1:' + port, 'localhost:' + port]);
  const url = 'http://127.0.0.1:' + port + '/#token=' + token;
  console.log('Bavin capture agent v' + VERSION);
  console.log(replay ? '  mode:    replay of ' + opts.replay + ' (' + replay.packets.length + ' packets)' : tool ? '  capture: ' + tool.kind + ' (' + tool.bin + ')' + (process.getuid && process.getuid() !== 0 ? '   ⚠ not running as root — capture will likely be denied' : '') : '  capture: no tool found (install tcpdump or Wireshark, or use --replay FILE)');
  console.log('  listens: 127.0.0.1:' + port + ' only');
  console.log('\n  Open this URL (it contains your private token):\n\n    ' + url + '\n');
  for (const o of opts.origins) console.log('  Or use the hosted copy at ' + o.url + ' with:\n\n    ' + o.url + '#agent=' + port + '&token=' + token + '\n');
  if (opts.origins.length) console.log('  (The token stays in the URL fragment, which browsers never send over the network.)\n');
  if (opts.open) {
    const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
    spawn(cmd, process.platform === 'win32' ? ['/c', 'start', '', url] : [url], { stdio: 'ignore', detached: true }).on('error', () => {}).unref();
  }
  const bye = () => { if (client) client.close(1001, 'agent exiting'); server.close(); setTimeout(() => process.exit(0), 200).unref(); };
  process.on('SIGINT', bye); process.on('SIGTERM', bye);
}

if (require.main === module) main().catch((e) => { console.error('bavin-agent: ' + e.message); process.exit(1); });
module.exports = { validateFilter };
