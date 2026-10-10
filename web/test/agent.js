// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
// Run with: node web/test/agent.js
// Starts the capture agent in --replay mode (no privileges needed) and exercises its HTTP/WebSocket surface.
'use strict';
const { spawn } = require('child_process');
let crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
require('../js/util.js');
const pcap = require('../js/pcap.js');
const samples = require('../js/samples.js');

let failed = 0;
const ok = (c, m) => { console.log((c ? '  ✓ ' : '  ✗ ') + m); if (!c) failed++; };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bavin-agent-'));
const file = path.join(tmp, 'lan.pcap');
const raws = samples.LIST[1].make();
fs.writeFileSync(file, pcap.write(raws, 1));

function get(port, urlPath, headers) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: urlPath, headers: Object.assign({ Host: '127.0.0.1:' + port }, headers) }, (res) => {
      const chunks = []; res.on('data', (d) => chunks.push(d)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject); req.end();
  });
}
function upgrade(port, query, headers) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/ws' + query, headers: Object.assign({ Host: '127.0.0.1:' + port, Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==' }, headers) });
    req.on('response', (res) => resolve(res.statusCode));
    req.on('upgrade', (res, socket) => { socket.destroy(); resolve(res.statusCode); });
    req.on('error', () => resolve('error'));
    req.end();
  });
}


// Minimal RFC 6455 client (masked frames out, unmasked frames in) — independent of the agent's own framing code.
function rawWs(port, token, origin) {
  const crypto = require('crypto');
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const req = http.request({ host: '127.0.0.1', port, path: '/ws?token=' + token, headers: { Host: '127.0.0.1:' + port, Origin: origin, Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key } });
    req.on('response', (res) => reject(new Error('handshake refused: ' + res.statusCode)));
    req.on('upgrade', (res, socket, head) => {
      const want = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      if (res.headers['sec-websocket-accept'] !== want) return reject(new Error('bad Sec-WebSocket-Accept'));
      // Messages can arrive in the same TCP chunk as the upgrade response, before the caller has set onmessage — queue them.
      const early = [];
      let handler = null;
      const c = { buf: Buffer.alloc(0) };
      Object.defineProperty(c, 'onmessage', { set(fn) { handler = fn; while (early.length) fn(...early.shift()); }, get() { return handler; } });
      const feed = (d) => {
        c.buf = Buffer.concat([c.buf, d]);
        for (;;) {
          const b = c.buf; if (b.length < 2) return;
          const op = b[0] & 15; let len = b[1] & 127, off = 2;
          if (b[1] & 128) throw new Error('server frames must not be masked');
          if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
          else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
          if (b.length < off + len) return;
          const payload = b.subarray(off, off + len); c.buf = b.subarray(off + len);
          if (op === 1 || op === 2) { const a = [Buffer.from(payload), op === 1]; if (handler) handler(...a); else early.push(a); }
        }
      };
      socket.on('data', feed); if (head.length) feed(head);
      c.sendJson = (obj) => {
        const p = Buffer.from(JSON.stringify(obj)), m = crypto.randomBytes(4);
        const h = p.length < 126 ? Buffer.from([0x81, 0x80 | p.length]) : Buffer.from([0x81, 0x80 | 126, p.length >> 8, p.length & 255]);
        socket.write(Buffer.concat([h, m, Buffer.from(p.map((x, i) => x ^ m[i & 3]))]));
      };
      c.socket = socket;
      c.close = () => socket.destroy();
      resolve(c);
    });
    req.on('error', reject); req.end();
  });
}

(async () => {
  const child = spawn(process.execPath, [path.join(__dirname, '../agent/bavin-agent.js'), '--port', '0', '--replay', file, '--speed', '1000'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  const ready = new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => { out += d; const m = /127\.0\.0\.1:(\d+)\/#token=([\w-]+)/.exec(out); if (m) resolve({ port: +m[1], token: m[2] }); });
    child.on('exit', (c) => reject(new Error('agent exited early: ' + c + '\n' + out)));
  });
  const { port, token } = await ready;
  try {
    console.log('# static files');
    const idx = await get(port, '/');
    ok(idx.status === 200 && /<title>Bavin Web/.test(idx.body.toString()), 'serves index.html');
    ok(idx.headers['x-content-type-options'] === 'nosniff' && idx.headers['cache-control'] === 'no-store', 'sends security headers');
    ok((await get(port, '/js/app.js')).status === 200, 'serves js/app.js');
    for (const p of ['/agent/bavin-agent.js', '/test/run.js', '/..%2fREADME.md', '/%00', '/.git/config']) {
      const r = await get(port, p);
      ok(r.status === 404 || r.status === 400, 'refuses ' + p + ' → ' + r.status);
    }
    // These collapse to /README.md (= web/README.md, which is legitimately served); the repo-root README must never leak.
    for (const p of ['/../README.md', '/%2e%2e/README.md', '/js/../../README.md', '/../../etc/passwd', '/..\\..\\README.md']) {
      const r = await get(port, p);
      ok(!/Realtime StackedUI Packet Analyzer for Students/.test(r.body.toString()) && !/root:/.test(r.body.toString()), 'cannot escape web/ via ' + p + ' (status ' + r.status + ')');
    }
    ok((await get(port, '/', { Host: 'evil.example:' + port })).status === 403, 'wrong Host header (DNS rebinding) → 403');
    ok((await get(port, '/', { Host: 'localhost:' + port })).status === 200, 'localhost Host is accepted');

    console.log('# websocket handshake');
    const origin = 'http://127.0.0.1:' + port;
    ok(await upgrade(port, '?token=' + token, { Origin: origin }) === 101, 'valid token + origin → 101');
    await new Promise((r) => setTimeout(r, 100));
    ok(await upgrade(port, '', { Origin: origin }) === 401, 'missing token → 401');
    ok(await upgrade(port, '?token=nope', { Origin: origin }) === 401, 'wrong token → 401');
    ok(await upgrade(port, '?token=' + token.slice(0, -1) + 'x', { Origin: origin }) === 401, 'almost-right token → 401');
    ok(await upgrade(port, '?token=' + token, { Origin: 'https://evil.example' }) === 403, 'foreign Origin (another website) → 403');
    ok(await upgrade(port, '?token=' + token, {}) === 403, 'no Origin header → 403');
    ok(await upgrade(port, '?token=' + token, { Origin: origin, Host: 'evil.example:' + port }) === 403, 'wrong Host on upgrade → 403');

    console.log('# streaming round-trip');
    const ws = await rawWs(port, token, origin);
    const texts = [];
    const got = [];
    let wake;
    let sp = null; // like the browser: the parser only exists once 'started' has arrived
    let binaryBeforeStarted = false;
    ws.onmessage = (data, isText) => {
      if (isText) { const m = JSON.parse(data.toString()); texts.push(m); if (m.type === 'started') sp = new pcap.StreamParser(); }
      else {
        if (!sp) binaryBeforeStarted = true;
        else { // feed in awkward 7-byte slices to prove chunk boundaries do not matter
          const u = new Uint8Array(data);
          for (let i = 0; i < u.length; i += 7) got.push(...sp.push(u.subarray(i, i + 7)));
        }
      }
      if (wake) wake();
    };
    const until = (cond, ms = 5000) => new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timeout waiting for condition; texts=' + JSON.stringify(texts))), ms);
      wake = () => { if (cond()) { clearTimeout(t); resolve(); } };
      wake();
    });
    await until(() => texts.some((t) => t.type === 'hello'));
    ok(texts[0].tool === 'replay' && texts[0].version === 1, 'hello announces replay mode');
    ws.sendJson(({ type: 'start', iface: 'replay' }));
    await until(() => texts.some((t) => t.type === 'error'));
    ok(/interface list first/.test(texts.find((t) => t.type === 'error').message), 'start before list is refused');
    ws.sendJson(({ type: 'list' }));
    await until(() => texts.some((t) => t.type === 'interfaces'));
    ok(texts.find((t) => t.type === 'interfaces').interfaces[0].id === 'replay', 'lists the replay "interface"');
    ws.sendJson(({ type: 'start', iface: 'en0; rm -rf /' }));
    await until(() => texts.filter((t) => t.type === 'error').length === 2);
    ok(/Unknown interface/.test(texts.filter((t) => t.type === 'error')[1].message), 'unknown interface name is refused');
    ws.sendJson(({ type: 'start', iface: 'replay' }));
    await until(() => got.length === raws.length && texts.some((t) => t.type === 'stopped'));
    ok(!binaryBeforeStarted, "no capture bytes arrive before the 'started' message");
    ok(got.length === raws.length, 'received all ' + raws.length + ' packets through a 7-byte-chunk parser');
    ok(got.every((p, i) => Buffer.compare(Buffer.from(p.data), Buffer.from(raws[i].data)) === 0 && Math.abs(p.ts - raws[i].ts) < 1e-5), 'every packet is byte-identical, timestamps preserved');
    ok(texts.some((t) => t.type === 'stopped' && t.reason === 'ended'), 'agent reports the replay ended');
    // a finished capture must not block the next one
    const n0 = got.length;
    let sp2 = null; ws.onmessage = (data, isText) => { if (isText) { if (JSON.parse(data.toString()).type === 'started') sp2 = new pcap.StreamParser(); } else if (sp2) got.push(...sp2.push(new Uint8Array(data))); if (wake) wake(); };
    ws.sendJson(({ type: 'start', iface: 'replay' }));
    await until(() => got.length >= n0 + 3);
    ws.sendJson(({ type: 'stop' }));
    await new Promise((r) => setTimeout(r, 150));
    ok(got.length >= n0 + 3, 'a second capture can start after the first finished, and be stopped');
    ws.close();

    console.log('# WebSocket protocol violations');
    {
      const frameOut = (op, payload, { masked = true, fin = true } = {}) => {
        const m = crypto.randomBytes(4); const n = payload.length;
        const head = n < 126 ? Buffer.from([(fin ? 0x80 : 0) | op, (masked ? 0x80 : 0) | n]) : Buffer.from([(fin ? 0x80 : 0) | op, (masked ? 0x80 : 0) | 126, n >> 8, n & 255]);
        return masked ? Buffer.concat([head, m, Buffer.from(payload.map((x, i) => x ^ m[i & 3]))]) : Buffer.concat([head, payload]);
      };
      const closedWith = async (label, bytes, expectCode) => {
        await new Promise((r) => setTimeout(r, 150));
        const c = await rawWs(port, token, origin);
        const got = []; let ended = false;
        c.socket.on('data', (d) => got.push(d)); c.socket.on('close', () => { ended = true; });
        c.socket.write(bytes);
        await new Promise((r) => setTimeout(r, 300));
        // The server's first frame is its hello; walk the frames to find the close frame (opcode 8) and its status code.
        const all = Buffer.concat(got); let code = null;
        for (let o = 0; o + 2 <= all.length;) {
          const op = all[o] & 15; let len = all[o + 1] & 127, hdr = 2;
          if (len === 126) { len = all.readUInt16BE(o + 2); hdr = 4; } else if (len === 127) { len = Number(all.readBigUInt64BE(o + 2)); hdr = 10; }
          if (op === 8 && len >= 2) { code = all.readUInt16BE(o + hdr); break; }
          o += hdr + len;
        }
        ok(ended && code === expectCode, label + ' → connection closed with code ' + code);
        c.socket.destroy();
      };
      crypto = require('crypto');
      await closedWith('an unmasked client frame', frameOut(1, Buffer.from('{"type":"list"}'), { masked: false }), 1002);
      await closedWith('a ping with a 200-byte payload (limit is 125)', frameOut(9, Buffer.alloc(200, 1)), 1002);
      await closedWith('a fragmented control frame', frameOut(9, Buffer.from('x'), { fin: false }), 1002);
      await closedWith('an unknown opcode (0x3)', frameOut(3, Buffer.from('x')), 1002);
      await closedWith('a fragmented text message', frameOut(1, Buffer.from('{"type":"list"}'), { fin: false }), 1003);
      await closedWith('a 2 MB frame header', Buffer.concat([Buffer.from([0x81, 0xff]), Buffer.alloc(8, 0).fill(0, 0, 8), Buffer.alloc(4)]).fill(0x00, 2, 10) && (() => { const h = Buffer.alloc(14); h[0] = 0x81; h[1] = 0xff; h.writeBigUInt64BE(2097152n, 2); return h; })(), 1009);
      // after the agent has closed on a violation it must not keep buffering what the peer keeps sending
      await new Promise((r) => setTimeout(r, 150));
      const c = await rawWs(port, token, origin); c.socket.write(frameOut(3, Buffer.from('x')));
      await new Promise((r) => setTimeout(r, 100));
      for (let i = 0; i < 50; i++) c.socket.write(Buffer.alloc(20000, 7));
      await new Promise((r) => setTimeout(r, 200));
      ok(true, 'the agent survives a peer that keeps sending after being closed (no crash)');
      c.socket.destroy();
      await new Promise((r) => setTimeout(r, 150));
      const alive = await rawWs(port, token, origin); alive.close();
      ok(true, 'and still accepts the next legitimate connection');
    }

    console.log('# single client');
    await new Promise((r) => setTimeout(r, 200));
    const a = await rawWs(port, token, origin);
    ok(await upgrade(port, '?token=' + token, { Origin: origin }) === 409, 'a second concurrent client is refused (409)');
    a.close();


    console.log('# standalone copy (curl -O) must not serve the folder it lives in');
    {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bavin-standalone-'));
      const sub = path.join(dir, 'Downloads'); fs.mkdirSync(sub);
      fs.writeFileSync(path.join(dir, 'private-notes.txt'), 'SECRET-NOTES');
      fs.writeFileSync(path.join(sub, 'bavin-agent.js'), fs.readFileSync(path.join(__dirname, '../agent/bavin-agent.js')));
      const sa = spawn(process.execPath, [path.join(sub, 'bavin-agent.js'), '--port', '0', '--origin', 'https://demo.example.github.io/bavin/'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let so = '';
      const sp2 = await new Promise((resolve, reject) => { sa.stdout.on('data', (d) => { so += d; const m = /#agent=(\d+)&token=([\w-]+)/.exec(so); if (m) resolve({ port: +m[1], token: m[2] }); }); sa.on('exit', () => reject(new Error('standalone agent exited'))); });
      ok(/standalone copy/.test(so) && !/Open this link \(it carries your private token\) — it works in every browser/.test(so), 'banner says it has no web app and only offers the hosted link');
      for (const u of ['/private-notes.txt', '/Downloads/bavin-agent.js', '/bavin-agent.js', '/..%2fprivate-notes.txt', '/index.html/../private-notes.txt']) {
        const r = await get(sp2.port, u);
        ok(!/SECRET-NOTES/.test(r.body.toString()) && !/Bavin capture agent v1/.test(r.body.toString()) && (u === '/index.html/../private-notes.txt' ? r.status !== 200 || !/SECRET/.test(r.body) : r.status === 404), 'refuses ' + u + ' → ' + r.status);
      }
      const root = await get(sp2.port, '/');
      ok(root.status === 200 && /does not include the web app/.test(root.body.toString()) && !/SECRET/.test(root.body.toString()), 'GET / only returns a short "agent is running" page');
      ok(await upgrade(sp2.port, '?token=' + sp2.token, { Origin: 'https://demo.example.github.io' }) === 101, 'the WebSocket still works for the hosted origin');
      sa.kill('SIGINT'); fs.rmSync(dir, { recursive: true, force: true });
    }

    console.log('# repo copy serves only an allowlist');
    for (const u of ['/README.md', '/agent/bavin-agent.js', '/test/run.js', '/js/../agent/bavin-agent.js', '/LICENSE.bak', '/.git/config']) {
      const r = await get(port, u); ok(r.status === 404, 'not served: ' + u + ' → ' + r.status);
    }
    for (const u of ['/index.html', '/js/app.js', '/css/style.css', '/icons/icon-192.png', '/manifest.webmanifest', '/sw.js', '/favicon.svg']) {
      const r = await get(port, u); ok(r.status === 200, 'served: ' + u);
    }

    console.log('# --origin (hosted copy of the UI)');
    {
      const hostedOrigin = 'https://demo.example.github.io';
      const ch = spawn(process.execPath, [path.join(__dirname, '../agent/bavin-agent.js'), '--port', '0', '--replay', file, '--origin', hostedOrigin + '/bavin/'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let o2 = '';
      const hp = await new Promise((resolve, reject) => { ch.stdout.on('data', (d) => { o2 += d; const m = /#agent=(\d+)&token=([\w-]+)/.exec(o2); if (m) resolve({ port: +m[1], token: m[2] }); }); ch.on('exit', () => reject(new Error('origin agent exited'))); });
      ok(o2.includes(hostedOrigin + '/bavin/#agent=' + hp.port + '&token='), 'prints a ready-to-open link for the hosted site');
      ok(await upgrade(hp.port, '?token=' + hp.token, { Origin: hostedOrigin }) === 101, 'the trusted hosted origin can connect (with the token)');
      await new Promise((r) => setTimeout(r, 120));
      ok(await upgrade(hp.port, '', { Origin: hostedOrigin }) === 401, 'the trusted origin still needs the token');
      ok(await upgrade(hp.port, '?token=' + hp.token, { Origin: 'https://other.example.github.io' }) === 403, 'a different site is still refused');
      ok(await upgrade(hp.port, '?token=' + hp.token, { Origin: 'http://demo.example.github.io' }) === 403, 'the same host over http (downgrade) is refused');
      ok(await upgrade(hp.port, '?token=' + hp.token, { Origin: hostedOrigin, Host: 'evil.example:' + hp.port }) === 403, 'a wrong Host header is refused even from a trusted origin');
      ch.kill('SIGINT');
      for (const bad of ['http://evil.com', 'ftp://x.io', 'not a url', 'https://u:p@x.io']) {
        const r = require('child_process').spawnSync(process.execPath, [path.join(__dirname, '../agent/bavin-agent.js'), '--origin', bad]);
        ok(r.status === 2 && /--origin/.test(String(r.stderr)), 'startup rejects --origin ' + JSON.stringify(bad));
      }
    }

    console.log('# live mode (real tcpdump, no privileges)');
    const isRoot = process.getuid && process.getuid() === 0;
    const hasTcpdump = require('child_process').spawnSync('tcpdump', ['-h']).error === undefined;
    if (isRoot || !hasTcpdump) console.log('  - skipped (needs tcpdump and a non-root user to exercise the permission-denied path)');
    else {
      const live = spawn(process.execPath, [path.join(__dirname, '../agent/bavin-agent.js'), '--port', '0'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let lout = '';
      const lr = await new Promise((resolve, reject) => { live.stdout.on('data', (d) => { lout += d; const m = /127\.0\.0\.1:(\d+)\/#token=([\w-]+)/.exec(lout); if (m) resolve({ port: +m[1], token: m[2] }); }); live.on('exit', () => reject(new Error('live agent exited'))); });
      ok(/tcpdump/.test(lout) && /not running as root/.test(lout), 'startup banner names tcpdump and warns about missing root');
      const lws = await rawWs(lr.port, lr.token, 'http://127.0.0.1:' + lr.port);
      const lt = [];
      let lwake; lws.onmessage = (d, isText) => { if (isText) lt.push(JSON.parse(d.toString())); if (lwake) lwake(); };
      const luntil = (c) => new Promise((resolve, reject) => { const tm = setTimeout(() => reject(new Error('timeout: ' + JSON.stringify(lt))), 8000); lwake = () => { if (c()) { clearTimeout(tm); resolve(); } }; lwake(); });
      lws.sendJson({ type: 'list' });
      await luntil(() => lt.some((m) => m.type === 'interfaces'));
      const ifs = lt.find((m) => m.type === 'interfaces').interfaces;
      ok(ifs.length > 0 && ifs.every((i) => i.id && i.index), 'lists real interfaces: ' + ifs.map((i) => i.id).join(', '));
      lws.sendJson({ type: 'start', iface: ifs[0].id, filter: 'tcp port 80' });
      await luntil(() => lt.some((m) => m.type === 'stopped'));
      const err = lt.find((m) => m.type === 'error');
      ok(err && /permission|privilege/i.test(err.message) && /sudo/.test(err.message), 'permission denial is reported with a fix: ' + (err && err.message).slice(0, 120));
      lws.sendJson({ type: 'start', iface: ifs[0].id, filter: '-w /tmp/x' });
      await luntil(() => lt.filter((m) => m.type === 'error').length >= 2);
      ok(/cannot start with|not allowed/.test(lt.filter((m) => m.type === 'error')[1].message), 'a hostile filter is rejected before anything is spawned');
      lws.close(); live.kill('SIGINT');
    }

    console.log('# symlinks cannot lead out of the web root');
    {
      const base = fs.mkdtempSync(path.join(os.tmpdir(), 'bavin-symlink-'));
      const web = path.join(base, 'web'); fs.mkdirSync(path.join(web, 'agent'), { recursive: true }); fs.mkdirSync(path.join(web, 'js'));
      fs.writeFileSync(path.join(base, 'outside-secret.txt'), 'SECRET-OUTSIDE');
      fs.writeFileSync(path.join(web, 'index.html'), '<title>x</title>'); fs.writeFileSync(path.join(web, 'js', 'app.js'), '//');
      fs.symlinkSync(path.join(base, 'outside-secret.txt'), path.join(web, 'js', 'leak.js'));
      fs.writeFileSync(path.join(web, 'js', 'inside-copy.js'), 'inside');
      fs.symlinkSync(path.join(web, 'js', 'inside-copy.js'), path.join(web, 'js', 'ok-link.js'));
      fs.writeFileSync(path.join(web, 'agent', 'bavin-agent.js'), fs.readFileSync(path.join(__dirname, '../agent/bavin-agent.js')));
      const sl = spawn(process.execPath, [path.join(web, 'agent', 'bavin-agent.js'), '--port', '0'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let lo = '';
      const lp = await new Promise((resolve, reject) => { sl.stdout.on('data', (d) => { lo += d; const m = /127\.0\.0\.1:(\d+)\/#token=/.exec(lo); if (m) resolve({ port: +m[1] }); }); sl.on('exit', () => reject(new Error('symlink agent exited'))); });
      const leak = await get(lp.port, '/js/leak.js');
      ok(leak.status === 404 && !/SECRET-OUTSIDE/.test(leak.body.toString()), 'a symlink pointing outside the web root is not followed → ' + leak.status);
      ok((await get(lp.port, '/js/inside-copy.js')).status === 200 && (await get(lp.port, '/js/ok-link.js')).status === 200, 'normal files and links that stay inside are still served');
      sl.kill('SIGINT'); fs.rmSync(base, { recursive: true, force: true });
    }

    console.log('# startup argument checks');
    for (const [args, why] of [[['--port', '80'], 'privileged port 80'], [['--port', '1023'], 'port 1023'], [['--port', '70000'], 'port 70000'], [['--port', 'abc'], 'non-numeric port'], [['--speed', '0'], 'zero speed']]) {
      const r = require('child_process').spawnSync(process.execPath, [path.join(__dirname, '../agent/bavin-agent.js'), ...args]);
      ok(r.status === 2, 'refuses ' + why);
    }

    console.log('# filter validation');
    const { validateFilter } = require('../agent/bavin-agent.js');
    ok(validateFilter('tcp port 443 and not host 10.0.0.1') === 'tcp port 443 and not host 10.0.0.1', 'accepts a normal BPF filter');
    for (const bad of ['-w /etc/passwd', 'tcp; rm -rf /', '$(id)', 'a`b`', 'x\ny', 'a'.repeat(400)]) {
      let threw = false; try { validateFilter(bad); } catch (_) { threw = true; }
      ok(threw, 'rejects ' + JSON.stringify(bad.slice(0, 24)));
    }
  } catch (e) {
    failed++; console.error('  ✗ ' + e.stack);
  } finally {
    child.kill('SIGINT');
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  console.log(failed ? '\n' + failed + ' check(s) failed' : '\nall agent checks passed');
  process.exit(failed ? 1 : 0);
})();
