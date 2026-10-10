// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
// Run with: node web/test/run.js   (add --dump DIR to also write the sample captures as .pcap files)
'use strict';
const fs = require('fs');
const path = require('path');
require('../js/util.js');
const pcap = require('../js/pcap.js');
const dissect = require('../js/dissect.js');
const samples = require('../js/samples.js');
const filter = require('../js/filter.js');

let failed = 0;
function ok(cond, msg) {
  if (!cond) { failed++; console.error('  ✗ ' + msg); } else console.log('  ✓ ' + msg);
}

const dumpIdx = process.argv.indexOf('--dump');
const dumpDir = dumpIdx > 0 ? process.argv[dumpIdx + 1] : null;

for (const s of samples.LIST) {
  console.log('\n# sample: ' + s.id);
  const raw = s.make();
  const file = pcap.write(raw, 1);
  if (dumpDir) fs.writeFileSync(path.join(dumpDir, s.id + '.pcap'), file);
  const parsed = pcap.parse(file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength));
  ok(parsed.packets.length === raw.length, 'pcap round-trip keeps ' + raw.length + ' packets');
  const pk = dissect.dissectAll(parsed.packets);
  for (const p of pk) {
    console.log('  ' + String(p.no).padStart(3) + ' ' + p.proto.padEnd(7) + ' ' + p.src.padEnd(26) + ' → ' + p.dst.padEnd(26) + ' ' + p.info);
  }
  ok(pk.every((p) => !p.malformed), 'no malformed packets');
  ok(pk.every((p) => !p.warn), 'no warnings (checksums valid): ' + pk.filter((p) => p.warn).map((p) => '#' + p.no + ' ' + p.warn).join('; '));
  ok(pk.every((p) => p.layers.every((l) => l.fields.every((f) => f.off >= 0 && f.off + f.len <= p.data.length))), 'all field byte ranges are inside the packet');
  ok(pk.every((p) => p.layers.every((l) => l.off + l.len <= p.data.length)), 'all layer ranges are inside the packet');
  ok(pk.every((p) => p.proto !== '?'), 'every packet got a protocol label');
  if (s.id === 'web') {
    const protos = new Set(pk.map((p) => p.proto));
    for (const want of ['ARP', 'DNS', 'TCP', 'HTTP', 'TLS']) ok(protos.has(want), 'web sample contains ' + want);
    const syn = pk.find((p) => p.tcp && p.tcp.flags === 0x02);
    ok(syn && syn.tcp.rel.seq === 0, 'SYN has relative seq 0');
    const synack = pk.find((p) => p.tcp && p.tcp.flags === 0x12);
    ok(synack && synack.tcp.rel.ack === 1, 'SYN/ACK acks relative 1');
    const tls = pk.find((p) => p.proto === 'TLS');
    ok(/SNI: example\.com/.test(tls.info), 'TLS ClientHello SNI extracted: ' + tls.info);
    const nx = pk.find((p) => /NXDOMAIN/.test(p.info));
    ok(!!nx, 'NXDOMAIN response recognised');
    const http = pk.find((p) => p.proto === 'HTTP' && /200/.test(p.info));
    ok(http && http.layers.find((l) => l.id === 'http').fields.some((f) => f.name === 'Content-Length'), 'HTTP response headers parsed');
  }
  if (s.id === 'lan') {
    const protos = new Set(pk.map((p) => p.proto));
    for (const want of ['DHCP', 'ARP', 'ICMP', 'SSDP', 'IGMP', 'mDNS', 'NBNS', 'LLMNR']) ok(protos.has(want), 'lan sample contains ' + want);
    ok(pk.some((p) => /WORKGROUP<00>/.test(p.info)), 'NBNS name decoded to WORKGROUP<00>');
    ok(pk.some((p) => /Gratuitous/.test(p.info)), 'gratuitous ARP recognised');
  }
  if (s.id === 'ipv6') {
    const protos = new Set(pk.map((p) => p.proto));
    ok(protos.has('ICMPv6'), 'ipv6 sample contains ICMPv6');
    ok(pk.some((p) => /Neighbor Advertisement .* is at 84:16:f9:0c:aa:01/.test(p.info)), 'neighbor advertisement shows MAC');
    ok(pk.some((p) => p.proto === 'DNS' && /AAAA/.test(p.info)), 'AAAA query over IPv6 parsed');
    ok(pk.some((p) => p.layers.some((l) => l.id === 'ip6ext')), 'hop-by-hop extension header parsed');
  }
}

console.log('\n# pcapng');
{
  // Hand-assembled pcapng: SHB + IDB (ns resolution option) + EPB per packet, both byte orders.
  const raw = samples.LIST[0].make().slice(0, 5);
  const build = (le) => {
    const parts = [];
    const u32 = (n) => { const b = Buffer.alloc(4); le ? b.writeUInt32LE(n >>> 0) : b.writeUInt32BE(n >>> 0); return b; };
    const u16 = (n) => { const b = Buffer.alloc(2); le ? b.writeUInt16LE(n) : b.writeUInt16BE(n); return b; };
    const pad = (b) => Buffer.concat([b, Buffer.alloc((4 - (b.length % 4)) % 4)]);
    const block = (type, body) => { const len = 12 + body.length; return Buffer.concat([u32(type), u32(len), body, u32(len)]); };
    parts.push(block(0x0a0d0d0a, Buffer.concat([u32(0x1a2b3c4d), u16(1), u16(0), Buffer.alloc(8, 0xff)])));
    const opt = Buffer.concat([u16(9), u16(1), pad(Buffer.from([9])), u16(0), u16(0)]); // if_tsresol = 9 (ns)
    parts.push(block(1, Buffer.concat([u16(1), u16(0), u32(65535), opt])));
    for (const p of raw) {
      const ns = BigInt(Math.round(p.ts * 1e6)) * 1000n;
      const hi = Number(ns >> 32n), lo = Number(ns & 0xffffffffn);
      parts.push(block(6, Buffer.concat([u32(0), u32(hi), u32(lo), u32(p.data.length), u32(p.data.length), pad(Buffer.from(p.data))])));
    }
    return Buffer.concat(parts);
  };
  for (const le of [true, false]) {
    const b = build(le);
    const r = pcap.parse(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
    ok(r.format === 'pcapng' && r.packets.length === 5, (le ? 'little' : 'big') + '-endian pcapng: 5 packets');
    ok(Math.abs(r.packets[2].ts - raw[2].ts) < 1e-3, '  timestamps survive the ns resolution option');
    ok(Buffer.compare(Buffer.from(r.packets[4].data), Buffer.from(raw[4].data)) === 0, '  packet bytes identical');
  }
  if (dumpDir) { fs.writeFileSync(path.join(dumpDir, 'web.pcapng'), build(true)); }
}

console.log('\n# robustness');
{
  // Truncation at every length must never throw.
  const base = samples.LIST[0].make();
  let threw = 0, n = 0;
  for (const r of base) {
    for (let cut = 0; cut <= r.data.length; cut += 3) {
      n++;
      try { dissect.dissectAll([{ ts: 0, data: r.data.subarray(0, cut), origLen: r.data.length, linktype: 1 }]); } catch (e) { threw++; if (threw < 4) console.error(e.stack); }
    }
  }
  ok(threw === 0, 'truncating packets at ' + n + ' cut points never throws');
  // Random garbage must never throw.
  let seed = 12345; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  threw = 0;
  for (let i = 0; i < 3000; i++) {
    const len = Math.floor(rnd() * 200);
    const d = new Uint8Array(len).map(() => Math.floor(rnd() * 256));
    if (len > 13 && i % 2) { d[12] = 0x08; d[13] = i % 4 === 1 ? 0x00 : 0x06; }
    try { dissect.dissectAll([{ ts: 0, data: d, origLen: len, linktype: 1 }]); } catch (e) { threw++; if (threw < 4) console.error(e.stack); }
  }
  ok(threw === 0, '3000 random frames never throw');
  // Bad files
  for (const [label, bytes] of [['garbage', new Uint8Array(40).fill(7)], ['gzip', Uint8Array.of(0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0)], ['tiny', new Uint8Array(3)]]) {
    let msg = '';
    try { pcap.parse(bytes.buffer); } catch (e) { msg = e.message; }
    ok(!!msg, label + ' file is rejected with a message: ' + msg);
  }
  const hx = pcap.fromHexText('0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 00 45 00   ..........E.\n0010  00 14 00 00 00 00 40 01 00 00 7f 00 00 01 7f 00   ......@.........\n0020  00 01');
  ok(hx.length === 34 && hx[12] === 8, 'Wireshark-style hex dump (with ASCII gutter) is parsed');
}

console.log('\n# filter');
{
  const all = [].concat(...samples.LIST.map((s) => dissect.dissectAll(s.make())));
  const count = (expr) => { const r = filter.compile(expr); if (r.error) return 'ERR ' + r.error; return r.fn ? all.filter(r.fn).length : all.length; };
  const expect = (expr, n) => ok(count(expr) === n, JSON.stringify(expr) + ' → ' + count(expr) + (count(expr) === n ? '' : ' (expected ' + n + ')'));
  const n = (f) => all.filter(f).length;
  expect('', all.length);
  expect('tcp', n((p) => p.ids.includes('tcp')));
  expect('dns', n((p) => p.ids.includes('dns')));
  expect('dns or dhcp', n((p) => p.ids.includes('dns') || p.ids.includes('dhcp')));
  expect('!arp', n((p) => !p.ids.includes('arp')));
  expect('tcp && port == 80', n((p) => p.ids.includes('tcp') && (p.sport === 80 || p.dport === 80)));
  expect('tcp port == 80', n((p) => p.ids.includes('tcp') && (p.sport === 80 || p.dport === 80)));
  expect('port != 80 && tcp', n((p) => p.ids.includes('tcp') && p.sport !== 80 && p.dport !== 80));
  expect('ip.addr == 192.168.1.0/24', n((p) => p.ipv === 4 && (p.src.startsWith('192.168.1.') || p.dst.startsWith('192.168.1.'))));
  expect('ip.src == 93.184.216.34', n((p) => p.src === '93.184.216.34'));
  expect('ipv6', n((p) => p.ids.includes('ip6')));
  expect('tcp.flags.syn == 1', 2);
  expect('syn && !ack', 1);
  expect('len > 200 && udp', n((p) => p.len > 200 && p.ids.includes('udp')));
  expect('info contains "GET"', 1);
  expect('example.com', n((p) => (p.info + p.src + p.dst).toLowerCase().includes('example.com')));
  expect('(arp or icmp) and !ipv6', n((p) => (p.ids.includes('arp') || p.ids.includes('icmp')) && !p.ids.includes('ip6')));
  expect('mdns', 1);
  ok(/Unknown field/.test(count('foo.bar == 3')), 'unknown field gives a helpful error');
  ok(/parenthesis/.test(count('(tcp')), 'unbalanced paren gives a helpful error');
  ok(/ends unexpectedly/.test(count('tcp &&')), 'dangling operator gives a helpful error');
}

console.log('\n# real tcpdump output');
{
  const cp = require('child_process');
  const probe = cp.spawnSync('tcpdump', ['-h']);
  if (probe.error) console.log('  - skipped (tcpdump not installed)');
  else {
    // `tcpdump -r FILE -w -` makes the real tool write a pcap stream to stdout, like the live agent receives.
    const tmp = require('os').tmpdir() + '/bavin-sd-' + process.pid + '.pcap';
    const raw = samples.LIST[1].make();
    fs.writeFileSync(tmp, pcap.write(raw, 1));
    const out = cp.execFileSync('tcpdump', ['-r', tmp, '-w', '-'], { stdio: ['ignore', 'pipe', 'ignore'] });
    fs.unlinkSync(tmp);
    const sp = new pcap.StreamParser();
    const got = [];
    for (let i = 0; i < out.length; i += 333) got.push(...sp.push(new Uint8Array(out.subarray(i, i + 333))));
    ok(got.length === raw.length, "StreamParser reads tcpdump's own stdout stream in 333-byte chunks (" + got.length + ' packets)');
    ok(got.every((p, i) => Buffer.compare(Buffer.from(p.data), Buffer.from(raw[i].data)) === 0), '  packet bytes identical');
  }
}

console.log('\n# hostile captures');
{
  const H = samples.helpers;
  const { cat, be16, be32, ip4, ethernet, ipv4, udp, mac } = H;
  const build = (frame) => dissect.dissectAll([{ ts: 0, data: frame, origLen: frame.length, linktype: 1 }])[0];
  const total = (p) => p.layers.reduce((a, l) => a + l.fields.length, 0);
  // thousands of tiny entries in one ~56 KB packet must not become thousands of UI elements
  const fixed = cat(Uint8Array.of(1, 1, 6, 0), be32(1), be16(0), be16(0), new Uint8Array(16), mac('a4:77:33:12:5b:90'), new Uint8Array(202), be32(0x63825363));
  const opts = []; for (let i = 0; i < 19000; i++) opts.push(Uint8Array.of(12, 1, 0x41));
  const dhcp = build(ethernet('ff:ff:ff:ff:ff:ff', 'a4:77:33:12:5b:90', 0x0800, ipv4('0.0.0.0', '255.255.255.255', 17, udp('0.0.0.0', '255.255.255.255', 68, 67, cat(fixed, ...opts, Uint8Array.of(255))))));
  ok(total(dhcp) < 400, 'DHCP with 19,000 options → ' + total(dhcp) + ' fields (capped)');
  ok(dhcp.layers.find((l) => l.id === 'dhcp').hidden > 18000, 'the layer records how many entries were not shown');
  const recs = []; for (let i = 0; i < 7000; i++) recs.push(cat(Uint8Array.of(1, 0), be16(0), ip4('224.0.' + (i >> 8) + '.' + (i & 255))));
  const igmp = build(ethernet('01:00:5e:00:00:16', 'a4:77:33:12:5b:90', 0x0800, ipv4('10.0.0.1', '224.0.0.22', 2, cat(Uint8Array.of(0x22, 0, 0, 0), be16(0), be16(7000), ...recs))));
  ok(total(igmp) < 400, 'IGMPv3 with 7,000 group records → ' + total(igmp) + ' fields (capped)');
  const ra = []; for (let i = 0; i < 7000; i++) ra.push(Uint8Array.of(1, 1, 1, 2, 3, 4, 5, 6));
  const rap = build(ethernet('33:33:00:00:00:01', 'a4:77:33:12:5b:90', 0x86dd, H.ipv6('fe80::1', 'ff02::1', 58, cat(Uint8Array.of(134, 0, 0, 0, 64, 0), be16(1800), be32(0), be32(0), ...ra))));
  ok(total(rap) < 400, 'ICMPv6 RA with 7,000 options → ' + total(rap) + ' fields (capped)');
  let hdr = 'GET / HTTP/1.1\r\n'; for (let i = 0; i < 30000; i++) hdr += 'X' + i + ': v\r\n';
  const http = build(ethernet('00:00:00:00:00:01', '00:00:00:00:00:02', 0x0800, ipv4('10.0.0.1', '10.0.0.2', 6, H.tcp('10.0.0.1', '10.0.0.2', 1, 80, 1, 1, 0x18, new TextEncoder().encode(hdr).subarray(0, 60000)))));
  ok(total(http) < 400, 'HTTP with 30,000 header lines → ' + total(http) + ' fields (capped)');
  ok(total(dissect.dissectAll(samples.LIST[0].make().slice(7, 8))[0]) > 20, 'normal packets are not affected by the cap');

  // mutation fuzzing: flip bytes, inflate length fields, splice garbage, truncate. Must never throw or crawl.
  const base = [].concat(...samples.LIST.map((s) => s.make()));
  let seed = 424242; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff; const ri = (n) => Math.floor(rnd() * n);
  let threw = 0, slow = 0; const t0 = Date.now();
  for (let i = 0; i < 60000; i++) {
    let d = Uint8Array.from(base[ri(base.length)].data);
    const mode = ri(5);
    if (mode === 0) for (let k = 0, n = 1 + ri(4); k < n; k++) d[ri(d.length)] = ri(256);
    else if (mode === 1) for (let k = 0, n = 1 + ri(3); k < n; k++) { const o = ri(d.length - 1); d[o] = 0xff; d[o + 1] = 0xff; }
    else if (mode === 2) d = d.subarray(0, ri(d.length + 1));
    else if (mode === 3) { const o = ri(d.length); d = Uint8Array.from([...d.subarray(0, o), ...Array.from({ length: ri(40) }, () => ri(256)), ...d.subarray(o)]); }
    else { const o = 12 + ri(Math.max(1, d.length - 12)); d[o] = 0xc0; d[o + 1] = 0x0c; }
    const s = Date.now();
    try { dissect.dissectAll([{ ts: 0, data: d, origLen: d.length, linktype: 1 }]); } catch (e) { threw++; if (threw < 3) console.error(e.stack); }
    if (Date.now() - s > 50) slow++;
  }
  ok(threw === 0 && slow === 0, '60,000 mutated packets: ' + threw + ' exceptions, ' + slow + ' slower than 50 ms (' + (Date.now() - t0) + ' ms total)');

  // a malformed capture file must be rejected, not crash or hang
  const evilPcap = new Uint8Array(24 + 16); const dv = new DataView(evilPcap.buffer);
  dv.setUint32(0, 0xa1b2c3d4, false); dv.setUint32(20, 1, false); dv.setUint32(24 + 8, 0xffffffff, false); // one record claiming 4 GB
  ok(pcap.parse(evilPcap.buffer).packets.length === 0, 'a pcap record claiming 4 GB is ignored safely');
  let sp = new pcap.StreamParser(), msg = '';
  try { sp.push(evilPcap.subarray(0, 24)); sp.push(evilPcap.subarray(24)); } catch (e) { msg = e.message; }
  ok(/Corrupt capture stream/.test(msg), 'the live stream parser refuses an absurd record size: ' + msg);
  const evilNg = new Uint8Array(32); new DataView(evilNg.buffer).setUint32(0, 0x0a0d0d0a, false); new DataView(evilNg.buffer).setUint32(4, 0xffffffff, false);
  let ngMsg = ''; try { pcap.parse(evilNg.buffer); } catch (e) { ngMsg = e.message; }
  ok(ngMsg.length > 0, 'a pcapng block with a bogus length is rejected without looping: ' + ngMsg);
}

console.log('\n# installable app (PWA)');
{
  const webDir = path.join(__dirname, '..');
  const manifest = JSON.parse(fs.readFileSync(path.join(webDir, 'manifest.webmanifest'), 'utf8'));
  ok(manifest.name && manifest.short_name && manifest.start_url === './' && manifest.scope === './' && manifest.display === 'standalone', 'manifest has name, start_url, scope and display');
  const pngSize = (f) => { const b = fs.readFileSync(path.join(webDir, f)); return b.readUInt32BE(16) + 'x' + b.readUInt32BE(20); };
  for (const i of manifest.icons) {
    if (i.type !== 'image/png') { ok(fs.existsSync(path.join(webDir, i.src)), 'icon exists: ' + i.src); continue; }
    ok(fs.existsSync(path.join(webDir, i.src)) && pngSize(i.src) === i.sizes, 'icon ' + i.src + ' is really ' + i.sizes);
  }
  ok(manifest.icons.some((i) => i.sizes === '192x192') && manifest.icons.some((i) => i.sizes === '512x512') && manifest.icons.some((i) => i.purpose === 'maskable'), 'has 192, 512 and maskable icons');
  const sw = fs.readFileSync(path.join(webDir, 'sw.js'), 'utf8');
  const shell = eval(/const SHELL = (\[[\s\S]*?\]);/.exec(sw)[1]);
  const missing = shell.filter((f) => f !== './' && !fs.existsSync(path.join(webDir, f)));
  ok(missing.length === 0, 'every file in the service-worker precache list exists' + (missing.length ? ' — missing: ' + missing : ''));
  const html = fs.readFileSync(path.join(webDir, 'index.html'), 'utf8');
  const scripts = [...html.matchAll(/<script src="([^"]+)"/g)].map((m) => m[1]);
  ok(scripts.every((s) => shell.includes(s)), 'every <script> in index.html is precached (offline works)');
  ok(/manifest-src 'self'/.test(html) && /worker-src 'self'/.test(html), 'CSP allows the manifest and the service worker');
}

if (failed) { console.error('\n' + failed + ' check(s) failed'); process.exit(1); }
console.log('\nall checks passed');
