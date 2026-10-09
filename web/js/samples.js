// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — built-in sample captures.
 * Packets are assembled byte-by-byte here (with correct checksums) so the demo needs no binary assets
 * and the same builders double as test fixtures.
 */
(function (B) {
  'use strict';
  const U = B.util || (typeof require !== 'undefined' ? require('./util.js') : null);

  // ── tiny byte builder ──
  const cat = (...parts) => {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const be16 = (n) => Uint8Array.of((n >> 8) & 255, n & 255);
  const be32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  const str = (s) => Uint8Array.from(s, (ch) => ch.charCodeAt(0) & 255);
  const mac = (s) => Uint8Array.from(s.split(':').map((x) => parseInt(x, 16)));
  const ip4 = (s) => Uint8Array.from(s.split('.').map(Number));
  function ip6(s) {
    let [l, r] = s.split('::');
    const L = l ? l.split(':') : [], R = r ? r.split(':') : [];
    const mid = s.includes('::') ? new Array(8 - L.length - R.length).fill('0') : [];
    const g = [...L, ...mid, ...R].map((x) => parseInt(x, 16));
    return cat(...g.map(be16));
  }
  const zeros = (n) => new Uint8Array(n);
  function csum(bytes) { return U.inetChecksum(bytes, 0, bytes.length); }

  const ethernet = (dst, src, type, body) => {
    const f = cat(mac(dst), mac(src), be16(type), body);
    return f.length < 60 ? cat(f, zeros(60 - f.length)) : f;
  };

  let ipId = 0x1a2b;
  function ipv4(src, dst, proto, body, opts) {
    opts = opts || {};
    const hdr = cat(
      Uint8Array.of(0x45, opts.tos || 0), be16(20 + body.length), be16(opts.id != null ? opts.id : ipId++),
      be16(opts.df === false ? 0 : 0x4000), Uint8Array.of(opts.ttl || 64, proto), be16(0), ip4(src), ip4(dst));
    const ck = csum(hdr);
    hdr[10] = ck >> 8; hdr[11] = ck & 255;
    return cat(hdr, body);
  }
  function ipv6(src, dst, nh, body, hop) {
    return cat(Uint8Array.of(0x60, 0, 0, 0), be16(body.length), Uint8Array.of(nh, hop || 255), ip6(src), ip6(dst), body);
  }
  function pseudo4(src, dst, proto, len) { return cat(ip4(src), ip4(dst), Uint8Array.of(0, proto), be16(len)); }
  function pseudo6(src, dst, nh, len) { return cat(ip6(src), ip6(dst), be32(len), Uint8Array.of(0, 0, 0, nh)); }

  function udp(src, dst, sp, dp, body) {
    const h = cat(be16(sp), be16(dp), be16(8 + body.length), be16(0));
    const ck = csum(cat(pseudo4(src, dst, 17, 8 + body.length), h, body)) || 0xffff;
    h[6] = ck >> 8; h[7] = ck & 255;
    return cat(h, body);
  }
  function tcp(src, dst, sp, dp, seq, ack, flags, body, opts) {
    opts = opts || {};
    const o = opts.options || new Uint8Array(0);
    const hl = 20 + o.length;
    const h = cat(be16(sp), be16(dp), be32(seq), be32(ack), Uint8Array.of((hl / 4) << 4, flags), be16(opts.win || 64240), be16(0), be16(0), o);
    const ck = csum(cat(pseudo4(src, dst, 6, hl + body.length), h, body));
    h[16] = ck >> 8; h[17] = ck & 255;
    return cat(h, body);
  }
  const SYN_OPTS = Uint8Array.of(2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0x12, 0xd6, 0x87, 0, 0, 0, 0, 1, 3, 3, 7);
  const TS_OPTS = (a, b) => cat(Uint8Array.of(1, 1, 8, 10), be32(a), be32(b));

  function dnsName(n) {
    const parts = [];
    for (const l of n.split('.')) parts.push(Uint8Array.of(l.length), str(l));
    return cat(...parts, Uint8Array.of(0));
  }
  function dnsQuery(id, name, type) {
    return cat(be16(id), be16(0x0100), be16(1), be16(0), be16(0), be16(0), dnsName(name), be16(type), be16(1));
  }
  // answers: [{type, data(Uint8Array), ttl}] — owner name uses a compression pointer to the question at offset 12.
  function dnsResponse(id, name, type, answers) {
    const rr = answers.map((a) => cat(Uint8Array.of(0xc0, 0x0c), be16(a.type), be16(1), be32(a.ttl || 300), be16(a.data.length), a.data));
    return cat(be16(id), be16(0x8180), be16(1), be16(answers.length), be16(0), be16(0), dnsName(name), be16(type), be16(1), ...rr);
  }

  function dhcpMsg(op, xid, chaddr, yiaddr, siaddr, opts) {
    const fixed = cat(Uint8Array.of(op, 1, 6, 0), be32(xid), be16(0), be16(op === 1 ? 0x8000 : 0), zeros(4), ip4(yiaddr), ip4(siaddr), zeros(4), mac(chaddr), zeros(10), zeros(64), zeros(128), be32(0x63825363));
    return cat(fixed, ...opts, Uint8Array.of(255), zeros(4));
  }
  const dopt = (k, v) => cat(Uint8Array.of(k, v.length), v);

  function nbEncode(name, suffix) {
    const raw = (name.toUpperCase().padEnd(15, ' ') + String.fromCharCode(suffix));
    let s = '';
    for (const ch of raw) { const c = ch.charCodeAt(0); s += String.fromCharCode(65 + (c >> 4), 65 + (c & 15)); }
    return cat(Uint8Array.of(32), str(s), Uint8Array.of(0));
  }

  function build(spec) {
    // spec: [{t: seconds-from-start, frame: Uint8Array}]
    const base = 1760000000;
    return spec.map((s) => ({ ts: base + s.t, data: s.frame, origLen: s.frame.length, linktype: 1 }));
  }

  // ───────────────────────────── sample 1: opening a web page ─────────────────────────────
  function webBrowsing() {
    const me = { mac: '3c:22:fb:7a:10:5e', ip: '192.168.1.105' };
    const gw = { mac: '84:16:f9:0c:aa:01', ip: '192.168.1.1' };
    const web = { ip: '93.184.216.34' };
    const dns = '192.168.1.1';
    const f = [];
    let t = 0;
    const add = (dt, frame) => { t += dt; f.push({ t, frame }); };
    const eth = (from, to, ip) => ethernet(to.mac, from.mac, 0x0800, ip);

    // ARP for the gateway
    add(0, ethernet('ff:ff:ff:ff:ff:ff', me.mac, 0x0806, cat(be16(1), be16(0x0800), Uint8Array.of(6, 4), be16(1), mac(me.mac), ip4(me.ip), zeros(6), ip4(gw.ip))));
    add(0.0021, ethernet(me.mac, gw.mac, 0x0806, cat(be16(1), be16(0x0800), Uint8Array.of(6, 4), be16(2), mac(gw.mac), ip4(gw.ip), mac(me.mac), ip4(me.ip))));
    // DNS lookup
    const q = dnsQuery(0x7a31, 'example.com', 1);
    add(0.0100, eth(me, gw, ipv4(me.ip, dns, 17, udp(me.ip, dns, 53211, 53, q))));
    const r = dnsResponse(0x7a31, 'example.com', 1, [{ type: 1, data: ip4(web.ip), ttl: 3600 }]);
    add(0.0240, eth(gw, me, ipv4(dns, me.ip, 17, udp(dns, me.ip, 53, 53211, r))));
    // TCP 3-way handshake
    const isn = 0x5a10c3e0, sisn = 0x1f44a0b2;
    add(0.0020, eth(me, gw, ipv4(me.ip, web.ip, 6, tcp(me.ip, web.ip, 49722, 80, isn, 0, 0x02, new Uint8Array(0), { options: SYN_OPTS }))));
    add(0.0310, eth(gw, me, ipv4(web.ip, me.ip, 6, tcp(web.ip, me.ip, 80, 49722, sisn, isn + 1, 0x12, new Uint8Array(0), { options: cat(Uint8Array.of(2, 4, 5, 0xb4, 1, 1, 4, 2, 1, 3, 3, 8)) }), { ttl: 52 })));
    add(0.0001, eth(me, gw, ipv4(me.ip, web.ip, 6, tcp(me.ip, web.ip, 49722, 80, isn + 1, sisn + 1, 0x10, new Uint8Array(0), { options: TS_OPTS(1, 2) }))));
    // HTTP request / response
    const req = str('GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Bavin-Demo/1.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n');
    add(0.0004, eth(me, gw, ipv4(me.ip, web.ip, 6, tcp(me.ip, web.ip, 49722, 80, isn + 1, sisn + 1, 0x18, req, { options: TS_OPTS(3, 2) }))));
    add(0.0302, eth(gw, me, ipv4(web.ip, me.ip, 6, tcp(web.ip, me.ip, 80, 49722, sisn + 1, isn + 1 + req.length, 0x10, new Uint8Array(0), { options: TS_OPTS(5, 3) }), { ttl: 52 })));
    const html = '<!doctype html>\n<html><head><title>Example Domain</title></head>\n<body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>\n';
    const resp = str('HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ' + html.length + '\r\nServer: ECS (dcb/7F83)\r\nConnection: close\r\n\r\n' + html);
    add(0.0008, eth(gw, me, ipv4(web.ip, me.ip, 6, tcp(web.ip, me.ip, 80, 49722, sisn + 1, isn + 1 + req.length, 0x18, resp, { options: TS_OPTS(6, 3) }), { ttl: 52 })));
    add(0.0001, eth(me, gw, ipv4(me.ip, web.ip, 6, tcp(me.ip, web.ip, 49722, 80, isn + 1 + req.length, sisn + 1 + resp.length, 0x10, new Uint8Array(0), { options: TS_OPTS(7, 6) }))));
    // Teardown
    add(0.0006, eth(gw, me, ipv4(web.ip, me.ip, 6, tcp(web.ip, me.ip, 80, 49722, sisn + 1 + resp.length, isn + 1 + req.length, 0x11, new Uint8Array(0), { options: TS_OPTS(8, 7) }), { ttl: 52 })));
    add(0.0002, eth(me, gw, ipv4(me.ip, web.ip, 6, tcp(me.ip, web.ip, 49722, 80, isn + 1 + req.length, sisn + 2 + resp.length, 0x11, new Uint8Array(0), { options: TS_OPTS(9, 8) }))));
    add(0.0299, eth(gw, me, ipv4(web.ip, me.ip, 6, tcp(web.ip, me.ip, 80, 49722, sisn + 2 + resp.length, isn + 2 + req.length, 0x10, new Uint8Array(0), { options: TS_OPTS(10, 9) }), { ttl: 52 })));
    // A failed lookup and a TLS ClientHello with SNI
    add(0.8, eth(me, gw, ipv4(me.ip, dns, 17, udp(me.ip, dns, 61820, 53, dnsQuery(0x11ee, 'no-such-host.invalid', 1)))));
    const nx = dnsQuery(0x11ee, 'no-such-host.invalid', 1); nx[2] = 0x81; nx[3] = 0x83;
    add(0.0210, eth(gw, me, ipv4(dns, me.ip, 17, udp(dns, me.ip, 53, 61820, nx))));
    const sni = str('example.com');
    const ext = cat(be16(0), be16(sni.length + 5), be16(sni.length + 3), Uint8Array.of(0), be16(sni.length), sni, be16(43), be16(5), Uint8Array.of(4, 0x03, 0x04, 0x03, 0x03));
    const chBody = cat(be16(0x0303), zeros(32), Uint8Array.of(0), be16(4), be16(0x1301), be16(0x1302), Uint8Array.of(1, 0), be16(ext.length), ext);
    const hs = cat(Uint8Array.of(1, 0, (chBody.length >> 8) & 255, chBody.length & 255), chBody);
    const rec = cat(Uint8Array.of(22), be16(0x0301), be16(hs.length), hs);
    add(0.4, eth(me, gw, ipv4(me.ip, web.ip, 6, tcp(me.ip, web.ip, 50111, 443, 4000, 9000, 0x18, rec, { options: TS_OPTS(11, 9) }))));
    const appData = cat(Uint8Array.of(23), be16(0x0303), be16(48), Uint8Array.from({ length: 48 }, (_, i) => (i * 37 + 11) & 255));
    add(0.031, eth(gw, me, ipv4(web.ip, me.ip, 6, tcp(web.ip, me.ip, 443, 50111, 9000, 4000 + rec.length, 0x18, appData, { options: TS_OPTS(12, 11) }), { ttl: 52 })));
    return build(f);
  }

  // ───────────────────────────── sample 2: chatty home LAN ─────────────────────────────
  function lanChatter() {
    const pc = { mac: '3c:22:fb:7a:10:5e', ip: '192.168.1.105' };
    const tv = { mac: 'a4:77:33:12:5b:90', ip: '192.168.1.42' };
    const win = { mac: '00:1a:2b:3c:4d:5e', ip: '192.168.1.77' };
    const gw = { mac: '84:16:f9:0c:aa:01', ip: '192.168.1.1' };
    const f = [];
    let t = 0;
    const add = (dt, frame) => { t += dt; f.push({ t, frame }); };

    // DHCP exchange (client has no IP yet)
    const xid = 0x3903f326;
    const cmac = 'a4:77:33:12:5b:90';
    const dhcpFrame = (fromMac, toMac, fromIp, toIp, sp, dp, msg, ipOpts) => ethernet(toMac, fromMac, 0x0800, ipv4(fromIp, toIp, 17, udp(fromIp, toIp, sp, dp, msg), ipOpts));
    const fromClient = (msg) => dhcpFrame(cmac, 'ff:ff:ff:ff:ff:ff', '0.0.0.0', '255.255.255.255', 68, 67, msg, { ttl: 128, df: false });
    const fromServer = (msg) => dhcpFrame(gw.mac, cmac, gw.ip, '192.168.1.42', 67, 68, msg);
    const none = '0.0.0.0';
    add(0, fromClient(dhcpMsg(1, xid, cmac, none, none, [dopt(53, Uint8Array.of(1)), dopt(61, cat(Uint8Array.of(1), mac(cmac))), dopt(12, str('Living-Room-TV')), dopt(55, Uint8Array.of(1, 3, 6, 15, 28, 51))])));
    add(0.012, fromServer(dhcpMsg(2, xid, cmac, '192.168.1.42', gw.ip, [dopt(53, Uint8Array.of(2)), dopt(54, ip4(gw.ip)), dopt(51, be32(86400)), dopt(1, ip4('255.255.255.0')), dopt(3, ip4(gw.ip)), dopt(6, cat(ip4(gw.ip), ip4('1.1.1.1')))])));
    add(0.004, fromClient(dhcpMsg(1, xid, cmac, none, none, [dopt(53, Uint8Array.of(3)), dopt(50, ip4('192.168.1.42')), dopt(54, ip4(gw.ip)), dopt(12, str('Living-Room-TV'))])));
    add(0.009, fromServer(dhcpMsg(2, xid, cmac, '192.168.1.42', gw.ip, [dopt(53, Uint8Array.of(5)), dopt(54, ip4(gw.ip)), dopt(51, be32(86400)), dopt(1, ip4('255.255.255.0')), dopt(3, ip4(gw.ip))])));
    // gratuitous ARP
    add(0.05, ethernet('ff:ff:ff:ff:ff:ff', tv.mac, 0x0806, cat(be16(1), be16(0x0800), Uint8Array.of(6, 4), be16(1), mac(tv.mac), ip4(tv.ip), zeros(6), ip4(tv.ip))));
    // ARP who-has / reply
    add(0.3, ethernet('ff:ff:ff:ff:ff:ff', pc.mac, 0x0806, cat(be16(1), be16(0x0800), Uint8Array.of(6, 4), be16(1), mac(pc.mac), ip4(pc.ip), zeros(6), ip4(tv.ip))));
    add(0.0008, ethernet(pc.mac, tv.mac, 0x0806, cat(be16(1), be16(0x0800), Uint8Array.of(6, 4), be16(2), mac(tv.mac), ip4(tv.ip), mac(pc.mac), ip4(pc.ip))));
    // ping the TV
    for (let i = 1; i <= 2; i++) {
      const echo = (type, body) => { const h = cat(Uint8Array.of(type, 0, 0, 0), be16(0x0001), be16(i), body); const ck = csum(h); h[2] = ck >> 8; h[3] = ck & 255; return h; };
      const data = Uint8Array.from({ length: 32 }, (_, k) => 0x61 + (k % 23));
      add(0.9, ethernet(tv.mac, pc.mac, 0x0800, ipv4(pc.ip, tv.ip, 1, echo(8, data), { ttl: 128 })));
      add(0.0031, ethernet(pc.mac, tv.mac, 0x0800, ipv4(tv.ip, pc.ip, 1, echo(0, data), { ttl: 64 })));
    }
    // ICMP port unreachable
    const orig = ipv4(pc.ip, tv.ip, 17, udp(pc.ip, tv.ip, 40000, 9, str('hello')));
    const unreach = cat(Uint8Array.of(3, 3, 0, 0, 0, 0, 0, 0), orig.subarray(0, 28)); const uck = csum(unreach); unreach[2] = uck >> 8; unreach[3] = uck & 255;
    add(0.6, ethernet(pc.mac, tv.mac, 0x0800, ipv4(tv.ip, pc.ip, 1, unreach)));
    // SSDP M-SEARCH and NOTIFY
    const msearch = str('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 3\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n');
    add(0.5, ethernet('01:00:5e:7f:ff:fa', pc.mac, 0x0800, ipv4(pc.ip, '239.255.255.250', 17, udp(pc.ip, '239.255.255.250', 58290, 1900, msearch), { ttl: 4 })));
    const notify = str('NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.42:8060/\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nSERVER: Roku/12.5 UPnP/1.0\r\n\r\n');
    add(0.2, ethernet('01:00:5e:7f:ff:fa', tv.mac, 0x0800, ipv4(tv.ip, '239.255.255.250', 17, udp(tv.ip, '239.255.255.250', 49152, 1900, notify), { ttl: 4 })));
    // IGMPv2 report + IGMPv3 report + query
    const igmp = (b) => { const ck = csum(b); b[2] = ck >> 8; b[3] = ck & 255; return b; };
    add(0.4, ethernet('01:00:5e:00:00:01', gw.mac, 0x0800, ipv4(gw.ip, '224.0.0.1', 2, igmp(cat(Uint8Array.of(0x11, 100, 0, 0), zeros(4))), { ttl: 1 })));
    add(0.8, ethernet('01:00:5e:7f:ff:fa', tv.mac, 0x0800, ipv4(tv.ip, '239.255.255.250', 2, igmp(cat(Uint8Array.of(0x16, 0, 0, 0), ip4('239.255.255.250'))), { ttl: 1 })));
    add(0.2, ethernet('01:00:5e:00:00:16', pc.mac, 0x0800, ipv4(pc.ip, '224.0.0.22', 2, igmp(cat(Uint8Array.of(0x22, 0, 0, 0), be16(0), be16(1), Uint8Array.of(4, 0), be16(0), ip4('224.0.0.251'))), { ttl: 1 })));
    // mDNS
    const mq = cat(be16(0), be16(0), be16(1), be16(0), be16(0), be16(0), dnsName('_googlecast._tcp.local'), be16(12), be16(0x8001));
    add(0.3, ethernet('01:00:5e:00:00:fb', pc.mac, 0x0800, ipv4(pc.ip, '224.0.0.251', 17, udp(pc.ip, '224.0.0.251', 5353, 5353, mq), { ttl: 255 })));
    // NBNS name query + LLMNR
    const nb = cat(be16(0x8a23), be16(0x0110), be16(1), be16(0), be16(0), be16(0), nbEncode('WORKGROUP', 0), be16(0x20), be16(1));
    add(0.4, ethernet('ff:ff:ff:ff:ff:ff', win.mac, 0x0800, ipv4(win.ip, '192.168.1.255', 17, udp(win.ip, '192.168.1.255', 137, 137, nb), { ttl: 128, df: false })));
    const ll = cat(be16(0x5e17), be16(0), be16(1), be16(0), be16(0), be16(0), dnsName('living-room-tv'), be16(1), be16(1));
    add(0.2, ethernet('01:00:5e:00:00:fc', win.mac, 0x0800, ipv4(win.ip, '224.0.0.252', 17, udp(win.ip, '224.0.0.252', 54123, 5355, ll), { ttl: 1 })));
    return build(f);
  }

  // ───────────────────────────── sample 3: IPv6 ─────────────────────────────
  function ipv6Demo() {
    const a = { mac: '3c:22:fb:7a:10:5e', ip: 'fe80::3e22:fbff:fe7a:105e' };
    const r = { mac: '84:16:f9:0c:aa:01', ip: 'fe80::8616:f9ff:fe0c:aa01' };
    const g = { ip: '2001:db8:85a3::1' }, me6 = '2001:db8:85a3::105e';
    const f = [];
    let t = 0;
    const add = (dt, frame) => { t += dt; f.push({ t, frame }); };
    const icmp6 = (src, dst, body) => {
      const h = cat(body); h[2] = 0; h[3] = 0;
      const ck = csum(cat(pseudo6(src, dst, 58, h.length), h)); h[2] = ck >> 8; h[3] = ck & 255; return h;
    };
    // Router solicitation
    add(0, ethernet('33:33:00:00:00:02', a.mac, 0x86dd, ipv6(a.ip, 'ff02::2', 58, icmp6(a.ip, 'ff02::2', cat(Uint8Array.of(133, 0, 0, 0), zeros(4), Uint8Array.of(1, 1), mac(a.mac))))));
    // Router advertisement
    const ra = cat(Uint8Array.of(134, 0, 0, 0, 64, 0x40), be16(1800), be32(0), be32(0), Uint8Array.of(1, 1), mac(r.mac), Uint8Array.of(5, 1, 0, 0), be32(1500), Uint8Array.of(3, 4, 64, 0xc0), be32(86400), be32(14400), zeros(4), ip6('2001:db8:85a3::'));
    add(0.012, ethernet('33:33:00:00:00:01', r.mac, 0x86dd, ipv6(r.ip, 'ff02::1', 58, icmp6(r.ip, 'ff02::1', ra))));
    // Neighbor solicitation / advertisement
    add(0.3, ethernet('33:33:ff:0c:aa:01', a.mac, 0x86dd, ipv6(me6, 'ff02::1:ff0c:aa01', 58, icmp6(me6, 'ff02::1:ff0c:aa01', cat(Uint8Array.of(135, 0, 0, 0), zeros(4), ip6(r.ip), Uint8Array.of(1, 1), mac(a.mac))))));
    add(0.0009, ethernet(a.mac, r.mac, 0x86dd, ipv6(r.ip, me6, 58, icmp6(r.ip, me6, cat(Uint8Array.of(136, 0, 0, 0, 0xe0, 0, 0, 0), ip6(r.ip), Uint8Array.of(2, 1), mac(r.mac))))));
    // ping6
    for (let i = 1; i <= 2; i++) {
      const data = Uint8Array.from({ length: 16 }, (_, k) => 0x30 + k);
      add(0.8, ethernet(r.mac, a.mac, 0x86dd, ipv6(me6, g.ip, 58, icmp6(me6, g.ip, cat(Uint8Array.of(128, 0, 0, 0), be16(0x77), be16(i), data)), 64)));
      add(0.0152, ethernet(a.mac, r.mac, 0x86dd, ipv6(g.ip, me6, 58, icmp6(g.ip, me6, cat(Uint8Array.of(129, 0, 0, 0), be16(0x77), be16(i), data)), 57)));
    }
    // MLDv2 report with hop-by-hop router alert
    const hbh = Uint8Array.of(58, 0, 5, 2, 0, 0, 1, 0);
    const mld = icmp6(a.ip, 'ff02::16', cat(Uint8Array.of(143, 0, 0, 0), be16(0), be16(1), Uint8Array.of(4, 0), be16(0), ip6('ff02::fb')));
    add(0.5, ethernet('33:33:00:00:00:16', a.mac, 0x86dd, ipv6(a.ip, 'ff02::16', 0, cat(hbh, mld), 1)));
    // DNS AAAA over IPv6 UDP
    const q = dnsQuery(0x4c01, 'ipv6.google.com', 28);
    add(0.4, ethernet(r.mac, a.mac, 0x86dd, (() => { const u = udp6(me6, '2001:4860:4860::8888', 40111, 53, q); return ipv6(me6, '2001:4860:4860::8888', 17, u, 64); })()));
    const resp = dnsResponse(0x4c01, 'ipv6.google.com', 28, [{ type: 28, data: ip6('2607:f8b0:4005:80a::200e'), ttl: 120 }]);
    add(0.02, ethernet(a.mac, r.mac, 0x86dd, ipv6('2001:4860:4860::8888', me6, 17, udp6('2001:4860:4860::8888', me6, 53, 40111, resp), 57)));
    function udp6(src, dst, sp, dp, body) {
      const h = cat(be16(sp), be16(dp), be16(8 + body.length), be16(0));
      const ck = csum(cat(pseudo6(src, dst, 17, 8 + body.length), h, body)) || 0xffff;
      h[6] = ck >> 8; h[7] = ck & 255;
      return cat(h, body);
    }
    return build(f);
  }

  const LIST = [
    { id: 'web', title: 'Loading a web page', blurb: 'ARP → DNS → TCP handshake → HTTP GET → close, then a TLS ClientHello.', make: webBrowsing, learn: 'Watch one request climb the whole stack.' },
    { id: 'lan', title: 'Chatty home network', blurb: 'DHCP, ARP, ping, SSDP, IGMP, mDNS, NBNS and LLMNR.', make: lanChatter, learn: 'The background noise every LAN makes.' },
    { id: 'ipv6', title: 'IPv6 neighbours', blurb: 'Router/Neighbor discovery, MLD, ping6 and an AAAA lookup.', make: ipv6Demo, learn: 'How IPv6 replaces ARP with ICMPv6.' },
  ];

  B.samples = { LIST, build, helpers: { cat, be16, be32, str, mac, ip4, ip6, ethernet, ipv4, ipv6, udp, tcp, csum } };
  if (typeof module !== 'undefined') module.exports = B.samples;
})(typeof window !== 'undefined' ? (window.Bavin = window.Bavin || {}) : (globalThis.Bavin = globalThis.Bavin || {}));
