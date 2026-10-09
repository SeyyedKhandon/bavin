// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — packet filter (a small, forgiving subset of Wireshark display filters).
 *
 *   tcp && port == 443          dns or dhcp            !arp
 *   ip.addr == 192.168.1.0/24   ip.src != 10.0.0.1     len > 1000
 *   tcp.flags.syn == 1          info contains "GET"    192.168.1.105     (bare text searches everything)
 */
(function (B) {
  'use strict';

  const ALIASES = { ip: 'ip', ipv4: 'ip', ipv6: 'ip6', ip6: 'ip6', icmpv6: 'icmp6', icmp6: 'icmp6', ethernet: 'eth', arp: 'arp', vlan: 'vlan' };
  const KNOWN_LAYERS = ['eth', 'vlan', 'ip', 'ip6', 'ip6ext', 'arp', 'icmp', 'icmp6', 'igmp', 'tcp', 'udp', 'dns', 'nbns', 'llmnr', 'dhcp', 'ssdp', 'http', 'tls', 'data'];
  const TCP_BITS = { fin: 0x01, syn: 0x02, rst: 0x04, psh: 0x08, ack: 0x10, urg: 0x20, ece: 0x40, cwr: 0x80 };

  function tokenize(s) {
    const re = /\s*(\(|\)|&&|\|\||==|!=|>=|<=|>|<|!|"[^"]*"|[^\s()!=<>&|]+)/y;
    const out = [];
    let m;
    re.lastIndex = 0;
    while (re.lastIndex < s.length && (m = re.exec(s))) out.push(m[1]);
    if (re.lastIndex < s.trimEnd().length) throw new Error('Unexpected character near "' + s.slice(re.lastIndex, re.lastIndex + 6) + '"');
    return out;
  }

  function ipv4ToInt(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) return null;
    const p = m.slice(1).map(Number);
    if (p.some((x) => x > 255)) return null;
    return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  }

  // Equality that understands CIDR for IPv4 and is case-insensitive for MAC/IPv6.
  function addrMatcher(value) {
    const cidr = /^(.+)\/(\d{1,2})$/.exec(value);
    if (cidr && ipv4ToInt(cidr[1]) !== null) {
      const bits = +cidr[2];
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      const net = ipv4ToInt(cidr[1]) & mask;
      return (a) => { const n = ipv4ToInt(a); return n !== null && ((n & mask) >>> 0) === (net >>> 0); };
    }
    const v = value.toLowerCase();
    return (a) => a != null && a.toLowerCase() === v;
  }

  function fieldGetter(name) {
    const n = name.toLowerCase();
    const isIp = (p) => !!p.ipv;
    switch (n) {
      case 'ip.addr': return { kind: 'addr', get: (p) => (isIp(p) ? [p.src, p.dst] : []) };
      case 'ip.src': return { kind: 'addr', get: (p) => (isIp(p) ? [p.src] : []) };
      case 'ip.dst': return { kind: 'addr', get: (p) => (isIp(p) ? [p.dst] : []) };
      case 'eth.addr': case 'mac': return { kind: 'addr', get: (p) => [p.macSrc, p.macDst].filter(Boolean) };
      case 'eth.src': return { kind: 'addr', get: (p) => [p.macSrc].filter(Boolean) };
      case 'eth.dst': return { kind: 'addr', get: (p) => [p.macDst].filter(Boolean) };
      case 'src': return { kind: 'addr', get: (p) => [p.src] };
      case 'dst': return { kind: 'addr', get: (p) => [p.dst] };
      case 'addr': return { kind: 'addr', get: (p) => [p.src, p.dst] };
      case 'port': return { kind: 'num', get: (p) => [p.sport, p.dport].filter((x) => x != null) };
      case 'tcp.port': return { kind: 'num', get: (p) => (p.transport === 'tcp' ? [p.sport, p.dport] : []) };
      case 'udp.port': return { kind: 'num', get: (p) => (p.transport === 'udp' ? [p.sport, p.dport] : []) };
      case 'srcport': case 'tcp.srcport': case 'udp.srcport': return { kind: 'num', get: (p) => (p.sport != null ? [p.sport] : []) };
      case 'dstport': case 'tcp.dstport': case 'udp.dstport': return { kind: 'num', get: (p) => (p.dport != null ? [p.dport] : []) };
      case 'len': case 'frame.len': case 'length': return { kind: 'num', get: (p) => [p.len] };
      case 'frame.number': case 'no': return { kind: 'num', get: (p) => [p.no] };
      case 'ttl': case 'ip.ttl': return { kind: 'num', get: (p) => (p.ttl != null ? [p.ttl] : []) };
      case 'info': return { kind: 'text', get: (p) => [p.info] };
      case 'proto': case 'protocol': return { kind: 'text', get: (p) => [p.proto] };
      default: {
        const m = /^tcp\.flags\.(\w+)$/.exec(n);
        if (m && TCP_BITS[m[1]]) return { kind: 'num', get: (p) => (p.tcp ? [(p.tcp.flags & TCP_BITS[m[1]]) ? 1 : 0] : []) };
        return null;
      }
    }
  }

  function textOf(p) {
    return (p.no + ' ' + p.proto + ' ' + p.src + ' ' + p.dst + ' ' + p.info).toLowerCase();
  }

  function compile(src) {
    const text = (src || '').trim();
    if (!text) return { fn: null, error: null };
    try {
      const toks = tokenize(text);
      let i = 0;
      const peek = () => toks[i];
      const next = () => toks[i++];
      const unq = (t) => (t && t[0] === '"' ? t.slice(1, -1) : t);

      function parseOr() {
        let l = parseAnd();
        while (peek() === '||' || (peek() || '').toLowerCase() === 'or') { next(); const r = parseAnd(); const a = l; l = (p) => a(p) || r(p); }
        return l;
      }
      function parseAnd() {
        let l = parseNot();
        for (;;) {
          const t = peek();
          if (t === '&&' || (t || '').toLowerCase() === 'and') next();
          else if (t === undefined || t === ')' || t === '||' || (t || '').toLowerCase() === 'or') break;
          const r = parseNot(); const a = l; l = (p) => a(p) && r(p);
        }
        return l;
      }
      function parseNot() {
        const t = peek();
        if (t === '!' || (t || '').toLowerCase() === 'not') { next(); const e = parseNot(); return (p) => !e(p); }
        return parseAtom();
      }
      function parseAtom() {
        const t = next();
        if (t === undefined) throw new Error('The filter ends unexpectedly.');
        if (t === '(') {
          const e = parseOr();
          if (next() !== ')') throw new Error('Missing closing parenthesis.');
          return e;
        }
        const OPS = ['==', '!=', '>=', '<=', '>', '<'];
        const nxt = peek();
        const nxtWord = (nxt || '').toLowerCase();
        if (OPS.includes(nxt) || nxtWord === 'contains') {
          const g = fieldGetter(t);
          if (!g) throw new Error('Unknown field "' + t + '". Try ip.addr, port, len, info, tcp.flags.syn …');
          next();
          const raw = next();
          if (raw === undefined) throw new Error('Missing value after ' + nxt + '.');
          const val = unq(raw);
          if (nxtWord === 'contains') { const v = val.toLowerCase(); return (p) => g.get(p).some((x) => String(x).toLowerCase().includes(v)); }
          if (g.kind === 'num') {
            const n = Number(val);
            if (Number.isNaN(n)) throw new Error('"' + val + '" is not a number.');
            const cmp = { '==': (a) => a === n, '!=': (a) => a !== n, '>': (a) => a > n, '<': (a) => a < n, '>=': (a) => a >= n, '<=': (a) => a <= n }[nxt];
            // != means "none of the values equal" so that `port != 80` excludes both directions.
            return nxt === '!=' ? (p) => { const v = g.get(p); return v.length > 0 && v.every(cmp); } : (p) => g.get(p).some(cmp);
          }
          if (nxt !== '==' && nxt !== '!=') throw new Error(nxt + ' only works on numeric fields.');
          const m = g.kind === 'addr' ? addrMatcher(val) : ((v) => (a) => String(a).toLowerCase() === v)(val.toLowerCase());
          return nxt === '==' ? (p) => g.get(p).some(m) : (p) => { const v = g.get(p); return v.length > 0 && !v.some(m); };
        }
        const lower = unq(t).toLowerCase();
        const id = ALIASES[lower] || lower;
        if (t[0] !== '"' && (KNOWN_LAYERS.includes(id) || lower === 'mdns')) {
          if (lower === 'mdns') return (p) => p.proto === 'mDNS';
          return (p) => p.ids.indexOf(id) >= 0;
        }
        if (t[0] !== '"' && ['syn', 'ack', 'fin', 'rst', 'psh'].includes(lower)) {
          return (p) => !!p.tcp && (p.tcp.flags & TCP_BITS[lower]) !== 0;
        }
        return (p) => textOf(p).includes(lower);
      }

      const fn = parseOr();
      if (i < toks.length) throw new Error('Unexpected "' + toks[i] + '".');
      return { fn, error: null };
    } catch (e) {
      return { fn: null, error: e.message };
    }
  }

  B.filter = { compile };
  if (typeof module !== 'undefined') module.exports = B.filter;
})(typeof window !== 'undefined' ? (window.Bavin = window.Bavin || {}) : (globalThis.Bavin = globalThis.Bavin || {}));
