// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — protocol dissectors.
 *
 * Every packet becomes a stack of layers (link → network → transport → application).
 * Each layer carries named fields with the exact byte range they came from, so the UI can
 * highlight a field in the hex dump and so students can see where each header lives.
 *
 * Protocols: Ethernet, IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP, UDP, TCP, HTTP, DNS, NBNS, LLMNR, SSDP, DHCP
 * (the 15 from the desktop app) plus 802.1Q VLAN, IPv6 extension headers, mDNS (as DNS) and TLS records.
 */
(function (B) {
  'use strict';
  const U = B.util || (typeof require !== 'undefined' ? require('./util.js') : null);
  const LINK = { NULL: 0, ETHERNET: 1, RAW_12: 12, RAW: 101, LOOP: 108, LINUX_SLL: 113, RAW_IPV4: 228, RAW_IPV6: 229 };

  const ETHERTYPES = {
    0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: '802.1Q VLAN', 0x88a8: '802.1ad QinQ', 0x8847: 'MPLS',
    0x88cc: 'LLDP', 0x8863: 'PPPoE Discovery', 0x8864: 'PPPoE Session', 0x0842: 'Wake-on-LAN', 0x8035: 'RARP',
  };
  const IPPROTO = {
    0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 4: 'IPv4-in-IP', 6: 'TCP', 17: 'UDP', 41: 'IPv6-in-IP', 43: 'IPv6-Route',
    44: 'IPv6-Frag', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 60: 'IPv6-Opts', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP',
  };
  const PORTS = {
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 67: 'dhcp-server', 68: 'dhcp-client',
    80: 'http', 110: 'pop3', 123: 'ntp', 137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn', 143: 'imap',
    161: 'snmp', 389: 'ldap', 443: 'https', 445: 'smb', 465: 'smtps', 514: 'syslog', 587: 'submission', 993: 'imaps',
    995: 'pop3s', 1900: 'ssdp', 3306: 'mysql', 3389: 'rdp', 5353: 'mdns', 5355: 'llmnr', 5432: 'postgres', 8080: 'http-alt', 8443: 'https-alt',
  };

  class Trunc extends Error {}
  function need(c, off, n, what) {
    if (off + n > c.end) throw new Trunc((what || 'Header') + ' is cut off (needs ' + n + ' bytes, only ' + Math.max(0, c.end - off) + ' available).');
  }

  function mk(c, id, name, tier, off, len) {
    const l = { id, name, tier, off, len, fields: [], _g: null };
    c.pkt.layers.push(l);
    return l;
  }
  function grp(l, title) { l._g = title; }
  function fld(l, name, off, len, value, hint) {
    const f = { name, off, len, value: String(value) };
    if (hint) f.hint = hint;
    if (l._g) f.group = l._g;
    l.fields.push(f);
    return f;
  }
  function bitsFld(l, name, off, len, defs, value) {
    const set = defs.filter((d) => d[1]).map((d) => d[0]);
    const f = fld(l, name, off, len, value != null ? value : (set.join(', ') || 'none'));
    f.bits = defs.map((d) => ({ n: d[0], on: !!d[1], tip: d[2] || '' }));
    return f;
  }
  const hexv = (n, w) => '0x' + n.toString(16).padStart(w, '0');
  const portName = (p) => (PORTS[p] ? p + ' (' + PORTS[p] + ')' : String(p));

  // ───────────────────────────── link layer ─────────────────────────────
  function dissectLink(c, raw) {
    const lt = raw.linktype;
    if (lt === LINK.ETHERNET) return ethernet(c, 0);
    if (lt === LINK.NULL || lt === LINK.LOOP) {
      need(c, 0, 4, 'Loopback header');
      const l = mk(c, 'eth', 'Loopback (BSD)', 'link', 0, 4);
      const fam = lt === LINK.NULL ? (c.buf[0] | (c.buf[1] << 8) | (c.buf[2] << 16) | (c.buf[3] << 24)) : U.u32(c.buf, 0);
      fld(l, 'Address family', 0, 4, fam === 2 ? 'IPv4 (2)' : fam === 24 || fam === 28 || fam === 30 ? 'IPv6 (' + fam + ')' : fam);
      c.pkt.src = c.pkt.dst = 'loopback';
      return fam === 2 ? ipv4(c, 4) : ipv6(c, 4);
    }
    if (lt === LINK.RAW || lt === LINK.RAW_12 || lt === LINK.RAW_IPV4 || lt === LINK.RAW_IPV6) {
      need(c, 0, 1, 'IP header');
      return c.buf[0] >> 4 === 6 ? ipv6(c, 0) : ipv4(c, 0);
    }
    if (lt === LINK.LINUX_SLL) {
      need(c, 0, 16, 'Linux cooked header');
      const l = mk(c, 'eth', 'Linux cooked capture', 'link', 0, 16);
      const types = ['Unicast to us', 'Broadcast', 'Multicast', 'Unicast to others', 'Sent by us'];
      fld(l, 'Packet type', 0, 2, types[U.u16(c.buf, 0)] || U.u16(c.buf, 0));
      fld(l, 'Link-layer address', 6, Math.min(8, U.u16(c.buf, 4)), U.hexBytes(c.buf, 6, Math.min(8, U.u16(c.buf, 4))).replace(/ /g, ':'));
      const et = U.u16(c.buf, 14);
      fld(l, 'Protocol', 14, 2, hexv(et, 4), ETHERTYPES[et]);
      c.pkt.src = c.pkt.dst = 'cooked';
      return byEtherType(c, et, 16);
    }
    const l = mk(c, 'eth', 'Unknown link type ' + lt, 'link', 0, 0);
    fld(l, 'Link type', 0, 0, lt, 'Bavin does not know this capture link-layer type');
    payload(c, 0, c.end);
  }

  function ethernet(c, off) {
    const b = c.buf;
    need(c, off, 14, 'Ethernet header');
    const l = mk(c, 'eth', 'Ethernet II', 'link', off, 14);
    const dst = U.mac(b, off), src = U.mac(b, off + 6);
    const bcast = dst === 'ff:ff:ff:ff:ff:ff';
    const mcast = !bcast && (b[off] & 1) === 1;
    fld(l, 'Destination MAC', off, 6, dst, bcast ? 'broadcast — everyone on the LAN' : mcast ? 'multicast group' : (b[off] & 2 ? 'locally administered' : 'unicast'));
    fld(l, 'Source MAC', off + 6, 6, src, b[off + 6] & 2 ? 'locally administered (random/virtual)' : undefined);
    let et = U.u16(b, off + 12);
    c.pkt.src = src; c.pkt.dst = dst;
    c.pkt.macSrc = src; c.pkt.macDst = dst;
    if (et <= 1500) {
      fld(l, 'Length (802.3)', off + 12, 2, et, 'IEEE 802.3 frame with LLC — payload not dissected');
      c.pkt.proto = '802.3'; c.pkt.info = 'IEEE 802.3 frame, length ' + et;
      return payload(c, off + 14, c.end);
    }
    fld(l, 'EtherType', off + 12, 2, hexv(et, 4), ETHERTYPES[et] || 'unknown');
    let p = off + 14;
    let guard = 0;
    while ((et === 0x8100 || et === 0x88a8) && guard++ < 2) {
      need(c, p, 4, '802.1Q tag');
      const v = mk(c, 'vlan', '802.1Q VLAN tag', 'link', p, 4);
      const tci = U.u16(b, p);
      fld(v, 'Priority (PCP)', p, 2, tci >> 13);
      fld(v, 'Drop eligible (DEI)', p, 2, (tci >> 12) & 1);
      fld(v, 'VLAN ID', p, 2, tci & 0xfff);
      et = U.u16(b, p + 2);
      fld(v, 'EtherType', p + 2, 2, hexv(et, 4), ETHERTYPES[et] || 'unknown');
      p += 4;
    }
    byEtherType(c, et, p);
  }

  function byEtherType(c, et, off) {
    if (et === 0x0800) return ipv4(c, off);
    if (et === 0x86dd) return ipv6(c, off);
    if (et === 0x0806) return arp(c, off);
    c.pkt.proto = ETHERTYPES[et] || hexv(et, 4);
    c.pkt.info = 'EtherType ' + hexv(et, 4) + (ETHERTYPES[et] ? ' (' + ETHERTYPES[et] + ')' : '') + ' — not dissected';
    payload(c, off, c.end);
  }

  // ───────────────────────────── network layer ─────────────────────────────
  function arp(c, off) {
    const b = c.buf;
    need(c, off, 8, 'ARP header');
    const hlen = b[off + 4], plen = b[off + 5];
    const size = 8 + 2 * hlen + 2 * plen;
    need(c, off, size, 'ARP packet');
    const l = mk(c, 'arp', 'ARP', 'network', off, size);
    const htype = U.u16(b, off), ptype = U.u16(b, off + 2), op = U.u16(b, off + 6);
    fld(l, 'Hardware type', off, 2, htype, htype === 1 ? 'Ethernet' : undefined);
    fld(l, 'Protocol type', off + 2, 2, hexv(ptype, 4), ETHERTYPES[ptype]);
    fld(l, 'Hardware size', off + 4, 1, hlen);
    fld(l, 'Protocol size', off + 5, 1, plen);
    const opName = { 1: 'request', 2: 'reply', 3: 'RARP request', 4: 'RARP reply' }[op] || 'op ' + op;
    fld(l, 'Opcode', off + 6, 2, op, opName);
    let p = off + 8;
    const sha = hlen === 6 ? U.mac(b, p) : U.hexBytes(b, p, hlen);
    fld(l, 'Sender MAC', p, hlen, sha); p += hlen;
    const spa = plen === 4 ? U.ipv4(b, p) : U.hexBytes(b, p, plen);
    fld(l, 'Sender IP', p, plen, spa); p += plen;
    const tha = hlen === 6 ? U.mac(b, p) : U.hexBytes(b, p, hlen);
    fld(l, 'Target MAC', p, hlen, tha, op === 1 ? 'unknown yet — that is what we are asking' : undefined); p += hlen;
    const tpa = plen === 4 ? U.ipv4(b, p) : U.hexBytes(b, p, plen);
    fld(l, 'Target IP', p, plen, tpa);
    const pkt = c.pkt;
    pkt.proto = 'ARP';
    if (op === 1) {
      pkt.info = spa === tpa ? 'Gratuitous ARP for ' + tpa + ' (announcing ' + sha + ')' : 'Who has ' + tpa + '? Tell ' + spa;
      l.summary = spa === tpa ? 'announcement' : 'who has ' + tpa + '?';
    } else if (op === 2) {
      pkt.info = spa + ' is at ' + sha;
      l.summary = spa + ' is at ' + sha;
    } else pkt.info = 'ARP ' + opName;
    pkt.arp = { op, spa, tpa };
    // Ethernet pads short frames — show any leftover bytes as padding.
    if (off + size < c.end) {
      const rest = c.end - (off + size);
      const pl = mk(c, 'data', 'Ethernet padding', 'data', off + size, rest);
      fld(pl, 'Length', off + size, rest, rest + ' bytes', 'frames under 60 bytes are padded to the minimum Ethernet size');
    }
  }

  function ipv4(c, off) {
    const b = c.buf;
    need(c, off, 20, 'IPv4 header');
    const ver = b[off] >> 4, ihl = (b[off] & 15) * 4;
    if (ver !== 4) throw new Trunc('IPv4 version field is ' + ver + ', expected 4.');
    if (ihl < 20) throw new Trunc('IPv4 header length ' + ihl + ' is invalid (minimum 20).');
    need(c, off, ihl, 'IPv4 header');
    const tot = U.u16(b, off + 2);
    const l = mk(c, 'ip', 'IPv4', 'network', off, ihl);
    fld(l, 'Version', off, 1, ver);
    fld(l, 'Header length (IHL)', off, 1, ihl + ' bytes', 'IHL=' + (ihl / 4) + ' × 4-byte words');
    const tos = b[off + 1];
    fld(l, 'Type of service', off + 1, 1, hexv(tos, 2), 'DSCP ' + (tos >> 2) + ', ECN ' + (tos & 3));
    fld(l, 'Total length', off + 2, 2, tot, 'header + payload');
    fld(l, 'Identification', off + 4, 2, U.u16(b, off + 4) + ' (' + hexv(U.u16(b, off + 4), 4) + ')');
    const ff = U.u16(b, off + 6);
    const fo = (ff & 0x1fff) * 8;
    bitsFld(l, 'Flags', off + 6, 1, [['Reserved', ff & 0x8000, 'must be 0'], ['DF', ff & 0x4000, "Don't Fragment"], ['MF', ff & 0x2000, 'More Fragments']]);
    fld(l, 'Fragment offset', off + 6, 2, fo, fo ? 'this is NOT the first fragment' : undefined);
    const ttl = b[off + 8], proto = b[off + 9];
    fld(l, 'Time to live', off + 8, 1, ttl, 'decremented by every router');
    fld(l, 'Protocol', off + 9, 1, proto, IPPROTO[proto] || 'unknown');
    const ck = U.u16(b, off + 10);
    const ok = U.inetChecksum(b, off, ihl) === 0;
    fld(l, 'Header checksum', off + 10, 2, hexv(ck, 4), ok ? 'valid ✓' : 'invalid ✗ (possible capture-side checksum offload)');
    const src = U.ipv4(b, off + 12), dst = U.ipv4(b, off + 16);
    fld(l, 'Source IP', off + 12, 4, src);
    fld(l, 'Destination IP', off + 16, 4, dst);
    if (ihl > 20) fld(l, 'Options', off + 20, ihl - 20, U.hexBytes(b, off + 20, ihl - 20, 16));
    c.pkt.src = src; c.pkt.dst = dst; c.pkt.ipv = 4; c.pkt.ttl = ttl;
    c.pkt.proto = IPPROTO[proto] || 'IPv4';
    c.pkt.info = src + ' → ' + dst + ' (' + (IPPROTO[proto] || 'protocol ' + proto) + ')';
    l.summary = src + ' → ' + dst;
    if (!ok) c.pkt.warn = 'IPv4 header checksum mismatch';
    const end = tot >= ihl && off + tot <= c.end ? off + tot : c.end;
    const saved = c.end;
    c.end = end;
    if (fo > 0) {
      c.pkt.proto = 'IPv4';
      c.pkt.info = 'Fragmented IP protocol (' + (IPPROTO[proto] || proto) + ') offset ' + fo + ' — ' + src + ' → ' + dst;
      payload(c, off + ihl, end, 'Fragment data');
    } else {
      c.fragmented = !!(ff & 0x2000);
      transport(c, proto, off + ihl);
    }
    // Anything after the IP datagram is link-layer padding/trailer.
    if (end < saved && c.pkt.layers[c.pkt.layers.length - 1].id !== 'data') {
      c.end = saved;
      const pl = mk(c, 'data', 'Trailer / padding', 'data', end, saved - end);
      fld(pl, 'Length', end, saved - end, (saved - end) + ' bytes', 'bytes after the IP datagram (usually Ethernet padding)');
    }
    c.end = saved;
  }

  const V6EXT = { 0: 'Hop-by-Hop Options', 43: 'Routing header', 44: 'Fragment header', 60: 'Destination Options' };
  function ipv6(c, off) {
    const b = c.buf;
    need(c, off, 40, 'IPv6 header');
    const ver = b[off] >> 4;
    if (ver !== 6) throw new Trunc('IPv6 version field is ' + ver + ', expected 6.');
    const l = mk(c, 'ip6', 'IPv6', 'network', off, 40);
    const w = U.u32(b, off);
    const tc = (w >>> 20) & 0xff, flow = w & 0xfffff;
    const plen = U.u16(b, off + 4);
    let nh = b[off + 6];
    const hop = b[off + 7];
    const src = U.ipv6(b, off + 8), dst = U.ipv6(b, off + 24);
    fld(l, 'Version', off, 1, 6);
    fld(l, 'Traffic class', off, 2, hexv(tc, 2), 'DSCP ' + (tc >> 2) + ', ECN ' + (tc & 3));
    fld(l, 'Flow label', off + 1, 3, hexv(flow, 5));
    fld(l, 'Payload length', off + 4, 2, plen, 'everything after this 40-byte header');
    fld(l, 'Next header', off + 6, 1, nh, IPPROTO[nh] || 'unknown');
    fld(l, 'Hop limit', off + 7, 1, hop, 'IPv6 name for TTL');
    fld(l, 'Source IP', off + 8, 16, src);
    fld(l, 'Destination IP', off + 24, 16, dst);
    c.pkt.src = src; c.pkt.dst = dst; c.pkt.ipv = 6; c.pkt.ttl = hop;
    c.pkt.proto = 'IPv6';
    c.pkt.info = src + ' → ' + dst + ' (' + (IPPROTO[nh] || 'next header ' + nh) + ')';
    l.summary = src + ' → ' + dst;
    const saved = c.end;
    const end = off + 40 + plen <= c.end ? off + 40 + plen : c.end;
    c.end = end;
    let p = off + 40;
    let guard = 0;
    let fragOff = 0;
    while (V6EXT[nh] !== undefined && guard++ < 6) {
      need(c, p, 8, V6EXT[nh]);
      const next = b[p];
      const hlen = nh === 44 ? 8 : (b[p + 1] + 1) * 8;
      need(c, p, hlen, V6EXT[nh]);
      const e = mk(c, 'ip6ext', 'IPv6 ' + V6EXT[nh], 'network', p, hlen);
      fld(e, 'Next header', p, 1, next, IPPROTO[next] || 'unknown');
      if (nh === 44) {
        const fo = U.u16(b, p + 2);
        fragOff = (fo >> 3) * 8;
        fld(e, 'Fragment offset', p + 2, 2, fragOff);
        fld(e, 'More fragments', p + 3, 1, fo & 1 ? 'yes' : 'no');
        fld(e, 'Identification', p + 4, 4, hexv(U.u32(b, p + 4), 8));
      } else {
        fld(e, 'Header length', p + 1, 1, hlen + ' bytes');
        if (hlen > 2) fld(e, 'Options', p + 2, hlen - 2, U.hexBytes(b, p + 2, hlen - 2, 16));
      }
      c.pkt.info = src + ' → ' + dst + ' (' + V6EXT[nh] + ' → ' + (IPPROTO[next] || next) + ')';
      nh = next;
      p += hlen;
    }
    if (fragOff > 0) { c.pkt.proto = 'IPv6'; payload(c, p, end, 'Fragment data'); } else transport(c, nh, p);
    if (end < saved && c.pkt.layers[c.pkt.layers.length - 1].id !== 'data') {
      c.end = saved;
      const pl = mk(c, 'data', 'Trailer / padding', 'data', end, saved - end);
      fld(pl, 'Length', end, saved - end, (saved - end) + ' bytes');
    }
    c.end = saved;
  }

  // ───────────────────────────── transport layer ─────────────────────────────
  function transport(c, proto, off) {
    if (proto === 6) return tcp(c, off);
    if (proto === 17) return udp(c, off);
    if (proto === 1) return icmp(c, off);
    if (proto === 58) return icmp6(c, off);
    if (proto === 2) return igmp(c, off);
    c.pkt.proto = IPPROTO[proto] || 'IP proto ' + proto;
    payload(c, off, c.end);
  }

  const ICMP_TYPES = {
    0: 'Echo reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo request', 9: 'Router advertisement',
    10: 'Router solicitation', 11: 'Time exceeded', 12: 'Parameter problem', 13: 'Timestamp request', 14: 'Timestamp reply',
  };
  const ICMP_UNREACH = { 0: 'network unreachable', 1: 'host unreachable', 2: 'protocol unreachable', 3: 'port unreachable', 4: 'fragmentation needed (DF set)', 5: 'source route failed', 13: 'administratively prohibited' };

  function icmp(c, off) {
    const b = c.buf;
    need(c, off, 8, 'ICMP header');
    const l = mk(c, 'icmp', 'ICMP', 'transport', off, 8);
    const type = b[off], code = b[off + 1];
    fld(l, 'Type', off, 1, type, ICMP_TYPES[type] || 'unknown');
    fld(l, 'Code', off + 1, 1, code, type === 3 ? ICMP_UNREACH[code] : undefined);
    const ok = U.inetChecksum(b, off, c.end - off) === 0;
    fld(l, 'Checksum', off + 2, 2, hexv(U.u16(b, off + 2), 4), ok ? 'valid ✓' : 'invalid ✗');
    let info = ICMP_TYPES[type] || 'type ' + type;
    if (type === 0 || type === 8) {
      const id = U.u16(b, off + 4), seq = U.u16(b, off + 6);
      fld(l, 'Identifier', off + 4, 2, id);
      fld(l, 'Sequence number', off + 6, 2, seq);
      info += '  id=' + id + ', seq=' + seq + ', ttl=' + (c.pkt.ttl || '?');
    } else if (type === 5) {
      fld(l, 'Gateway', off + 4, 4, U.ipv4(b, off + 4));
    } else if (type === 3 && code === 4) {
      fld(l, 'Next-hop MTU', off + 6, 2, U.u16(b, off + 6));
    } else fld(l, 'Unused', off + 4, 4, hexv(U.u32(b, off + 4), 8));
    if (type === 3) info += ' (' + (ICMP_UNREACH[code] || 'code ' + code) + ')';
    c.pkt.proto = 'ICMP'; c.pkt.info = info; l.summary = ICMP_TYPES[type] || 'type ' + type;
    if ([3, 4, 5, 11, 12].includes(type) && c.end - (off + 8) >= 20) {
      const io = off + 8;
      grp(l, 'Original datagram (the packet that caused this error)');
      fld(l, 'Inner source', io + 12, 4, U.ipv4(b, io + 12));
      fld(l, 'Inner destination', io + 16, 4, U.ipv4(b, io + 16));
      fld(l, 'Inner protocol', io + 9, 1, IPPROTO[b[io + 9]] || b[io + 9]);
      info += ' — original ' + U.ipv4(b, io + 12) + ' → ' + U.ipv4(b, io + 16);
      c.pkt.info = info;
    }
    if (off + 8 < c.end) payload(c, off + 8, c.end, 'ICMP data');
  }

  const ICMP6_TYPES = {
    1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 4: 'Parameter problem', 128: 'Echo request', 129: 'Echo reply',
    130: 'Multicast listener query', 131: 'Multicast listener report', 132: 'Multicast listener done', 133: 'Router solicitation',
    134: 'Router advertisement', 135: 'Neighbor solicitation', 136: 'Neighbor advertisement', 137: 'Redirect', 143: 'Multicast listener report v2',
  };
  function icmp6(c, off) {
    const b = c.buf;
    need(c, off, 4, 'ICMPv6 header');
    const l = mk(c, 'icmp6', 'ICMPv6', 'transport', off, 4);
    const type = b[off], code = b[off + 1];
    fld(l, 'Type', off, 1, type, ICMP6_TYPES[type] || 'unknown');
    fld(l, 'Code', off + 1, 1, code);
    fld(l, 'Checksum', off + 2, 2, hexv(U.u16(b, off + 2), 4));
    let info = ICMP6_TYPES[type] || 'type ' + type;
    let p = off + 4;
    const optionsFrom = (q) => {
      while (q + 2 <= c.end) {
        const t = b[q], n = b[q + 1] * 8;
        if (n === 0 || q + n > c.end) break;
        if (t === 1 || t === 2) fld(l, t === 1 ? 'Source link-layer address' : 'Target link-layer address', q + 2, 6, U.mac(b, q + 2));
        else if (t === 5) fld(l, 'MTU', q + 4, 4, U.u32(b, q + 4));
        else if (t === 3 && n >= 32) fld(l, 'Prefix', q + 16, 16, U.ipv6(b, q + 16) + '/' + b[q + 2], 'valid lifetime ' + U.u32(b, q + 4) + 's');
        else fld(l, 'Option ' + t, q, n, U.hexBytes(b, q + 2, n - 2, 12));
        q += n;
      }
    };
    if (type === 128 || type === 129) {
      need(c, off, 8, 'ICMPv6 echo');
      fld(l, 'Identifier', off + 4, 2, U.u16(b, off + 4));
      fld(l, 'Sequence number', off + 6, 2, U.u16(b, off + 6));
      info += '  id=' + U.u16(b, off + 4) + ', seq=' + U.u16(b, off + 6) + ', hop limit=' + (c.pkt.ttl || '?');
      p = off + 8;
    } else if (type === 135 || type === 136) {
      need(c, off, 24, 'ICMPv6 neighbor message');
      if (type === 136) {
        const fl = b[off + 4];
        bitsFld(l, 'Flags', off + 4, 1, [['Router', fl & 0x80], ['Solicited', fl & 0x40], ['Override', fl & 0x20]]);
      } else fld(l, 'Reserved', off + 4, 4, '0');
      const tgt = U.ipv6(b, off + 8);
      fld(l, 'Target address', off + 8, 16, tgt);
      info = type === 135 ? 'Neighbor Solicitation for ' + tgt : 'Neighbor Advertisement ' + tgt + ' is at …';
      optionsFrom(off + 24);
      if (type === 136 && l.fields.some((f) => f.name === 'Target link-layer address')) {
        info = 'Neighbor Advertisement ' + tgt + ' is at ' + l.fields.find((f) => f.name === 'Target link-layer address').value;
      }
    } else if (type === 133) {
      fld(l, 'Reserved', off + 4, 4, '0');
      optionsFrom(off + 8);
    } else if (type === 134) {
      need(c, off, 16, 'Router advertisement');
      const fl = b[off + 5];
      fld(l, 'Current hop limit', off + 4, 1, b[off + 4]);
      bitsFld(l, 'Flags', off + 5, 1, [['Managed (M)', fl & 0x80, 'use DHCPv6 for addresses'], ['Other (O)', fl & 0x40, 'use DHCPv6 for other info']]);
      fld(l, 'Router lifetime', off + 6, 2, U.u16(b, off + 6) + ' s');
      fld(l, 'Reachable time', off + 8, 4, U.u32(b, off + 8) + ' ms');
      fld(l, 'Retrans timer', off + 12, 4, U.u32(b, off + 12) + ' ms');
      optionsFrom(off + 16);
    } else if (type === 130 || type === 131 || type === 132) {
      need(c, off, 24, 'MLD message');
      fld(l, 'Max response delay', off + 4, 2, U.u16(b, off + 4) + ' ms');
      const g = U.ipv6(b, off + 8);
      fld(l, 'Multicast address', off + 8, 16, g);
      info += ' ' + (g === '::' ? '(general query)' : g);
    } else if (type === 143) {
      need(c, off, 8, 'MLDv2 report');
      fld(l, 'Number of records', off + 6, 2, U.u16(b, off + 6));
      info += ', ' + U.u16(b, off + 6) + ' record(s)';
    } else if (type === 2) {
      fld(l, 'MTU', off + 4, 4, U.u32(b, off + 4));
    } else fld(l, 'Message body', off + 4, Math.max(0, c.end - off - 4), U.hexBytes(b, off + 4, Math.max(0, c.end - off - 4), 12));
    l.len = Math.max(4, Math.min(c.end - off, type === 128 || type === 129 ? 8 : c.end - off));
    c.pkt.proto = 'ICMPv6'; c.pkt.info = info; l.summary = ICMP6_TYPES[type] || 'type ' + type;
    if ((type === 128 || type === 129) && p < c.end) payload(c, p, c.end, 'Echo data');
  }

  const IGMP_TYPES = { 0x11: 'Membership query', 0x12: 'v1 membership report', 0x16: 'v2 membership report', 0x17: 'Leave group', 0x22: 'v3 membership report' };
  function igmp(c, off) {
    const b = c.buf;
    need(c, off, 8, 'IGMP message');
    const type = b[off];
    const l = mk(c, 'igmp', 'IGMP', 'transport', off, Math.min(8, c.end - off));
    fld(l, 'Type', off, 1, hexv(type, 2), IGMP_TYPES[type] || 'unknown');
    const ok = U.inetChecksum(b, off, c.end - off) === 0;
    let info = IGMP_TYPES[type] || 'type ' + hexv(type, 2);
    if (type === 0x22) {
      fld(l, 'Reserved', off + 1, 1, b[off + 1]);
      fld(l, 'Checksum', off + 2, 2, hexv(U.u16(b, off + 2), 4), ok ? 'valid ✓' : 'invalid ✗');
      const n = U.u16(b, off + 6);
      fld(l, 'Number of group records', off + 6, 2, n);
      let p = off + 8;
      const RT = { 1: 'MODE_IS_INCLUDE', 2: 'MODE_IS_EXCLUDE', 3: 'CHANGE_TO_INCLUDE', 4: 'CHANGE_TO_EXCLUDE', 5: 'ALLOW_NEW_SOURCES', 6: 'BLOCK_OLD_SOURCES' };
      const groups = [];
      for (let i = 0; i < n && p + 8 <= c.end; i++) {
        const ns = U.u16(b, p + 2), aux = b[p + 1];
        grp(l, 'Group record ' + (i + 1));
        fld(l, 'Record type', p, 1, RT[b[p]] || b[p]);
        fld(l, 'Multicast address', p + 4, 4, U.ipv4(b, p + 4), ns + ' source(s)');
        groups.push(U.ipv4(b, p + 4));
        p += 8 + ns * 4 + aux * 4;
      }
      l.len = Math.min(c.end - off, p - off);
      info += groups.length ? ' for ' + groups.join(', ') : '';
    } else {
      const mrt = b[off + 1];
      fld(l, type === 0x11 ? 'Max response time' : 'Unused', off + 1, 1, type === 0x11 ? (mrt / 10) + ' s' : mrt);
      fld(l, 'Checksum', off + 2, 2, hexv(U.u16(b, off + 2), 4), ok ? 'valid ✓' : 'invalid ✗');
      const g = U.ipv4(b, off + 4);
      fld(l, 'Group address', off + 4, 4, g, g === '0.0.0.0' ? 'all groups (general query)' : undefined);
      info += ' ' + (g === '0.0.0.0' ? '(general)' : g);
    }
    c.pkt.proto = 'IGMP'; c.pkt.info = info; l.summary = IGMP_TYPES[type] || 'type';
    if (off + l.len < c.end) payload(c, off + l.len, c.end);
  }

  function udp(c, off) {
    const b = c.buf;
    need(c, off, 8, 'UDP header');
    const l = mk(c, 'udp', 'UDP', 'transport', off, 8);
    const sp = U.u16(b, off), dp = U.u16(b, off + 2), len = U.u16(b, off + 4), ck = U.u16(b, off + 6);
    fld(l, 'Source port', off, 2, portName(sp));
    fld(l, 'Destination port', off + 2, 2, portName(dp));
    fld(l, 'Length', off + 4, 2, len, 'header (8) + payload (' + Math.max(0, len - 8) + ')');
    fld(l, 'Checksum', off + 6, 2, hexv(ck, 4), ck === 0 ? 'not used (optional over IPv4)' : undefined);
    const pkt = c.pkt;
    pkt.proto = 'UDP'; pkt.sport = sp; pkt.dport = dp; pkt.transport = 'udp';
    pkt.info = sp + ' → ' + dp + '  Len=' + Math.max(0, len - 8);
    l.summary = sp + ' → ' + dp;
    const end = len >= 8 && off + len <= c.end ? off + len : c.end;
    const saved = c.end;
    c.end = end;
    const p = off + 8;
    if (p < end && !c.fragmented) {
      const head = U.text(b, p, Math.min(12, end - p));
      if (sp === 53 || dp === 53 || sp === 5353 || dp === 5353) dnsLike(c, p, 'dns');
      else if (sp === 137 || dp === 137) dnsLike(c, p, 'nbns');
      else if (sp === 5355 || dp === 5355) dnsLike(c, p, 'llmnr');
      else if (sp === 67 || sp === 68 || dp === 67 || dp === 68) dhcp(c, p);
      else if ((sp === 1900 || dp === 1900) && /^(M-SEARCH|NOTIFY|HTTP\/1)/.test(head)) httpText(c, p, 'ssdp');
      else payload(c, p, end);
    } else if (p < end) payload(c, p, end);
    c.end = saved;
  }

  const TCP_FLAGS = [['CWR', 0x80], ['ECE', 0x40], ['URG', 0x20], ['ACK', 0x10], ['PSH', 0x08], ['RST', 0x04], ['SYN', 0x02], ['FIN', 0x01]];
  const TCP_FLAG_TIPS = {
    CWR: 'Congestion Window Reduced', ECE: 'ECN-Echo', URG: 'Urgent pointer is valid', ACK: 'Acknowledgement number is valid',
    PSH: 'Push — deliver to the app now', RST: 'Reset the connection', SYN: 'Synchronise sequence numbers (open)', FIN: 'No more data from sender (close)',
  };
  const HTTP_RE = /^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT|TRACE) |^HTTP\/1\.[01] /;

  function tcp(c, off) {
    const b = c.buf;
    need(c, off, 20, 'TCP header');
    const doff = (b[off + 12] >> 4) * 4;
    if (doff < 20) throw new Trunc('TCP data offset ' + doff + ' is invalid (minimum 20).');
    need(c, off, doff, 'TCP header');
    const l = mk(c, 'tcp', 'TCP', 'transport', off, doff);
    const sp = U.u16(b, off), dp = U.u16(b, off + 2), seq = U.u32(b, off + 4), ack = U.u32(b, off + 8);
    const fl = b[off + 13], win = U.u16(b, off + 14);
    fld(l, 'Source port', off, 2, portName(sp));
    fld(l, 'Destination port', off + 2, 2, portName(dp));
    const seqF = fld(l, 'Sequence number', off + 4, 4, seq);
    const ackF = fld(l, 'Acknowledgement number', off + 8, 4, ack, (fl & 0x10) ? undefined : 'not used (ACK flag not set)');
    fld(l, 'Header length (data offset)', off + 12, 1, doff + ' bytes', 'offset=' + (doff / 4) + ' × 4-byte words');
    const f = bitsFld(l, 'Flags', off + 13, 1, TCP_FLAGS.map((x) => [x[0], fl & x[1], TCP_FLAG_TIPS[x[0]]]));
    fld(l, 'Window size', off + 14, 2, win, 'how many bytes the sender of this packet can receive');
    fld(l, 'Checksum', off + 16, 2, hexv(U.u16(b, off + 16), 4));
    fld(l, 'Urgent pointer', off + 18, 2, U.u16(b, off + 18), (fl & 0x20) ? undefined : 'unused (URG not set)');
    // options
    let p = off + 20;
    if (doff > 20) {
      grp(l, 'Options');
      const oend = off + doff;
      while (p < oend) {
        const k = b[p];
        if (k === 0) { fld(l, 'End of options', p, 1, 'EOL'); break; }
        if (k === 1) { fld(l, 'No-operation', p, 1, 'NOP', 'padding'); p++; continue; }
        const n = b[p + 1];
        if (n < 2 || p + n > oend) break;
        if (k === 2 && n === 4) fld(l, 'Maximum segment size', p, 4, U.u16(b, p + 2) + ' bytes');
        else if (k === 3 && n === 3) fld(l, 'Window scale', p, 3, '×' + (1 << b[p + 2]), 'shift ' + b[p + 2]);
        else if (k === 4) fld(l, 'SACK permitted', p, 2, 'yes');
        else if (k === 5) fld(l, 'SACK blocks', p, n, (n - 2) / 8 + ' block(s)');
        else if (k === 8 && n === 10) fld(l, 'Timestamps', p, 10, 'TSval ' + U.u32(b, p + 2) + ', TSecr ' + U.u32(b, p + 6));
        else if (k === 34) fld(l, 'TCP Fast Open', p, n, U.hexBytes(b, p + 2, n - 2, 8));
        else fld(l, 'Option kind ' + k, p, n, U.hexBytes(b, p + 2, n - 2, 8));
        p += n;
      }
    }
    const pkt = c.pkt;
    const pstart = off + doff;
    const plen = Math.max(0, c.end - pstart);
    pkt.proto = 'TCP'; pkt.sport = sp; pkt.dport = dp; pkt.transport = 'tcp';
    pkt.tcp = { seq, ack, flags: fl, plen, win, seqF, ackF, flagsF: f };
    l.summary = sp + ' → ' + dp + ' [' + flagNames(fl) + ']';
    pkt.info = tcpInfo(pkt);
    if (plen > 0 && !c.fragmented) {
      const head = U.text(b, pstart, Math.min(16, plen));
      if (HTTP_RE.test(head)) httpText(c, pstart, 'http');
      else if (sp === 53 || dp === 53) dnsLike(c, pstart, 'dns', true);
      else if (looksTls(b, pstart, c.end)) tls(c, pstart);
      else payload(c, pstart, c.end);
    } else if (plen > 0) payload(c, pstart, c.end);
  }

  // Conventional reading order (as in Wireshark): [SYN, ACK], [FIN, PSH, ACK] — not header bit order.
  const FLAG_READ_ORDER = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'];
  function flagNames(fl) {
    const on = TCP_FLAGS.filter((x) => fl & x[1]).map((x) => x[0]);
    on.sort((a, b) => FLAG_READ_ORDER.indexOf(a) - FLAG_READ_ORDER.indexOf(b));
    return on.join(', ') || 'no flags';
  }
  function tcpInfo(pkt, rel) {
    const t = pkt.tcp;
    const seq = rel ? rel.seq : t.seq;
    const ack = rel ? rel.ack : t.ack;
    let s = pkt.sport + ' → ' + pkt.dport + ' [' + flagNames(t.flags) + '] Seq=' + seq;
    if (t.flags & 0x10) s += ' Ack=' + ack;
    s += ' Win=' + t.win + ' Len=' + t.plen;
    return s;
  }

  // ───────────────────────────── application layer ─────────────────────────────
  function payload(c, off, end, title) {
    if (off >= end) return;
    const l = mk(c, 'data', title || 'Payload', 'data', off, end - off);
    const n = end - off;
    fld(l, 'Length', off, n, n + ' bytes');
    fld(l, 'Hex preview', off, Math.min(n, 32), U.hexBytes(c.buf, off, n, 32));
    fld(l, 'Text preview', off, Math.min(n, 64), U.ascii(c.buf, off, Math.min(n, 64)));
    const top = c.pkt.layers[c.pkt.layers.length - 2];
    if (top && !c.pkt.appNote && (top.id === 'tcp' || top.id === 'udp') && c.pkt.info.indexOf(' Len=') < 0) c.pkt.info += ' Len=' + n;
  }

  function httpText(c, off, kind) {
    const b = c.buf;
    const end = c.end;
    const l = mk(c, kind, kind === 'ssdp' ? 'SSDP' : 'HTTP', 'app', off, end - off);
    let p = off;
    const lines = [];
    let headerEnd = -1;
    while (p < end && lines.length < 80) {
      let q = p;
      while (q < end && b[q] !== 0x0a) q++;
      const lineEnd = b[q - 1] === 0x0d ? q - 1 : q;
      if (lineEnd === p) { headerEnd = Math.min(end, q + 1); break; }
      lines.push({ off: p, len: lineEnd - p, text: U.text(b, p, lineEnd - p) });
      p = q + 1;
    }
    const first = lines[0] ? lines[0].text : '';
    let info = first;
    grp(l, 'Start line');
    const req = /^([A-Z-]+) (\S+) (HTTP\/\d\.\d)$/.exec(first);
    const res = /^(HTTP\/\d\.\d) (\d{3})\s?(.*)$/.exec(first);
    if (req) {
      fld(l, 'Method', lines[0].off, req[1].length, req[1]);
      fld(l, 'Target', lines[0].off + req[1].length + 1, req[2].length, req[2]);
      fld(l, 'Version', lines[0].off + lines[0].len - req[3].length, req[3].length, req[3]);
    } else if (res) {
      fld(l, 'Version', lines[0].off, res[1].length, res[1]);
      fld(l, 'Status code', lines[0].off + res[1].length + 1, 3, res[2], STATUS[res[2]] || undefined);
      fld(l, 'Reason', lines[0].off + res[1].length + 5, res[3].length, res[3] || '—');
    } else if (first) fld(l, 'Line', lines[0].off, lines[0].len, first);
    grp(l, 'Headers');
    let host = '', nt = '', clen = -1;
    for (let i = 1; i < lines.length; i++) {
      const m = /^([^:\s][^:]*):\s?(.*)$/.exec(lines[i].text);
      if (!m) continue;
      fld(l, m[1], lines[i].off, lines[i].len, m[2] || '—');
      const k = m[1].toLowerCase();
      if (k === 'host') host = m[2];
      if (k === 'nts') nt = m[2];
      if (k === 'content-length') clen = parseInt(m[2], 10);
    }
    if (headerEnd >= 0 && headerEnd < end) {
      grp(l, 'Body');
      fld(l, 'Body length', headerEnd, end - headerEnd, (end - headerEnd) + ' bytes' + (clen >= 0 ? ' (Content-Length: ' + clen + ')' : ''));
    } else if (headerEnd < 0 && lines.length) {
      fld(l, 'Note', end, 0, 'Headers continue in the next TCP segment');
    }
    if (kind === 'ssdp') {
      if (nt) info += '  (' + nt + ')';
      c.pkt.proto = 'SSDP';
    } else {
      if (req && host) info = req[1] + ' ' + req[2] + ' ' + req[3] + '  (Host: ' + host + ')';
      c.pkt.proto = 'HTTP';
    }
    c.pkt.info = info;
    l.summary = first;
    c.pkt.appNote = true;
  }
  const STATUS = {
    200: 'OK', 201: 'Created', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified', 400: 'Bad Request',
    401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed', 418: "I'm a teapot", 500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
  };

  // DNS, mDNS, LLMNR and NBNS all share the 12-byte header + question/record layout from RFC 1035.
  const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY', 32: 'NB', 33.5: 'NBSTAT' };
  const DNS_RCODE = { 0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name (NXDOMAIN)', 4: 'Not implemented', 5: 'Refused' };
  const NBNS_OPS = { 0: 'Name query', 5: 'Registration', 6: 'Release', 7: 'WACK', 8: 'Refresh' };

  function rrTypeName(t, kind) {
    if (kind === 'nbns') return t === 0x20 ? 'NB' : t === 0x21 ? 'NBSTAT' : 'type ' + t;
    return DNS_TYPES[t] || 'type ' + t;
  }

  function dnsName(b, o, base, end) {
    const labels = [];
    let p = o, next = -1, guard = 0;
    while (guard++ < 128) {
      if (p >= end) throw new Trunc('DNS name runs past the end of the packet.');
      const n = b[p];
      if (n === 0) { p++; break; }
      if ((n & 0xc0) === 0xc0) {
        if (next < 0) next = p + 2;
        p = base + (((n & 0x3f) << 8) | b[p + 1]);
        continue;
      }
      if (p + 1 + n > end) throw new Trunc('DNS label is cut off.');
      labels.push(U.text(b, p + 1, n));
      p += 1 + n;
    }
    return { name: labels.join('.') || '<Root>', next: next >= 0 ? next : p };
  }

  // NetBIOS first-level encoding: 32 chars A–P → 16 bytes (15-char name + service suffix).
  function nbName(enc) {
    const dot = enc.indexOf('.');
    const first = dot < 0 ? enc : enc.slice(0, dot);
    if (first.length !== 32 || !/^[A-P]{32}$/.test(first)) return enc;
    let s = '';
    for (let i = 0; i < 32; i += 2) s += String.fromCharCode(((first.charCodeAt(i) - 65) << 4) | (first.charCodeAt(i + 1) - 65));
    const suffix = s.charCodeAt(15);
    return s.slice(0, 15).replace(/\s+$/, '') + '<' + suffix.toString(16).padStart(2, '0') + '>' + (dot < 0 ? '' : enc.slice(dot));
  }

  function dnsLike(c, off, kind, tcpPrefixed) {
    const b = c.buf;
    let o = off;
    if (tcpPrefixed) {
      if (c.end - off < 2 || U.u16(b, off) + 2 > c.end) return payload(c, off, c.end);
      o += 2;
    }
    if (c.end - o < 12) return payload(c, off, c.end);
    const names = { dns: 'DNS', nbns: 'NBNS', llmnr: 'LLMNR' };
    const sp = c.pkt.sport, dp = c.pkt.dport;
    const isMdns = kind === 'dns' && (sp === 5353 || dp === 5353);
    const l = mk(c, kind, isMdns ? 'mDNS (DNS)' : names[kind], 'app', off, c.end - off);
    if (tcpPrefixed) fld(l, 'TCP length prefix', off, 2, U.u16(b, off), 'DNS over TCP starts with a 2-byte length');
    const id = U.u16(b, o), fl = U.u16(b, o + 2);
    const qd = U.u16(b, o + 4), an = U.u16(b, o + 6), ns = U.u16(b, o + 8), ar = U.u16(b, o + 10);
    const qr = (fl >> 15) & 1, opcode = (fl >> 11) & 15, rcode = fl & 15;
    fld(l, 'Transaction ID', o, 2, hexv(id, 4));
    const flagDefs = [['QR', fl & 0x8000, '1 = response']];
    if (kind === 'nbns') flagDefs.push(['AA', fl & 0x400], ['TC', fl & 0x200], ['RD', fl & 0x100], ['RA', fl & 0x80], ['B', fl & 0x10, 'broadcast']);
    else if (kind === 'llmnr') flagDefs.push(['C', fl & 0x400, 'conflict'], ['TC', fl & 0x200, 'truncated'], ['T', fl & 0x100, 'tentative']);
    else flagDefs.push(['AA', fl & 0x400, 'authoritative answer'], ['TC', fl & 0x200, 'truncated'], ['RD', fl & 0x100, 'recursion desired'], ['RA', fl & 0x80, 'recursion available']);
    bitsFld(l, 'Flags', o + 2, 2, flagDefs, hexv(fl, 4));
    fld(l, 'Opcode', o + 2, 2, opcode, kind === 'nbns' ? NBNS_OPS[opcode] : opcode === 0 ? 'standard query' : undefined);
    fld(l, 'Response code', o + 2, 2, rcode, DNS_RCODE[rcode]);
    fld(l, 'Questions', o + 4, 2, qd);
    fld(l, 'Answer RRs', o + 6, 2, an);
    fld(l, 'Authority RRs', o + 8, 2, ns);
    fld(l, 'Additional RRs', o + 10, 2, ar);

    let p = o + 12;
    const end = c.end;
    const qs = [];
    const answers = [];
    const nameOf = (s) => (kind === 'nbns' ? nbName(s) : s);
    try {
      if (qd) grp(l, 'Questions');
      for (let i = 0; i < Math.min(qd, 16); i++) {
        const r = dnsName(b, p, o, end);
        need(c, r.next, 4, 'DNS question');
        const t = U.u16(b, r.next), cl = U.u16(b, r.next + 2) & 0x7fff;
        const nm = nameOf(r.name);
        fld(l, rrTypeName(t, kind) + ' query', p, r.next + 4 - p, nm, 'class ' + (cl === 1 ? 'IN' : cl));
        qs.push({ name: nm, type: rrTypeName(t, kind) });
        p = r.next + 4;
      }
      const sections = [['Answers', an], ['Authority', ns], ['Additional', ar]];
      for (let si = 0; si < sections.length; si++) {
        const [title, count] = sections[si];
        if (count) grp(l, title);
        for (let i = 0; i < Math.min(count, 32); i++) {
          const r = dnsName(b, p, o, end);
          need(c, r.next, 10, 'DNS record');
          const t = U.u16(b, r.next), ttl = U.u32(b, r.next + 4), rl = U.u16(b, r.next + 8);
          const ro = r.next + 10;
          need(c, ro, rl, 'DNS record data');
          const tn = rrTypeName(t, kind);
          let data = '';
          if (t === 1 && rl === 4) data = U.ipv4(b, ro);
          else if (t === 28 && rl === 16) data = U.ipv6(b, ro);
          else if (kind !== 'nbns' && (t === 2 || t === 5 || t === 12)) data = dnsName(b, ro, o, end).name;
          else if (kind !== 'nbns' && t === 15) data = 'pref ' + U.u16(b, ro) + ' ' + dnsName(b, ro + 2, o, end).name;
          else if (kind !== 'nbns' && t === 33) data = 'prio ' + U.u16(b, ro) + ' weight ' + U.u16(b, ro + 2) + ' port ' + U.u16(b, ro + 4) + ' ' + dnsName(b, ro + 6, o, end).name;
          else if (kind !== 'nbns' && t === 16) {
            const parts = []; let q = ro;
            while (q < ro + rl) { const n = b[q]; parts.push('"' + U.text(b, q + 1, n) + '"'); q += 1 + n; }
            data = parts.join(' ');
          } else if (kind === 'nbns' && t === 0x20 && rl >= 6) data = U.ipv4(b, ro + 2);
          else data = U.hexBytes(b, ro, rl, 12);
          const nm = nameOf(r.name);
          fld(l, nm, p, ro + rl - p, tn + ' ' + data, 'TTL ' + ttl + 's');
          if (si === 0) answers.push(tn + ' ' + data);
          p = ro + rl;
        }
      }
    } catch (e) {
      if (!(e instanceof Trunc)) throw e;
      fld(l, 'Note', p, 0, e.message);
    }
    const q0 = qs[0];
    let info;
    if (kind === 'nbns') {
      info = (NBNS_OPS[opcode] || 'opcode ' + opcode) + (qr ? ' response' : '') + (q0 ? ' ' + q0.type + ' ' + q0.name : '');
      if (qr && answers.length) info += ' → ' + answers.slice(0, 2).join(', ');
    } else {
      info = (qr ? 'Standard query response ' : 'Standard query ') + hexv(id, 4) + (q0 ? ' ' + q0.type + ' ' + q0.name : '');
      if (qr && rcode) info += ' — ' + (DNS_RCODE[rcode] || 'rcode ' + rcode);
      else if (qr && answers.length) info += ' → ' + answers.slice(0, 3).join(', ') + (answers.length > 3 ? ', …' : '');
    }
    c.pkt.proto = isMdns ? 'mDNS' : names[kind];
    c.pkt.info = info;
    c.pkt.appNote = true;
    l.summary = q0 ? q0.type + ' ' + q0.name : names[kind];
  }

  const DHCP_TYPES = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
  const DHCP_OPTS = {
    1: 'Subnet mask', 3: 'Router', 6: 'DNS servers', 12: 'Host name', 15: 'Domain name', 28: 'Broadcast address', 42: 'NTP servers', 43: 'Vendor info',
    50: 'Requested IP', 51: 'Lease time', 53: 'Message type', 54: 'Server identifier', 55: 'Parameter request list', 57: 'Max message size',
    58: 'Renewal time (T1)', 59: 'Rebinding time (T2)', 60: 'Vendor class', 61: 'Client identifier', 81: 'Client FQDN', 119: 'Domain search', 252: 'WPAD',
  };
  function dhcp(c, off) {
    const b = c.buf;
    if (c.end - off < 240) return payload(c, off, c.end);
    const l = mk(c, 'dhcp', 'DHCP', 'app', off, c.end - off);
    const op = b[off];
    fld(l, 'Message op', off, 1, op, op === 1 ? 'BOOTREQUEST (client → server)' : op === 2 ? 'BOOTREPLY (server → client)' : undefined);
    fld(l, 'Hardware type', off + 1, 1, b[off + 1], b[off + 1] === 1 ? 'Ethernet' : undefined);
    fld(l, 'Hardware length', off + 2, 1, b[off + 2]);
    fld(l, 'Hops', off + 3, 1, b[off + 3]);
    const xid = U.u32(b, off + 4);
    fld(l, 'Transaction ID', off + 4, 4, hexv(xid, 8));
    fld(l, 'Seconds elapsed', off + 8, 2, U.u16(b, off + 8));
    const fl = U.u16(b, off + 10);
    bitsFld(l, 'BOOTP flags', off + 10, 2, [['Broadcast', fl & 0x8000, 'ask the server to reply by broadcast']], hexv(fl, 4));
    const ip = (o) => U.ipv4(b, o);
    fld(l, 'Client IP (ciaddr)', off + 12, 4, ip(off + 12));
    fld(l, 'Your IP (yiaddr)', off + 16, 4, ip(off + 16), 'address being offered/assigned');
    fld(l, 'Server IP (siaddr)', off + 20, 4, ip(off + 20));
    fld(l, 'Gateway IP (giaddr)', off + 24, 4, ip(off + 24));
    fld(l, 'Client MAC (chaddr)', off + 28, 6, U.mac(b, off + 28));
    const cookie = U.u32(b, off + 236);
    fld(l, 'Magic cookie', off + 236, 4, hexv(cookie, 8), cookie === 0x63825363 ? 'DHCP ✓' : 'unexpected');
    grp(l, 'Options');
    let p = off + 240, mt = 0, host = '';
    while (p < c.end) {
      const k = b[p];
      if (k === 255) { fld(l, 'End', p, 1, 'end of options'); break; }
      if (k === 0) { p++; continue; }
      const n = b[p + 1];
      if (p + 2 + n > c.end) break;
      const o = p + 2;
      let v;
      if (k === 53) { mt = b[o]; v = DHCP_TYPES[mt] || mt; }
      else if ([1, 3, 6, 28, 42, 50, 54].includes(k)) { const a = []; for (let i = 0; i + 4 <= n; i += 4) a.push(ip(o + i)); v = a.join(', '); }
      else if ([51, 58, 59].includes(k)) v = U.u32(b, o) + ' s';
      else if ([12, 15, 60, 119].includes(k)) { v = U.text(b, o, n); if (k === 12) host = v; }
      else if (k === 55) v = Array.from(b.subarray(o, o + n)).map((x) => DHCP_OPTS[x] || x).join(', ');
      else if (k === 61 && n === 7 && b[o] === 1) v = 'Ethernet ' + U.mac(b, o + 1);
      else if (k === 57) v = U.u16(b, o);
      else v = U.hexBytes(b, o, n, 12);
      fld(l, DHCP_OPTS[k] || 'Option ' + k, p, 2 + n, v);
      p += 2 + n;
    }
    c.pkt.proto = 'DHCP';
    c.pkt.info = 'DHCP ' + (DHCP_TYPES[mt] || (op === 1 ? 'Request' : 'Reply')) + ' - Transaction ID ' + hexv(xid, 8) + (host ? ' (' + host + ')' : '');
    c.pkt.appNote = true;
    l.summary = 'DHCP ' + (DHCP_TYPES[mt] || '');
  }

  // ───────────────────────────── TLS (minimal — not one of the 15 originals) ─────────────────────────────
  const TLS_CT = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat' };
  const TLS_HS = { 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished' };
  const TLS_VER = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
  function looksTls(b, o, end) {
    return end - o >= 5 && b[o] >= 20 && b[o] <= 24 && b[o + 1] === 3 && b[o + 2] <= 4 && U.u16(b, o + 3) <= 16640;
  }
  function tls(c, off) {
    const b = c.buf;
    const l = mk(c, 'tls', 'TLS', 'app', off, c.end - off);
    let p = off, n = 0;
    const infos = [];
    let ver = '';
    while (p + 5 <= c.end && looksTls(b, p, c.end) && n++ < 4) {
      const ct = b[p], v = U.u16(b, p + 1), rl = U.u16(b, p + 3);
      grp(l, 'Record ' + n);
      fld(l, 'Content type', p, 1, ct, TLS_CT[ct]);
      fld(l, 'Record version', p + 1, 2, hexv(v, 4), TLS_VER[v]);
      const complete = p + 5 + rl <= c.end;
      fld(l, 'Record length', p + 3, 2, rl, complete ? undefined : 'continues in the next TCP segment');
      let label = TLS_CT[ct] || 'type ' + ct;
      if (ct === 22 && p + 9 <= c.end) {
        const ht = b[p + 5];
        fld(l, 'Handshake type', p + 5, 1, ht, TLS_HS[ht]);
        label = TLS_HS[ht] || 'Handshake';
        if (ht === 1 && complete) {
          const ch = clientHello(b, p + 5, Math.min(c.end, p + 5 + rl));
          if (ch.sni) { fld(l, 'Server name (SNI)', ch.sniOff, ch.sni.length, ch.sni, 'which website the client wants — sent in clear text'); label += ' (SNI: ' + ch.sni + ')'; }
          if (ch.version) { fld(l, 'Highest version offered', ch.verOff, 2, ch.version); ver = ch.version; }
        }
      } else if (ct === 23) fld(l, 'Encrypted data', p + 5, Math.min(rl, c.end - p - 5), Math.min(rl, c.end - p - 5) + ' bytes', 'unreadable without the session keys');
      infos.push(label);
      p += 5 + rl;
      if (!complete) break;
    }
    l.len = Math.min(c.end - off, p - off);
    c.pkt.proto = 'TLS';
    c.pkt.info = infos.join(', ') || 'TLS';
    c.pkt.appNote = true;
    l.summary = infos[0] || 'TLS';
    if (p < c.end && n < 4) payload(c, p, c.end);
  }
  function clientHello(b, o, end) {
    const out = {};
    try {
      let p = o + 4; // handshake header
      const legacy = U.u16(b, p);
      out.version = TLS_VER[legacy]; out.verOff = p;
      p += 2 + 32;
      p += 1 + b[p];
      p += 2 + U.u16(b, p);
      p += 1 + b[p];
      const extEnd = Math.min(end, p + 2 + U.u16(b, p));
      p += 2;
      while (p + 4 <= extEnd) {
        const t = U.u16(b, p), n = U.u16(b, p + 2), d = p + 4;
        if (t === 0 && n >= 5) { const sl = U.u16(b, d + 3); out.sni = U.text(b, d + 5, sl); out.sniOff = d + 5; }
        if (t === 43 && n >= 3) {
          let best = 0, bestOff = d;
          for (let i = d + 1; i + 1 < d + n; i += 2) { const v = U.u16(b, i); if ((v & 0x0f0f) !== 0x0a0a && v > best) { best = v; bestOff = i; } }
          if (TLS_VER[best]) { out.version = TLS_VER[best] + ' (via supported_versions)'; out.verOff = bestOff; }
        }
        p = d + n;
      }
    } catch (_) { /* partial hello — keep what we have */ }
    return out;
  }

  // ───────────────────────────── driver ─────────────────────────────
  function dissect(raw, no, t0) {
    const buf = raw.data;
    const pkt = {
      no, ts: raw.ts, rel: raw.ts - t0, len: raw.origLen || buf.length, caplen: buf.length, data: buf,
      layers: [], src: '', dst: '', proto: '?', info: '',
    };
    const c = { buf, pkt, end: buf.length, fragmented: false };
    try {
      dissectLink(c, raw);
    } catch (e) {
      if (!(e instanceof Trunc)) throw e;
      pkt.malformed = e.message;
      pkt.info = 'Malformed: ' + e.message;
    }
    if (pkt.caplen < pkt.len && !pkt.malformed) pkt.warn = pkt.warn || 'Capture truncated (' + pkt.caplen + ' of ' + pkt.len + ' bytes saved)';
    pkt.ids = pkt.layers.map((l) => l.id);
    pkt.top = pkt.layers.length ? pkt.layers[pkt.layers.length - 1] : null;
    return pkt;
  }

  // A session keeps the cross-packet state (capture start time, TCP flows for relative sequence numbers),
  // so packets can be dissected one batch at a time while a live capture is running.
  function createSession(t0) {
    let start = t0;
    const flows = new Map();
    return {
      add(raw, no) {
        if (start == null) start = raw.ts;
        const p = dissect(raw, no, start);
        if (p.tcp) {
          const a = p.src + ':' + p.sport, z = p.dst + ':' + p.dport;
          const fwd = a < z;
          const key = fwd ? a + '|' + z : z + '|' + a;
          let f = flows.get(key);
          if (!f) {
            if (flows.size > 20000) flows.clear(); // bound memory on very long live captures
            f = {}; flows.set(key, f);
          }
          const me = fwd ? 'a' : 'z', peer = fwd ? 'z' : 'a';
          if (f[me] === undefined) f[me] = p.tcp.seq;
          const rel = { seq: (p.tcp.seq - f[me]) >>> 0, ack: f[peer] !== undefined ? (p.tcp.ack - f[peer]) >>> 0 : p.tcp.ack };
          p.tcp.rel = rel;
          p.tcp.seqF.hint = 'relative: ' + rel.seq;
          if (p.tcp.flags & 0x10 && f[peer] !== undefined) p.tcp.ackF.hint = 'relative: ' + rel.ack;
          if (p.top && (p.top.id === 'tcp' || p.top.id === 'data')) p.info = tcpInfo(p, rel);
          p.flow = key;
        } else if (p.transport === 'udp') {
          const a = p.src + ':' + p.sport, z = p.dst + ':' + p.dport;
          p.flow = a < z ? a + '|' + z : z + '|' + a;
        }
        return p;
      },
    };
  }

  function dissectAll(rawPackets) {
    const session = createSession(rawPackets.length ? rawPackets[0].ts : 0);
    const out = new Array(rawPackets.length);
    for (let i = 0; i < rawPackets.length; i++) out[i] = session.add(rawPackets[i], i + 1);
    return out;
  }

  B.dissect = { dissect, dissectAll, createSession, ETHERTYPES, IPPROTO, PORTS };
  if (typeof module !== 'undefined') module.exports = B.dissect;
})(typeof window !== 'undefined' ? (window.Bavin = window.Bavin || {}) : (globalThis.Bavin = globalThis.Bavin || {}));
