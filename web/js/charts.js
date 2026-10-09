// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — protocol groups, capture statistics and the traffic chart. */
(function (B) {
  'use strict';
  const { h, svg, clear } = B.dom;
  const U = B.util;

  // Protocols are folded into families so the chart stays readable and every colour is distinguishable.
  const GROUPS = [
    { id: 'tcp', label: 'TCP', protos: ['TCP'] },
    { id: 'udp', label: 'UDP', protos: ['UDP'] },
    { id: 'web', label: 'HTTP / TLS', protos: ['HTTP', 'TLS'] },
    { id: 'dns', label: 'Name lookup', sub: 'DNS · mDNS · LLMNR · NBNS', protos: ['DNS', 'mDNS', 'LLMNR', 'NBNS'] },
    { id: 'dhcp', label: 'DHCP', protos: ['DHCP'] },
    { id: 'arp', label: 'ARP', protos: ['ARP'] },
    { id: 'icmp', label: 'ICMP', sub: 'ICMP · ICMPv6', protos: ['ICMP', 'ICMPv6'] },
    { id: 'igmp', label: 'IGMP', protos: ['IGMP'] },
    { id: 'ssdp', label: 'SSDP', protos: ['SSDP'] },
    { id: 'other', label: 'Other', protos: [] },
  ];
  const BY_PROTO = {};
  for (const g of GROUPS) for (const p of g.protos) BY_PROTO[p] = g;
  const OTHER = GROUPS[GROUPS.length - 1];
  const groupOf = (proto) => BY_PROTO[proto] || OTHER;
  const KNOWN = GROUPS.flatMap((g) => g.protos);
  const filterFor = (g) => (g.protos.length
    ? g.protos.map((p) => 'proto == ' + p).join(' or ')
    : '!(' + KNOWN.map((p) => 'proto == ' + p).join(' or ') + ')');

  function computeStats(packets) {
    const n = packets.length;
    const t0 = n ? packets[0].ts : 0;
    let tEnd = t0, bytes = 0;
    const groups = new Map();
    const hosts = new Map();
    const convs = new Map();
    for (const p of packets) {
      if (p.ts > tEnd) tEnd = p.ts;
      bytes += p.len;
      const g = groupOf(p.proto);
      let gs = groups.get(g.id);
      if (!gs) { gs = { g, packets: 0, bytes: 0 }; groups.set(g.id, gs); }
      gs.packets++; gs.bytes += p.len;
      if (p.ipv) {
        for (const a of [p.src, p.dst]) {
          let hs = hosts.get(a);
          if (!hs) { hs = { addr: a, packets: 0, bytes: 0 }; hosts.set(a, hs); }
          hs.packets++; hs.bytes += p.len;
        }
        const [x, y] = p.src < p.dst ? [p.src, p.dst] : [p.dst, p.src];
        const key = p.flow || x + '|' + y;
        let cs = convs.get(key);
        if (!cs) { cs = { a: x, b: y, proto: p.proto, transport: p.transport || '', ports: p.sport != null ? [p.sport, p.dport] : null, packets: 0, bytes: 0 }; convs.set(key, cs); }
        cs.packets++; cs.bytes += p.len;
        if ((cs.proto === 'TCP' || cs.proto === 'UDP') && p.proto !== cs.proto && p.proto !== 'TCP' && p.proto !== 'UDP') cs.proto = p.proto; // prefer the application protocol
      }
    }
    const duration = tEnd - t0;
    return {
      count: n, bytes, duration, t0,
      groups: [...groups.values()].sort((a, b) => b.bytes - a.bytes),
      hosts: [...hosts.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 8),
      convs: [...convs.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 8),
      buckets: bucketize(packets, t0, duration),
    };
  }

  const NICE = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600];
  function bucketize(packets, t0, duration) {
    const target = 48;
    let size = NICE.find((s) => duration / s <= target) || 3600;
    if (duration === 0) size = 1;
    const count = Math.max(1, Math.floor(duration / size) + 1);
    const buckets = Array.from({ length: count }, (_, i) => ({ t: i * size, packets: 0, bytes: 0, by: {} }));
    for (const p of packets) {
      const b = buckets[Math.min(count - 1, Math.floor((p.ts - t0) / size))];
      const gid = groupOf(p.proto).id;
      const e = b.by[gid] || (b.by[gid] = { packets: 0, bytes: 0 });
      e.packets++; e.bytes += p.len; b.packets++; b.bytes += p.len;
    }
    return { size, list: buckets };
  }

  const niceMax = (v) => {
    if (v <= 0) return 1;
    const e = Math.pow(10, Math.floor(Math.log10(v)));
    const m = v / e;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * e;
  };
  const fmtT = (s, size) => (size < 1 ? s.toFixed(size < 0.01 ? 3 : 2) + 's' : s < 120 ? s.toFixed(s % 1 ? 1 : 0) + 's' : Math.round(s / 60) + 'm');

  // Stacked column chart: one column per time bucket, one segment per protocol family.
  function trafficChart(host, stats, mode, onPick) {
    clear(host);
    const { list, size } = stats.buckets;
    const W = 960, H = 210, m = { l: 48, r: 12, t: 12, b: 28 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const val = (b, gid) => (b.by[gid] ? b.by[gid][mode] : 0);
    const max = niceMax(Math.max(...list.map((b) => b[mode])));
    const colW = iw / list.length;
    const barW = Math.max(1, Math.min(28, colW * 0.78));
    const root = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'chart', role: 'img', 'aria-label': 'Stacked chart of ' + (mode === 'bytes' ? 'bytes' : 'packets') + ' per time slice, split by protocol family. The table below lists the same totals.' });
    // gridlines + y labels
    for (let i = 0; i <= 4; i++) {
      const y = m.t + ih - (ih * i) / 4;
      root.appendChild(svg('line', { x1: m.l, x2: W - m.r, y1: y, y2: y, class: i === 0 ? 'axis' : 'grid' }));
      root.appendChild(svg('text', { x: m.l - 8, y: y + 4, class: 'tick', 'text-anchor': 'end' }, mode === 'bytes' ? U.fmtBytes((max * i) / 4).replace(/\.0 /, ' ') : String(Math.round((max * i) / 4))));
    }
    // x labels
    const every = Math.max(1, Math.ceil(list.length / 8));
    list.forEach((b, i) => {
      if (i % every === 0) root.appendChild(svg('text', { x: m.l + i * colW + colW / 2, y: H - 8, class: 'tick', 'text-anchor': 'middle' }, fmtT(b.t, size)));
    });
    // bars
    const cols = [];
    list.forEach((b, i) => {
      const x = m.l + i * colW + (colW - barW) / 2;
      const gcol = svg('g', { class: 'col' });
      gcol.appendChild(svg('rect', { x: m.l + i * colW, y: m.t, width: colW, height: ih, class: 'hit' }));
      let yy = m.t + ih;
      for (const g of GROUPS) {
        const v = val(b, g.id);
        if (!v) continue;
        const hh = Math.max(1.5, (v / max) * ih);
        yy -= hh;
        const r = svg('rect', { x, y: yy, width: barW, height: hh, class: 'seg' });
        r.style.fill = 'var(--g-' + g.id + ')';
        gcol.appendChild(r);
      }
      root.appendChild(gcol);
      cols.push(gcol);
    });
    const tip = h('div', { class: 'tip', role: 'status', hidden: true });
    host.append(root, tip);
    const show = (i, ev) => {
      const b = list[i];
      clear(tip);
      tip.appendChild(h('strong', null, fmtT(b.t, size) + ' – ' + fmtT(b.t + size, size)));
      tip.appendChild(h('div', { class: 'tip-sum' }, b.packets + ' packet' + (b.packets === 1 ? '' : 's') + ' · ' + U.fmtBytes(b.bytes)));
      for (const g of GROUPS) {
        if (!b.by[g.id]) continue;
        const sw = h('i', { class: 'sw' });
        sw.style.background = 'var(--g-' + g.id + ')';
        tip.appendChild(h('div', { class: 'tip-row' }, sw, h('span', null, g.label), h('b', null, mode === 'bytes' ? U.fmtBytes(b.by[g.id].bytes) : String(b.by[g.id].packets))));
      }
      tip.hidden = false;
      const hr = host.getBoundingClientRect();
      const x = ev.clientX - hr.left, y = ev.clientY - hr.top;
      tip.style.left = Math.min(Math.max(0, x + 14), Math.max(0, hr.width - tip.offsetWidth - 4)) + 'px';
      tip.style.top = Math.max(0, y - tip.offsetHeight - 10) + 'px';
    };
    cols.forEach((g, i) => {
      g.addEventListener('mousemove', (ev) => show(i, ev));
      g.addEventListener('mouseleave', () => { tip.hidden = true; });
      g.addEventListener('click', () => onPick && onPick(list[i], size));
    });
  }

  B.charts = { GROUPS, groupOf, filterFor, computeStats, trafficChart };
})(window.Bavin);
