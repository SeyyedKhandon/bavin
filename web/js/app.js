// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — application shell: loading captures, packet list, stacked layer view, hex dump, overview. */
(function () {
  'use strict';
  const B = window.Bavin;
  const { h, svg, clear } = B.dom;
  const U = B.util;
  const $ = (id) => document.getElementById(id);

  const TIER_LABEL = { link: 'Link', network: 'Network', transport: 'Transport', app: 'Application', data: 'Data' };
  const BLURBS = {
    eth: 'Moves a frame between two devices on the same local network. Addresses here are MACs — hardware identifiers of network cards.',
    vlan: 'A tag that splits one physical network into several virtual LANs.',
    ip: 'Carries a packet across networks, hop by hop, using IP addresses. The TTL shrinks at every router so lost packets cannot circle forever.',
    ip6: 'IPv6, the successor to IPv4: 128-bit addresses and a simpler fixed-size header. “Hop limit” is its TTL.',
    ip6ext: 'Optional extra headers chained between the IPv6 header and the transport layer.',
    arp: 'Asks “who has this IP address?” so a device can learn the MAC address it must send frames to on the local network.',
    icmp: 'Diagnostics and error reports for IP. It is what ping and traceroute are built on.',
    icmp6: 'ICMP for IPv6. It also does ARP’s job (Neighbor Discovery) and lets hosts configure themselves from router advertisements.',
    igmp: 'Tells routers which devices want to receive a multicast group, so streams are only sent where they are wanted.',
    udp: 'Fast, connectionless delivery: no handshake, no retransmission, no ordering. The app handles loss if it cares.',
    tcp: 'A reliable, ordered byte stream. Sequence and acknowledgement numbers detect loss; the SYN, FIN and RST flags open and close the connection.',
    http: 'The web’s request/response protocol. Without TLS it is plain text, readable by anyone on the path.',
    tls: 'Encrypts application data. The handshake picks keys (and, in the clear, names the site via SNI); after that the payload is unreadable.',
    dns: 'Turns names like example.com into IP addresses. The same message format is reused by mDNS.',
    nbns: 'NetBIOS Name Service — legacy Windows name lookup on a local network. Names are encoded two letters per byte.',
    llmnr: 'Link-Local Multicast Name Resolution — Windows asking nearby devices for a name when DNS has no answer.',
    dhcp: 'Hands out an IP address and network settings to a device that joins the network. The four steps are Discover, Offer, Request, ACK.',
    ssdp: 'Simple Service Discovery (UPnP): how TVs, printers and routers announce themselves on a LAN.',
    data: 'Bytes Bavin does not decode as a known protocol.',
  };
  const PROTOCOL_NAMES = ['Ethernet', 'IPv4', 'IPv6', 'ARP', 'ICMP', 'ICMPv6', 'IGMP', 'UDP', 'TCP', 'HTTP', 'DNS', 'NBNS', 'LLMNR', 'SSDP', 'DHCP'];

  const S = {
    name: '', format: '', packets: [], view: [], sel: -1, filter: '', fn: null, stats: null,
    selNo: -1, tab: 'packets', wireOrder: false, chartMode: 'bytes', pinned: null, chipExpr: '',
  };

  // ───────────────────────────── helpers ─────────────────────────────
  function lsGet(k) { try { return localStorage.getItem(k); } catch (_) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* private mode etc. */ } }

  let toastTimer = 0;
  function toast(msg, bad) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.toggle('bad', !!bad);
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, bad ? 7000 : 3500);
  }
  const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));
  async function busy(msg) { $('busyText').textContent = msg; $('busy').hidden = false; await nextFrame(); }
  const unbusy = () => { $('busy').hidden = true; };
  const fmtRel = (s) => (s < 100 ? s.toFixed(4) : s.toFixed(2));
  const badge = (proto) => h('span', { class: 'badge', 'data-g': B.charts.groupOf(proto).id }, proto);

  // ───────────────────────────── theme ─────────────────────────────
  function effectiveTheme() {
    const t = document.documentElement.dataset.theme;
    return t || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }
  function initTheme() {
    const saved = lsGet('bavin-theme');
    if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
    $('btnTheme').addEventListener('click', () => {
      const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      lsSet('bavin-theme', next);
    });
  }

  // ───────────────────────────── loading ─────────────────────────────
  async function loadFile(file) {
    if (!file) return;
    if (file.size > 1.5e9) return toast('That file is over 1.5 GB — too large to analyze in a browser tab. Try trimming it with editcap or tcpdump -c.', true);
    try {
      await busy('Reading ' + file.name + '…');
      const buf = await file.arrayBuffer();
      const parsed = B.pcap.parse(buf);
      await loadPackets(file.name, parsed.packets, parsed.format);
    } catch (e) {
      unbusy();
      toast(e.message || String(e), true);
    }
  }

  async function loadPackets(name, raws, format) {
    if (!raws.length) { unbusy(); return toast('That capture contains no packets.', true); }
    leaveLive();
    $('busyText').textContent = 'Dissecting ' + raws.length.toLocaleString() + ' packets…';
    await nextFrame();
    S.packets = B.dissect.dissectAll(raws);
    S.name = name; S.format = format;
    S.stats = B.charts.computeStats(S.packets);
    S.filter = ''; S.fn = null; S.chipExpr = ''; S.sel = -1; S.pinned = null;
    $('workspace').dataset.view = 'list';
    $('filter').value = '';
    $('filterMsg').textContent = '';
    $('filterClear').hidden = true;
    $('landing').hidden = true;
    $('tabs').hidden = false;
    buildChips();
    applyFilter();
    setTab('packets');
    updateFileInfo();
    renderOverview();
    unbusy();
    if (S.view.length) select(0, true);
    $('listBody').focus({ preventScroll: true });
  }

  function updateFileInfo() {
    const st = S.stats;
    const fi = $('fileinfo');
    clear(fi);
    fi.append(h('b', null, S.name), ' · ' + st.count.toLocaleString() + ' packets · ' + U.fmtBytes(st.bytes) + ' · ' + U.fmtDuration(st.duration));
    document.title = S.name + ' — Bavin Web';
  }

  async function loadSample(sample) {
    try {
      await busy('Building sample…');
      const raws = sample.make();
      await loadPackets(sample.title + ' (sample)', raws, 'sample');
    } catch (e) { unbusy(); toast(e.message, true); }
  }

  function downloadBlob(bytes, filename, type) {
    const url = URL.createObjectURL(new Blob([bytes], { type }));
    const a = h('a', { href: url, download: filename });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ───────────────────────────── filter / chips ─────────────────────────────
  function applyFilter() {
    const keep = S.view[S.sel] ? S.view[S.sel].no : -1;
    S.view = S.fn ? S.packets.filter(S.fn) : S.packets;
    const idx = keep >= 0 ? S.view.findIndex((p) => p.no === keep) : -1;
    S.sel = idx;
    $('listSpacer').style.height = S.view.length * rowH() + 'px';
    renderList();
    renderFoot();
    if (idx < 0) { renderDetail(null); if (S.view.length && keep >= 0) select(0, true); }
  }

  function setFilter(text, fromChip) {
    S.filter = text;
    const r = B.filter.compile(text);
    const wrap = $('filter').parentElement;
    wrap.classList.toggle('bad', !!r.error);
    $('filter').setAttribute('aria-invalid', r.error ? 'true' : 'false');
    $('filterMsg').textContent = r.error || '';
    $('filterClear').hidden = !text;
    if (!fromChip) S.chipExpr = '';
    syncChips();
    if (r.error) return;
    S.fn = r.fn;
    applyFilter();
  }

  function buildChips() {
    const box = clear($('chips'));
    for (const gs of S.stats.groups) {
      const g = gs.g;
      const dot = h('i'); dot.style.background = 'var(--g-' + g.id + ')';
      const expr = B.charts.filterFor(g);
      box.appendChild(h('button', {
        class: 'chip', type: 'button', 'aria-pressed': 'false', dataset: { expr }, title: g.sub || g.label,
        onclick: () => { const on = S.chipExpr === expr; $('filter').value = on ? '' : expr; S.chipExpr = on ? '' : expr; setFilter(on ? '' : expr, true); },
      }, dot, g.label, h('b', null, String(gs.packets))));
    }
  }
  // During a live capture the counts change constantly; only rebuild the chips when a new family appears.
  function refreshChips() {
    const have = [...$('chips').children].map((c) => c.dataset.expr).join('|');
    const want = S.stats.groups.map((gs) => B.charts.filterFor(gs.g)).join('|');
    if (have !== want) return buildChips();
    [...$('chips').children].forEach((c, i) => { c.lastChild.textContent = String(S.stats.groups[i].packets); });
  }
  function syncChips() {
    for (const c of $('chips').children) c.setAttribute('aria-pressed', String(c.dataset.expr === S.chipExpr && S.chipExpr !== ''));
  }

  function renderFoot() {
    const n = S.view.length, total = S.packets.length;
    $('listFoot').textContent = n === total ? total.toLocaleString() + ' packets' : n.toLocaleString() + ' of ' + total.toLocaleString() + ' packets match';
  }

  function exportCsv() {
    const q = (s) => '"' + String(s).replace(/"/g, '""') + '"';
    const lines = ['No,Time,Source,Destination,Protocol,Length,Info'];
    for (const p of S.view) lines.push([p.no, p.rel.toFixed(6), q(p.src), q(p.dst), p.proto, p.len, q(p.info)].join(','));
    downloadBlob(lines.join('\n'), S.name.replace(/\.[^.]+$/, '').replace(/[^\w.-]+/g, '_') + '.csv', 'text/csv');
  }

  // ───────────────────────────── packet list (virtualised) ─────────────────────────────
  const rowH = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--row-h')) || 48;

  function renderList() {
    const body = $('listBody');
    const spacer = $('listSpacer');
    const RH = rowH();
    spacer.style.height = S.view.length * RH + 'px';
    const first = Math.max(0, Math.floor(body.scrollTop / RH) - 4);
    const last = Math.min(S.view.length, Math.ceil((body.scrollTop + body.clientHeight) / RH) + 4);
    const frag = document.createDocumentFragment();
    for (let i = first; i < last; i++) {
      const p = S.view[i];
      const row = h('div', {
        class: 'row' + (p.warn || p.malformed ? ' warn' : ''), role: 'option', id: 'r' + p.no, 'aria-selected': String(i === S.sel), dataset: { i },
        title: p.warn || p.malformed || '',
      },
      h('span', { class: 'n' }, String(p.no)),
      h('span', { class: 't' }, fmtRel(p.rel)),
      h('span', { class: 'p' }, badge(p.proto)),
      h('span', { class: 'a' }, p.src, h('span', { class: 'arrow' }, '→'), p.dst),
      h('span', { class: 'l' }, String(p.len)),
      h('span', { class: 'i' }, p.info));
      row.style.top = i * RH + 'px';
      frag.appendChild(row);
    }
    for (const old of [...spacer.children]) old.remove();
    spacer.appendChild(frag);
    if (S.view.length === 0) spacer.appendChild(h('div', { class: 'emptyrows' }, S.packets.length ? 'No packets match this filter.' : 'No packets.'));
  }

  function select(i, scroll) {
    if (i < 0 || i >= S.view.length) return;
    S.sel = i;
    S.selNo = S.view[i].no;
    S.pinned = null;
    const body = $('listBody');
    if (scroll) {
      const RH = rowH();
      const top = i * RH, bottom = top + RH;
      if (top < body.scrollTop) body.scrollTop = top;
      else if (bottom > body.scrollTop + body.clientHeight) body.scrollTop = bottom - body.clientHeight;
    }
    renderList();
    body.setAttribute('aria-activedescendant', 'r' + S.view[i].no);
    renderDetail(S.view[i]);
  }

  // ───────────────────────────── detail: stack + hex ─────────────────────────────
  let hexBytes = [], ascBytes = [], curPkt = null, fieldEls = [];

  function renderDetail(p) {
    curPkt = p;
    const head = clear($('detailHead')), stack = clear($('stack'));
    $('detailEmpty').hidden = !!p;
    fieldEls = [];
    if (!p) { clear($('hex')); head.appendChild(h('span', { class: 'meta' }, ' ')); return; }

    head.append(
      h('button', { class: 'btn ghost small back', type: 'button', onclick: () => { $('workspace').dataset.view = 'list'; } }, '← Packets'),
      h('span', { class: 'title' }, 'Packet ' + p.no),
      h('span', { class: 'meta' }, p.len + ' bytes' + (p.caplen < p.len ? ' (' + p.caplen + ' captured)' : '') + ' · +' + fmtRel(p.rel) + ' s' + ' · ' + new Date(p.ts * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC')),
      h('span', { class: 'spacer-x' }));
    if (p.transport && p.flow) {
      head.appendChild(h('button', {
        class: 'btn ghost small', type: 'button', title: 'Filter the list to this connection',
        onclick: () => { const e = 'ip.addr == ' + p.src + ' && ip.addr == ' + p.dst + ' && port == ' + p.sport + ' && port == ' + p.dport; $('filter').value = e; setFilter(e); },
      }, 'Only this conversation'));
    }

    if (p.malformed) stack.appendChild(h('div', { class: 'warnbar' }, '⚠ Malformed packet: ' + p.malformed));
    else if (p.warn) stack.appendChild(h('div', { class: 'warnbar' }, '⚠ ' + p.warn));

    // proportional byte bar
    const bar = h('div', { class: 'bytebar', role: 'group', 'aria-label': 'Layers by size. Click one to jump to it.' });
    const total = p.caplen || 1;
    p.layers.forEach((l, i) => {
      if (l.len <= 0) return;
      const b = h('button', { type: 'button', dataset: { tier: l.tier }, title: l.name + ' — ' + l.len + ' bytes', onclick: () => focusLayer(i) }, l.name);
      b.style.flex = Math.max(l.len, total * 0.07) + ' 1 0';
      bar.appendChild(b);
    });
    const stackbar = h('div', { class: 'stackbar' },
      h('span', null, S.wireOrder ? 'On the wire: outermost header first.' : 'Top of the stack first. Read bottom-up to see how the data was wrapped.'),
      h('button', { class: 'btn ghost small', type: 'button', onclick: () => { S.wireOrder = !S.wireOrder; lsSet('bavin-order', S.wireOrder ? 'wire' : 'stack'); renderDetail(curPkt); } }, S.wireOrder ? 'Show stack order' : 'Show wire order'));

    // DOM order == visual order, so keyboard focus follows what the eye sees.
    const order = p.layers.map((l, i) => i);
    if (!S.wireOrder) order.reverse();
    const layersBox = h('div', { class: 'stack' }, ...order.map((i) => layerCard(p.layers[i], i)));
    stack.append(bar, stackbar, layersBox);

    renderHex(p);
    $('detailScroll').scrollTop = 0;
  }

  function layerCard(l, idx) {
    const open = true;
    const chev = svg('svg', { class: 'chev', viewBox: '0 0 16 16', 'aria-hidden': 'true' }, svg('path', { d: 'm4 6 4 4 4-4', fill: 'none', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));
    const range = l.len > 0 ? 'bytes ' + l.off + '–' + (l.off + l.len - 1) + ' · ' + l.len + ' B' : '';
    const card = h('section', { class: 'layer', dataset: { tier: l.tier, open: String(open), idx } });
    const hd = h('button', { class: 'lh', type: 'button', 'aria-expanded': String(open) },
      h('span', { class: 'tier' }, TIER_LABEL[l.tier]),
      h('span', { class: 'name' }, l.name),
      h('span', { class: 'sum' }, l.summary || ''),
      h('span', { class: 'range' }, range), chev);
    hd.addEventListener('click', () => { const o = card.dataset.open !== 'true'; card.dataset.open = String(o); hd.setAttribute('aria-expanded', String(o)); });
    hd.addEventListener('mouseenter', () => markLayer(l, true));
    hd.addEventListener('mouseleave', () => markLayer(l, false));

    const body = h('div', { class: 'lb' });
    if (BLURBS[l.id]) body.appendChild(h('p', { class: 'blurb' }, BLURBS[l.id]));
    const grid = h('div', { class: 'grid' });
    let lastGroup = null;
    for (const f of l.fields) {
      if (f.group !== lastGroup) { lastGroup = f.group; if (f.group) grid.appendChild(h('div', { class: 'group' }, f.group)); }
      grid.appendChild(fieldTile(f, l));
    }
    body.appendChild(grid);
    card.append(hd, body);
    return card;
  }

  function fieldTile(f, l) {
    const long = f.value.length > 48;
    const t = h('div', { class: 'fld' + (long || f.bits ? ' wide' : ''), tabindex: '0', dataset: { off: f.off, len: f.len } },
      h('span', { class: 'k' }, f.name),
      h('span', { class: 'v' }, f.value));
    if (f.bits) {
      const bits = h('span', { class: 'bits' });
      for (const b of f.bits) bits.appendChild(h('span', { class: 'bit' + (b.on ? ' on' : ''), title: b.tip || b.n }, b.n));
      t.appendChild(bits);
    }
    if (f.hint) t.appendChild(h('span', { class: 'hint' }, f.hint));
    t.style.setProperty('--c', 'var(--t-' + l.tier + ')');
    const on = () => markField(f, l);
    t.addEventListener('mouseenter', on); t.addEventListener('focus', on);
    t.addEventListener('mouseleave', clearMarks); t.addEventListener('blur', clearMarks);
    // click pins a field so its bytes stay lit while you look around the hex dump
    t.addEventListener('click', () => {
      const wasPinned = S.pinned === t;
      if (S.pinned) S.pinned.classList.remove('pin');
      S.pinned = wasPinned ? null : t;
      if (S.pinned) { t.classList.add('pin'); markField(f, l); if (hexBytes[f.off]) hexBytes[f.off].scrollIntoView({ block: 'nearest', inline: 'nearest' }); } else clearMarks();
    });
    t._f = f; t._l = l; fieldEls.push(t);
    return t;
  }

  function focusLayer(i) {
    const card = $('stack').querySelector('.layer[data-idx="' + i + '"]');
    if (!card) return;
    card.dataset.open = 'true';
    card.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'nearest' });
    card.classList.remove('flash'); void card.offsetWidth; card.classList.add('flash');
    markLayer(curPkt.layers[i], true);
    setTimeout(() => markLayer(curPkt.layers[i], false), 1200);
  }

  // hex dump
  const HEX_CAP = 4096;
  function ownerTiers(p) {
    const own = new Array(Math.min(p.data.length, HEX_CAP)).fill('data');
    for (const l of p.layers) for (let i = l.off; i < l.off + l.len && i < own.length; i++) own[i] = l.tier;
    return own;
  }
  function renderHex(p) {
    const box = clear($('hex'));
    hexBytes = []; ascBytes = [];
    const n = Math.min(p.data.length, HEX_CAP);
    const own = ownerTiers(p);
    for (let r = 0; r < n; r += 16) {
      const hb = h('span', { class: 'hb' }), as = h('span', { class: 'as' });
      for (let i = r; i < Math.min(n, r + 16); i++) {
        const c = p.data[i];
        const a = h('span', { dataset: { t: own[i], i } }, U.hex2(c));
        const b = h('span', { dataset: { t: own[i], i } }, c >= 32 && c < 127 ? String.fromCharCode(c) : '·');
        hexBytes[i] = a; ascBytes[i] = b; hb.appendChild(a); as.appendChild(b);
      }
      box.appendChild(h('div', { class: 'hrow' }, h('span', { class: 'off' }, U.hex4(r)), hb, as));
    }
    if (p.data.length > n) box.appendChild(h('div', { class: 'more' }, '… ' + (p.data.length - n).toLocaleString() + ' more bytes not shown'));
    setStatus(IDLE);
  }
  const describe = (f, l) => l.name + ' › ' + f.name + ' · bytes ' + f.off + (f.len > 1 ? '–' + (f.off + f.len - 1) : '') + ' (' + f.len + ' B)';
  function paint(from, len, cls) {
    for (let i = from; i < from + len; i++) if (hexBytes[i]) { hexBytes[i].classList.add(cls); ascBytes[i].classList.add(cls); }
  }
  function clearMarks() {
    for (const arr of [hexBytes, ascBytes]) for (const e of arr) if (e) e.classList.remove('hl', 'lay');
    if (S.pinned && S.pinned._f) { paint(S.pinned._f.off, S.pinned._f.len, 'hl'); setStatus(describe(S.pinned._f, S.pinned._l)); } else setStatus(IDLE);
  }
  function markField(f, l) { clearMarks(); paint(f.off, f.len, 'hl'); setStatus(describe(f, l)); }
  function markLayer(l, on) {
    clearMarks();
    if (!on) return;
    paint(l.off, l.len, 'lay');
    setStatus(l.name + ' · bytes ' + l.off + '–' + (l.off + l.len - 1) + ' (' + l.len + ' B)');
  }
  const IDLE = 'Hover a byte or a field to link them.';
  const setStatus = (t) => { $('hexStatus').textContent = t; };

  // hover a byte → light up the field that owns it
  function initHexHover() {
    const hex = $('hex');
    hex.addEventListener('mouseover', (e) => {
      const t = e.target.closest('span[data-i]');
      if (!t || !curPkt) return;
      const i = +t.dataset.i;
      let best = null, bestLayer = null;
      for (const l of curPkt.layers) for (const f of l.fields) {
        if (f.len > 0 && i >= f.off && i < f.off + f.len && (!best || f.len < best.len)) { best = f; bestLayer = l; }
      }
      for (const el of fieldEls) el.classList.toggle('hot', best && el._f === best);
      if (best) {
        setStatus(bestLayer.name + ' › ' + best.name + ' = ' + (best.value.length > 60 ? best.value.slice(0, 60) + '…' : best.value) + ' · bytes ' + best.off + (best.len > 1 ? '–' + (best.off + best.len - 1) : ''));
        const el = fieldEls.find((x) => x._f === best);
        if (el) el.scrollIntoView({ block: 'nearest' });
      } else setStatus('Byte ' + i + ' · 0x' + U.hex2(curPkt.data[i]));
    });
    hex.addEventListener('mouseleave', () => { for (const el of fieldEls) el.classList.remove('hot'); clearMarks(); });
  }

  // ───────────────────────────── overview ─────────────────────────────
  function renderOverview() {
    const root = clear($('overview'));
    const st = S.stats;
    if (!st) return;
    const kpi = (k, v) => h('div', { class: 'kpi' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v));
    const rate = st.duration > 0 ? U.fmtBytes(st.bytes / st.duration) + '/s' : '—';
    const wrap = h('div');
    wrap.appendChild(h('div', { class: 'kpis' },
      kpi('Packets', st.count.toLocaleString()), kpi('Data', U.fmtBytes(st.bytes)), kpi('Duration', U.fmtDuration(st.duration)),
      kpi('Average rate', rate), kpi('Protocol families', String(st.groups.length))));

    // traffic chart
    const chartHost = h('div', { class: 'chartwrap' });
    const modeBtn = (m, label) => h('button', { type: 'button', 'aria-pressed': String(S.chartMode === m), onclick: () => { S.chartMode = m; renderOverview(); } }, label);
    wrap.appendChild(h('div', { class: 'panel' },
      h('div', { class: 'head' }, h('div', null, h('h2', null, 'Traffic over time'), h('p', { class: 'sub' }, 'Each column is ' + (st.buckets.size < 1 ? Math.round(st.buckets.size * 1000) + ' ms' : st.buckets.size + ' s') + ' of the capture. Hover for details, click to jump to that moment.')),
        h('div', { class: 'seg-toggle', role: 'group', 'aria-label': 'Chart unit' }, modeBtn('bytes', 'Bytes'), modeBtn('packets', 'Packets'))),
      chartHost,
      h('div', { class: 'chips', style: { paddingInline: '0' }, 'aria-hidden': 'true' }, ...st.groups.map((gs) => { const d = h('i'); d.style.background = 'var(--g-' + gs.g.id + ')'; return h('span', { class: 'chip', style: { cursor: 'default' } }, d, gs.g.label); }))));
    B.charts.trafficChart(chartHost, st, S.chartMode, (bucket, size) => {
      // The filter language has no time field, so jump to the first packet of that slice instead.
      const idx = S.view.findIndex((p) => p.rel >= bucket.t && p.rel < bucket.t + size);
      setTab('packets');
      if (idx >= 0) select(idx, true); else toast('No packets in that slice match the current filter.');
    });

    // protocol mix
    const mix = h('table', { class: 't' }, h('thead', null, h('tr', null, h('th', null, 'Protocol'), h('th', { class: 'num' }, 'Packets'), h('th', { class: 'num' }, 'Bytes'), h('th', null, 'Share'))),
      h('tbody', null, ...st.groups.map((gs) => {
        const bar = h('span', { class: 'share' });
        bar.style.width = Math.max(2, (gs.bytes / st.bytes) * 100) + '%';
        bar.style.setProperty('--c', 'var(--g-' + gs.g.id + ')');
        const tr = h('tr', { class: 'click', tabindex: '0', title: 'Show these packets' },
          h('td', null, h('span', { class: 'badge', 'data-g': gs.g.id }, gs.g.label), gs.g.sub ? h('div', { class: 'fine' }, gs.g.sub) : null),
          h('td', { class: 'num' }, gs.packets.toLocaleString()), h('td', { class: 'num' }, U.fmtBytes(gs.bytes)),
          h('td', null, h('span', { class: 'share-wrap' }, bar)));
        const go = () => { const e = B.charts.filterFor(gs.g); S.chipExpr = e; $('filter').value = e; setTab('packets'); setFilter(e, true); };
        tr.addEventListener('click', go); tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } });
        return tr;
      })));
    const hosts = h('table', { class: 't' }, h('thead', null, h('tr', null, h('th', null, 'Address'), h('th', { class: 'num' }, 'Packets'), h('th', { class: 'num' }, 'Bytes'))),
      h('tbody', null, ...st.hosts.map((x) => {
        const tr = h('tr', { class: 'click', tabindex: '0', title: 'Show packets to/from this address' }, h('td', { class: 'mono-cell' }, x.addr), h('td', { class: 'num' }, x.packets.toLocaleString()), h('td', { class: 'num' }, U.fmtBytes(x.bytes)));
        const go = () => { const e = 'ip.addr == ' + x.addr; $('filter').value = e; setTab('packets'); setFilter(e); };
        tr.addEventListener('click', go); tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } });
        return tr;
      })));
    const convs = h('table', { class: 't' }, h('thead', null, h('tr', null, h('th', null, 'Conversation'), h('th', null, 'Proto'), h('th', { class: 'num' }, 'Packets'), h('th', { class: 'num' }, 'Bytes'))),
      h('tbody', null, ...st.convs.map((x) => {
        const label = x.ports ? x.a + ' ⇄ ' + x.b + '  (ports ' + x.ports.join(', ') + ')' : x.a + ' ⇄ ' + x.b;
        const tr = h('tr', { class: 'click', tabindex: '0', title: 'Show this conversation' }, h('td', { class: 'mono-cell' }, label), h('td', null, badge(x.proto)), h('td', { class: 'num' }, x.packets.toLocaleString()), h('td', { class: 'num' }, U.fmtBytes(x.bytes)));
        const go = () => { const e = 'ip.addr == ' + x.a + ' && ip.addr == ' + x.b + (x.ports ? ' && port == ' + x.ports[0] + ' && port == ' + x.ports[1] : ''); $('filter').value = e; setTab('packets'); setFilter(e); };
        tr.addEventListener('click', go); tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } });
        return tr;
      })));
    wrap.appendChild(h('div', { class: 'two' },
      h('div', { class: 'panel' }, h('h2', null, 'Protocol mix'), h('p', { class: 'sub' }, 'Click a row to filter the packet list.'), mix),
      h('div', { class: 'panel' }, h('h2', null, 'Busiest addresses'), h('p', { class: 'sub' }, 'By bytes, sent and received.'), st.hosts.length ? hosts : h('p', { class: 'sub' }, 'No IP traffic in this capture.'))));
    wrap.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Top conversations'), h('p', { class: 'sub' }, 'Packets between the same two endpoints (and ports, for TCP/UDP).'), st.convs.length ? convs : h('p', { class: 'sub' }, 'No IP conversations.')));
    root.appendChild(wrap);
  }

  // ───────────────────────────── tabs / navigation ─────────────────────────────
  function setTab(tab) {
    S.tab = tab;
    $('workspace').hidden = tab !== 'packets' || !(S.packets.length || S.format === 'live'); // a live capture is shown even before its first packet
    $('overview').hidden = tab !== 'overview';
    for (const b of $('tabs').children) b.setAttribute('aria-selected', String(b.dataset.tab === tab));
    if (tab === 'packets' && S.packets.length) { renderList(); if (S.view[S.sel]) $('listBody').scrollTop = Math.max(0, $('listBody').scrollTop); }
  }

  function showLanding() {
    S.packets = []; S.view = []; S.stats = null;
    $('landing').hidden = false; $('workspace').hidden = true; $('overview').hidden = true; $('tabs').hidden = true;
    clear($('fileinfo')); document.title = 'Bavin Web';
  }

  // ───────────────────────────── paste hex ─────────────────────────────
  function initPaste() {
    const dlg = $('pasteDlg');
    $('btnPaste').addEventListener('click', () => { $('pasteErr').textContent = ''; dlg.showModal(); $('pasteText').focus(); });
    $('pasteGo').addEventListener('click', async () => {
      try {
        const bytes = B.pcap.fromHexText($('pasteText').value);
        dlg.close();
        await busy('Dissecting…');
        await loadPackets('Pasted packet', [{ ts: Date.now() / 1000, data: bytes, origLen: bytes.length, linktype: 1 }], 'hex');
      } catch (e) { $('pasteErr').textContent = e.message; unbusy(); }
    });
  }


  // ───────────────────────────── live capture (via the local agent) ─────────────────────────────
  const LIVE_LIMIT = 100000;
  const L = { client: null, state: 'off', tool: null, ifaces: [], pending: [], session: null, seq: 0, follow: true, iface: '', filter: '', linktype: 1, since: 0, sinceCount: 0, flushTimer: 0, statsTimer: 0, rate: 0 };

  function setLiveState(st) {
    L.state = st;
    $('btnLive').dataset.state = st === 'capturing' ? 'capturing' : st === 'ready' || st === 'stopped' ? 'ready' : 'off';
  }

  // err === undefined leaves the current error message alone; pass '' to clear it.
  function liveStatus(text, err) { $('liveStatus').textContent = text; if (err !== undefined) $('liveErr').textContent = err; }

  // The page's own folder URL, e.g. https://you.github.io/bavin/ — used to build copy-paste commands.
  function siteDir() { return location.origin + location.pathname.replace(/[^/]*$/, ''); }

  function renderLiveDialog() {
    const connected = L.state === 'ready' || L.state === 'stopped';
    // Pairing steps work from any served copy of the site. The "open the URL it prints" steps only make sense
    // for a file:// copy or when this page might itself be the agent's (loopback).
    const hosted = location.protocol !== 'file:';
    $('liveHosted').hidden = !hosted;
    $('liveLocal').hidden = !(location.protocol === 'file:' || B.live.sameOriginAgent());
    if (hosted) {
      $('cmdFetch').textContent = 'curl -O ' + siteDir() + 'agent/bavin-agent.js';
      $('cmdRun').textContent = 'sudo node bavin-agent.js --origin ' + siteDir();
    }
    $('liveSetup').hidden = connected || L.state === 'capturing';
    $('liveReady').hidden = !connected;
    $('liveStart').hidden = !connected;
    if (connected) liveStatus(L.tool === 'replay' ? 'Agent connected — replay mode (no privileges needed)' : L.tool ? 'Agent connected — capturing with ' + L.tool : 'Agent connected — but no capture tool was found', '');
    else if (L.state === 'capturing') liveStatus('Capturing on ' + L.iface, '');
    else if (L.state === 'connecting') liveStatus('Connecting to the agent…', '');
    else liveStatus(B.live.agentAvailable() || B.live.hasConnection() ? 'Agent not connected' : 'Not connected to an agent yet');
  }

  async function connectAgent(silent) {
    if (L.state === 'connecting' || L.state === 'ready' || L.state === 'capturing' || L.state === 'stopped') return;
    L.client = new B.live.LiveClient({
      onHello: (m) => { L.tool = m.tool; },
      onInterfaces: (list) => {
        L.ifaces = list;
        const sel = clear($('liveIface'));
        const pref = list.find((i) => /^(en\d|eth\d|wlan|wl[a-z0-9]+|Ethernet|Wi-?Fi|replay)/i.test(i.id)) || list[0];
        for (const i of list) sel.appendChild(h('option', { value: i.id, selected: i === pref }, i.id + (i.desc ? ' — ' + i.desc : '')));
        renderLiveDialog();
      },
      onStarted: (m) => beginLive(m.iface, m.filter),
      onPackets: (raws) => { for (const r of raws) L.pending.push(r); scheduleFlush(); },
      onStopped: (m) => endLive(m.reason),
      onError: (msg) => { if ($('liveDlg').open) $('liveErr').textContent = msg; else toast(msg, true); },
      onClose: () => { const was = L.state; flushLive(); setLiveState('off'); L.client = null; if (was === 'capturing') endLive('disconnected'); renderLiveDialog(); toast('The capture agent disconnected.', true); },
    });
    setLiveState('connecting'); renderLiveDialog();
    try {
      await L.client.connect();
      setLiveState('ready');
      L.client.list();
    } catch (e) {
      setLiveState('off'); L.client = null;
      renderLiveDialog();
      if (!silent) $('liveErr').textContent = e.message; // shown after the redraw below, which must not wipe it
    }
    renderLiveDialog();
  }

  function beginLive(iface, filter) {
    leaveLive(true);
    L.iface = iface; L.filter = filter || ''; L.session = B.dissect.createSession(null); L.seq = 0; L.pending = []; L.rate = 0; L.sinceCount = 0; L.since = performance.now();
    S.packets = []; S.view = S.packets; S.sel = -1; S.selNo = -1; S.pinned = null; S.name = 'Live · ' + iface; S.format = 'live';
    S.stats = B.charts.computeStats(S.packets);
    S.filter = ''; S.fn = null; S.chipExpr = '';
    $('filter').value = ''; $('filterMsg').textContent = ''; $('filterClear').hidden = true;
    $('landing').hidden = true; $('tabs').hidden = false; $('workspace').dataset.view = 'list';
    setLiveState('capturing');
    L.follow = true; $('liveFollow').checked = true;
    const bar = $('liveBar'); bar.hidden = false; bar.dataset.state = 'capturing';
    $('liveStop').hidden = false; $('liveSave').hidden = true;
    $('liveText').textContent = 'Capturing on ' + iface + (L.filter ? ' · ' + L.filter : '');
    $('liveRate').textContent = 'waiting for packets…';
    buildChips(); applyFilter(); setTab('packets'); updateFileInfo(); renderOverview(); renderDetail(null);
    if ($('liveDlg').open) $('liveDlg').close();
    clearInterval(L.statsTimer); L.statsTimer = setInterval(liveTick, 1000);
  }

  function scheduleFlush() { if (!L.flushTimer) L.flushTimer = setTimeout(flushLive, 120); }

  function flushLive() {
    L.flushTimer = 0;
    if (!L.pending.length || !L.session) return;
    const raws = L.pending; L.pending = [];
    const direct = S.view === S.packets; // unfiltered: the view *is* the packet array
    for (const r of raws) {
      L.linktype = r.linktype;
      const p = L.session.add(r, ++L.seq);
      S.packets.push(p);
      if (!direct && (!S.fn || S.fn(p))) S.view.push(p);
    }
    L.sinceCount += raws.length;
    if (S.packets.length > LIVE_LIMIT) {
      S.packets.splice(0, S.packets.length - Math.floor(LIVE_LIMIT * 0.9)); // trim to 90% so we are not trimming on every flush
      if (!direct) { const first = S.packets[0].no; S.view = S.view.filter((p) => p.no >= first); }
      S.sel = S.selNo >= 0 ? S.view.findIndex((p) => p.no === S.selNo) : -1;
    }
    renderList(); renderFoot();
    if (L.follow) { const b = $('listBody'); b.scrollTop = b.scrollHeight; renderList(); }
  }

  function liveTick() {
    const now = performance.now();
    L.rate = L.sinceCount / Math.max(0.25, (now - L.since) / 1000);
    L.since = now; L.sinceCount = 0;
    if (L.state === 'capturing') $('liveRate').textContent = S.packets.length.toLocaleString() + ' packets · ' + Math.round(L.rate) + '/s';
    if (S.packets.length) { S.stats = B.charts.computeStats(S.packets); refreshChips(); updateFileInfo(); if (S.tab === 'overview') renderOverview(); }
  }

  function endLive(reason) {
    flushLive();
    clearInterval(L.statsTimer);
    if (L.state === 'capturing') setLiveState(L.client ? 'ready' : 'off');
    if (S.format !== 'live') return;
    const bar = $('liveBar'); bar.hidden = false; bar.dataset.state = 'stopped';
    $('liveText').textContent = (reason === 'ended' ? 'Replay finished' : reason === 'disconnected' ? 'Agent disconnected' : 'Stopped') + ' · ' + L.iface;
    $('liveRate').textContent = S.packets.length.toLocaleString() + ' packets';
    $('liveStop').hidden = true; $('liveSave').hidden = !S.packets.length;
    if (S.packets.length) { S.stats = B.charts.computeStats(S.packets); refreshChips(); updateFileInfo(); renderOverview(); }
  }

  // Called when something else (a file, a sample, a new capture) replaces the live session.
  function leaveLive(keepBar) {
    if (L.state === 'capturing' && L.client) { L.client.stop(); setLiveState('ready'); }
    clearInterval(L.statsTimer); clearTimeout(L.flushTimer); L.flushTimer = 0; L.pending = []; L.session = null;
    if (!keepBar) $('liveBar').hidden = true;
  }

  function setFollow(v, fromScroll) {
    L.follow = v; $('liveFollow').checked = v;
    if (v && !fromScroll) { const b = $('listBody'); b.scrollTop = b.scrollHeight; renderList(); }
  }

  function saveLive() {
    const raws = S.packets.map((p) => ({ ts: p.ts, data: p.data, origLen: p.len }));
    const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
    downloadBlob(B.pcap.write(raws, L.linktype), 'bavin-live-' + stamp + '.pcap', 'application/vnd.tcpdump.pcap');
  }

  function initLive() {
    B.live.takeConnection();
    $('btnLive').addEventListener('click', () => { $('liveErr').textContent = ''; renderLiveDialog(); $('liveDlg').showModal(); if (B.live.hasConnection()) connectAgent(false); });
    $('btnLive2').addEventListener('click', () => $('btnLive').click());
    $('liveStart').addEventListener('click', () => {
      const iface = $('liveIface').value;
      if (!iface) { $('liveErr').textContent = 'Choose an interface first.'; return; }
      $('liveErr').textContent = '';
      L.client.start(iface, $('liveFilter').value.trim());
    });
    const copy = (id) => { const t = $(id).textContent; if (navigator.clipboard) navigator.clipboard.writeText(t).then(() => toast('Copied'), () => toast('Select the text and copy it manually', true)); else toast('Select the text and copy it manually', true); };
    for (const b of document.querySelectorAll('.copy')) b.addEventListener('click', () => copy(b.dataset.copy));
    const connectFromLink = () => {
      if (!B.live.setConnectionFromText($('liveLink').value)) { $('liveErr').textContent = 'That does not look like the link the agent printed (it should contain #agent=…&token=…).'; return; }
      $('liveErr').textContent = ''; connectAgent(false);
    };
    $('liveConnect').addEventListener('click', connectFromLink);
    $('liveLink').addEventListener('paste', () => setTimeout(connectFromLink, 0));
    $('liveLink').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); connectFromLink(); } });
    $('liveStop').addEventListener('click', () => { if (L.client) L.client.stop(); });
    $('liveSave').addEventListener('click', saveLive);
    $('liveFollow').addEventListener('change', (e) => setFollow(e.target.checked));
    if (B.live.agentAvailable() && B.live.hasConnection()) connectAgent(true); // opened via the agent's link: connect quietly
    // The same link opened in a tab that already shows the site only changes the #fragment (no reload) — pick it up.
    window.addEventListener('hashchange', () => {
      if (!/token=/.test(location.hash) || !B.live.takeConnection()) return;
      if (L.client && L.state === 'ready') return; // already connected
      connectAgent(true);
    });
  }

  // ───────────────────────────── wiring ─────────────────────────────
  function init() {
    initTheme();
    S.wireOrder = lsGet('bavin-order') === 'wire';

    // landing content
    const grid = $('sampleGrid');
    for (const s of B.samples.LIST) {
      const dl = h('button', { class: 'dl', type: 'button', onclick: (e) => { e.stopPropagation(); const raws = s.make(); downloadBlob(B.pcap.write(raws, 1), 'bavin-' + s.id + '.pcap', 'application/vnd.tcpdump.pcap'); } }, 'Download .pcap');
      const card = h('div', { class: 'sample', role: 'button', tabindex: '0', onclick: () => loadSample(s) },
        h('h3', null, s.title), h('p', null, s.blurb), h('p', { class: 'learn' }, s.learn), h('div', { class: 'sfoot' }, h('span', { class: 'fine' }, 'Click to open'), dl));
      card.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === card) { e.preventDefault(); loadSample(s); } });
      grid.appendChild(card);
    }
    for (const p of PROTOCOL_NAMES) $('protoList').appendChild(h('li', null, p));

    // file input & drop
    const input = $('fileInput');
    const pick = () => input.click();
    $('btnOpen').addEventListener('click', pick);
    $('drop').addEventListener('click', pick);
    $('drop').addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(); } });
    input.addEventListener('change', () => { const f = input.files[0]; input.value = ''; loadFile(f); });
    let depth = 0;
    const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
    window.addEventListener('dragenter', (e) => { if (!hasFiles(e)) return; e.preventDefault(); depth++; $('dropVeil').hidden = false; });
    window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
    window.addEventListener('dragleave', (e) => { if (!hasFiles(e)) return; if (--depth <= 0) { depth = 0; $('dropVeil').hidden = true; } });
    window.addEventListener('drop', (e) => { if (!hasFiles(e)) return; e.preventDefault(); depth = 0; $('dropVeil').hidden = true; loadFile(e.dataTransfer.files[0]); });

    // tabs
    for (const b of $('tabs').children) b.addEventListener('click', () => setTab(b.dataset.tab));
    $('tabs').addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const next = S.tab === 'packets' ? 'overview' : 'packets';
      setTab(next); $('tab-' + next).focus();
    });

    // filter
    let timer = 0;
    $('filter').addEventListener('input', (e) => { clearTimeout(timer); timer = setTimeout(() => setFilter(e.target.value), 120); });
    $('filter').addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.target.value = ''; setFilter(''); $('listBody').focus(); } if (e.key === 'ArrowDown') { e.preventDefault(); $('listBody').focus(); } });
    $('filterClear').addEventListener('click', () => { $('filter').value = ''; setFilter(''); $('filter').focus(); });
    $('btnHelp').addEventListener('click', () => $('helpDlg').showModal());
    $('btnCsv').addEventListener('click', exportCsv);

    // list
    const body = $('listBody');
    body.addEventListener('scroll', () => {
      requestAnimationFrame(renderList);
      if (L.state === 'capturing') { const atBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 8; if (atBottom !== L.follow) setFollow(atBottom, true); }
    }, { passive: true });
    new ResizeObserver(() => renderList()).observe(body);
    body.addEventListener('click', (e) => {
      const r = e.target.closest('.row');
      if (!r) return;
      select(+r.dataset.i, false);
      $('workspace').dataset.view = 'detail';
    });
    body.addEventListener('keydown', (e) => {
      const step = { ArrowDown: 1, j: 1, ArrowUp: -1, k: -1, PageDown: 10, PageUp: -10 }[e.key];
      if (step) { e.preventDefault(); select(Math.max(0, Math.min(S.view.length - 1, (S.sel < 0 ? 0 : S.sel) + step)), true); }
      else if (e.key === 'Home') { e.preventDefault(); select(0, true); }
      else if (e.key === 'End') { e.preventDefault(); select(S.view.length - 1, true); }
      else if (e.key === 'Enter') $('workspace').dataset.view = 'detail';
    });
    window.addEventListener('keydown', (e) => {
      if (e.key === '/' && !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName) && S.packets.length) { e.preventDefault(); setTab('packets'); $('filter').focus(); }
    });

    initHexHover();
    initPaste();
    initLive();

    $('workspace').addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('workspace').dataset.view === 'detail' && matchMedia('(max-width: 900px)').matches) $('workspace').dataset.view = 'list'; });
    $('landing').hidden = false;
    $('workspace').hidden = true;
  }

  B.app = { showLanding, openFile: loadFile, toast, _state: S };
  init();
})();
