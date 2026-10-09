// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — capture file reader. Handles classic pcap (µs/ns, either endianness) and pcapng. */
(function (B) {
  'use strict';

  const LINK = { NULL: 0, ETHERNET: 1, RAW_12: 12, RAW: 101, LOOP: 108, LINUX_SLL: 113, RAW_IPV4: 228, RAW_IPV6: 229 };

  function parse(arrayBuffer) {
    const buf = new Uint8Array(arrayBuffer);
    if (buf.length < 12) throw new Error('File is too small to be a packet capture.');
    const dv = new DataView(arrayBuffer);
    const magic = dv.getUint32(0, false);
    if (magic === 0x0a0d0d0a) return parsePcapng(buf, dv);
    if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 || magic === 0xa1b23c4d || magic === 0x4d3cb2a1) {
      return parsePcap(buf, dv, magic);
    }
    if (buf[0] === 0x1f && buf[1] === 0x8b) throw new Error('This file is gzip-compressed. Decompress it first (gunzip) and try again.');
    throw new Error('Not a pcap or pcapng file (unknown magic number 0x' + magic.toString(16) + ').');
  }

  function parsePcap(buf, dv, magic) {
    const le = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
    const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
    if (buf.length < 24) throw new Error('Truncated pcap header.');
    const linktype = dv.getUint32(20, le) & 0x0fffffff;
    const packets = [];
    let o = 24;
    while (o + 16 <= buf.length) {
      const sec = dv.getUint32(o, le);
      const frac = dv.getUint32(o + 4, le);
      const caplen = dv.getUint32(o + 8, le);
      const origLen = dv.getUint32(o + 12, le);
      o += 16;
      if (caplen > buf.length - o) break; // truncated tail — keep what we have
      packets.push({ ts: sec + frac / (nano ? 1e9 : 1e6), data: buf.subarray(o, o + caplen), origLen, linktype });
      o += caplen;
    }
    return { format: 'pcap', linktype, packets };
  }

  function parsePcapng(buf, dv) {
    const packets = [];
    const ifaces = []; // { linktype, tsDiv }
    let le = true;
    let o = 0;
    while (o + 12 <= buf.length) {
      const type = dv.getUint32(o, le);
      if (type === 0x0a0d0d0a) {
        // Byte-order magic decides the endianness of this section.
        le = dv.getUint32(o + 8, true) === 0x1a2b3c4d;
        ifaces.length = 0;
      }
      const total = dv.getUint32(o + 4, le);
      if (total < 12 || o + total > buf.length) break;
      const body = o + 8;
      if (type === 1) {
        // Interface Description Block
        const linktype = dv.getUint16(body, le);
        let tsres = 6; // default: microseconds
        let p = body + 8;
        const end = o + total - 4;
        while (p + 4 <= end) {
          const code = dv.getUint16(p, le);
          const len = dv.getUint16(p + 2, le);
          if (code === 0) break;
          if (code === 9 && len >= 1) {
            const v = buf[p + 4];
            tsres = v & 0x80 ? 6 : v; // power-of-two resolutions are rare; treat as µs
            break;
          }
          p += 4 + ((len + 3) & ~3);
        }
        ifaces.push({ linktype, tsDiv: Math.pow(10, tsres) });
      } else if (type === 6) {
        // Enhanced Packet Block
        const ifid = dv.getUint32(body, le);
        const hi = dv.getUint32(body + 4, le);
        const lo = dv.getUint32(body + 8, le);
        const caplen = dv.getUint32(body + 12, le);
        const origLen = dv.getUint32(body + 16, le);
        const ifc = ifaces[ifid] || { linktype: LINK.ETHERNET, tsDiv: 1e6 };
        if (body + 20 + caplen <= buf.length) {
          packets.push({ ts: (hi * 4294967296 + lo) / ifc.tsDiv, data: buf.subarray(body + 20, body + 20 + caplen), origLen, linktype: ifc.linktype });
        }
      } else if (type === 3) {
        // Simple Packet Block (no timestamp)
        const origLen = dv.getUint32(body, le);
        const ifc = ifaces[0] || { linktype: LINK.ETHERNET };
        const caplen = Math.min(origLen, total - 16);
        packets.push({ ts: 0, data: buf.subarray(body + 4, body + 4 + caplen), origLen, linktype: ifc.linktype });
      }
      o += total;
    }
    if (!packets.length && !ifaces.length) throw new Error('No packets found in this pcapng file.');
    return { format: 'pcapng', linktype: ifaces[0] ? ifaces[0].linktype : LINK.ETHERNET, packets };
  }

  // Serialise packets as a classic little-endian pcap (used for the "download sample" button and tests).
  function write(packets, linktype) {
    let size = 24;
    for (const p of packets) size += 16 + p.data.length;
    const out = new Uint8Array(size);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, 0xa1b2c3d4, true);
    dv.setUint16(4, 2, true);
    dv.setUint16(6, 4, true);
    dv.setUint32(16, 65535, true);
    dv.setUint32(20, linktype || LINK.ETHERNET, true);
    let o = 24;
    for (const p of packets) {
      const sec = Math.floor(p.ts);
      dv.setUint32(o, sec, true);
      dv.setUint32(o + 4, Math.round((p.ts - sec) * 1e6), true);
      dv.setUint32(o + 8, p.data.length, true);
      dv.setUint32(o + 12, p.origLen || p.data.length, true);
      out.set(p.data, o + 16);
      o += 16 + p.data.length;
    }
    return out;
  }

  // Accepts "00 11 22", "0x00,0x11", Wireshark "0000  00 11 22 ... ascii" dumps, or a bare hex string.
  function fromHexText(str) {
    const lines = str.split(/\r?\n/);
    const bytes = [];
    const offsetLine = /^\s*[0-9a-fA-F]{4,8}\s{2,}/;
    for (const raw of lines) {
      let line = raw;
      if (offsetLine.test(line)) {
        line = line.replace(/^\s*[0-9a-fA-F]{4,8}\s+/, '');
        const gap = line.search(/\s{3,}/); // ASCII gutter after the hex columns
        if (gap > 0) line = line.slice(0, gap);
      }
      line = line.replace(/0x/gi, ' ').replace(/[,;:|]/g, ' ');
      const tokens = line.trim().split(/\s+/).filter(Boolean);
      if (tokens.length === 1 && tokens[0].length > 2 && tokens[0].length % 2 === 0) {
        if (!/^[0-9a-fA-F]+$/.test(tokens[0])) throw new Error('Could not read "' + tokens[0].slice(0, 12) + '" as hex.');
        for (let i = 0; i < tokens[0].length; i += 2) bytes.push(parseInt(tokens[0].substr(i, 2), 16));
        continue;
      }
      for (const t of tokens) {
        if (!/^[0-9a-fA-F]{1,2}$/.test(t)) throw new Error('Could not read "' + t.slice(0, 12) + '" as a hex byte.');
        bytes.push(parseInt(t, 16));
      }
    }
    if (bytes.length < 14) throw new Error('That is shorter than an Ethernet header (14 bytes).');
    return Uint8Array.from(bytes);
  }


  // Incremental reader for a classic pcap *stream* (global header, then records) arriving in arbitrary chunks —
  // what the live-capture agent sends. push() returns the packets completed by that chunk.
  class StreamParser {
    constructor() { this.buf = new Uint8Array(0); this.hdr = null; }
    push(chunk) {
      let b = chunk;
      if (this.buf.length) { b = new Uint8Array(this.buf.length + chunk.length); b.set(this.buf, 0); b.set(chunk, this.buf.length); }
      const out = [];
      let o = 0;
      if (!this.hdr) {
        if (b.length < 24) { this.buf = b; return out; }
        const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
        const magic = dv.getUint32(0, false);
        const known = { 0xa1b2c3d4: [false, false], 0xd4c3b2a1: [true, false], 0xa1b23c4d: [false, true], 0x4d3cb2a1: [true, true] }[magic];
        if (!known) throw new Error('The capture stream is not in pcap format (magic 0x' + magic.toString(16) + ').');
        this.hdr = { le: known[0], nano: known[1], linktype: dv.getUint32(20, known[0]) & 0x0fffffff };
        o = 24;
      }
      const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
      const { le, nano, linktype } = this.hdr;
      while (o + 16 <= b.length) {
        const caplen = dv.getUint32(o + 8, le);
        if (caplen > 16 * 1024 * 1024) throw new Error('Corrupt capture stream (record of ' + caplen + ' bytes).');
        if (o + 16 + caplen > b.length) break;
        const sec = dv.getUint32(o, le), frac = dv.getUint32(o + 4, le);
        out.push({ ts: sec + frac / (nano ? 1e9 : 1e6), data: b.slice(o + 16, o + 16 + caplen), origLen: dv.getUint32(o + 12, le), linktype });
        o += 16 + caplen;
      }
      this.buf = b.slice(o);
      return out;
    }
  }

  B.pcap = { LINK, parse, write, fromHexText, StreamParser };
  if (typeof module !== 'undefined') module.exports = B.pcap;
})(typeof window !== 'undefined' ? (window.Bavin = window.Bavin || {}) : (globalThis.Bavin = globalThis.Bavin || {}));
