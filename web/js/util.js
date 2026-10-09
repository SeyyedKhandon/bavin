// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — shared helpers. Classic script (no modules) so index.html also works from file://. */
(function (B) {
  'use strict';

  const hex2 = (n) => (n & 0xff).toString(16).padStart(2, '0');
  const hex4 = (n) => (n & 0xffff).toString(16).padStart(4, '0');

  function u8(buf, o) { return buf[o]; }
  function u16(buf, o) { return (buf[o] << 8) | buf[o + 1]; }
  function u32(buf, o) { return ((buf[o] * 0x1000000) + ((buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3])); }

  function mac(buf, o) {
    const p = [];
    for (let i = 0; i < 6; i++) p.push(hex2(buf[o + i]));
    return p.join(':');
  }

  function ipv4(buf, o) {
    return buf[o] + '.' + buf[o + 1] + '.' + buf[o + 2] + '.' + buf[o + 3];
  }

  // RFC 5952 style compression of the longest run of zero groups.
  function ipv6(buf, o) {
    const g = [];
    for (let i = 0; i < 8; i++) g.push(u16(buf, o + i * 2));
    let bestS = -1, bestL = 0, curS = -1, curL = 0;
    for (let i = 0; i < 8; i++) {
      if (g[i] === 0) {
        if (curS < 0) { curS = i; curL = 0; }
        curL++;
        if (curL > bestL) { bestL = curL; bestS = curS; }
      } else curS = -1;
    }
    if (bestL < 2) return g.map((x) => x.toString(16)).join(':');
    const left = g.slice(0, bestS).map((x) => x.toString(16)).join(':');
    const right = g.slice(bestS + bestL).map((x) => x.toString(16)).join(':');
    return left + '::' + right;
  }

  function ascii(buf, o, len) {
    let s = '';
    for (let i = 0; i < len && o + i < buf.length; i++) {
      const c = buf[o + i];
      s += c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
    }
    return s;
  }

  // Text decode that tolerates binary garbage.
  function text(buf, o, len) {
    let s = '';
    const end = Math.min(buf.length, o + len);
    for (let i = o; i < end; i++) s += String.fromCharCode(buf[i]);
    return s;
  }

  function hexBytes(buf, o, len, max) {
    const n = Math.min(len, max || len);
    let s = '';
    for (let i = 0; i < n; i++) s += (i ? ' ' : '') + hex2(buf[o + i]);
    return len > n ? s + ' …' : s;
  }

  // RFC 1071 internet checksum over [o, o+len). Returns 0 for a valid header (checksum field included).
  function inetChecksum(buf, o, len) {
    let sum = 0;
    for (let i = 0; i + 1 < len; i += 2) sum += (buf[o + i] << 8) | buf[o + i + 1];
    if (len & 1) sum += buf[o + len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
  }

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  function fmtDuration(sec) {
    if (sec < 1) return (sec * 1000).toFixed(0) + ' ms';
    if (sec < 60) return sec.toFixed(2) + ' s';
    const m = Math.floor(sec / 60);
    return m + 'm ' + Math.round(sec - m * 60) + 's';
  }

  B.util = { hex2, hex4, u8, u16, u32, mac, ipv4, ipv6, ascii, text, hexBytes, inetChecksum, fmtBytes, fmtDuration };
  if (typeof module !== 'undefined') module.exports = B.util;
})(typeof window !== 'undefined' ? (window.Bavin = window.Bavin || {}) : (globalThis.Bavin = globalThis.Bavin || {}));
