// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — tiny DOM helpers. Packet data is untrusted, so nothing here ever uses innerHTML. */
(function (B) {
  'use strict';
  const SVG_NS = 'http://www.w3.org/2000/svg';

  function apply(e, props) {
    if (!props) return e;
    for (const k of Object.keys(props)) {
      const v = props[k];
      if (v === false || v == null) continue;
      if (k === 'class') e.setAttribute('class', v);
      else if (k === 'text') e.textContent = v;
      else if (k === 'dataset') Object.assign(e.dataset, v);
      else if (k === 'style') Object.assign(e.style, v); // CSSOM only — allowed under a strict CSP
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? '' : String(v));
    }
    return e;
  }
  function add(e, kids) {
    for (const k of kids) {
      if (k == null || k === false) continue;
      if (Array.isArray(k)) add(e, k);
      else e.appendChild(typeof k === 'string' || typeof k === 'number' ? document.createTextNode(String(k)) : k);
    }
    return e;
  }
  const h = (tag, props, ...kids) => add(apply(document.createElement(tag), props), kids);
  const svg = (tag, props, ...kids) => add(apply(document.createElementNS(SVG_NS, tag), props), kids);
  const clear = (e) => { while (e.firstChild) e.removeChild(e.firstChild); return e; };

  B.dom = { h, svg, clear };
})(typeof window !== 'undefined' ? (window.Bavin = window.Bavin || {}) : (globalThis.Bavin = globalThis.Bavin || {}));
