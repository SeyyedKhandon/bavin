// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web service worker — makes the app installable and usable offline.
 * Strategy: network first (so a new deploy shows up on the next load), falling back to the cache when offline.
 * Only same-origin GET requests are handled; the live-capture WebSocket and everything cross-origin pass through untouched. */
'use strict';
const VERSION = 'bavin-web-v1';
const SHELL = [
  './', 'index.html', 'css/style.css',
  'js/util.js', 'js/dom.js', 'js/pcap.js', 'js/dissect.js', 'js/filter.js', 'js/samples.js', 'js/charts.js', 'js/live.js', 'js/app.js', 'js/pwa.js',
  'favicon.svg', 'manifest.webmanifest', 'icons/icon-192.png', 'icons/icon-512.png', 'icons/icon-maskable-512.png', 'icons/icon.svg', 'icons/apple-touch-icon.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  e.respondWith((async () => {
    try {
      const res = await fetch(req);
      if (res.ok && res.type === 'basic') { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(req, copy)); }
      return res;
    } catch (_) {
      const hit = await caches.match(req, { ignoreSearch: true });
      if (hit) return hit;
      if (req.mode === 'navigate') { const page = await caches.match('index.html'); if (page) return page; }
      return Response.error();
    }
  })());
});
