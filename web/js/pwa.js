// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — "install as an app", offline support and opening .pcap files from the OS. */
(function (B) {
  'use strict';
  const $ = (id) => document.getElementById(id);
  let deferred = null;

  const standalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

  function init() {
    // Service workers need https (or localhost); file:// pages simply skip this.
    const secure = location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    if ('serviceWorker' in navigator && secure) navigator.serviceWorker.register('sw.js').catch(() => { /* offline support is optional */ });

    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault(); // keep the event so Install can be offered from our own button
      deferred = e;
      $('btnInstall').hidden = false;
    });
    $('btnInstall').addEventListener('click', async () => {
      if (!deferred) return;
      const ev = deferred; deferred = null;
      $('btnInstall').hidden = true;
      ev.prompt();
      try { await ev.userChoice; } catch (_) { /* dismissed */ }
    });
    window.addEventListener('appinstalled', () => { $('btnInstall').hidden = true; B.app.toast('Installed — Bavin is now in your apps'); });

    // iOS/iPadOS Safari has no install prompt; tell people the manual way.
    if (/iphone|ipad|ipod/i.test(navigator.userAgent) && !standalone()) $('installHint').hidden = false;

    // Installed Chromium apps can be the default opener for .pcap/.pcapng (see file_handlers in the manifest).
    if ('launchQueue' in window) {
      window.launchQueue.setConsumer(async (params) => {
        if (!params.files || !params.files.length) return;
        B.app.openFile(await params.files[0].getFile());
      });
    }
  }
  B.pwa = { init };
  init();
})(window.Bavin);
