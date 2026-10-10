// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
/* Bavin Web — client for the local capture agent (web/agent/bavin-agent.js). */
(function (B) {
  'use strict';

  const isLoopback = (h) => h === '127.0.0.1' || h === 'localhost';

  // Where is the agent?
  //  - served BY the agent (http://127.0.0.1:PORT/): same origin, only a token is needed
  //  - a hosted copy of the UI: the agent prints a link ending in #agent=PORT&token=…, which we connect to at
  //    ws://127.0.0.1:PORT (the agent must have been started with --origin for this site)
  let conn = null;

  function parseFragment(text) {
    const q = new URLSearchParams(String(text).replace(/^[^#]*#/, '').replace(/^#/, ''));
    const token = q.get('token');
    const port = q.get('agent');
    if (!token || !/^[\w-]{16,64}$/.test(token)) return null;
    if (port && !/^\d{4,5}$/.test(port)) return null;
    if (port && (Number(port) < 1024 || Number(port) > 65535)) return null; // never poke privileged/system ports from a link
    return { token, port: port ? Number(port) : null };
  }

  // Read the connection details from the URL hash, remember them for reloads, and scrub the URL.
  function takeConnection() {
    let c = parseFragment(location.hash);
    const fresh = !!c; // arrived via a link the agent printed (as opposed to being remembered from this tab)
    if (c) {
      try { sessionStorage.setItem('bavin-conn', JSON.stringify(c)); } catch (_) { /* private mode */ }
      try { history.replaceState(null, '', location.pathname + location.search); } catch (_) { /* ignore */ }
    } else {
      try { c = JSON.parse(sessionStorage.getItem('bavin-conn') || 'null'); } catch (_) { c = null; }
    }
    conn = c;
    return c ? Object.assign({ fresh }, c) : null;
  }
  // Accept whatever the user pastes: the full link the agent printed, or just "#agent=…&token=…".
  function setConnectionFromText(text) {
    const c = parseFragment(String(text).trim());
    if (!c) return null;
    conn = c;
    try { sessionStorage.setItem('bavin-conn', JSON.stringify(c)); } catch (_) { /* ignore */ }
    return c;
  }

  const sameOriginAgent = () => typeof location !== 'undefined' && location.protocol === 'http:' && isLoopback(location.hostname);
  // True when there is somewhere to connect: we are the agent's own page, or we hold agent details.
  const agentAvailable = () => sameOriginAgent() || !!(conn && conn.port);
  const hasConnection = () => !!(conn && conn.token);
  const wsUrl = () => (conn && conn.port ? 'ws://127.0.0.1:' + conn.port : 'ws://' + location.host) + '/ws?token=' + encodeURIComponent(conn.token);

  class LiveClient {
    // handlers: onHello, onInterfaces, onStarted, onStopped, onError, onPackets, onClose, onSlow
    constructor(h) { this.h = h; this.ws = null; this.parser = null; this.open = false; }

    connect() {
      return new Promise((resolve, reject) => {
        if (!hasConnection()) return reject(new Error('No agent details yet. Paste the link the agent printed in your terminal.'));
        if (!agentAvailable()) return reject(new Error('Paste the link the agent printed — it contains the port this page should connect to.'));
        let settled = false;
        const ws = new WebSocket(wsUrl());
        ws.binaryType = 'arraybuffer';
        this.ws = ws;
        const finish = (fn, arg) => { if (settled) return false; settled = true; clearTimeout(slow); clearTimeout(dead); fn(arg); return true; };
        // A browser can hold a connection to 127.0.0.1 open-but-pending (for example while it waits for you to answer a
        // "connect to devices on your local network" prompt). Say so after a moment, and give up after a while.
        const slow = setTimeout(() => { if (!settled && this.h.onSlow) this.h.onSlow(); }, LiveClient.SLOW_MS);
        const dead = setTimeout(() => finish(reject, new Error(
          'The browser did not finish connecting to the agent (' + Math.round(LiveClient.TIMEOUT_MS / 1000) + ' s). '
          + 'If it asked for permission to access devices on your local network, allow it and press Connect again. '
          + 'Brave Shields, ad blockers and Safari can block connections to 127.0.0.1 from a website. '
          + 'The agent also prints its own link (starting with http://127.0.0.1) — opening that always works.')), LiveClient.TIMEOUT_MS);
        // The connection only counts once the other end says hello like a Bavin agent. A link can name any local port, so
        // we must not start talking to (or trusting) whatever service happens to be there.
        let helloTimer = 0, gotHello = false;
        ws.onopen = () => {
          this.open = true;
          helloTimer = setTimeout(() => { if (!gotHello) { finish(reject, new Error('Something is listening on that port but it did not answer like a Bavin agent.')); try { ws.close(); } catch (_) { /* ignore */ } } }, LiveClient.HELLO_MS);
        };
        ws.onerror = () => finish(reject, new Error('Could not connect to the agent. Check that it is still running, that the link is the one it printed this time (the token changes on every start), that it was started with --origin for this site, and that no other tab is connected.'));
        ws.onclose = () => {
          clearTimeout(helloTimer);
          const was = this.open; this.open = false;
          if (!finish(reject, new Error('The agent refused the connection.')) && was) this.h.onClose && this.h.onClose();
        };
        ws.onmessage = (e) => {
          if (!gotHello) {
            let m = null;
            if (typeof e.data === 'string') { try { m = JSON.parse(e.data); } catch (_) { m = null; } }
            if (!m || m.type !== 'hello' || typeof m.version !== 'number') {
              clearTimeout(helloTimer);
              finish(reject, new Error('Whatever is listening on that port is not a Bavin agent.'));
              try { ws.close(); } catch (_) { /* ignore */ }
              return;
            }
            gotHello = true; clearTimeout(helloTimer);
            if (this.h.onHello) this.h.onHello(m);
            finish(resolve);
            return;
          }
          this.onMessage(e.data);
        };
      });
    }

    onMessage(data) {
      if (typeof data === 'string') {
        let m; try { m = JSON.parse(data); } catch (_) { return; }
        if (m.type === 'hello') this.h.onHello && this.h.onHello(m);
        else if (m.type === 'interfaces') this.h.onInterfaces && this.h.onInterfaces(m.interfaces);
        else if (m.type === 'started') { this.parser = new B.pcap.StreamParser(); this.h.onStarted && this.h.onStarted(m); }
        else if (m.type === 'stopped') this.h.onStopped && this.h.onStopped(m);
        else if (m.type === 'error') this.h.onError && this.h.onError(m.message);
        return;
      }
      if (!this.parser) return;
      try {
        const raws = this.parser.push(new Uint8Array(data));
        if (raws.length) this.h.onPackets(raws);
      } catch (e) { this.parser = null; this.h.onError && this.h.onError(e.message); this.stop(); }
    }

    send(obj) { if (this.ws && this.open) this.ws.send(JSON.stringify(obj)); }
    list() { this.send({ type: 'list' }); }
    start(iface, filter) { this.send({ type: 'start', iface, filter: filter || '' }); }
    stop() { this.send({ type: 'stop' }); }
    disconnect() { if (this.ws) { this.open = false; try { this.ws.close(); } catch (_) { /* ignore */ } } }
  }

  LiveClient.SLOW_MS = 2500;      // show the "still connecting" hint
  LiveClient.TIMEOUT_MS = 10000;  // give up
  LiveClient.HELLO_MS = 3000;     // a real agent greets immediately

  B.live = { LiveClient, agentAvailable, hasConnection, takeConnection, setConnectionFromText, sameOriginAgent };
})(window.Bavin);
