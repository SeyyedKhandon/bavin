# Developing Bavin Web

For using Bavin, see the [Guide](GUIDE.md). This page is for changing it.

**Contents** — [Principles](#principles) · [Layout](#layout) · [Data model](#data-model) · [Add a protocol](#add-a-protocol) · [The capture agent](#the-capture-agent) · [Tests](#tests) · [CI and deployment](#ci-and-deployment) · [Regenerating the README art](#regenerating-the-readme-art)

## Principles

1. **A capture is untrusted input.** DNS names, HTTP headers and TLS server names are attacker-controlled. Everything derived from packets is inserted with `textContent` (see `js/dom.js`), never `innerHTML`. The page's Content-Security-Policy backs this up; do not weaken it. Every dissector must survive truncated and garbage input — the tests fuzz this — and must not be able to make the UI build an unbounded number of elements: `fld()` caps a layer at 150 fields and records the rest in `layer.hidden`. Anything exported (CSV) must neutralise spreadsheet formulas.
2. **Every field knows its bytes.** A field is `(name, offset, length, value)`. That is what powers the linked hex dump, so never build a field without a real byte range.
3. **No build step.** Plain classic scripts sharing a `window.Bavin` namespace, so the app works from `file://`, from any static host, and in Node for tests.
4. **Nothing leaves the machine.** The only network access allowed is a WebSocket to `127.0.0.1` for the optional agent.

## Layout

```
web/
  index.html            page shell + Content-Security-Policy + dialogs
  css/style.css         design tokens (light/dark), layout, components
  js/
    util.js             byte readers, address formatting, checksum, formatting
    dom.js              h()/svg() element helpers (textContent only)
    pcap.js             pcap + pcapng reader, incremental StreamParser, writer, hex-text parser
    dissect.js          the protocol dissectors  ← the core
    filter.js           the display-filter language
    samples.js          packet builders for the built-in samples (also test fixtures)
    charts.js           protocol families, statistics, the traffic chart
    live.js             WebSocket client for the agent
    pwa.js, sw.js       install button, offline cache, file handler
    app.js              UI: loading, packet list, stack view, hex dump, overview, live
  agent/bavin-agent.js  local capture agent (Node, no dependencies)
  test/                 run.js (libraries), agent.js (agent)
docs/                   this guide, the user guide, README art
scripts/readme/         generators for the README panels and screenshots
.github/workflows/      pages.yml: test, then deploy to GitHub Pages
```

Dependencies flow one way: `util → dom/pcap → dissect → filter/charts → live → app`. `dissect.js`, `pcap.js`, `filter.js`, `samples.js` and `util.js` also run in Node (they `module.exports` when available), which is how they are tested without a browser.

## Data model

`Bavin.dissect.dissectAll(rawPackets)` turns `{ts, data, origLen, linktype}` records into packets:

```js
packet = {
  no, ts, rel, len, caplen, data,            // identity, timing, bytes
  src, dst, sport, dport, proto, info,       // what the list shows
  ipv, ttl, transport, flow, tcp,            // used by filters, stats, "only this conversation"
  ids: ['eth','ip','tcp','http'],            // layer ids, for filters (`tcp`, `http`, …)
  layers: [ layer, … ],                      // wire order: outermost first
  warn, malformed,                           // checksum/truncation notes, parse failures
}
layer = { id, name, tier: 'link'|'network'|'transport'|'app'|'data', off, len, summary, fields: [ field, … ] }
field = { name, off, len, value, hint?, group?, bits? }   // bits = [{ n, on, tip }] renders as chips
```

For a live capture use `createSession()`: it keeps the cross-packet state (capture start, TCP flows for relative sequence numbers) so batches can be dissected as they arrive.

## Add a protocol

Example: NTP on UDP 123.

1. **Dissector** in `js/dissect.js`. Use the helpers: `need(c, off, n, what)` throws a controlled `Trunc` if the packet is too short (the driver reports it as *malformed*); `mk(c, id, name, tier, off, len)` adds a layer; `fld(layer, name, off, len, value, hint)` adds a field; `grp(layer, 'Title')` starts a group of fields; `bitsFld` makes a flags row.

   ```js
   function ntp(c, off) {
     need(c, off, 48, 'NTP message');
     const b = c.buf;
     const l = mk(c, 'ntp', 'NTP', 'app', off, c.end - off);
     fld(l, 'Version', off, 1, (b[off] >> 3) & 7);
     fld(l, 'Mode', off, 1, b[off] & 7, ['', 'symmetric active', 'symmetric passive', 'client', 'server'][b[off] & 7]);
     fld(l, 'Stratum', off + 1, 1, b[off + 1]);
     c.pkt.proto = 'NTP';
     c.pkt.info = 'NTP ' + (['', '', '', 'client', 'server'][b[off] & 7] || 'message');
     c.pkt.appNote = true;          // tells payload() not to append " Len=…" to the info
   }
   ```
2. **Hook it in.** In `udp()` (or `tcp()`), add a branch: `else if (sp === 123 || dp === 123) ntp(c, p);`.
3. **UI text.** Add a one-sentence entry to `BLURBS` in `app.js` (this is the "what is this layer for" note — it is the educational part).
4. **Filter and chart.** Add the layer id to `KNOWN_LAYERS` in `filter.js`; add the protocol to a family in `GROUPS` in `charts.js` (otherwise it is counted under *Other*).
5. **Sample + test.** Build a packet in `samples.js` (checksums included, so `tcpdump` can cross-check it) and assert on it in `test/run.js`. Compare with `tcpdump -nn -r` / Wireshark; if they disagree, one of you is wrong.

## The capture agent

`agent/bavin-agent.js` — one file, Node ≥ 18, no dependencies. It serves `web/`, speaks a minimal RFC 6455 WebSocket, spawns `tcpdump`/`dumpcap` without a shell, and relays the pcap stream.

Messages (JSON text frames; capture bytes are binary frames):

| Direction | Message |
| --- | --- |
| agent → page | `{type:'hello', version, tool, platform}` right after connect |
| page → agent | `{type:'list'}` → `{type:'interfaces', interfaces:[{id,index,desc}]}` |
| page → agent | `{type:'start', iface, filter}` → `{type:'started', iface, filter}`, then **binary pcap stream** (global header first) |
| page → agent | `{type:'stop'}` → `{type:'stopped', reason}` |
| agent → page | `{type:'error', message}` at any time; `{type:'stopped', reason:'ended'\|'error'}` when the tool exits |

**Invariants — do not break them:** the page must not send anything until the peer has said `hello` with a numeric `version`, and must refuse ports below 1024 (a link can name any local port); `started` must be sent *before* any capture bytes (the page creates its parser on it); the agent listens on `127.0.0.1` only; the WebSocket demands the token, a matching `Host`, and an `Origin` that is the agent's own or one given with `--origin`; one client at a time; the interface must come from the tool's own list; the filter is validated and passed as a single argv element; static files are served only from the repository layout and only from an allowlist (a standalone copy serves none); HTTP-server sockets are half-open, so treat `'end'` as a disconnect.

`--replay FILE` feeds a capture through the same pipeline on a virtual clock (batched, back-pressured), which is how the live path is tested without privileges.

## Tests

No dependencies; Node ≥ 18.

```sh
node web/test/run.js            # dissectors, pcap/pcapng, filters, robustness (truncation + random frames), PWA assets
node web/test/run.js --dump DIR # also write the samples as .pcap into DIR, to compare with tcpdump/Wireshark
node web/test/agent.js          # agent: auth, Host/Origin, --origin, streaming, path traversal, filter validation
```

What they prove, and what they do not:

- Samples are built independently of the parser (`samples.js` writes bytes; `dissect.js` reads them) and cross-checked against real `tcpdump`. When adding a dissector, also run `tcpdump -nn -r` on the dumped file.
- The agent tests drive a real subprocess with a hand-written WebSocket client, including the real `tcpdump` as far as the permission error. **Actual packet capture on an interface needs privileges and is not in CI** — test it by hand with `sudo`.
- Browser-level (UI) tests are not part of this repository; the libraries and the agent are what the suites above cover.

## CI and deployment

`.github/workflows/pages.yml`:

- **Pull requests** touching `web/**` run the two test suites.
- **Pushes to `master`** run the tests, then assemble `web/` minus `test/` and `README.md`, and deploy to GitHub Pages. One-time setup: *Settings → Pages → Source: GitHub Actions*.

Service-worker caching is **network-first**, so a deploy is visible on the next load. If you add a file the app needs offline, list it in `SHELL` in `sw.js` (a test fails if a listed file is missing, or an `index.html` script is not listed).

## Regenerating the README art

The README panels are generated, not hand-edited:

```sh
node scripts/readme/build-panels.mjs      # 12 SVGs → docs/assets/ (light + dark of each panel); no dependencies
```

Each panel is an SVG wrapping an HTML card in `<foreignObject>` (the same technique as the author's profile README) with Inter embedded as a base64 subset (`docs/assets/fonts/Inter-subset.woff2`, SIL OFL 1.1). The script refuses HTML-only entities such as `&nbsp;` (SVG is strict XML — use `&#160;`). After changing a panel, check it is well-formed (`xmllint --noout docs/assets/*.svg`) and that the fixed height still fits the content.

Screenshots (needs a browser driver):

```sh
npm i --no-save playwright-core
CHROME_PATH="/path/to/chrome" node scripts/readme/screenshots.mjs   # PW_DIR=<folder containing node_modules> if installed elsewhere
```

It opens the app with the built-in samples and the agent in replay mode, so the screenshots are reproducible.
