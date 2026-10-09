# Bavin Web

A browser version of Bavin: open a packet capture and read it **layer by layer** — Ethernet → IP → TCP/UDP → application — with every field linked to the exact bytes it came from.

Everything runs client-side: no build step, no dependencies, nothing uploaded. The page's Content-Security-Policy only allows WebSocket connections to `127.0.0.1`/`localhost` (used by the optional live-capture agent below), so it *cannot* send your capture to another machine.

## Run it

Open `index.html` directly, or serve the folder with anything static (live capture needs the agent's URL instead — see below):

```sh
python3 -m http.server -d web 8000   # then visit http://localhost:8000
```

## Put it online

The site is plain static files, so any static host works. This repo ships a GitHub Pages workflow (`.github/workflows/pages.yml`) that runs the tests and then publishes `web/` on every push to `master` that touches it.

**One-time setup:** repository **Settings → Pages → Build and deployment → Source: “GitHub Actions”**, then push (or run the workflow manually from the *Actions* tab). The site appears at `https://<user>.github.io/<repo>/` — for this repo, <https://seyyedkhandon.github.io/bavin/>.

All asset paths are relative, so it works from a sub-path like `/bavin/`; a custom domain needs no changes.

## Install it (one click)

The site is a Progressive Web App. In Chrome, Edge and other Chromium browsers an **Install** button appears in the top bar (or use the install icon in the address bar); on iPhone/iPad use *Share → Add to Home Screen*; in Safari on macOS use *File → Add to Dock*. Once installed it:

- opens in its own window and **works offline** (analysis needs no network);
- can be set as the opener for `.pcap` / `.pcapng` files (Chromium file handlers; availability depends on your OS and browser);
- always updates itself: the service worker is network-first, so a new deploy shows up on the next load.

## What it does

- **Opens** `.pcap` and `.pcapng` files (drag & drop or file picker), or a single packet pasted as hex.
- **Stacked protocol view** — the idea behind the original desktop app — with a plain-language explanation of each layer, TCP flags and IP flags as chips, and relative TCP sequence numbers.
- **Hex dump linked to fields** — hover a field to light up its bytes; hover a byte to see which field owns it; click a field to pin it.
- **Wireshark-style filters** — `tcp && port == 443`, `ip.addr == 192.168.1.0/24`, `dns or dhcp`, `!arp`, `info contains "GET"`, or plain text.
- **Overview** — traffic over time by protocol family, protocol mix, busiest addresses, top conversations; every row drills down into the packet list.
- Three built-in sample captures (generated in the browser, downloadable as `.pcap`), light/dark theme, keyboard navigation, and a phone-friendly layout.

### Protocols

The 15 from the desktop app — Ethernet, IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP, UDP, TCP, HTTP, DNS, NBNS, LLMNR, SSDP, DHCP — plus 802.1Q VLAN, IPv6 extension headers, mDNS and TLS record headers (including the SNI hostname).

## Live capture (optional local agent)

Browsers cannot open a network interface, so the page alone analyzes *recorded* captures. For live traffic, run the small agent on your own computer. It captures with `tcpdump` (or Wireshark's `dumpcap` on Windows), serves this same UI, and streams packets to it over a WebSocket:

```sh
sudo node web/agent/bavin-agent.js        # prints a URL ending in #token=…
```

The agent also serves the UI itself, so that URL works with no hosting at all. Open it, click **Live**, pick an interface (and optionally a BPF capture filter such as `tcp port 443`), and press **Start capturing**. Packets appear as they arrive, with Follow, filters, the stack view and Overview all working live. **Stop** ends the capture; **Save .pcap** writes what you captured (the newest 100,000 packets are kept).

### Live capture from the hosted site

You can also use the *online* copy for live capture. Start the agent and tell it which site to trust:

```sh
curl -O https://seyyedkhandon.github.io/bavin/agent/bavin-agent.js   # read it first — it runs with admin rights
sudo node bavin-agent.js --origin https://seyyedkhandon.github.io/bavin/
```

It prints a link ending in `#agent=PORT&token=…`. Open it (or paste it into **Live → Connect**) and the hosted page connects to `ws://127.0.0.1:PORT`. The Live dialog generates these commands for whichever site you are on.

Notes: the agent trusts *only* the origins you pass with `--origin` (https, or `http://localhost` for development) and still demands the token; the token travels in the URL fragment, which is never sent to any server. Safari blocks `https` pages from talking to `ws://127.0.0.1`, so use Chrome, Edge or Firefox for this, or the agent's own page. Recent Chrome versions may ask to allow “access to devices on your local network” — that is this connection.

No privileges handy? `node web/agent/bavin-agent.js --replay web/some.pcap --speed 2` streams a capture file as if it were live — good for trying the feature.

| Platform | How to grant capture rights |
| --- | --- |
| macOS | `sudo node …`, or install Wireshark's *ChmodBPF* helper and run without sudo |
| Linux | `sudo node …`, or `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)` |
| Windows | install Wireshark (Npcap + `dumpcap`) and run from an Administrator terminal |

### Agent security model

The agent can see all your traffic, so it is deliberately paranoid:

- listens on `127.0.0.1` only — never a public interface;
- the WebSocket requires a random token (printed once, passed in the URL *fragment*, which browsers never send over the network);
- `Host` and `Origin` are checked, so other websites and DNS-rebinding tricks are rejected — only the agent's own page and sites you pass with `--origin` are trusted; only one browser tab may connect;
- the capture tool is spawned without a shell, the interface must be one the tool listed, and the capture filter is validated and passed as a single argument;
- only `web/` is served (not `agent/` or `test/`), with path-traversal protection.

`node web/test/agent.js` tests all of this.

### What it deliberately does not do

It does not bundle a packet driver or capture by itself — live capture needs `tcpdump`/Wireshark on the machine and the privileges described above. The Windows desktop app in this repository still captures on its own.

## Layout

| File | Purpose |
| --- | --- |
| `js/pcap.js` | pcap / pcapng reader, hex-text parser |
| `js/dissect.js` | the protocol dissectors (each field records its byte range) |
| `js/filter.js` | filter language |
| `js/samples.js` | sample-traffic builders (also test fixtures) |
| `js/charts.js` | protocol families, statistics, traffic chart |
| `js/live.js` | WebSocket client for the agent |
| `js/pwa.js`, `sw.js`, `manifest.webmanifest` | install button, offline cache, file handler |
| `js/app.js` | UI |
| `agent/bavin-agent.js` | local capture agent (Node, no dependencies) |

Plain classic scripts (no modules) so the page also works from `file://`. All packet-derived text is inserted with `textContent`, never `innerHTML`, because a capture is untrusted input.

## Tests

```sh
node web/test/run.js            # dissectors, pcap/pcapng, filters, robustness (truncation + random frames)
node web/test/run.js --dump DIR # also write the sample captures to DIR to compare with tcpdump/Wireshark
node web/test/agent.js          # the capture agent: auth, Host/Origin checks, streaming, path traversal, filter validation
```

## Author and license

© 2026 SeyyedKhandon. The web version (everything in `web/`) is released under the [MIT License](LICENSE). The rest of the repository keeps its own licenses: the root [`LICENSE`](../LICENSE) (GPL-2.0) and the MIT license of the original Windows desktop app in `PacketAnalyzer/`.
