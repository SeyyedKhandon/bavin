# Bavin guide

How to use Bavin, learn from it, capture your own traffic, and put it online. For architecture and contributing, see [DEVELOPING.md](DEVELOPING.md).

**Contents** — [The idea](#the-idea) · [Run it](#run-it) · [Reading a packet](#reading-a-packet) · [Lab 1: loading a web page](#lab-1-loading-a-web-page) · [Lab 2: a chatty home network](#lab-2-a-chatty-home-network) · [Lab 3: IPv6](#lab-3-ipv6) · [Filters](#filters) · [Capture your own traffic](#capture-your-own-traffic) · [Live capture](#live-capture) · [Keyboard](#keyboard-shortcuts) · [Put it online](#put-it-online) · [Troubleshooting](#troubleshooting)

---

## The idea

Network data travels in **layers**, each wrapping the one above it, like envelopes inside envelopes:

```
 ┌─────────────────────────────────────────────────────────────┐
 │ Ethernet   who on this LAN?        dst MAC · src MAC        │  Link
 │ ┌─────────────────────────────────────────────────────────┐ │
 │ │ IPv4/IPv6  which machine?       src IP · dst IP · TTL    │ │  Network
 │ │ ┌─────────────────────────────────────────────────────┐ │ │
 │ │ │ TCP/UDP  which program?    ports · seq/ack · flags   │ │ │  Transport
 │ │ │ ┌─────────────────────────────────────────────────┐ │ │ │
 │ │ │ │ HTTP/DNS/TLS…   the actual conversation          │ │ │ │  Application
 │ │ │ └─────────────────────────────────────────────────┘ │ │ │
 │ │ └─────────────────────────────────────────────────────┘ │ │
 │ └─────────────────────────────────────────────────────────┘ │
 └─────────────────────────────────────────────────────────────┘
```

Bavin shows exactly that. Click a packet and it is unwrapped into one card per layer — **application on top, link at the bottom** (the *stack*), because that is how protocols are drawn in textbooks. A button flips it to **wire order** (outermost header first), which is how the bytes are actually laid out.

Every field remembers the bytes it came from. Hover a field and its bytes light up in the hex dump; hover a byte and the field that owns it lights up. That link between *meaning* and *bytes* is the whole point.

## Run it

### Online
Open **<https://seyyedkhandon.github.io/bavin/>**. Pick a built-in sample or drop a `.pcap` / `.pcapng` file on the page. Everything is analyzed in your browser tab; the capture is never uploaded.

### Install it
The site is a Progressive Web App.

| Where | How |
| --- | --- |
| Chrome, Edge, other Chromium | Press **Install** in Bavin's top bar, or use the install icon in the address bar |
| iPhone / iPad (Safari) | **Share → Add to Home Screen** |
| Safari on macOS | **File → Add to Dock** |

Once installed it opens in its own window, works **offline**, and updates itself (a new deploy appears on the next launch). Chromium can also offer it as an opener for `.pcap` / `.pcapng` files (the app declares this; it depends on your OS and browser).

> The **Install** button only appears when the browser decides the page is installable: served over **https** (or `localhost`) and not already installed.

### Run it locally
It is plain static files — no build step, no dependencies.

```sh
git clone https://github.com/SeyyedKhandon/bavin.git
cd bavin
python3 -m http.server -d web 8000          # then open http://localhost:8000
```

Use a **full path** for `-d` if you start the server from another folder:
`python3 -m http.server -d /full/path/to/bavin/web 8000`. You can also just double-click `web/index.html`; everything except Live capture and Install works from `file://`.

---

## Reading a packet

Click any row in the packet list. The right-hand side shows:

1. **A proportional bar** of the layers (click a segment to jump to that card).
2. **One card per layer.** Each has a short note on what the layer is *for*, then its fields as tiles. Small chips show flags (TCP `SYN`/`ACK`/`FIN`…, IPv4 `DF`/`MF`, DNS `QR`/`RD`…) with the set ones lit.
3. **The raw bytes**, colour-coded by layer. Hover to link fields and bytes; **click a field to pin** it so its bytes stay lit.

Some things that are computed for you:

- **Relative TCP sequence numbers.** Raw sequence numbers are huge random values; Bavin shows `relative: 0, 1, 104…` per connection, like Wireshark.
- **Checksums.** The IPv4 header checksum is verified (`valid ✓` / `invalid ✗`). Packets captured on the machine that *sent* them often show bad TCP/UDP checksums because the network card fills them in afterwards ("checksum offload"), so those are not flagged.
- **The Info column** summarises each packet in one line (`GET / HTTP/1.1`, `Who has 192.168.1.1? Tell …`, `[SYN, ACK] Seq=0 Ack=1`).
- **Warnings.** A `!` next to a packet number means a checksum mismatch or a truncated capture; malformed packets are labelled, never hidden.

The **Overview** tab shows traffic over time (stacked by protocol family), the protocol mix, the busiest addresses and the top conversations. Every row there is clickable: it filters the packet list.

---

## Lab 1: loading a web page

Open the sample **Loading a web page**. All addresses are made up, but the bytes are real, valid packets (checksums included), so you can export them with *Download .pcap* and open them in Wireshark to compare.

| Packets | What to look for |
| --- | --- |
| **1–2 ARP** | #1 is a **broadcast** (`ff:ff:ff:ff:ff:ff`) asking *who has 192.168.1.1?* The target MAC is all zeros: that is the question. #2 answers with the MAC. This is how an IP address becomes a hardware address on a LAN. |
| **3–4 DNS** | A UDP datagram to port 53. Note the **transaction ID `0x7a31`** repeated in the reply, and in the answer's name a *compression pointer* back to the question. The answer is `A 93.184.216.34` with a TTL. |
| **5–7 TCP handshake** | **SYN** (relative seq 0) → **SYN, ACK** (seq 0, ack 1) → **ACK** (seq 1, ack 1). Open the TCP card on #5 and read the options: *Maximum segment size*, *Window scale*, *SACK permitted*, *Timestamps*. |
| **8 HTTP request** | `GET / HTTP/1.1`, plain text. The TCP card shows `PSH, ACK` and **Len=103**. Click the HTTP `Method` field: three bytes light up in the hex dump (`47 45 54`). |
| **9 ACK** | The server acknowledges: `Ack=104` — that is 1 + the 103 bytes it received. Acknowledgement numbers say *"I have everything before this byte."* |
| **10–11 response** | `HTTP/1.1 200 OK` carrying 287 bytes; the client ACKs `288`. Look at `Content-Length` in the headers. |
| **12–14 teardown** | `FIN, ACK` each way, then a final `ACK`. Closing a connection takes its own exchange. |
| **15–16 NXDOMAIN** | A lookup for `no-such-host.invalid` fails: response code **3, "No such name"**. |
| **17–18 TLS** | #17 is a `Client Hello` and the site name (**SNI**, `example.com`) is visible **in clear text** — even though everything after it is encrypted. #18 is `Application Data`: unreadable bytes. |

Try: `tcp.flags.syn == 1` (the two packets that open connections), `dns` (the lookups), `tls` (the encrypted part).

## Lab 2: a chatty home network

Open **Chatty home network**. This is the background noise every LAN makes.

| Packets | What to look for |
| --- | --- |
| **1–4 DHCP** | The famous four: **D**iscover → **O**ffer → **R**equest → **A**CK. The client has no address yet, so it sends from `0.0.0.0` to `255.255.255.255`. The `BOOTP flags` chip shows **Broadcast**. The offer's `Your IP (yiaddr)` is the address it will get. Same *Transaction ID* throughout. |
| **5 gratuitous ARP** | A device announcing *its own* address (sender IP = target IP). |
| **6–7 ARP** | A normal who-has / is-at pair. |
| **8–11 ping** | ICMP echo request/reply pairs. Compare the **TTL**: `128` from the PC, `64` from the TV — different operating systems pick different starting values. |
| **12 ICMP unreachable** | *Port unreachable*, and it quotes the **original datagram** (the packet that caused the error) so the sender can tell which one failed. |
| **13–14 SSDP** | UPnP discovery: an `M-SEARCH` question to the multicast address `239.255.255.250`, and a device's `NOTIFY` announcement. It is HTTP-shaped text over UDP. |
| **15–17 IGMP** | Multicast membership: a router *query*, a v2 *report*, a v3 report. |
| **18 mDNS** | DNS on multicast (`224.0.0.251`, port 5353) looking for Chromecasts. |
| **19 NBNS** | A legacy Windows name lookup: the name `WORKGROUP<00>` is stored as 32 letters in the packet, two per byte. Bavin decodes it. |
| **20 LLMNR** | Another Windows name lookup, to `224.0.0.252`. |

## Lab 3: IPv6

Open **IPv6 neighbours**. IPv6 has no ARP: ICMPv6 does that job.

| Packets | What to look for |
| --- | --- |
| **1–2** | A host sends a **Router Solicitation**; the router answers with a **Router Advertisement** — prefix, MTU, lifetime, and the `M`/`O` chips saying whether to use DHCPv6. This is how an IPv6 host configures itself. |
| **3–4** | **Neighbor Solicitation / Advertisement**: *"who has fe80::…?"* → *"it is at 84:16:f9:0c:aa:01."* The same job as ARP. |
| **5–8** | `ping6`. IPv6 calls the TTL **Hop limit**. |
| **9** | An MLDv2 report. It has an **IPv6 extension header** (Hop-by-Hop) between IPv6 and ICMPv6 — see the extra card. |
| **10–11** | A DNS `AAAA` lookup (the IPv6 record type) over IPv6/UDP. |

---

## Filters

The filter bar above the packet list uses a forgiving subset of Wireshark's display filters, so what you learn carries over. Press <kbd>/</kbd> to focus it, <kbd>Esc</kbd> to clear it, or press the **Syntax** button for a cheat sheet. The **chips** under the bar are one-click filters for the protocol families in your capture.

| Want | Type |
| --- | --- |
| Only one protocol | `tcp` · `udp` · `dns` · `dhcp` · `arp` · `icmp` · `icmp6` · `igmp` · `tls` · `http` · `ssdp` · `mdns` · `ipv6` |
| Combine | `tcp && port == 443` · `dns or dhcp` · `!arp` · `(arp or icmp) and !ipv6` |
| By address | `ip.addr == 192.168.1.105` · `ip.src == 10.0.0.1` · `ip.addr == 192.168.1.0/24` · `eth.addr == aa:bb:cc:dd:ee:ff` |
| By port | `port == 80` · `tcp.port == 443` · `udp.port == 53` · `port != 443` |
| By size / TTL | `len > 1000` · `ttl < 5` |
| TCP flags | `tcp.flags.syn == 1` · or simply `syn`, `ack`, `fin`, `rst`, `psh` · `syn && !ack` |
| Text | `info contains "GET"` · `example.com` (a bare word searches addresses, protocol and info) |

Operators: `==  !=  >  <  >=  <=  contains`, and `&&  ||  !` or `and  or  not`. Mistakes get a plain-language message under the bar (`Unknown field "foo.bar"…`) and never break the list.

**Quick exercises:** find every packet whose TTL is below 100 (`ttl < 100`); find the DHCP messages sent *by the client* before it has an address (`dhcp && ip.src == 0.0.0.0` — two packets, both with the `Broadcast` chip lit); show only one TCP connection (open a TCP packet and press **Only this conversation**).

---

## Capture your own traffic

Bavin opens standard capture files. Record one with:

```sh
# macOS (Wi-Fi is usually en0; list interfaces with:  tcpdump -D)
sudo tcpdump -i en0 -w capture.pcap

# Linux
sudo tcpdump -i any -w capture.pcap

# Windows (or anywhere): Wireshark → pick an interface → Start … Stop → File → Save
```

Stop with <kbd>Ctrl</kbd>+<kbd>C</kbd>, then drop `capture.pcap` on Bavin. Things worth knowing:

- **Privacy.** A capture contains everything that crossed the interface: pages, cookies, DNS lookups, passwords on unencrypted protocols. Treat it like a password file. Do not commit it to Git or share it publicly. (This repo's `.gitignore` excludes `*.pcap`.)
- **What you can see.** On a modern switched or Wi-Fi network you only see *your own* traffic plus broadcasts and multicast. Most web traffic is encrypted (TLS): you see the TCP/IP layers and the TLS handshake — including the server name — but not the contents.
- **Size.** Browser limits apply: files over about 1.5 GB are refused. Trim with `tcpdump -c 100000 …` or `editcap`. Compressed files (`.gz`) must be decompressed first.
- **Formats.** Classic `.pcap` (microsecond or nanosecond, either byte order) and `.pcapng`. Link types: Ethernet, loopback/null, raw IP and Linux "cooked" captures.

You can also paste **one packet as hex** (the *Paste hex* button): plain hex, a C array, or Wireshark's *Copy → as hex dump*.

---

## Live capture

Watch traffic as it happens. A browser cannot read a network card, so a small **agent** runs on your computer and streams packets to the page.

```
  Bavin page ──ws://127.0.0.1──▶ agent (Node) ──▶ tcpdump ──▶ network card
```

### With the repository (simplest)

```sh
sudo node web/agent/bavin-agent.js
```

It prints a link ending in `#token=…`. **Open it** — the Live dialog opens and connects by itself. Choose the interface (your Wi-Fi is usually `en0` on a Mac), optionally type a capture filter such as `tcp port 443`, and press **Start capturing**. Packets stream in. **Follow** keeps the newest packet in view (scroll up and it turns itself off). **Stop** ends it; **Save .pcap** writes what you captured; the newest 100,000 packets are kept.

### With the online site

```sh
curl -O https://seyyedkhandon.github.io/bavin/agent/bavin-agent.js    # one file; read it before running as admin
sudo node bavin-agent.js --origin https://seyyedkhandon.github.io/bavin/
```

The agent prints a link like `https://…/bavin/#agent=8765&token=…`. **Just open it**: the Live dialog pops up already connected, with the interface picker ready — there is nothing to copy or paste. (If you opened the link in another browser or window, paste it into **Live → Connect** instead.) The Live dialog generates these two commands for whatever site you are on.

### Without admin rights

```sh
node web/agent/bavin-agent.js --replay my.pcap --speed 2
```

streams a capture file as if it were live — handy for trying the feature.

### Giving the agent capture rights

| Platform | Options |
| --- | --- |
| macOS | `sudo node …`, or install Wireshark's *ChmodBPF* helper and run without sudo |
| Linux | `sudo node …`, or `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)` |
| Windows | Install Wireshark (Npcap + `dumpcap`) and run from an Administrator terminal |

### Is it safe?
The agent can see all your traffic, so it is strict: it listens on `127.0.0.1` only; it needs a random **token** (printed once, carried in the URL *fragment*, which browsers never send to any server); it checks `Host` and `Origin`, so other websites and DNS-rebinding tricks are refused; only one tab may connect; it never uses a shell; the interface must be one the tool listed; the capture filter is validated. It trusts your own page, plus only the sites you pass with `--origin`. Details: [DEVELOPING.md](DEVELOPING.md#the-capture-agent).

Browser notes: Safari blocks `https` pages from talking to `ws://127.0.0.1`, so use Chrome, Edge or Firefox for the *online* site (the agent's own page works everywhere). Recent Chrome versions may ask permission to access "devices on your local network" — that is this connection.

---

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| <kbd>↑</kbd> <kbd>↓</kbd> or <kbd>j</kbd> <kbd>k</kbd> | previous / next packet |
| <kbd>PageUp</kbd> <kbd>PageDown</kbd> | move 10 |
| <kbd>Home</kbd> <kbd>End</kbd> | first / last packet |
| <kbd>/</kbd> | focus the filter |
| <kbd>Esc</kbd> | clear the filter · (on a phone) close the packet |
| <kbd>Enter</kbd> | (on a phone) open the selected packet |

---

## Put it online

The web version is static files, so any static host works. This repository publishes to **GitHub Pages** automatically.

### GitHub Pages (this repo)
1. In the repository: **Settings → Pages → Build and deployment → Source: "GitHub Actions"** (once).
2. Merge to `master`. The workflow `.github/workflows/pages.yml` runs the tests, assembles `web/` (without `test/`), and deploys it.
3. The site is at `https://<user>.github.io/<repo>/` — here <https://seyyedkhandon.github.io/bavin/>.

Every path is relative, so it works from a sub-path; a custom domain needs no changes. Pull requests run the tests but do not deploy.

### Any other host
Copy the contents of `web/` (except `test/`) to the web root — nginx, Caddy, Netlify, S3 + CloudFront, anything. Serve it over **https**: installing and offline use require a secure context. No special headers are needed (the Content-Security-Policy is in the page itself). If you serve a copy that should pair with the live-capture agent, use that copy's URL in `--origin`.

### Checking a deployment
1. Open the site, load a sample — it should analyze with no errors in the console.
2. Reload with the network off (DevTools → Network → Offline): it should still load.
3. Look for the **Install** button (Chromium).
4. Optionally pair the agent (above) and capture a few packets.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| **`Error code: 404 — File not found`** from `python3 -m http.server` | You started it from the wrong folder, so `web` does not exist there. Use the full path: `python3 -m http.server -d /full/path/to/bavin/web 8000`. Also check the URL: locally the app is at `/`, not `/bavin/` (that is only the GitHub Pages path). |
| "Not a pcap or pcapng file" | Wrong file type (or a compressed `.gz`; decompress it). |
| Live says *permission denied* | The agent is not running as an administrator. Restart it with `sudo` (macOS/Linux) or from an Administrator terminal (Windows). |
| Live says *Could not connect to the agent* | The agent stopped, you opened an old link (the token changes on every start), the site was not passed with `--origin`, or another tab already holds the connection (only one is allowed). |
| The agent says *standalone copy — it does not serve the web app* | Expected for the single downloaded file: it only talks to a Bavin site, so run it with `--origin https://…` and open the hosted link it prints. From a repository checkout it also serves the app itself. |
| Live shows **"Connecting to the agent…"** and never finishes | The browser is holding the connection to `127.0.0.1`. Recent Chrome and Edge ask permission to "access devices on your local network" — look for the prompt near the address bar and choose **Allow**, then press **Connect** again (after 10 seconds Bavin gives up and says so). Brave Shields and some ad blockers also block it, and Safari blocks it from https pages. The reliable alternative: open the agent's **own** link, the one starting with `http://127.0.0.1`, which works in every browser. |
| Live does nothing on the online site in Safari | Safari blocks https → `ws://127.0.0.1`. Use Chrome/Edge/Firefox, or open the agent's own link. |
| No **Install** button | Needs https (or `localhost`), a supported browser, and not already installed. Safari uses *Add to Home Screen* / *Add to Dock* instead. |
| A page works online but not from `file://` for Live/Install | By design: those need a served origin. Run `python3 -m http.server`. |
| Packets show a `!` or "checksum mismatch" | Often harmless: capture-side checksum offload on the machine that sent the packet. |
| Everything looks like "TCP" with no HTTP | The traffic is TLS-encrypted. You will see the handshake and server name (SNI), not the content. |
| Cannot see other devices' traffic | A switched/Wi-Fi network only delivers your own traffic and broadcasts to you. |

---

## The original desktop app

The Windows desktop version (C#, WinForms + WinPcap) is still in [`PacketAnalyzer/`](../PacketAnalyzer/) and remains the way to sniff live on Windows with nothing but a double-click. Requirements: Windows, [.NET Framework 4](https://dotnet.microsoft.com/en-us/download/dotnet-framework) and WinPcap (installer included). Open it, select a network interface, and it starts listening. See the [root README](../README.md#the-original-desktop-app-c) for screenshots.
