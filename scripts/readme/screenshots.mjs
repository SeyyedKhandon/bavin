// SPDX-License-Identifier: MIT — Copyright (c) 2026 SeyyedKhandon
// Regenerates the README screenshots in docs/assets/ (web-*, overview-*, live-*  ×  light/dark).
//   npm i --no-save playwright-core        # one-off, anywhere on your machine
//   CHROME_PATH=/path/to/chrome node scripts/readme/screenshots.mjs
// The live shot starts the capture agent in replay mode, so no privileges or network are needed.
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const out = join(root, 'docs', 'assets');
const require = createRequire(process.env.PW_DIR ? join(process.env.PW_DIR, 'x.js') : import.meta.url);
const { chromium } = require('playwright-core');
const CHROME = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
mkdirSync(out, { recursive: true });

// a replay source for the live shot: the "chatty LAN" sample, written as a temp .pcap
globalThis.window = {}; // samples.js/util.js attach to window.Bavin or globalThis.Bavin
const B = (globalThis.Bavin = {});
require(join(root, 'web/js/util.js')); const pcap = require(join(root, 'web/js/pcap.js')); const samples = require(join(root, 'web/js/samples.js'));
const tmp = join(tmpdir(), 'bavin-shots-' + process.pid); mkdirSync(tmp, { recursive: true });
writeFileSync(join(tmp, 'lan.pcap'), pcap.write(samples.LIST[1].make(), 1));

const agent = spawn(process.execPath, [join(root, 'web/agent/bavin-agent.js'), '--port', '0', '--replay', join(tmp, 'lan.pcap'), '--speed', '40'], { stdio: ['ignore', 'pipe', 'inherit'] });
const link = await new Promise((resolve) => { let o = ''; agent.stdout.on('data', (d) => { o += d; const m = /http:\/\/127\.0\.0\.1:\d+\/#token=[\w-]+/.exec(o); if (m) resolve(m[0]); }); });

const browser = await chromium.launch({ executablePath: CHROME });
const shot = (page, name, mode) => page.screenshot({ path: join(out, `${name}-${mode}.jpg`), type: 'jpeg', quality: 88 });

for (const mode of ['light', 'dark']) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 860 }, colorScheme: mode, deviceScaleFactor: 1 });
  const p = await ctx.newPage();
  await p.goto(pathToFileURL(join(root, 'web/index.html')).href);
  await p.locator('.sample').first().click();
  await p.waitForSelector('.row');
  await p.locator('.row', { hasText: 'GET /' }).first().click();
  await p.locator('.fld', { hasText: 'Method' }).first().click(); // pin a field: its bytes light up in the hex dump
  await p.mouse.move(700, 880);
  await shot(p, 'web', mode);
  await p.locator('#tab-overview').click();
  await p.waitForSelector('.chart');
  await p.waitForTimeout(300);
  await shot(p, 'overview', mode);
  await ctx.close();

  // live capture (agent in replay mode)
  const lctx = await browser.newContext({ viewport: { width: 1440, height: 860 }, colorScheme: mode });
  const lp = await lctx.newPage();
  await lp.goto(link);
  await lp.waitForFunction(() => document.getElementById('btnLive').dataset.state === 'ready');
  await lp.locator('#btnLive').click();
  await lp.waitForSelector('#liveIface option', { state: 'attached' });
  await lp.locator('#liveStart').click();
  await lp.waitForFunction(() => Bavin.app._state.packets.length >= 12);
  await lp.waitForTimeout(150);
  await lp.waitForSelector('#liveBar[data-state="stopped"]', { timeout: 20000 }).catch(() => {});
  await lp.locator('.row', { hasText: 'DHCP Discover' }).first().click().catch(() => {});
  await shot(lp, 'live', mode);
  await lctx.close();
}
await browser.close(); agent.kill('SIGINT'); rmSync(tmp, { recursive: true, force: true });
console.log('screenshots written to docs/assets/');
