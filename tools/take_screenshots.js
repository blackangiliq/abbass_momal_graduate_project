/*
 * Regenerate the dashboard screenshots used in the README (Node + Playwright).
 *
 * Start two instances first (on one machine, different ports):
 *   python -m secure_transfer --name Laptop-1  --port 5001 --web-port 8000 --data-dir ./demoA --no-browser
 *   python -m secure_transfer --name Desktop-2 --port 5002 --web-port 8001 --data-dir ./demoB --no-browser
 * Then:  node tools/take_screenshots.js <file1> [file2 ...]
 */
const { chromium } = require("playwright");
const path = require("path");
const fs = require("fs");

const OUT = path.join(__dirname, "..", "docs", "images");
fs.mkdirSync(OUT, { recursive: true });
const files = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shot = (page, name, full = false) => page.screenshot({ path: path.join(OUT, name), fullPage: full });

(async () => {
  const br = await chromium.launch();
  const ctx = await br.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, locale: "ar-IQ" });
  const a = await ctx.newPage(); await a.goto("http://127.0.0.1:8000/");
  const b = await ctx.newPage(); await b.goto("http://127.0.0.1:8001/");
  await sleep(2500);
  await shot(a, "01_dashboard_sender.png");

  await a.click(".peer >> nth=0");
  await a.setInputFiles("#fileInput", files);
  await sleep(1200);
  await shot(a, "02_select_device_and_files.png");

  await a.click("#sendBtn");
  await b.waitForSelector("#modal:not([hidden])", { timeout: 20000 });
  await sleep(1200);
  await shot(b, "03_receiver_incoming_request_sas.png");
  await shot(a, "04_sender_waiting_same_sas.png");

  for (let i = 0; i < files.length; i++) {
    await b.waitForSelector("#modal:not([hidden])", { timeout: 20000 });
    await b.click("#mAccept");
    await sleep(1500);
  }
  await sleep(3000);
  await shot(b, "05_receiver_done_sha256_verified.png");
  await shot(a, "06_sender_done.png");

  await a.fill("#manIp", "192.168.1.20");
  await a.click("#scanBtn");
  await sleep(300);
  await shot(a, "07_scan_and_manual_ip.png");

  const m = await (await br.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 })).newPage();
  await m.goto("http://127.0.0.1:8001/"); await sleep(2000);
  await shot(m, "08_mobile_width.png", true);
  await br.close();
  console.log("screenshots saved to", OUT);
})();
