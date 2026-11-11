/* Render a text file as a terminal-style PNG:  node tools/render_terminal.js in.txt out.png [title] */
const { chromium } = require("playwright");
const fs = require("fs");
const [inp, out, title = "Terminal"] = process.argv.slice(2);
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
let txt = esc(fs.readFileSync(inp, "utf8"))
  .replace(/^(###.*)$/gm, '<b style="color:#fbbf24">$1</b>')
  .replace(/(\[ATTACK\].*|.*security.*|.*failed.*)$/gm, '<b style="color:#f87171">$1</b>')
  .replace(/(.*(verified|done).*)$/gm, '<b style="color:#34d399">$1</b>');
(async () => {
  const br = await chromium.launch();
  const p = await br.newPage({ viewport: { width: 1000, height: 400 }, deviceScaleFactor: 2 });
  await p.setContent(`<body style="margin:0;background:#0b1220;padding:18px">
   <div id="t" style="display:inline-block;background:#0f172a;border:1px solid #1f3050;border-radius:10px;overflow:hidden">
    <div style="background:#1b2d4d;color:#cbd5e1;font:13px Segoe UI,sans-serif;padding:8px 14px">● ● ●&nbsp;&nbsp; ${esc(title)}</div>
    <pre style="margin:0;padding:14px 18px;color:#e2e8f0;font:12.5px/1.45 Consolas,'DejaVu Sans Mono',monospace">${txt}</pre></div></body>`);
  await (await p.$("#t")).screenshot({ path: out });
  await br.close();
})();
