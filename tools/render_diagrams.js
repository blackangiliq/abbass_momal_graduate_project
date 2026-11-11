/*
 * Render docs/diagrams/*.mmd to PNG (docs/images/diagram_*.png) with Mermaid + Playwright.
 * Usage:  npm install mermaid@11.4.1   (anywhere)
 *         node tools/render_diagrams.js <path/to/node_modules/mermaid/dist/mermaid.min.js>
 */
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const mermaidJs = fs.readFileSync(process.argv[2], "utf8");
const SRC = path.join(__dirname, "..", "docs", "diagrams");
const OUT = path.join(__dirname, "..", "docs", "images");

(async () => {
  const br = await chromium.launch();
  const page = await br.newPage({ deviceScaleFactor: 2, viewport: { width: 1600, height: 1000 } });
  for (const f of fs.readdirSync(SRC).filter((x) => x.endsWith(".mmd")).sort()) {
    const code = fs.readFileSync(path.join(SRC, f), "utf8");
    await page.setContent(`<html><body style="margin:0;background:#fff">
      <div id="c" style="display:inline-block;padding:24px;background:#fff"></div></body></html>`);
    await page.addScriptTag({ content: mermaidJs });
    await page.evaluate(async (code) => {
      mermaid.initialize({ startOnLoad: false, theme: "default", securityLevel: "loose",
        flowchart: { htmlLabels: true, curve: "basis" }, sequence: { mirrorActors: false } });
      const { svg } = await mermaid.render("g", code);
      document.getElementById("c").innerHTML = svg;
    }, code);
    const el = await page.$("#c");
    const out = path.join(OUT, "diagram_" + f.replace(".mmd", ".png"));
    await el.screenshot({ path: out });
    console.log("rendered", out);
  }
  await br.close();
})();
