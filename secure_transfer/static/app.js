"use strict";
const $ = (id) => document.getElementById(id);
const TOKEN = window.SFT_TOKEN;
let selected = null;          // selected peer
let files = [];               // files chosen for sending
let modalFor = null;          // transfer id shown in the modal
let lastState = null;
let nameEditing = false;

const STATUS_AR = {
  connecting: "جارِ الاتصال", hashing: "حساب البصمة", waiting: "بانتظار الموافقة",
  transferring: "جارِ النقل", done: "اكتمل ✓", failed: "فشل", rejected: "مرفوض",
};
const TRUST_AR = { trusted: "موثوق", new: "جديد", changed: "⚠ تغيّر المفتاح!" };

function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function fmtSize(n) {
  if (!n && n !== 0) return "";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
const B = (s) => `<bdi dir="ltr">${s}</bdi>`;
function toast(msg, ms = 3000) {
  const t = $("toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toast._h); toast._h = setTimeout(() => (t.hidden = true), ms);
}
async function api(path, opts = {}) {
  opts.headers = Object.assign({ "X-SFT-Token": TOKEN }, opts.headers || {});
  if (opts.json !== undefined) {
    opts.body = JSON.stringify(opts.json); opts.headers["Content-Type"] = "application/json"; delete opts.json;
  }
  const r = await fetch(path, opts);
  let data = {}; try { data = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

// ------------------------------------------------------------------ render
function renderMe(me) {
  $("myIp").textContent = me.primary_ip;
  $("myIps").textContent = me.interfaces.filter((i) => i.ip !== me.primary_ip).map((i) => i.ip).join("  ·  ");
  if (!nameEditing) $("myName").value = me.name;
  $("myPort").textContent = me.port;
  $("myFp").textContent = me.fingerprint;
  $("recvDir").textContent = me.received_dir;
  $("autoAccept").checked = me.auto_accept_trusted;
}

function renderPeers(st) {
  const ul = $("peerList");
  $("scanBtn").classList.toggle("busy", st.scanning);
  $("scanBtn").querySelector(".t").textContent = st.scanning ? "جارِ المسح…" : "🔍 مسح الشبكة";
  if (st.last_scan) $("scanInfo").textContent =
    `آخر مسح: ${new Date(st.last_scan * 1000).toLocaleTimeString("ar-IQ")} — عدد الأجهزة: ${st.peers.length}`;
  if (!st.peers.length) {
    ul.innerHTML = `<li class="empty">لم يتم العثور على أجهزة بعد.<br>شغّل البرنامج على الجهاز الآخر ثم اضغط «مسح الشبكة».</li>`;
    return;
  }
  ul.innerHTML = st.peers.map((p) => `
    <li class="peer ${selected && selected.device_id === p.device_id ? "sel" : ""}" data-id="${esc(p.device_id)}">
      <span class="dot ${p.online ? "on" : ""}"></span>
      <span class="nm">${esc(p.name)}</span>
      <span class="badge b-${esc(p.trust)}">${TRUST_AR[p.trust] || p.trust}</span>
      <span class="addr mono">${esc(p.ip)}:${esc(p.port)}</span>
      <span></span>
      <span class="fps mono">${esc(p.fingerprint)}</span>
    </li>`).join("");
  ul.querySelectorAll(".peer").forEach((li) => li.onclick = () => {
    selected = st.peers.find((p) => p.device_id === li.dataset.id);
    renderPeers(lastState); renderTarget();
  });
  if (selected) {
    const fresh = st.peers.find((p) => p.device_id === selected.device_id);
    if (fresh) selected = fresh;
  }
}

function renderTarget() {
  const t = $("target");
  if (selected) {
    t.className = "target ok";
    t.innerHTML = `الإرسال إلى: <b>${esc(selected.name)}</b> <span class="mono">(${esc(selected.ip)}:${esc(selected.port)})</span>`;
  } else {
    t.className = "target"; t.textContent = "لم يتم اختيار جهاز — اختر جهازاً من القائمة";
  }
  $("sendBtn").disabled = !(selected && files.length);
}

function renderFiles() {
  $("fileList").innerHTML = files.map((f, i) =>
    `<li><span>${esc(f.name)}</span><span>${B(fmtSize(f.size))} <span class="x" data-i="${i}">✕</span></span></li>`).join("");
  $("fileList").querySelectorAll(".x").forEach((x) => x.onclick = (e) => {
    e.preventDefault(); files.splice(+x.dataset.i, 1); renderFiles();
  });
  renderTarget();
}

function renderTransfers(list) {
  const box = $("transferList");
  if (!list.length) { box.innerHTML = `<div class="empty">لا توجد عمليات نقل بعد</div>`; return; }
  box.innerHTML = list.map((t) => {
    const pct = t.size ? Math.min(100, (t.done / t.size) * 100) : (t.status === "done" ? 100 : 0);
    const peer = t.peer_name ? `${esc(t.peer_name)} <span class="mono">(${esc(t.peer_ip)})</span>` : `<span class="mono">${esc(t.peer_ip)}</span>`;
    return `<div class="tr">
      <div class="tr-h">
        <div class="tr-n"><span class="dir ${t.direction}">${t.direction === "send" ? "↑ إرسال" : "↓ استلام"}</span>
          <span class="fn" title="${esc(t.filename)}">${esc(t.filename)}</span></div>
        <span class="st ${t.status}">${STATUS_AR[t.status] || t.status}</span>
      </div>
      <div class="bar"><i style="width:${pct.toFixed(1)}%"></i></div>
      <div class="tr-m">
        <span>${t.direction === "send" ? "إلى" : "من"}: <b>${peer}</b></span>
        <span>${B(`<b>${fmtSize(t.done)}</b> / ${fmtSize(t.size)} (${pct.toFixed(0)}%)`)}</span>
        ${t.speed ? `<span>السرعة: ${B(`<b>${fmtSize(t.speed)}/s</b>`)}</span>` : ""}
        ${t.sas ? `<span>رمز التحقق: <span class="sasx">${esc(t.sas)}</span></span>` : ""}
        ${t.trust ? `<span class="badge b-${esc(t.trust)}">${TRUST_AR[t.trust] || t.trust}</span>` : ""}
        ${t.needs_decision ? `<span class="link" data-open="${t.id}">عرض الطلب</span>` : ""}
        ${t.saved_as ? `<span class="link" data-path="${esc(t.saved_as)}">📂 إظهار الملف</span>` : ""}
      </div>
      ${t.status === "done" && t.sha256 ? `<div class="hash mono">SHA-256 ✓ ${esc(t.sha256)}</div>` : ""}
      ${t.error ? `<div class="errline">${esc(t.error)}</div>` : ""}
    </div>`;
  }).join("");
  box.querySelectorAll("[data-open]").forEach((a) => a.onclick = () => openModal(list.find((t) => t.id === a.dataset.open)));
  box.querySelectorAll("[data-path]").forEach((a) => a.onclick = () => api("/api/open-folder", { method: "POST", json: { path: a.dataset.path } }));
}

function openModal(t) {
  if (!t) return;
  modalFor = t.id;
  $("mFrom").innerHTML = `${esc(t.peer_name)} <span class="mono">(${esc(t.peer_ip)})</span>`;
  $("mFile").textContent = t.filename;
  $("mSize").innerHTML = B(fmtSize(t.size));
  $("mFp").textContent = t.peer_fp;
  $("mSas").textContent = t.sas;
  const w = $("mWarn");
  if (t.trust === "changed") {
    w.hidden = false;
    w.textContent = "تحذير أمني: مفتاح هوية هذا الجهاز تغيّر منذ آخر اتصال! قد يكون هجوم وسيط (MITM). لا تقبل إلا إذا تأكدت أن الجهاز أُعيد تنصيبه.";
  } else if (t.trust === "new") {
    w.hidden = false;
    w.style.cssText = "background:rgba(34,211,238,.08);border-color:#1d5a69;color:#bae6fd";
    w.textContent = "جهاز جديد: قارن رمز التحقق مع الشخص المرسل قبل القبول.";
  } else w.hidden = true;
  $("modal").hidden = false;
}
function closeModal() { $("modal").hidden = true; modalFor = null; }

async function decide(accept) {
  if (!modalFor) return;
  const id = modalFor; closeModal();
  await api(`/api/decision/${id}`, { method: "POST", json: { accept, trust: $("mTrust").checked } });
  toast(accept ? "تم القبول — جارِ الاستلام المشفّر" : "تم رفض الطلب");
}

// ------------------------------------------------------------------ polling
async function refresh() {
  try {
    const st = await api("/api/state");
    lastState = st;
    renderMe(st.me); renderPeers(st); renderTarget(); renderTransfers(st.transfers);
    const pending = st.transfers.find((t) => t.needs_decision);
    if (pending && !modalFor && !refresh.dismissed?.has(pending.id)) openModal(pending);
    if (modalFor && !st.transfers.find((t) => t.id === modalFor && t.needs_decision)) closeModal();
  } catch (e) { console.error(e); }
}
refresh.dismissed = new Set();

// ------------------------------------------------------------------ events
$("scanBtn").onclick = async () => { await api("/api/scan", { method: "POST" }); toast("جارِ مسح الشبكة المحلية…"); refresh(); };
$("manAdd").onclick = async () => {
  $("manErr").textContent = "";
  const ip = $("manIp").value.trim(), port = $("manPort").value.trim() || "5001";
  try {
    const r = await api("/api/probe", { method: "POST", json: { ip, port } });
    toast(`تم العثور على: ${r.peer.name}`);
    await refresh();
    selected = lastState.peers.find((p) => p.device_id === r.peer.id) || null;
    renderPeers(lastState); renderTarget();
  } catch (e) { $("manErr").textContent = e.message; }
};
$("manIp").addEventListener("keydown", (e) => { if (e.key === "Enter") $("manAdd").click(); });
$("myName").onfocus = () => (nameEditing = true);
$("myName").onblur = () => setTimeout(() => (nameEditing = false), 300);
$("saveName").onclick = async () => { await api("/api/settings", { method: "POST", json: { name: $("myName").value } }); nameEditing = false; toast("تم حفظ الاسم"); };
$("autoAccept").onchange = (e) => api("/api/settings", { method: "POST", json: { auto_accept_trusted: e.target.checked } });
$("openFolder").onclick = () => api("/api/open-folder", { method: "POST", json: {} });
$("fileInput").onchange = (e) => { files.push(...e.target.files); e.target.value = ""; renderFiles(); };
const drop = $("drop");
["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => { files.push(...e.dataTransfer.files); renderFiles(); });
$("sendBtn").onclick = async () => {
  if (!selected || !files.length) return;
  const fd = new FormData();
  fd.append("ip", selected.ip); fd.append("port", selected.port); fd.append("fingerprint", selected.fingerprint);
  files.forEach((f) => fd.append("files", f, f.name));
  $("sendBtn").disabled = true;
  try {
    await api("/api/send", { method: "POST", body: fd });
    toast(`بدأ إرسال ${files.length} ملف — قارن رمز التحقق مع المستلم`);
    files = []; renderFiles(); refresh();
  } catch (e) { toast("خطأ: " + e.message); $("sendBtn").disabled = false; }
};
$("mAccept").onclick = () => decide(true);
$("mReject").onclick = () => decide(false);

refresh();
setInterval(refresh, 1000);
