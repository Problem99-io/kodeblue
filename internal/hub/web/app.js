// kodeblue hub console. Everything a server sends is untrusted (an attacker
// on a monitored host controls file names, log lines, process names and can
// influence what the agents write), so this script never uses innerHTML for
// data: every value goes through text nodes.
"use strict";

const app = document.getElementById("app");
const S = { me: null, csrf: "", info: null, timer: null, open: new Set(), cache: {}, servers: [], serversAt: 0,
  board: null, q: "", viewKey: "", loginShown: false, drafts: {}, conn: true, sel: new Set(), selAnchor: "",
  stopping: new Set(), // session ids the operator asked to stop
  filt: loadFilters() };
const enc = encodeURIComponent;
// Board filters are this browser's own view; pins are shared on the hub.
function loadFilters() {
  const f = { sev: [], kind: [], srv: "", pinned: false, attn: false };
  try { Object.assign(f, JSON.parse(localStorage.getItem("kb.filt") || "{}")); } catch { /* none saved */ }
  if (!Array.isArray(f.sev)) f.sev = [];
  if (!Array.isArray(f.kind)) f.kind = [];
  return f;
}

// ---------- DOM helpers ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
      else if (k === "style") el.style.cssText = v; // CSSOM: allowed under the strict CSP
      else if (k === "html") throw new Error("no html");
      else el.setAttribute(k, v === true ? "" : String(v));
    }
  }
  add(el, kids);
  return el;
}
function add(el, kids) {
  for (const k of [kids].flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
const svgNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs) {
  const el = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  return el;
}
function toast(msg, bad, action) {
  document.querySelectorAll(".toast.act").forEach((x) => x.remove());
  const t = h("div", { class: "toast" + (bad ? " bad" : "") + (action ? " act" : ""), role: "status" }, h("span", null, msg),
    action ? h("button", { class: "tbtn", type: "button", on: { click: () => { t.remove(); action.click(); } } }, action.label) : null);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), action ? 6000 : 2600);
}
function store(k, v) {
  try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { /* private mode */ }
  return null;
}

// ---------- icons (lucide-style line icons) ----------
const ICONS = {
  x: ["M18 6 6 18", "m6 6 12 12"],
  chevDown: ["m6 9 6 6 6-6"],
  chevRight: ["m9 18 6-6-6-6"],
  wrench: ["M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"],
  terminal: ["m4 17 6-6-6-6", "M12 19h8"],
  list: ["M3 5h.01", "M3 12h.01", "M3 19h.01", "M8 5h13", "M8 12h13", "M8 19h13"],
  shield: ["M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"],
  clock: ["c:12,12,10", "M12 6v6l4 2"],
  search: ["c:11,11,8", "m21 21-4.3-4.3"],
  server: ["r:2,2,20,8,2", "r:2,14,20,8,2", "M6 6h.01", "M6 18h.01"],
  plus: ["M5 12h14", "M12 5v14"],
  send: ["m5 12 7-7 7 7", "M12 19V5"],
  more: ["c:12,12,1", "c:19,12,1", "c:5,12,1"],
  logout: ["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "m16 17 5-5-5-5", "M21 12H9"],
  alert: ["m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3", "M12 9v4", "M12 17h.01"],
  file: ["M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z", "M14 2v4a2 2 0 0 0 2 2h4", "M16 13H8", "M16 17H8", "M10 9H8"],
  layout: ["r:3,3,7,9,1", "r:14,3,7,5,1", "r:14,12,7,9,1", "r:3,16,7,5,1"],
  bot: ["M12 8V4H8", "r:4,8,16,12,2", "M2 14h2", "M20 14h2", "M15 13v2", "M9 13v2"],
  copy: ["r:8,8,14,14,2", "M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"],
  refresh: ["M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8", "M21 3v5h-5", "M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16", "M8 16H3v5"],
  user: ["M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2", "c:12,7,4"],
  key: ["c:7.5,15.5,5.5", "m21 2-9.6 9.6", "m15.5 7.5 3 3L22 7l-3-3"],
  trash: ["M3 6h18", "M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6", "M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2"],
  ban: ["c:12,12,10", "m4.9 4.9 14.2 14.2"],
  bell: ["M10.268 21a2 2 0 0 0 3.464 0", "M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326"],
  sliders: ["M20 7h-9", "M14 17H5", "c:17,17,3", "c:7,7,3"],
  archive: ["r:2,3,20,5,1", "M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8", "M10 12h4"],
  check: ["M20 6 9 17l-5-5"],
  pause: ["r:6,4,4,16,1", "r:14,4,4,16,1"],
  pin: ["M12 17v5", "M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"],
  filter: ["M22 3H2l8 9.46V19l4 2v-8.54L22 3z"],
  checkSq: ["r:3,3,18,18,3", "m8 12 3 3 5-6"],
  layers: ["M12 2 2 7l10 5 10-5-10-5Z", "m2 17 10 5 10-5", "m2 12 10 5 10-5"],
  external: ["M15 3h6v6", "M10 14 21 3", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"],
};
function ic(name, size = 14, cls) {
  const s = svg("svg", { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor", "stroke-width": 2,
    "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: "ic" + (cls ? " " + cls : "") });
  for (const part of ICONS[name] || []) {
    if (part.startsWith("c:")) { const [cx, cy, r] = part.slice(2).split(","); s.appendChild(svg("circle", { cx, cy, r })); }
    else if (part.startsWith("r:")) { const [x, y, w, hh, rx] = part.slice(2).split(","); s.appendChild(svg("rect", { x, y, width: w, height: hh, rx })); }
    else s.appendChild(svg("path", { d: part }));
  }
  return s;
}

// ---------- logo: the KodeBlue wordmark with blue brackets ----------
const LOGO_KODE = "M13.944 37V13.64H16.824V23.656H20.28L25.464 13.64H28.6L22.808 24.872L28.92 37H25.624L20.184 26.184H16.824V37H13.944ZM39.7875 37.256C38.3795 37.256 37.1635 36.9893 36.1395 36.456C35.1155 35.9227 34.3155 35.1547 33.7395 34.152C33.1848 33.128 32.9075 31.9227 32.9075 30.536V25.864C32.9075 24.456 33.1848 23.2507 33.7395 22.248C34.3155 21.2453 35.1155 20.4773 36.1395 19.944C37.1635 19.4107 38.3795 19.144 39.7875 19.144C41.1955 19.144 42.4115 19.4107 43.4355 19.944C44.4595 20.4773 45.2488 21.2453 45.8035 22.248C46.3795 23.2507 46.6675 24.4453 46.6675 25.832V30.536C46.6675 31.9227 46.3795 33.128 45.8035 34.152C45.2488 35.1547 44.4595 35.9227 43.4355 36.456C42.4115 36.9893 41.1955 37.256 39.7875 37.256ZM39.7875 34.696C41.0462 34.696 42.0275 34.344 42.7315 33.64C43.4355 32.936 43.7875 31.9013 43.7875 30.536V25.864C43.7875 24.4987 43.4355 23.464 42.7315 22.76C42.0275 22.056 41.0462 21.704 39.7875 21.704C38.5502 21.704 37.5688 22.056 36.8435 22.76C36.1395 23.464 35.7875 24.4987 35.7875 25.864V30.536C35.7875 31.9013 36.1395 32.936 36.8435 33.64C37.5688 34.344 38.5502 34.696 39.7875 34.696ZM57.951 37.32C56.2017 37.32 54.783 36.7333 53.695 35.56C52.6283 34.3867 52.095 32.7973 52.095 30.792V25.64C52.095 23.6133 52.6283 22.0133 53.695 20.84C54.7617 19.6667 56.1803 19.08 57.951 19.08C59.4017 19.08 60.5643 19.4747 61.439 20.264C62.3137 21.0533 62.751 22.1093 62.751 23.432L62.175 22.76H62.815L62.751 18.76V13.64H65.631V37H62.751V33.64H62.175L62.751 32.968C62.751 34.312 62.3137 35.3787 61.439 36.168C60.5643 36.936 59.4017 37.32 57.951 37.32ZM58.911 34.824C60.1057 34.824 61.0443 34.4507 61.727 33.704C62.4097 32.9573 62.751 31.9227 62.751 30.6V25.8C62.751 24.4773 62.4097 23.4427 61.727 22.696C61.0443 21.9493 60.1057 21.576 58.911 21.576C57.695 21.576 56.735 21.9387 56.031 22.664C55.327 23.3893 54.975 24.4347 54.975 25.8V30.6C54.975 31.9653 55.327 33.0107 56.031 33.736C56.735 34.4613 57.695 34.824 58.911 34.824ZM78.1625 37.32C76.7758 37.32 75.5598 37.0427 74.5145 36.488C73.4905 35.9333 72.6905 35.1547 72.1145 34.152C71.5598 33.128 71.2825 31.944 71.2825 30.6V25.8C71.2825 24.4347 71.5598 23.2507 72.1145 22.248C72.6905 21.2453 73.4905 20.4667 74.5145 19.912C75.5598 19.3573 76.7758 19.08 78.1625 19.08C79.5492 19.08 80.7545 19.3573 81.7785 19.912C82.8238 20.4667 83.6238 21.2453 84.1785 22.248C84.7545 23.2507 85.0425 24.4347 85.0425 25.8V28.904H74.0985V30.6C74.0985 31.9867 74.4505 33.0533 75.1545 33.8C75.8585 34.5253 76.8612 34.888 78.1625 34.888C79.2718 34.888 80.1678 34.696 80.8505 34.312C81.5332 33.9067 81.9492 33.3093 82.0985 32.52H84.9785C84.7865 33.992 84.0612 35.1653 82.8025 36.04C81.5652 36.8933 80.0185 37.32 78.1625 37.32ZM82.2265 26.984V25.8C82.2265 24.4133 81.8745 23.3467 81.1705 22.6C80.4878 21.8533 79.4852 21.48 78.1625 21.48C76.8612 21.48 75.8585 21.8533 75.1545 22.6C74.4505 23.3467 74.0985 24.4133 74.0985 25.8V26.728H82.4505L82.2265 26.984Z";
const LOGO_BLUE = "M101.976 37V13.64H108.6C110.733 13.64 112.397 14.1733 113.592 15.24C114.808 16.3067 115.416 17.7893 115.416 19.688C115.416 20.7547 115.192 21.6827 114.744 22.472C114.296 23.2613 113.656 23.8693 112.824 24.296C112.013 24.7227 111.032 24.9253 109.88 24.904V24.424C111.117 24.4027 112.184 24.6373 113.08 25.128C113.997 25.6187 114.701 26.3227 115.192 27.24C115.704 28.1573 115.96 29.2453 115.96 30.504C115.96 31.8267 115.683 32.9787 115.128 33.96C114.573 34.9413 113.784 35.6987 112.76 36.232C111.736 36.744 110.509 37 109.08 37H101.976ZM104.792 34.408H108.76C110.104 34.408 111.16 34.056 111.928 33.352C112.717 32.6267 113.112 31.6453 113.112 30.408C113.112 29.128 112.717 28.0933 111.928 27.304C111.16 26.4933 110.104 26.088 108.76 26.088H104.792V34.408ZM104.792 23.592H108.568C109.805 23.592 110.776 23.2613 111.48 22.6C112.205 21.9387 112.568 21.0427 112.568 19.912C112.568 18.7813 112.216 17.8853 111.512 17.224C110.808 16.5627 109.837 16.232 108.6 16.232H104.792V23.592ZM130.36 37Q128.024 37 126.632 35.64Q125.24 34.28 125.24 32.04V16.264H119.16V13.64H128.12V32.04Q128.12 33.128 128.728 33.752Q129.336 34.376 130.36 34.376H135.8V37ZM146.968 37.32Q143.928 37.32 142.104 35.512Q140.28 33.704 140.28 30.6V19.4H143.16V30.6Q143.16 32.52 144.184 33.656Q145.208 34.792 146.968 34.792Q148.76 34.792 149.8 33.656Q150.84 32.52 150.84 30.6V19.4H153.72V30.6Q153.72 33.704 151.864 35.512Q150.008 37.32 146.968 37.32ZM166.2 37.32Q163.096 37.32 161.192 35.448Q159.288 33.576 159.288 30.28V26.12Q159.288 22.824 161.192 20.952Q163.096 19.08 166.2 19.08Q168.28 19.08 169.832 19.912Q171.384 20.744 172.248 22.248Q173.112 23.752 173.112 25.8V28.936H162.104V30.6Q162.104 32.552 163.224 33.688Q164.344 34.824 166.2 34.824Q167.8 34.824 168.84 34.2Q169.88 33.576 170.104 32.52H172.984Q172.696 34.728 170.84 36.024Q168.984 37.32 166.2 37.32ZM162.104 26.696H170.296V25.8Q170.296 23.72 169.224 22.584Q168.152 21.448 166.2 21.448Q164.248 21.448 163.176 22.584Q162.104 23.72 162.104 25.8Z";
const LOGO_K = "M14.944 37V13.64H17.824V23.656H21.28L26.464 13.64H29.6L23.808 24.872L29.92 37H26.624L21.184 26.184H17.824V37H14.944Z";
function logo(icon) {
  const w = icon ? 42 : 180, bw = icon ? 42 : 93;
  const s = svg("svg", { viewBox: `0 0 ${w} 52`, class: icon ? "logo-icon" : "logo", role: "img", "aria-label": "kodeblue" });
  if (icon) s.appendChild(svg("path", { d: LOGO_K, class: "lg-t" }));
  else { s.appendChild(svg("path", { d: LOGO_KODE, class: "lg-t" })); s.appendChild(svg("path", { d: LOGO_BLUE, class: "lg-w" })); }
  for (const [x, y, rw, rh] of [[0, 49, bw, 3], [bw - 3, 41, 3, 11], [0, 41, 3, 11], [0, 0, bw, 3], [bw - 3, 0, 3, 11], [0, 0, 3, 11]]) {
    s.appendChild(svg("rect", { x, y, width: rw, height: rh, class: "lg-b" }));
  }
  return s;
}

// ---------- formatting ----------
const SEV = ["critical", "high", "medium", "low", "info"];
function sevBadge(s) { return h("span", { class: "badge b-" + (SEV.includes(s) ? s : "info") }, s || "—"); }
function validTime(t) {
  if (!t) return null;
  const d = new Date(t);
  return isNaN(d) || d.getFullYear() < 2000 ? null : d;
}
function ago(t) {
  const d = validTime(t);
  if (!d) return "—";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
}
function when(t) {
  const d = validTime(t);
  return d ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
}
function clock(t) {
  const d = validTime(t);
  return d ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
}
function usd(v) { return "$" + (Number(v) || 0).toFixed((Number(v) || 0) < 1 ? 4 : 2); }
function statusBadge(st) {
  const cls = { resolved: "b-ok", closed: "b-ok", benign: "b-ok", done: "b-ok", investigating: "b-accent", needs_human: "b-bad", needs_ack: "b-warn",
    escalated: "b-warn", incident: "b-accent", open: "b-warn", queued: "b-warn", delivered: "b-accent", failed: "b-bad", refused: "b-bad",
    pending: "b-warn", undone: "", digest: "" }[st] || "";
  return h("span", { class: "badge " + cls }, (st || "—").replace(/_/g, " "));
}
function verdictBadge(v) {
  if (!v) return null;
  const cls = { true_positive: "b-bad", malicious: "b-bad", suspicious: "b-warn", inconclusive: "b-warn", false_positive: "b-ok", benign_change: "b-ok", benign: "b-ok", error: "b-bad" }[v] || "";
  return h("span", { class: "badge " + cls }, v.replace(/_/g, " "));
}
function kindBadge(k) { return h("span", { class: "kind k-" + (["incident", "learning", "review", "operator", "coverage"].includes(k) ? k : "incident") }, k || "case"); }
function phaseBadge(p) {
  const cls = { watching: "b-ok", learning: "b-accent", maintenance: "b-warn" }[p] || "b-warn";
  return h("span", { class: "badge " + cls, title: p ? null : "enrolled, but no report received yet" }, p || "not reporting yet");
}
function modeBadge(m) {
  const cls = { contain: "b-bad", recommend: "b-warn", off: "" }[m] || "";
  return h("span", { class: "badge " + cls, title: "containment policy on the server" }, "response: " + (m || "?"));
}
function pct(a, b) { return b > 0 ? Math.min(100, Math.round((a / b) * 100)) : 0; }

// Minimal markdown → DOM (headings, lists, code fences, tables, inline code,
// bold). Text only ever becomes text nodes.
function md(src, cls) {
  const root = h("div", { class: "prose" + (cls ? " " + cls : "") });
  const lines = String(src || "").replace(/\r/g, "").split("\n");
  let list = null, para = [];
  const flush = () => {
    if (para.length) { root.appendChild(h("p", null, inline(para.join(" ")))); para = []; }
  };
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (/^```/.test(ln)) {
      flush(); list = null;
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      root.appendChild(h("pre", null, h("code", null, buf.join("\n"))));
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(ln)) {
      flush(); list = null;
      const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) rows.push(lines[i++]);
      i--;
      const cells = (r) => r.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const body = rows.filter((r) => !/^\s*\|?\s*:?-{2,}/.test(r));
      const head = rows.length > 1 && /^\s*\|?\s*:?-{2,}/.test(rows[1]) ? cells(body.shift()) : null;
      root.appendChild(h("div", { class: "tbl-wrap" }, h("table", { class: "md" },
        head ? h("thead", null, h("tr", null, head.map((c) => h("th", null, inline(c))))) : null,
        h("tbody", null, body.map((r) => h("tr", null, cells(r).map((c) => h("td", null, inline(c)))))))));
      continue;
    }
    let m;
    if ((m = ln.match(/^(#{1,4})\s+(.*)$/))) { flush(); list = null; root.appendChild(h("h" + Math.min(m[1].length + 1, 4), null, inline(m[2]))); continue; }
    if ((m = ln.match(/^\s*([-*]|\d+[.)])\s+(.*)$/))) {
      flush();
      const ordered = /\d/.test(m[1]);
      if (!list || list.ordered !== ordered) { list = h(ordered ? "ol" : "ul"); list.ordered = ordered; root.appendChild(list); }
      list.appendChild(h("li", null, inline(m[2])));
      continue;
    }
    if (/^\s*>\s?/.test(ln)) { flush(); list = null; root.appendChild(h("blockquote", null, inline(ln.replace(/^\s*>\s?/, "")))); continue; }
    if (!ln.trim()) { flush(); list = null; continue; }
    if (list && /^\s{2,}\S/.test(ln)) { list.lastChild.appendChild(document.createTextNode(" " + ln.trim())); continue; }
    list = null;
    para.push(ln);
  }
  flush();
  return root;
}
function inline(s) {
  const out = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let last = 0, m;
  while ((m = re.exec(s))) {
    if (m.index > last) out.push(s.slice(last, m.index));
    const t = m[0];
    out.push(t[0] === "`" ? h("code", null, t.slice(1, -1)) : h("strong", null, t.slice(2, -2)));
    last = m.index + t.length;
  }
  if (last < s.length) out.push(s.slice(last));
  return out;
}
function prettyJSON(s) {
  try { return JSON.stringify(typeof s === "string" ? JSON.parse(s) : s, null, 2); } catch { return String(s); }
}

// ---------- API ----------
class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }
async function api(method, path, body) {
  const opt = { method, headers: { "Accept": "application/json" }, credentials: "same-origin" };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  if (method !== "GET") opt.headers["X-Kodeblue-CSRF"] = S.csrf;
  let r;
  try { r = await fetch(path, opt); } catch { setConn(false); throw new ApiError("Can't reach the hub", 0); }
  setConn(r.status < 500 || r.status === 501);
  let data = null;
  try { data = await r.json(); } catch { /* empty */ }
  if (r.status === 401 && path !== "/api/login") {
    if (S.me) sessionLost();
    throw new ApiError("signed out", 401);
  }
  if (!r.ok) throw new ApiError((data && data.error) || ("HTTP " + r.status), r.status);
  return data;
}
const recs = (id, kind, q = "") => api("GET", `/api/servers/${enc(id)}/records/${kind}${q}`);
const parse = (r) => (r && r.data) || {};
function setConn(ok) {
  if (S.conn === ok) return;
  S.conn = ok;
  const c = document.getElementById("conn");
  if (c) paintConn(c);
}
function paintConn(c) {
  c.className = "conn" + (S.conn ? "" : " down");
  c.title = S.conn ? "Connected to the hub" : "The hub is not answering; retrying";
  clear(c).append(h("span", { class: "cdot" }), h("span", { class: "ctext" }, S.conn ? "Connected" : "Reconnecting…"));
}
async function loadServers(force) {
  if (!force && Date.now() - S.serversAt < 15000 && S.servers.length) return S.servers;
  S.servers = (await api("GET", "/api/fleet")) || [];
  S.serversAt = Date.now();
  return S.servers;
}
const serverName = (id) => (S.servers.find((s) => s.id === id) || {}).name || id;

// ---------- timers ----------
function setTimer(fn, ms) {
  if (S.timer) clearInterval(S.timer);
  S.timerFn = fn;
  S.timer = fn ? setInterval(() => { if (!document.hidden && !document.querySelector(".scrim")) fn(); }, ms) : null;
}
document.addEventListener("visibilitychange", () => {
  if (document.hidden || !S.me) return;
  if (S.timerFn && !document.querySelector(".scrim")) S.timerFn();
  if (P.el) panelRefresh(false);
});

// ---------- sign-in ----------
function sessionLost() {
  S.me = null; S.csrf = "";
  renderLogin("Your session ended. Sign in again to pick up where you were.");
}

async function logout() {
  try { await api("POST", "/api/logout", {}); } catch { /* signed out either way */ }
  S.me = null; S.csrf = ""; S.info = null;
  renderLogin();
}

function renderLogin(msg) {
  if (S.loginShown) { if (msg) { const e = document.querySelector(".lerr"); if (e && !e.textContent) e.textContent = msg; } return; }
  closeWarRoom();
  const warTab = document.getElementById("war-tab"); if (warTab) warTab.hidden = true;
  S.loginShown = true; S.viewKey = "";
  setTimer(null); closePanel();
  document.querySelectorAll(".scrim, .menu").forEach((x) => x.remove());
  clear(app);
  const saved = store("kb.user") || "";
  const name = h("input", { type: "text", name: "username", autocomplete: "username", autocapitalize: "none", spellcheck: "false", required: true, value: saved });
  const pw = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true });
  const caps = h("div", { class: "caps", hidden: true }, "Caps Lock is on");
  const err = h("div", { class: "lerr", role: "alert" }, msg || "");
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Sign in");
  const capsCheck = (e) => { if (e.getModifierState) caps.hidden = !e.getModifierState("CapsLock"); };
  pw.addEventListener("keydown", capsCheck); pw.addEventListener("keyup", capsCheck);
  let busy = false;
  const form = h("form", { class: "lcard", novalidate: true, on: { submit: async (e) => {
    e.preventDefault();
    if (busy) return;
    const user = name.value.trim();
    if (!user || !pw.value) { err.textContent = "Enter your user name and password."; (user ? pw : name).focus(); return; }
    busy = true; btn.disabled = true; btn.textContent = "Signing in…"; err.textContent = "";
    try {
      const r = await api("POST", "/api/login", { name: user, password: pw.value });
      S.me = r.user; S.csrf = r.csrf; S.loginShown = false;
      store("kb.user", user);
      route();
    } catch (x) {
      busy = false; btn.disabled = false; btn.textContent = "Sign in";
      err.textContent = x.status === 0 ? "Can't reach the hub. Check your connection and try again."
        : x.status === 401 ? "Wrong user name or password." : x.message;
      if (x.status !== 0) pw.value = "";
      pw.focus();
    }
  } } },
    h("div", { class: "lbrand" }, logo(false)),
    h("div", { class: "lsub" }, "hub · sign in"),
    h("label", null, h("span", null, "user"), name),
    h("label", null, h("span", null, "password"), pw),
    caps, err, btn,
    h("div", { class: "lfoot" }, "Operators are added on the hub with ", h("code", null, "kodeblue-hub user add")));
  app.appendChild(h("div", { class: "login" }, form));
  (saved ? pw : name).focus();
}

function renderOffline(retry) {
  setTimer(null);
  clear(app);
  let n = 5;
  const left = h("span", null, "");
  const tick = setInterval(() => { n--; left.textContent = n > 0 ? ` Retrying in ${n}s…` : " Retrying…"; if (n <= 0) { clearInterval(tick); retry(); } }, 1000);
  app.appendChild(h("div", { class: "login" }, h("div", { class: "lcard" },
    h("div", { class: "lbrand" }, logo(false)),
    h("div", { class: "lerr" }, "Can't reach the hub."),
    h("div", { class: "muted small" }, "The console will reconnect on its own.", left),
    h("button", { class: "btn block", on: { click: () => { clearInterval(tick); retry(); } } }, "Retry now"))));
}

// ---------- router ----------
function parseHash() {
  const p = (location.hash.replace(/^#\/?/, "") || "").split("/").filter((x) => x !== "").map((x) => { try { return decodeURIComponent(x); } catch { return x; } });
  if (p[0] === "fleet") return { view: "fleet" };
  if (p[0] === "audit") return { view: "audit" };
  if (p[0] === "notifications") return { view: "notifications" };
  if (p[0] === "settings") return { view: "settings" };
  if (p[0] === "t" && p[1] && p[2]) return { view: "board", srv: null, task: { srv: p[1], id: p[2] } };
  if (p[0] === "new") return { view: "board", srv: null, newTask: true };
  if (p[0] === "s" && p[1]) {
    const srv = p[1];
    if (!p[2] || p[2] === "board" || p[2] === "messages") return { view: "board", srv };
    if ((p[2] === "t" || p[2] === "incidents") && p[3]) return { view: "board", srv, task: { srv, id: p[3] } };
    if (p[2] === "incidents") return { view: "board", srv };
    if (p[2] === "new") return { view: "board", srv, newTask: true };
    return { view: "server", srv, tab: p[2], item: p[3] };
  }
  return { view: "board", srv: null };
}
const boardHash = (srv) => (srv ? "#/s/" + enc(srv) : "#/");
const taskHash = (ctx, srv, id) => (ctx ? `#/s/${enc(ctx)}/t/${enc(id)}` : `#/t/${enc(srv)}/${enc(id)}`);

let routing = 0;
async function route() {
  const my = ++routing;
  if (!S.me) {
    try { const r = await api("GET", "/api/me"); S.me = r.user; S.csrf = r.csrf; S.info = r; }
    catch (e) { if (e.status === 401 || e.status === 403) renderLogin(); else renderOffline(route); return; }
  }
  S.loginShown = false;
  if (!S.info) api("GET", "/api/me").then((r) => (S.info = r)).catch(() => {});
  const r = parseHash();
  const key = [r.view, r.srv || "", r.tab || "", r.item || ""].join("|");
  if (key !== S.viewKey || !document.getElementById("view")) {
    S.viewKey = key;
    closePanel();
    await renderView(r);
  }
  if (my !== routing || !S.me || S.loginShown) return;
  if (r.view === "board") syncPanel(r); else closePanel();
}
window.addEventListener("hashchange", route);
document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "")) {
    const q = document.getElementById("q");
    if (q) { e.preventDefault(); q.focus(); }
  }
  const typing = document.activeElement && document.activeElement.tagName === "TEXTAREA" && document.activeElement.value.trim();
  const modalUp = document.querySelector(".scrim, .menu");
  if (e.key === "Escape" && P.el && !typing && !modalUp) closeToBoard();
  else if (e.key === "Escape" && S.sel.size && !modalUp) clearSel();
  const field = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "");
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "a" && !field && !P.el && !modalUp && document.querySelector(".board")) {
    e.preventDefault();
    selectAll();
  }
});

// ---------- shell ----------
function menu(anchor, items, cls) {
  document.querySelectorAll(".menu").forEach((x) => x.remove());
  const m = h("div", { class: "menu" + (cls ? " " + cls : ""), role: "menu" }, items);
  document.body.appendChild(m);
  const r = anchor.getBoundingClientRect();
  const mh = m.offsetHeight;
  m.style.top = (r.bottom + 4 + mh <= window.innerHeight - 8 ? r.bottom + 4 : Math.max(8, Math.min(r.top - 4, window.innerHeight - 8) - mh)) + "px";
  const w = m.offsetWidth;
  if (r.left + w <= window.innerWidth - 8) m.style.left = Math.max(8, r.left) + "px";
  else if (r.right - w >= 8) m.style.right = window.innerWidth - r.right + "px";
  else m.style.left = Math.max(8, (window.innerWidth - w) / 2) + "px";
  const close = (e) => {
    if (e && e.type === "keydown" && e.key !== "Escape") return;
    if (e && e.type === "mousedown" && (m.contains(e.target) || anchor.contains(e.target))) return;
    m.remove();
    document.removeEventListener("mousedown", close, true);
    document.removeEventListener("keydown", close, true);
  };
  setTimeout(() => { document.addEventListener("mousedown", close, true); document.addEventListener("keydown", close, true); });
  m.addEventListener("click", (e) => { if (e.target.closest("a,button")) close(); });
  return m;
}
function menuItem(label, opts) {
  return h(opts.href ? "a" : "button", { class: "mi" + (opts.cls ? " " + opts.cls : ""), href: opts.href, type: opts.href ? null : "button", role: "menuitem",
    disabled: opts.disabled ? true : null, on: opts.click ? { click: opts.click } : null },
    opts.icon ? ic(opts.icon, 13) : opts.icon === null ? h("span", { class: "mi-i" }) : null, h("span", { class: "mi-l" }, label), opts.right || null);
}

function header(r) {
  const cur = r.srv ? S.servers.find((s) => s.id === r.srv) : null;
  const sw = h("button", { class: "switch", type: "button", "aria-haspopup": "menu", title: "Switch server" },
    h("span", { class: "sw-l" }, cur ? cur.name : r.srv ? serverName(r.srv) : "All servers"), ic("chevDown", 14));
  sw.addEventListener("click", () => {
    if (document.querySelector(".menu")) { document.querySelectorAll(".menu").forEach((x) => x.remove()); return; }
    const tab = r.view === "server" ? r.tab : "";
    const fq = h("input", { class: "msearch", type: "search", placeholder: "Search servers…", "aria-label": "Search servers", autocomplete: "off", spellcheck: "false" });
    const all = menuItem("All servers", { href: "#/", icon: "layout", cls: !r.srv ? "on" : "", right: h("span", { class: "mi-r" }, String(S.servers.length)) });
    const items = S.servers.map((s) => ({ s, el: menuItem(s.name, { href: "#/s/" + enc(s.id) + (tab ? "/" + tab : ""), cls: s.id === r.srv ? "on" : "",
      right: h("span", { class: "dot " + (s.online ? "on" : s.enrolled ? "off" : "") }) }) }));
    const none = h("div", { class: "mnone", hidden: true }, "No matching servers");
    fq.addEventListener("input", () => {
      const q = fq.value.trim().toLowerCase();
      let n = 0;
      for (const it of items) {
        const hit = !q || [it.s.name, it.s.hostname, it.s.id, it.s.last_ip].some((x) => String(x || "").toLowerCase().includes(q));
        it.el.hidden = !hit;
        if (hit) n++;
      }
      all.hidden = !!q;
      none.hidden = n > 0;
    });
    fq.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      const first = items.find((it) => !it.el.hidden);
      if (first) first.el.click();
    });
    menu(sw, [
      h("div", { class: "msw" }, ic("search", 13, "c-muted"), fq),
      h("div", { class: "mlist" }, all, items.map((it) => it.el), none),
      h("div", { class: "msep" }),
      menuItem("Add server", { icon: "plus", cls: "c-blue", click: addServerDialog }),
      menuItem("Manage servers", { href: "#/fleet", icon: "list" }),
    ], "mserv");
    setTimeout(() => fq.focus(), 0);
  });
  const q = h("input", { id: "q", type: "search", placeholder: "Search cases…", value: S.q, "aria-label": "Search cases", autocomplete: "off" });
  q.addEventListener("input", () => { S.q = q.value; if (S.redrawBoard) S.redrawBoard(); });
  const search = r.view === "board" ? h("div", { class: "search" }, ic("search", 15, "c-muted"), q, h("kbd", null, "/")) : h("div", { class: "search-sp" });
  const nav = (href, icon, label, on) => h("a", { class: "hbtn" + (on ? " on" : ""), href, title: label }, ic(icon, 15), h("span", { class: "hl" }, label));
  const conn = h("span", { id: "conn" });
  paintConn(conn);
  const me = S.me ? S.me.name : "";
  const av = h("button", { class: "avatar", type: "button", title: me, "aria-haspopup": "menu" }, (me[0] || "?").toUpperCase());
  av.addEventListener("click", () => menu(av, [
    h("div", { class: "mwho" }, h("div", { class: "fg" }, me), h("div", { class: "muted small" }, "operator")),
    menuItem("Audit log", { href: "#/audit", icon: "file" }),
    menuItem("Sign out", { icon: "logout", cls: "c-red", click: logout }),
  ]));
  return h("header", { class: "hdr" },
    h("div", { class: "hdr-l" }, h("a", { class: "brand", href: "#/", "aria-label": "kodeblue hub" }, logo(false), logo(true)), sw),
    search,
    h("div", { class: "hdr-r" },
      nav("#/", "layout", "Board", r.view === "board" && !r.srv),
      nav("#/fleet", "server", "Servers", r.view === "fleet"),
      nav("#/audit", "file", "Audit", r.view === "audit"),
      nav("#/settings", "sliders", "Settings", r.view === "settings"),
      bellButton(r), conn, av));
}

// ---------- notification bell ----------
// The bell polls the hub's Slack notification log; "new" is anything newer
// than the last one this browser opened the bell on.
const BELL = { list: null, off: false, last: 0 };
const seenNote = () => Number(store("kb.seenNote")) || 0;
function bellButton(r) {
  const b = h("button", { id: "bell", class: "hbtn bell" + (r.view === "notifications" ? " on" : ""), type: "button", title: "Notifications", "aria-label": "Notifications", "aria-haspopup": "menu" },
    ic("bell", 15), h("span", { class: "bn", hidden: true }));
  b.addEventListener("click", () => openBell(b));
  return b;
}
async function bellLoad() {
  if (BELL.off || !S.me || S.loginShown) return;
  try { BELL.list = (await api("GET", "/api/notifications?limit=30")) || []; }
  catch (e) { if (e.status === 404) BELL.off = true; return; }
  paintBell();
}
function paintBell() {
  const b = document.getElementById("bell");
  if (!b) return;
  const seen = seenNote();
  const n = (BELL.list || []).filter((x) => x.id > seen).length;
  const badge = b.querySelector(".bn");
  badge.textContent = n > 9 ? "9+" : String(n);
  badge.hidden = !n;
  b.title = n ? n + " new notification" + (n === 1 ? "" : "s") : "Notifications";
  const top = (BELL.list || []).reduce((m, x) => Math.max(m, x.id), 0);
  if (BELL.last && top > BELL.last) { b.classList.remove("ring"); void b.offsetWidth; b.classList.add("ring"); }
  BELL.last = top;
}
async function openBell(anchor) {
  if (document.querySelector(".menu.npop")) { document.querySelectorAll(".menu").forEach((x) => x.remove()); return; }
  if (!BELL.list && !BELL.off) await bellLoad();
  const list = BELL.list || [];
  const seen = seenNote();
  const fresh = list.filter((x) => x.id > seen).length;
  const item = (n) => h("a", { class: "np-i" + (n.id > seen ? " new" : "") + (n.status === "failed" ? " bad" : ""),
    href: n.incident_id ? taskHash(null, n.server_id, n.incident_id) : "#/s/" + enc(n.server_id) + "/notifications" },
    h("span", { class: "np-dot s-" + (SEV.includes(n.severity) ? n.severity : "info") }),
    h("span", { class: "np-m" },
      h("span", { class: "np-ti" }, n.title || n.kind || "notification"),
      n.body ? h("span", { class: "np-bd" }, n.body) : null,
      h("span", { class: "np-me" }, h("span", null, n.server_name || serverName(n.server_id)), n.incident_id ? h("span", null, "case #" + n.incident_id) : null,
        n.status !== "delivered" ? h("span", { class: n.status === "failed" ? "c-red" : "" }, n.status) : null, h("span", null, ago(n.at)))));
  menu(anchor, [
    h("div", { class: "np-hd" }, h("span", { class: "np-t" }, "Notifications"), fresh ? h("span", { class: "badge b-accent" }, fresh + " new") : null,
      h("div", { class: "sp" }), h("a", { class: "ibtn", href: "#/settings", title: "Notification settings", "aria-label": "Notification settings" }, ic("sliders", 13))),
    BELL.off ? h("div", { class: "np-empty" }, "This hub does not send notifications yet.")
      : !list.length ? h("div", { class: "np-empty" }, ic("bell", 18), h("span", null, "You're all caught up."), h("span", { class: "faint small" }, "Alerts kodeblue sends to configured destinations show up here."))
      : h("div", { class: "np-list" }, list.slice(0, 15).map(item)),
    h("a", { class: "np-all", href: "#/notifications" }, "View all notifications", ic("chevRight", 12)),
  ], "npop");
  if (list.length) store("kb.seenNote", String(list.reduce((a, x) => Math.max(a, x.id), 0)));
  paintBell();
}
setInterval(() => { if (!document.hidden) bellLoad(); }, 20000);

async function renderView(r) {
  mountWarRoom();
  try { await loadServers(); } catch (e) { if (e.status === 401) return; }
  setTimer(null);
  clear(app);
  S.redrawBoard = null;
  S.sel.clear(); S.selAnchor = "";
  document.body.classList.remove("selbar-on");
  app.appendChild(header(r));
  if (BELL.list) paintBell(); else bellLoad();
  const main = h("main", { id: "view", class: r.view === "board" ? "main board-main" : "main" });
  if (r.view === "fleet") { app.appendChild(main); return vFleet(main); }
  if (r.view === "audit") { app.appendChild(main); return vAudit(main); }
  if (r.view === "notifications") { app.appendChild(main); return vNotifications(null, main); }
  if (r.view === "settings") { app.appendChild(main); return vSettings(main); }
  let srv = null;
  if (r.srv) {
    try { srv = await api("GET", "/api/servers/" + enc(r.srv)); }
    catch (e) { app.appendChild(main); main.appendChild(h("div", { class: "empty" }, e.status === 404 ? "This server is not on the hub (deleted?). " : e.message, h("a", { href: "#/" }, "Back to the board"))); return; }
    app.appendChild(serverBar(srv, r.view === "board" ? "board" : r.tab));
  }
  app.appendChild(main);
  if (r.view === "board") return vBoard(r, main, srv);
  const views = { overview: vOverview, vulnerabilities: vVulnerabilities, autoblock: vAutoblock, services: vServices, findings: vFindings, monitors: vMonitors, evaluation: vEvaluation, activity: vActivity, knowledge: vKnowledge, notifications: vNotifications, settings: vServerSettings };
  if (r.tab === "notifications") return vNotifications(srv, main);
  const fn = views[r.tab] || vOverview;
  const draw = async () => { try { await fn(srv, main, r.item); } catch (e) { if (e.status !== 401) console.error(e); } };
  await draw();
  if (r.tab === "overview" || !views[r.tab]) setTimer(async () => {
    try { srv = await api("GET", "/api/servers/" + enc(r.srv)); } catch { return; }
    await fn(srv, main);
  }, 8000);
}

// ---------- server bar ----------
const STABS = [["board", "Board"], ["overview", "Overview"], ["vulnerabilities", "Vulnerabilities"], ["autoblock", "Auto-block"], ["services", "Services"],
  ["findings", "Findings & triage"], ["monitors", "Monitors"], ["evaluation", "Self-evaluation"], ["activity", "Activity"], ["knowledge", "Knowledge"], ["notifications", "Notifications"], ["settings", "Settings"]];
function serverBar(srv, tab) {
  const st = srv.status || {};
  const c = srv.counts;
  const nOpen = Object.values(c.open_incidents || {}).reduce((a, b) => a + b, 0);
  return h("div", { class: "sbar" },
    h("div", { class: "sbar-top" },
      h("span", { class: "dot " + (srv.online ? "on" : srv.enrolled ? "off" : "") }),
      h("h1", null, srv.name),
      srv.enrolled ? phaseBadge(st.phase) : h("span", { class: "badge" }, srv.revoked ? "revoked" : "not enrolled"),
      st.response_mode ? modeBadge(st.response_mode) : null,
      st.models_enabled === false ? h("span", { class: "badge b-warn", title: "no model endpoint configured, or the agent engine is not running" }, "models off") : null,
      h("span", { class: "smeta" },
        h("span", null, srv.online ? "online" : "last seen " + ago(srv.last_seen)),
        srv.hostname ? h("span", null, srv.hostname) : null,
        st.os ? h("span", null, st.os) : null,
        srv.version ? h("span", null, "v" + String(srv.version).replace(/^v/, "")) : null,
        updateAvailable(srv) ? h("a", { class: "badge b-warn", href: `#/s/${enc(srv.id)}/overview`, title: "The hub runs " + hubVersion() + ": update the server from its Overview" }, "update available") : null,
        srv.last_ip ? h("span", null, srv.last_ip) : null),
      h("div", { class: "sp" }),
      h("div", { class: "btns" },
        h("button", { class: "btn small", type: "button", on: { click: () => reinstall(srv) } }, ic("key", 12), srv.enrolled ? "New install token" : "Install command"),
        srv.enrolled && !srv.revoked ? h("button", { class: "btn small danger", type: "button", on: { click: () => revoke(srv) } }, ic("ban", 12), "Revoke key") : null,
        h("button", { class: "btn small danger", type: "button", on: { click: () => del(srv) } }, ic("trash", 12), "Delete"))),
    h("nav", { class: "stabs" }, STABS.map(([k, label]) => h("a", { href: k === "board" ? "#/s/" + enc(srv.id) : `#/s/${enc(srv.id)}/${k}`, class: tab === k ? "on" : "" }, label,
      k === "board" && nOpen ? h("span", { class: "n" }, nOpen) : null,
      k === "findings" && c.needs_ack ? h("span", { class: "n" }, c.needs_ack) : null,
      k === "vulnerabilities" && openVulns(c) ? h("span", { class: "n" + (worstVuln(c) ? " warn" : ""), title: "open vulnerabilities" }, openVulns(c)) : null,
      k === "autoblock" && c.rules_waiting ? h("span", { class: "n warn", title: "auto-block rules waiting for approval" }, c.rules_waiting) : null,
      k === "activity" && c.pending_actions ? h("span", { class: "n warn" }, c.pending_actions) : null))),
    learnWaitAlert(st));
}

// learnWaits: the server's learner session and vulnerability assessment
// cannot run without a model. Detection watches regardless; both start on
// their own once a model is set.
// modelSet: the server has models configured (models_enabled also needs a
// running agent engine).
function modelSet(st) { return !!(st.triage_model || (st.models || {}).triage); }
// hubModelComing: the hub has a Default model and the server takes hub
// settings; it applies them on its next sync and restart.
function hubModelComing(st) { return !!(S.info && S.info.fleet_model && st.accepts_settings); }
// modelOnItsWay: no model on the server yet, but the hub's is coming, or the
// server has received it and restarts to apply it.
function modelOnItsWay(st) { return !modelSet(st) && (!!st.settings_saved || hubModelComing(st)); }
// During the first learning st.learning is set from the start, so a server
// still collecting its baseline without a model counts as waiting too; a
// pending learner that is running now does not.
function learnWaits(st) { return (st.phase === "learning" && !modelSet(st)) || (!!st.learner_pending && !st.learning); }
// baselineText: how far the baseline is, from servers that report it
// ("snapshot 7 of 10, the last around 01:35, in about 9 min").
function baselineText(st) {
  if (st.phase !== "learning" || !st.baseline_sweeps) return "";
  let t = `snapshot ${st.baseline_sweep} of ${st.baseline_sweeps}`;
  const eta = validTime(st.baseline_eta);
  if (eta && st.baseline_sweep < st.baseline_sweeps) {
    const min = Math.round((eta.getTime() - Date.now()) / 60000);
    t += ", the last around " + eta.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) + (min > 0 ? ` (in about ${min} min)` : "");
  }
  return t;
}
const learnerModel = (st) => (st.models || {}).learner || st.agent_model || "the learner model";
// learnModelNote: what follows the baseline, given where the model is.
function learnModelNote(st) {
  if (modelSet(st) && st.baseline_at && !baselineText(st)) return `The learning session (server profile, monitors, skills) and the vulnerability assessment are running with ${learnerModel(st)}; follow them on the board.`;
  if (modelSet(st)) return `The learning session (server profile, monitors, skills) and the vulnerability assessment run right after it, with ${learnerModel(st)}; they show on the board while they run.`;
  if (st.settings_saved) return "The server has received the hub's model and restarts to use it as soon as no agent session runs; the baseline carries on where it left off. The learning session and the vulnerability assessment then follow it.";
  if (hubModelComing(st)) return `The hub's Default model (${S.info.fleet_model}) is on its way: the server picks it up on its next sync and restarts to use it, then runs the learning session and the vulnerability assessment after the baseline.`;
  return "";
}
function learnWaitAlert(st) {
  if (st.phase === "learning") {
    const prog = baselineText(st);
    // A server that reports progress and has none collects no baseline now:
    // past it (baseline_at), the learning session or assessment runs.
    const doing = prog ? `kodeblue is collecting this server's baseline: ${prog}. `
      : st.baseline_at ? "kodeblue has collected this server's baseline. "
        : "kodeblue is collecting this server's baseline (about 30 minutes) or learning it. ";
    if (modelSet(st) || modelOnItsWay(st)) {
      return h("div", { class: "callout info sbar-alert" }, h("div", { class: "lbl" }, "Learning this server"), doing, learnModelNote(st));
    }
    return h("div", { class: "callout warn sbar-alert" }, h("div", { class: "lbl" }, "Learning is waiting for a model"), doing,
      "The learning session (server profile, monitors, skills) and the vulnerability assessment follow it, and they need a model. ",
      ["Add a model connection and pick a default model in ", h("a", { href: "#/settings" }, "Settings"), " (or set one on the server with ", h("code", null, "sudo kodeblue inference"), "); they start on their own."]);
  }
  if (!learnWaits(st)) return null;
  const set = modelSet(st) || modelOnItsWay(st);
  return h("div", { class: "callout warn sbar-alert" }, h("div", { class: "lbl" }, set ? "Learning has not run yet" : "Learning is waiting for a model"),
    "kodeblue is watching this server with its deterministic detection, but the learning session (server profile, monitors, skills) and the vulnerability assessment have not run. ",
    set
      ? (modelSet(st) ? "A model is set; kodeblue runs them once its agent engine works, and retries them if they fail (see the server's log)."
        : "The hub's Default model reaches this server on its next sync; it restarts to use it and then runs them on its own.")
      : ["Add a model connection and pick a default model in ", h("a", { href: "#/settings" }, "Settings"), " (or set one on the server with ", h("code", null, "sudo kodeblue inference"), "); they start on their own."]);
}

// ---------- board ----------
const COLS = [
  { k: "live", name: "Investigating", color: "orange", empty: "No agent is working right now." },
  { k: "human", name: "Needs human", color: "red", empty: "Nothing is waiting on you." },
  { k: "done", name: "Resolved", color: "green", empty: "Nothing resolved yet." },
];
const norm = (s) => String(s || "").replace(/\s+/g, " ").trim();
// An operator task's title is "Operator: " + the start of the first message.
function titleMatches(task, m) {
  if (task.kind !== "operator" || task._srv !== m.server_id) return false;
  const t = norm(String(task.title || "").replace(/^Operator:\s*/, "").replace(/…$/, ""));
  if (!t || !norm(m.body).startsWith(t)) return false;
  const tc = validTime(task.created_at), mc = validTime(m.created_at);
  return !tc || !mc || tc.getTime() >= mc.getTime() - 120000;
}
// boardModel links operator messages to tasks and returns the board items.
function boardModel(d) {
  const tasks = (d.tasks || []).map((row) => {
    const t = Object.assign({}, parse(row));
    t._srv = row.server_id; t._srvName = row.server_name; t._key = row.server_id + ":" + t.id; t._board = row.board || null; t._pin = row.pin || null;
    return t;
  });
  const bySess = new Map();
  for (const t of tasks) if (t.session_id) bySess.set(t._srv + "|" + t.session_id, t);
  // Approve/deny rulings and learning commands travel as messages but are not chat.
  const all = (d.messages || []).slice().sort((a, b) => a.id - b.id);
  const msgs = all.filter((m) => !m.decision && !m.command);
  const decisions = new Map();
  for (const m of all) if (m.decision) decisions.set(m.server_id + "|" + m.request_id, m);
  const approvals = new Map();
  for (const a of d.approvals || []) {
    const x = parse(a);
    if (!x || !x.id) continue;
    x._srv = a.server_id;
    if (decidedDone(decisions.get(a.server_id + "|" + x.id))) continue;
    const k = a.server_id + ":" + x.incident_id;
    approvals.set(k, (approvals.get(k) || []).concat(x));
  }
  const convTask = new Map();
  for (const m of msgs) {
    const t = m.session_id && bySess.get(m.server_id + "|" + m.session_id);
    if (t) convTask.set(m.server_id + "|" + m.conversation_id, t);
  }
  const placeholders = [];
  const firstOfConv = new Set();
  for (const m of msgs) {
    const ck = m.server_id + "|" + m.conversation_id;
    if (m.incident_id || firstOfConv.has(ck)) continue;
    firstOfConv.add(ck);
    if (convTask.has(ck)) continue;
    const t = tasks.find((x) => titleMatches(x, m));
    if (t) { convTask.set(ck, t); continue; }
    placeholders.push(m);
  }
  const pending = new Map();
  for (const m of msgs) {
    if (m.status !== "queued" && m.status !== "delivered") continue;
    const t = m.incident_id ? tasks.find((x) => x._srv === m.server_id && String(x.id) === String(m.incident_id)) : convTask.get(m.server_id + "|" + m.conversation_id);
    if (t) pending.set(t._key, m);
  }
  return { tasks, placeholders, pending, convTask, approvals, decisions };
}
// autoColumn is where the agent's own status puts a case.
function autoColumn(t, pending, appr) {
  if (pending || t.status === "investigating") return "live";
  if (appr && appr.length) return "human";
  if (["resolved", "closed", "benign", "done"].includes(t.status)) return "done";
  return "human";
}
// boardState is the hub's board state for a case while it still holds: an
// operator's move or archive lasts until the agent changes the case again.
function boardState(t) {
  const b = t._board;
  if (!b) return null;
  const at = validTime(b.updated_at), up = validTime(t.updated_at);
  return !at || !up || at.getTime() >= up.getTime() - 1000 ? b : null;
}
function column(t, pending, appr) {
  const auto = autoColumn(t, pending, appr);
  const b = boardState(t);
  return auto !== "live" && b && b.column ? b.column : auto;
}
function isArchived(t) { const b = boardState(t); return !!(b && b.archived); }

async function vBoard(r, main, srv) {
  const cols = h("div", { class: "board" });
  const fbar = h("div", { class: "fbar", role: "toolbar", "aria-label": "Filter cases" });
  const count = h("span", { class: "count" }, "…");
  const newHref = r.srv ? `#/s/${enc(r.srv)}/new` : "#/new";
  const archBtn = h("button", { class: "btn ghost arch-t", type: "button", "aria-pressed": S.showArchived ? "true" : "false", title: "Show archived cases",
    on: { click: () => { S.showArchived = !S.showArchived; S.sel.clear(); archBtn.setAttribute("aria-pressed", S.showArchived ? "true" : "false"); bbT.textContent = boardTitle(r); S.redrawBoard(); } } },
  ic("archive", 14), h("span", null, "Archived"), h("span", { class: "acnt" }, ""));
  const bbT = h("h2", { class: "bb-t" }, boardTitle(r));
  main.append(h("div", { class: "board-bar" },
    bbT, count,
    h("span", { class: "bb-sub" }, r.srv ? "every investigation, learning run, review and operator chat on this server" : "every investigation, learning run, review and operator chat, across " + S.servers.length + " server" + (S.servers.length === 1 ? "" : "s")),
    h("div", { class: "sp" }), archBtn,
    srv && (!srv.enrolled || srv.revoked) ? h("button", { class: "btn primary", type: "button", disabled: true, title: "This server is not connected to the hub" }, ic("plus", 14), "New case")
      : h("a", { class: "btn primary", href: newHref }, ic("plus", 14), "New case")), fbar, cols);
  if (!r.srv && !S.servers.length) {
    cols.appendChild(h("div", { class: "empty big" }, logo(true),
      h("h2", null, "No servers yet"),
      h("p", { class: "muted" }, "Add a server to get a one-line install command. The server connects out to this hub with its own key; its incidents, learning runs and reviews show up here as cases."),
      h("button", { class: "btn primary", type: "button", on: { click: addServerDialog } }, ic("plus", 14), "Add server")));
    count.textContent = "0";
    return;
  }
  const paint = () => {
    if (S.dragging) { S.paintLater = true; return; }
    const d = S.board;
    const model = boardModel(d);
    S.model = model;
    const q = S.q.trim().toLowerCase();
    const f = S.filt;
    const hit = (t) => (!q || [t.title, "#" + t.id, t._srvName, t.kind, t.status, t.verdict].some((x) => String(x || "").toLowerCase().includes(q))) && passes(t, f, r, model);
    const arch = !!S.showArchived;
    const buckets = { live: [], human: [], done: [] };
    const filtering = filterCount(f, r) > 0;
    if (!arch && !filtering) for (const m of model.placeholders) {
      if (q && !m.body.toLowerCase().includes(q)) continue;
      buckets[m.status === "queued" || m.status === "delivered" ? "live" : "done"].push(placeholderCard(m, r));
    }
    let n = 0, archived = 0;
    const pinned = { live: [], human: [], done: [] };
    for (const t of model.tasks) {
      const a = isArchived(t);
      if (a) archived++;
      if (a !== arch || !hit(t)) continue;
      n++;
      const pm = model.pending.get(t._key);
      const ap = model.approvals.get(t._key);
      const col = column(t, pm, ap);
      (t._pin ? pinned : buckets)[col].push(taskCard(t, r, pm, ap));
    }
    for (const k of Object.keys(buckets)) buckets[k] = pinned[k].concat(buckets[k]);
    count.textContent = String(n + (arch || filtering ? 0 : model.placeholders.length));
    paintFilters(fbar, r, model);
    archBtn.lastChild.textContent = archived ? String(archived) : "";
    clear(cols);
    for (const c of COLS) {
      const list = buckets[c.k];
      const bd = h("div", { class: "col-bd" }, list.length ? list : h("div", { class: "col-empty" }, q || filtering ? "No matching cases" : arch ? "No archived cases here." : c.empty));
      cols.appendChild(h("section", { class: "col cc-" + c.color, "data-col": c.k },
        h("div", { class: "col-hd" }, h("span", { class: "cdot c-" + c.color }), h("h2", null, c.name), h("span", { class: "cnt" }, String(list.length)),
          c.k === "live" && list.length ? h("span", { class: "col-live" }, h("span", { class: "pulse" }), "live") : null),
        bd, h("div", { class: "col-drop" }, ic(c.k === "live" ? "bot" : c.k === "done" ? "check" : "user", 14), h("span", null, DROP_HINT[c.k]))));
    }
    markSel();
    paintSel();
  };
  main.append(h("div", { class: "selbar", role: "toolbar", "aria-label": "Selected cases", hidden: true }));
  wireBoard(cols, r);
  S.redrawBoard = () => { if (S.board) paint(); };
  const draw = async (force) => {
    let d;
    try { d = await api("GET", "/api/tasks" + (r.srv ? "?server=" + enc(r.srv) : "")); } catch { return; }
    if (!force && unchanged(cols, "board", d)) return;
    S.board = d;
    paint();
  };
  await draw(true);
  setTimer(draw, 5000);
}

const DROP_HINT = { live: "Ask the agent to look again", human: "Move to Needs human", done: "Mark resolved" };

// ----- board filters (kept in this browser) and pins (shared on the hub)
const KINDS = ["incident", "learning", "review", "operator", "coverage"];
const sevOf = (t) => (SEV.includes(t.severity) ? t.severity : "info");
const kindOf = (t) => (KINDS.includes(t.kind) ? t.kind : "incident");
// needsYou: waiting on a person: approvals, or the Needs human column.
function needsYou(t, model) {
  const ap = model.approvals.get(t._key);
  return !!(ap && ap.length) || column(t, model.pending.get(t._key), ap) === "human";
}
function passes(t, f, r, model) {
  if (f.sev.length && !f.sev.includes(sevOf(t))) return false;
  if (f.kind.length && !f.kind.includes(kindOf(t))) return false;
  if (!r.srv && srvFilter(f) && t._srv !== f.srv) return false;
  if (f.pinned && !t._pin) return false;
  if (f.attn && !needsYou(t, model)) return false;
  return true;
}
// srvFilter: the saved server filter, while that server is still listed and
// the select that shows it is drawn.
function srvFilter(f) { return !!f.srv && S.servers.length > 1 && S.servers.some((x) => x.id === f.srv); }
function filterCount(f, r) { return f.sev.length + f.kind.length + (!r.srv && srvFilter(f) ? 1 : 0) + (f.pinned ? 1 : 0) + (f.attn ? 1 : 0); }
function saveFilters() {
  try { localStorage.setItem("kb.filt", JSON.stringify(S.filt)); } catch { /* private mode */ }
  redraw();
}
function toggleIn(list, v) { const i = list.indexOf(v); if (i >= 0) list.splice(i, 1); else list.push(v); }
// paintFilters draws the filter bar with live counts of what each choice
// would show among the cases on the board.
function paintFilters(bar, r, model) {
  const f = S.filt;
  const arch = !!S.showArchived;
  const base = model.tasks.filter((t) => isArchived(t) === arch);
  const sig = JSON.stringify([f, r.srv, arch, base.map((t) => [t._key, t.severity, t.kind, !!t._pin, needsYou(t, model)])]);
  if (bar.dataset.sig === sig) return;
  bar.dataset.sig = sig;
  const tally = (pred) => base.filter(pred).length;
  const chip = (on, label, n, click, cls, title) => h("button", { class: "fchip" + (on ? " on" : "") + (cls ? " " + cls : ""), type: "button", "aria-pressed": on ? "true" : "false", title,
    on: { click } }, label, h("span", { class: "fn" }, String(n)));
  const grp = (label, kids) => h("div", { class: "fgrp" }, h("span", { class: "flbl" }, label), kids);
  const nPinned = tally((t) => !!t._pin), nAttn = tally((t) => needsYou(t, model));
  const kids = [
    chip(f.attn, [ic("user", 12), "Needs you"], nAttn, () => { f.attn = !f.attn; saveFilters(); }, "attn", "Cases waiting on a person: approvals and Needs human"),
    chip(f.pinned, [ic("pin", 12), "Pinned"], nPinned, () => { f.pinned = !f.pinned; saveFilters(); }, "pinf", "Only pinned cases"),
    h("span", { class: "fsep" }),
    grp("Severity", SEV.map((s) => chip(f.sev.includes(s), [h("i", { class: "sdot s-" + s }), s], tally((t) => sevOf(t) === s), () => { toggleIn(f.sev, s); saveFilters(); }, "cap"))),
    h("span", { class: "fsep" }),
    grp("Type", KINDS.map((k) => chip(f.kind.includes(k), k, tally((t) => kindOf(t) === k), () => { toggleIn(f.kind, k); saveFilters(); }, "cap")))];
  if (!r.srv && S.servers.length > 1) {
    const sel = h("select", { class: "fsel" + (srvFilter(f) ? " on" : ""), "aria-label": "Server", on: { change: () => { f.srv = sel.value; saveFilters(); } } },
      h("option", { value: "" }, "All servers"), S.servers.map((x) => h("option", { value: x.id, selected: f.srv === x.id }, x.name)));
    kids.push(h("span", { class: "fsep" }), grp("Server", sel));
  }
  const n = filterCount(f, r);
  // On a phone the bar folds behind one button.
  kids.unshift(h("button", { class: "ftog", type: "button", "aria-expanded": S.filtOpen ? "true" : "false",
    on: { click: () => { S.filtOpen = !S.filtOpen; bar.classList.toggle("open", S.filtOpen); bar.querySelector(".ftog").setAttribute("aria-expanded", S.filtOpen ? "true" : "false"); } } },
  ic("filter", 12), "Filters", n ? h("span", { class: "fn" }, String(n)) : null, ic("chevDown", 12)));
  if (n) kids.push(h("button", { class: "fclear", type: "button", on: { click: () => { Object.assign(f, { sev: [], kind: [], srv: "", pinned: false, attn: false }); saveFilters(); } } }, ic("x", 12), "Clear filters"));
  clear(bar);
  add(bar, kids);
  bar.classList.toggle("active", n > 0);
  bar.classList.toggle("open", !!S.filtOpen);
}
// setPins pins or unpins cases for every operator, painting at once.
async function setPins(list, on) {
  list = list.filter((t) => !!t._pin !== on);
  if (!list.length) return;
  const by = S.me ? S.me.name : "";
  const prev = list.map((t) => { const row = boardRow(t); const p = row ? row.pin : null; if (row) row.pin = on ? { by, at: new Date().toISOString() } : null; return p; });
  redraw();
  const res = await Promise.allSettled(list.map((t) => api("POST", "/api/cases/state", { server_id: t._srv, incident_id: Number(t.id), pinned: on })));
  const bad = res.filter((x, i) => {
    if (x.status === "fulfilled") return false;
    const row = boardRow(list[i]); if (row) row.pin = prev[i];
    return true;
  });
  redraw();
  if (bad.length) { toast("Not saved: " + (bad[0].reason && bad[0].reason.message || "error"), true); return; }
  toast(on ? `Pinned ${caseLabel(list).toLowerCase()} to the top for everyone` : `Unpinned ${caseLabel(list).toLowerCase()}`);
}
function boardTitle(r) { return S.showArchived ? "Archived cases" : r.srv ? "Cases" : "Fleet cases"; }
function caseByKey(key) { return S.model ? S.model.tasks.find((t) => t._key === key) : null; }

// wireBoard adds drag-and-drop between columns and the right-click menu.
// Listeners sit on the board, which survives repaints.
function wireBoard(cols, r) {
  let drag = null; // { keys, from: Set of columns, fromCol }
  const colOf = (e) => e.target.closest && e.target.closest(".col[data-col]");
  const clearDrop = () => cols.querySelectorAll(".col.drop-ok").forEach((c) => c.classList.remove("drop-ok"));
  // A column takes the drop unless every dragged case is already in it.
  const canDrop = (c) => !(drag.from.size === 1 && drag.from.has(c.dataset.col));
  cols.addEventListener("dragstart", (e) => {
    const card = e.target.closest(".card[data-key]");
    const t = card && caseByKey(card.dataset.key);
    if (!t) { e.preventDefault(); return; }
    // Dragging a selected card carries the whole selection.
    const keys = S.sel.has(t._key) && S.sel.size > 1 ? [...S.sel] : [t._key];
    const list = keys.map(caseByKey).filter(Boolean);
    drag = { keys, from: new Set(list.map(curColumn)), fromCol: card.closest(".col").dataset.col };
    S.dragging = true;
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/x-kodeblue-case", keys.join(","));
    if (list.length > 1) {
      const ghost = h("div", { class: "drag-ghost" }, ic("layers", 14), plural(list.length, "case"));
      document.body.appendChild(ghost);
      e.dataTransfer.setDragImage(ghost, 16, 16);
      setTimeout(() => ghost.remove());
    }
    // Restyle after the browser has taken the drag image; changing layout
    // inside dragstart cancels the drag in Chrome.
    setTimeout(() => {
      if (!drag) return;
      for (const k of drag.keys) { const c = cols.querySelector(`.card[data-key="${CSS.escape(k)}"]`); if (c) c.classList.add("dragging"); }
      cols.classList.add("dnd");
      if (drag.from.size === 1) cols.querySelector(`.col[data-col="${drag.fromCol}"]`).classList.add("drop-src");
    });
  });
  cols.addEventListener("dragend", () => {
    drag = null; clearDrop();
    S.dragging = false;
    if (S.paintLater) { S.paintLater = false; setTimeout(() => S.redrawBoard()); }
    cols.classList.remove("dnd");
    cols.querySelectorAll(".dragging, .drop-src").forEach((x) => x.classList.remove("dragging", "drop-src"));
  });
  cols.addEventListener("dragover", (e) => {
    const c = colOf(e);
    if (!drag || !c || !canDrop(c)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    if (!c.classList.contains("drop-ok")) { clearDrop(); c.classList.add("drop-ok"); }
  });
  cols.addEventListener("dragleave", (e) => { const c = colOf(e); if (c && !c.contains(e.relatedTarget)) c.classList.remove("drop-ok"); });
  cols.addEventListener("drop", (e) => {
    const c = colOf(e);
    if (!drag || !c || !canDrop(c)) return;
    e.preventDefault();
    const list = drag.keys.map(caseByKey).filter(Boolean);
    clearDrop();
    if (list.length) moveCases(list, c.dataset.col);
  });
  // Cmd/Ctrl-click or the card's checkbox toggles a card, Shift-click selects
  // a range. While anything is selected a plain click toggles too.
  cols.addEventListener("click", (e) => {
    const card = e.target.closest(".card[data-key]");
    if (!card || !caseByKey(card.dataset.key)) return;
    const key = card.dataset.key;
    if (e.target.closest(".pinb")) {
      e.preventDefault();
      const t = caseByKey(key);
      setPins([t], !t._pin);
      return;
    }
    const ck = e.target.closest(".ck");
    if (!ck && !e.metaKey && !e.ctrlKey && !e.shiftKey && !S.sel.size) return;
    e.preventDefault();
    if (e.shiftKey && S.selAnchor && S.selAnchor !== key) selectRange(cols, S.selAnchor, key);
    else toggleSel(key);
    if (S.sel.size && P.el) closeToBoard();
    paintSel();
  });
  cols.addEventListener("contextmenu", (e) => {
    const card = e.target.closest(".card[data-key]");
    if (!card) return;
    e.preventDefault();
    const t = caseByKey(card.dataset.key);
    const href = card.getAttribute("href");
    const at = pointAnchor(e.clientX, e.clientY);
    if (t && S.sel.has(t._key) && S.sel.size > 1) { menu(at, bulkMenu(selCases()), "mctx"); return; }
    let items = null;
    if (t) {
      items = caseMenu(t, r, href);
      items.splice(3, 0, menuItem(S.sel.has(t._key) ? "Deselect" : "Select", { icon: "checkSq", right: h("span", { class: "mi-r" }, IS_MAC ? "⌘-click" : "Ctrl-click"),
        click: () => { toggleSel(t._key); paintSel(); } }));
    }
    menu(at, items || [
      menuItem("Open", { icon: "chevRight", href }),
      menuItem("Copy link", { icon: "copy", click: () => copyText(new URL(href, location.href).href, "Link copied") })], "mctx");
  });
}
function pointAnchor(x, y) {
  return { getBoundingClientRect: () => ({ left: x, right: x, top: y, bottom: y }), contains: () => false };
}
async function copyText(text, done) {
  try { await navigator.clipboard.writeText(text); toast(done || "Copied"); } catch { toast("Copy failed", true); }
}

// caseMenu is the right-click (and panel "more") menu for one case.
function caseMenu(t, r, href) {
  href = href || taskHash(r.srv, t._srv, t.id);
  const model = S.model || { pending: new Map(), approvals: new Map() };
  const pm = model.pending.get(t._key), ap = model.approvals.get(t._key) || [];
  const cur = column(t, pm, ap.length ? ap : null);
  const b = boardState(t);
  const arch = isArchived(t);
  const items = [
    menuItem("Open", { icon: "chevRight", href }),
    menuItem("Open in new tab", { icon: "external", click: () => window.open(new URL(href, location.href).href, "_blank", "noopener") }),
    menuItem("Copy link", { icon: "copy", click: () => copyText(new URL(href, location.href).href, "Link copied") }),
    h("div", { class: "msep" }), h("div", { class: "mlbl" }, "Move to")];
  for (const c of COLS) {
    items.push(menuItem(c.name, { icon: c.k === cur ? "check" : null, cls: (c.k === cur ? "on " : "") + "mcol", disabled: c.k === cur,
      right: h("span", { class: "cdot c-" + c.color }), click: c.k === cur ? null : () => moveCase(t, c.k) }));
  }
  if (b && b.column && !arch) items.push(menuItem("Follow the agent's status", { icon: "refresh", click: () => setCaseState(t, { column: "" }, "Back on the agent's status") }));
  if (ap.length) {
    items.push(h("div", { class: "msep" }));
    items.push(menuItem(`Review ${ap.length} pending approval${ap.length === 1 ? "" : "s"}`, { icon: "shield", cls: "warn",
      click: () => {
        P.ext = "containment"; store("kb.ext", "containment");
        if (P.el && P.key === t._key) { paintRail(); P.st.extSig = ""; paintExt(); } else location.hash = href;
      } }));
  }
  items.push(h("div", { class: "msep" }));
  items.push(menuItem(t._pin ? "Unpin" : "Pin to top", { icon: "pin", click: () => setPins([t], !t._pin) }));
  items.push(arch ? menuItem("Unarchive", { icon: "archive", click: () => setCaseState(t, { archived: false }, "Case #" + t.id + " is back on the board") })
    : menuItem("Archive", { icon: "archive", click: () => setCaseState(t, { archived: true }, "Archived case #" + t.id + ". It comes back if the agent updates it.", true) }));
  if (!r.srv) items.push(menuItem("Open server", { icon: "server", href: "#/s/" + enc(t._srv) + "/overview" }));
  return items;
}

// setCasesState saves hub board state for several cases, painting it at once
// and undoing the paint for any the hub refuses. jobs: [{ t, change }].
function setCaseState(t, change, msg, undo) { return setCasesState([{ t, change }], msg, undo); }
function boardRow(t) { return S.board && (S.board.tasks || []).find((x) => x.server_id === t._srv && String(parse(x).id) === String(t.id)); }
function redraw() { if (S.redrawBoard) S.redrawBoard(); }
async function setCasesState(jobs, msg, undo) {
  if (!jobs.length) return;
  const by = S.me ? S.me.name : "";
  const prep = jobs.map(({ t, change }) => {
    const row = boardRow(t), base = boardState(t) || {};
    const next = { column: "column" in change ? change.column : base.column || "", archived: "archived" in change ? change.archived : !!base.archived,
      updated_at: new Date().toISOString(), updated_by: by };
    const p = { t, change, row, prev: row ? row.board : undefined, base, next };
    if (row) row.board = next;
    return p;
  });
  redraw();
  const res = await Promise.allSettled(prep.map((p) => api("POST", "/api/cases/state", Object.assign({ server_id: p.t._srv, incident_id: Number(p.t.id) }, p.change))));
  const ok = [], bad = [];
  res.forEach((x, i) => {
    const p = prep[i];
    if (x.status === "fulfilled") { if (p.row) p.row.board = x.value; ok.push(p); } else { if (p.row) p.row.board = p.prev; bad.push(x.reason); }
  });
  redraw();
  if (bad.length) {
    const why = bad[0] && bad[0].message ? bad[0].message : "error";
    toast(ok.length ? `${ok.length} saved, ${bad.length} not saved: ${why}` : "Not saved: " + why, true);
    return;
  }
  if (msg) toast(msg, false, undo ? { label: "Undo", click: () => setCasesState(ok.map((p) => ({
    t: Object.assign({}, p.t, { _board: p.next, updated_at: p.t.updated_at }), change: revert(p.change, p.base) }))) } : null);
}
function revert(change, base) {
  const out = {};
  if ("column" in change) out.column = base.column || "";
  if ("archived" in change) out.archived = !!base.archived;
  return out;
}
function curColumn(t) {
  const ap = S.model && S.model.approvals.get(t._key);
  return column(t, S.model && S.model.pending.get(t._key), ap && ap.length ? ap : null);
}
function plural(n, one) { return n + " " + one + (n === 1 ? "" : "s"); }
function caseLabel(list) { return list.length === 1 ? "Case #" + list[0].id : plural(list.length, "case"); }

// moveCases handles a drop (or a "Move to"). Needs human and Resolved are hub
// board state; Investigating means asking the agent to look again.
function moveCase(t, col) { return moveCases([t], col); }
async function moveCases(list, col) {
  list = list.filter((t) => curColumn(t) !== col);
  if (!list.length) return;
  if (col !== "live") {
    const name = COLS.find((c) => c.k === col).name;
    // Moving a case back to where the agent has it just drops the override.
    return setCasesState(list.map((t) => {
      const auto = autoColumn(t, S.model && S.model.pending.get(t._key), S.model && S.model.approvals.get(t._key));
      return { t, change: { column: auto === col ? "" : col } };
    }), `${caseLabel(list)} moved to ${name}`, true);
  }
  const why = (t) => {
    const s = S.servers.find((x) => x.id === t._srv);
    if (s && (!s.enrolled || s.revoked)) return "This server is not connected to the hub";
    if (s && (s.status || {}).accepts_messages === false) return "This server has hub messages disabled (hub.accept_messages = false)";
    return "";
  };
  const skip = list.filter((t) => why(t));
  const send = list.filter((t) => !why(t));
  if (!send.length) { toast(list.length === 1 ? why(list[0]) : "None of these servers accept hub messages", true); return; }
  const ta = h("textarea", { class: "ta", rows: 3, maxlength: 8000, "aria-label": "Message" }, "Please take another look at this case: re-check what you found and update the case.");
  const go = h("button", { class: "btn primary", type: "button" }, ic("bot", 14), "Ask the agent");
  const one = send[0];
  const srvs = new Set(send.map((t) => t._srv));
  const m = modal("Investigate again", [
    h("p", { class: "muted" }, send.length === 1
      ? `kodeblue on ${one._srvName || serverName(one._srv)} continues case #${one.id} with this message. It moves to Investigating while the agent works.`
      : srvs.size === 1 ? `kodeblue on ${one._srvName || serverName(one._srv)} continues these ${send.length} cases with this message. They move to Investigating while the agent works.`
        : `kodeblue continues ${send.length} cases on ${srvs.size} servers with this message. They move to Investigating while the agents work.`),
    skip.length ? h("p", { class: "muted warn-t" }, `Skipping ${skip.map((t) => "#" + t.id).join(", ")}: ${why(skip[0])}.`) : null, ta], [go]);
  setTimeout(() => { ta.focus(); ta.select(); });
  go.addEventListener("click", async () => {
    const text = ta.value.trim();
    if (!text) return;
    go.disabled = true;
    let sent = 0, err = null;
    for (const t of send) {
      const body = { body: text, incident_id: 0, conversation_id: "" };
      const conv = t.kind === "operator" ? convOf(t) : "";
      if (conv) body.conversation_id = conv; else body.incident_id = Number(t.id);
      try {
        await api("POST", `/api/servers/${enc(t._srv)}/messages`, body);
        sent++;
        if (boardState(t) && boardState(t).column) await api("POST", "/api/cases/state", { server_id: t._srv, incident_id: Number(t.id), column: "" }).catch(() => null);
      } catch (e) { err = e; }
    }
    if (!sent) { go.disabled = false; toast("Not sent: " + err.message, true); return; }
    m.close();
    if (err) toast(`Sent ${sent} of ${send.length}. Not sent: ${err.message}`, true);
    else toast(send.length === 1 ? `Sent to the agent on ${one._srvName || serverName(one._srv)}` : `Sent to the agents for ${plural(sent, "case")}`);
    if (S.timerFn) S.timerFn();
  });
}
function convOf(t) {
  if (!S.model) return "";
  let conv = "";
  for (const [k, v] of S.model.convTask) if (v === t || v._key === t._key) conv = k.split("|")[1];
  return conv;
}

// Cards: one-line title, a quiet chips row, and a
// terminal-style line while an agent is working. No mascot.
function sevChip(sev) {
  const k = SEV.includes(sev) ? sev : "info";
  return h("span", { class: "chip2 s-" + k, title: "severity" }, h("i"), k);
}
function kindChip(kind) {
  const k = ["incident", "learning", "review", "operator", "coverage"].includes(kind) ? kind : "incident";
  return h("span", { class: "chip2 k-" + k }, k);
}
function liveRow(text, at) {
  return h("div", { class: "card-live" }, ic("terminal", 11), h("span", { class: "lt" }, text), at ? h("span", { class: "lw" }, ago(at)) : null);
}
function taskCard(t, r, pm, ap) {
  const live = !!pm || t.status === "investigating";
  const sv = SEV.includes(t.severity) ? t.severity : "info";
  const b = boardState(t);
  return h("a", { class: "card sv-" + sv + (live ? " live" : "") + (isArchived(t) ? " arch" : "") + (t._pin ? " pinned" : ""), href: taskHash(r.srv, t._srv, t.id), "data-key": t._key, draggable: "true" },
    h("div", { class: "card-hd" },
      h("div", { class: "card-r1" }, h("h3", { class: "card-t", title: t.title }, t.title), h("span", { class: "card-id" }, "#" + t.id),
        h("span", { class: "pinb", role: "button", "aria-pressed": t._pin ? "true" : "false", "aria-label": t._pin ? "Unpin case #" + t.id : "Pin case #" + t.id,
          title: t._pin ? `Pinned by ${t._pin.by || "an operator"} ${ago(t._pin.at)}. Click to unpin.` : "Pin to the top of its column, for everyone" }, ic("pin", 12)),
        h("span", { class: "ck", role: "checkbox", "aria-checked": S.sel.has(t._key) ? "true" : "false", "aria-label": "Select case #" + t.id, title: "Select" }, ic("check", 11))),
      t.summary ? h("p", { class: "card-desc" }, t.summary) : null,
      h("div", { class: "card-r2" },
        h("span", { class: "card-meta" }, kindChip(t.kind), r.srv ? null : h("span", null, t._srvName), h("span", null, ago(t.updated_at))),
        h("span", { class: "card-tags" },
          ap && ap.length ? h("span", { class: "chip2 appr", title: ap.map((a) => a.action).join(", ") + " waiting for approval" }, ic("shield", 10), ap.length + " to approve") : null,
          b && b.column && !live ? h("span", { class: "chip2 moved", title: "Moved by " + (b.updated_by || "an operator") + " " + ago(b.updated_at) + ". It follows the agent again when the agent updates the case." }, ic("user", 10)) : null,
          sevChip(t.severity)))),
    live ? liveRow(pm ? (pm.status === "queued" ? "message queued for the server" : "answering " + pm.author + ": " + pm.body) : "investigating…", pm ? pm.created_at : t.updated_at) : null);
}
function placeholderCard(m, r) {
  const pending = m.status === "queued" || m.status === "delivered";
  return h("a", { class: "card" + (pending ? " live" : ""), href: taskHash(r.srv, m.server_id, "m" + m.id), "data-key": m.server_id + ":m" + m.id },
    h("div", { class: "card-hd" },
      h("div", { class: "card-r1" }, h("h3", { class: "card-t", title: m.body }, m.body)),
      h("p", { class: "card-desc" }, m.status === "queued" ? "Waiting for the server to pick up this message." : m.status === "delivered" ? "The agent is opening a case for this message." : "Message " + m.status + "."),
      h("div", { class: "card-r2" },
        h("span", { class: "card-meta" }, kindChip("operator"), r.srv ? null : h("span", null, serverName(m.server_id)), h("span", null, m.author)),
        h("span", { class: "card-tags" }, h("span", { class: "chip2 st-" + m.status }, m.status)))),
    pending ? liveRow(m.status === "queued" ? "waiting for the server to pick it up" : "opening a new case…", m.created_at) : null);
}
function markSel() {
  document.querySelectorAll(".card.sel").forEach((c) => c.classList.remove("sel"));
  if (!P.key) return;
  const c = document.querySelector(`.card[data-key="${CSS.escape(P.key)}"]`);
  if (c) c.classList.add("sel");
}

// ---------- multi-select ----------
const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
function selCards() { return [...document.querySelectorAll(".board .card[data-key]")].filter((c) => caseByKey(c.dataset.key)); }
function selCases() { return [...S.sel].map(caseByKey).filter(Boolean); }
function toggleSel(key) {
  if (S.sel.has(key)) S.sel.delete(key); else S.sel.add(key);
  S.selAnchor = key;
}
function selectRange(cols, a, b) {
  const keys = selCards().map((c) => c.dataset.key);
  const i = keys.indexOf(a), j = keys.indexOf(b);
  if (i < 0 || j < 0) { toggleSel(b); return; }
  for (const k of keys.slice(Math.min(i, j), Math.max(i, j) + 1)) S.sel.add(k);
  S.selAnchor = b;
}
function selectAll() { for (const c of selCards()) S.sel.add(c.dataset.key); paintSel(); }
function clearSel() { S.sel.clear(); S.selAnchor = ""; paintSel(); }

// paintSel marks selected cards, drops keys that left the board (filtered,
// archived, deleted) and repaints the selection bar.
function paintSel() {
  const board = document.querySelector(".board");
  const cards = selCards();
  const present = new Set(cards.map((c) => c.dataset.key));
  for (const k of [...S.sel]) if (!present.has(k)) S.sel.delete(k);
  for (const c of cards) {
    const on = S.sel.has(c.dataset.key);
    c.classList.toggle("msel", on);
    const ck = c.querySelector(".ck");
    if (ck) ck.setAttribute("aria-checked", on ? "true" : "false");
  }
  if (board) board.classList.toggle("selecting", S.sel.size > 0);
  const bar = document.querySelector(".selbar");
  if (!bar) return;
  const list = selCases();
  bar.hidden = !list.length;
  document.body.classList.toggle("selbar-on", !!list.length);
  clear(bar);
  if (!list.length) return;
  const cols = new Set(list.map(curColumn));
  const arch = list.every(isArchived);
  add(bar, [
    h("span", { class: "sb-n" }, String(list.length)), h("span", { class: "sb-l" }, "selected"),
    h("span", { class: "sb-sep" }),
    h("span", { class: "sb-l sb-mv" }, "Move to"),
    COLS.map((c) => h("button", { class: "btn small sb-col", type: "button", disabled: cols.size === 1 && cols.has(c.k),
      title: c.k === "live" ? "Ask the agents to look again" : "Move to " + c.name, on: { click: () => moveCases(list, c.k) } },
      h("span", { class: "cdot c-" + c.color }), h("span", { class: "sb-cn" }, c.name))),
    h("span", { class: "sb-sep" }),
    h("button", { class: "btn small", type: "button", on: { click: () => archiveCases(list, !arch) } }, ic("archive", 13), h("span", { class: "sb-cn" }, arch ? "Unarchive" : "Archive")),
    h("button", { class: "btn small ghost sb-all", type: "button", title: "Select every case on the board (" + (IS_MAC ? "⌘A" : "Ctrl+A") + ")", on: { click: selectAll } }, "All"),
    h("button", { class: "hbtn sb-x", type: "button", title: "Clear selection (Esc)", "aria-label": "Clear selection", on: { click: clearSel } }, ic("x", 15))]);
}
function archiveCases(list, on) {
  list = list.filter((t) => isArchived(t) !== on);
  if (!list.length) return;
  const n = caseLabel(list);
  setCasesState(list.map((t) => ({ t, change: { archived: on } })),
    on ? (list.length === 1 ? `Archived ${n.toLowerCase()}. It comes back if the agent updates it.` : `Archived ${n}. They come back if the agents update them.`)
      : `${n} ${list.length === 1 ? "is" : "are"} back on the board`, true);
}
// bulkMenu is the right-click menu on a card that is part of a selection.
function bulkMenu(list) {
  const cols = new Set(list.map(curColumn));
  const arch = list.every(isArchived);
  const items = [h("div", { class: "mlbl" }, plural(list.length, "case") + " selected"), h("div", { class: "mlbl" }, "Move to")];
  for (const c of COLS) {
    const here = cols.size === 1 && cols.has(c.k);
    items.push(menuItem(c.name, { icon: here ? "check" : null, cls: (here ? "on " : "") + "mcol", disabled: here,
      right: h("span", { class: "cdot c-" + c.color }), click: here ? null : () => moveCases(list, c.k) }));
  }
  if (!arch && list.some((t) => (boardState(t) || {}).column)) items.push(menuItem("Follow the agent's status", { icon: "refresh",
    click: () => setCasesState(list.filter((t) => (boardState(t) || {}).column).map((t) => ({ t, change: { column: "" } })), "Back on the agent's status") }));
  items.push(h("div", { class: "msep" }));
  const allPinned = list.every((t) => !!t._pin);
  items.push(menuItem(allPinned ? "Unpin" : "Pin to top", { icon: "pin", click: () => setPins(list, !allPinned) }));
  items.push(menuItem(arch ? "Unarchive" : "Archive", { icon: "archive", click: () => archiveCases(list, !arch) }));
  items.push(menuItem("Copy links", { icon: "copy", click: () => copyText(list.map((t) => new URL(taskHash(parseHash().srv, t._srv, t.id), location.href).href).join("\n"), "Links copied") }));
  items.push(menuItem("Clear selection", { icon: "x", click: clearSel }));
  return items;
}

// ---------- task panel ----------
const P = { el: null, key: "", r: null, timer: null, ext: null, st: {}, busy: false };
const EXT = [["overview", "list", "overview"], ["findings", "alert", "findings"], ["containment", "shield", "containment"], ["details", "clock", "details"]];

function syncPanel(r) {
  const key = r.newTask ? "new:" + (r.srv || "") : r.task ? r.task.srv + ":" + r.task.id : "";
  if (!key) { closePanel(); return; }
  if (P.el && P.key === key) return;
  closePanel();
  openPanel(r, key);
}
function closePanel() {
  if (P.timer) clearInterval(P.timer);
  P.timer = null;
  if (P.st && P.st.fast) clearTimeout(P.st.fast);
  if (P.el) P.el.remove();
  P.el = null; P.key = ""; P.st = {};
  document.body.classList.remove("tp-open");
  markSel();
}
function closeToBoard() { location.hash = boardHash(parseHash().srv); }

function openPanel(r, key) {
  if (S.loginShown) return;
  P.key = key; P.r = r;
  const srv = r.task ? r.task.srv : r.srv || "";
  const id = r.task ? r.task.id : "";
  P.st = { srv, id, placeholder: id.startsWith("m"), isNew: !!r.newTask, first: true, chatSig: "", hdSig: "", extSig: "" };
  if (!P.st.isNew && !P.st.placeholder) {
    // Side panel as last left; on a phone it would cover the chat, so the chat comes first.
    const pref = store("kb.ext");
    P.ext = window.innerWidth < 900 ? null : pref === "none" ? null : pref || (window.innerWidth >= 1280 ? "overview" : null);
  }
  const dot = h("span", { class: "tdot" });
  const titleLbl = h("span", { class: "tt" }, P.st.isNew ? "New case" : "Case chat");
  const more = h("button", { class: "ibtn", type: "button", title: "More", "aria-label": "More" }, ic("more", 14));
  more.addEventListener("click", () => {
    const t = !P.st.isNew && !P.st.placeholder ? caseByKey(P.key) : null;
    menu(more, [
      menuItem("Copy link", { icon: "copy", click: () => copyText(location.href, "Link copied") }),
      menuItem("Refresh", { icon: "refresh", click: () => { P.st.chatSig = ""; P.st.apprSig = ""; panelRefresh(true); } }),
      srv ? menuItem("Open server", { icon: "server", href: "#/s/" + enc(srv) + "/overview" }) : null,
      t ? [h("div", { class: "msep" }), h("div", { class: "mlbl" }, "Move to"),
        COLS.map((c) => menuItem(c.name, { icon: null, right: h("span", { class: "cdot c-" + c.color }), click: () => moveCase(t, c.k) })),
        h("div", { class: "msep" }),
        isArchived(t) ? menuItem("Unarchive", { icon: "archive", click: () => setCaseState(t, { archived: false }, "Case #" + t.id + " is back on the board") })
          : menuItem("Archive", { icon: "archive", click: () => { setCaseState(t, { archived: true }, "Archived case #" + t.id + ". It comes back if the agent updates it.", true); closeToBoard(); } })] : null,
    ]);
  });
  const titlebar = h("div", { class: "tp-title" }, dot, titleLbl, h("div", { class: "sp" }), more,
    h("button", { class: "ibtn", type: "button", title: "Close (Esc)", "aria-label": "Close", on: { click: closeToBoard } }, ic("x", 14)));
  const hd = h("div", { class: "tp-hd" });
  const rail = h("div", { class: "tp-rail" });
  const chat = h("div", { class: "tp-chat", "aria-live": "polite" });
  const appr = h("div", { class: "tp-appr", hidden: true });
  const comp = composer();
  const ext = h("aside", { class: "tp-ext", hidden: true });
  const panel = h("section", { class: "tp", role: "dialog", "aria-label": "Case chat" }, titlebar, hd,
    h("div", { class: "tp-body" }, rail, h("div", { class: "tp-main" }, chat, appr, comp.el)));
  const grip = h("div", { class: "tp-grip", title: "Drag to resize" });
  const wrap = h("div", { class: "tp-wrap" }, grip, ext, panel);
  P.el = wrap; P.dot = dot; P.hd = hd; P.rail = rail; P.chat = chat; P.comp = comp; P.extEl = ext; P.panel = panel; P.appr = appr;
  applyWidth();
  grip.addEventListener("mousedown", (e) => {
    e.preventDefault();
    const move = (ev) => { const w = Math.round(window.innerWidth - ev.clientX - 20 - (P.ext ? P.extEl.offsetWidth : 0)); P.width = Math.max(420, Math.min(w, window.innerWidth - 80)); applyWidth(); };
    const up = () => { document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); store("kb.pw", String(P.width)); };
    document.addEventListener("mousemove", move); document.addEventListener("mouseup", up);
  });
  document.body.appendChild(wrap);
  document.body.classList.add("tp-open");
  void wrap.offsetWidth; // commit the start state so the fade-in runs, even in a background tab
  wrap.classList.add("in");
  paintRail();
  markSel();
  if (P.st.isNew) paintNew();
  else { clear(chat).appendChild(h("div", { class: "tp-empty" }, h("p", null, "~ loading…"), h("span", { class: "cursor" }))); panelRefresh(true); }
  P.timer = setInterval(() => { if (!document.hidden) panelRefresh(false); }, 5000);
  if (!P.st.isNew) setTimeout(() => comp.ta.focus({ preventScroll: true }), 50);
}
function applyWidth() {
  if (!P.panel) return;
  if (!P.width) P.width = Number(store("kb.pw")) || 0;
  if (P.width) P.panel.style.width = Math.min(P.width, window.innerWidth - 40) + "px";
}
function paintRail() {
  clear(P.rail);
  const off = P.st.isNew || P.st.placeholder;
  for (const [k, icon, label] of EXT) {
    P.rail.appendChild(h("button", { class: "rb" + (P.ext === k && !off ? " on" : ""), type: "button", title: label, "aria-label": label, disabled: off ? true : null,
      on: { click: () => { P.ext = P.ext === k ? null : k; store("kb.ext", P.ext || "none"); paintRail(); P.st.extSig = ""; paintExt(); } } }, ic(icon, 14)));
  }
  P.extEl.hidden = !P.ext || off;
  P.el.classList.toggle("has-ext", !!P.ext && !off);
}

function composer() {
  const ta = h("textarea", { rows: 1, maxlength: 8000, "aria-label": "Message the agent", placeholder: "Message the agent…" });
  const send = h("button", { class: "send", type: "button", title: "Send (Enter)", "aria-label": "Send" }, ic("send", 16));
  const chip = h("span", { class: "chip" }, ic("server", 11), h("span", { class: "chip-l" }, "kodeblue"));
  const note = h("span", { class: "cnote" }, "enter to send · shift+enter newline");
  const grow = () => { ta.style.height = "auto"; ta.style.height = Math.min(ta.scrollHeight, 220) + "px"; };
  ta.addEventListener("input", () => { S.drafts[P.key] = ta.value; grow(); send.disabled = !ta.value.trim(); });
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send.click(); } });
  send.addEventListener("click", () => sendMessage(ta.value));
  const el = h("div", { class: "comp" }, h("div", { class: "comp-in" }, h("span", { class: "prompt" }, ">"), ta),
    h("div", { class: "comp-sep" }), h("div", { class: "comp-ft" }, chip, note, h("div", { class: "sp" }), send));
  setTimeout(() => { ta.value = S.drafts[P.key] || ""; grow(); send.disabled = !ta.value.trim(); });
  return { el, ta, send, chip, note, setChip: (t) => { chip.lastChild.textContent = t; }, setNote: (t, bad) => { note.textContent = t; note.classList.toggle("bad", !!bad); } };
}

async function sendMessage(text) {
  text = text.trim();
  if (!text || P.busy) return;
  const st = P.st;
  let srv = st.srv;
  const body = { body: text, incident_id: 0, conversation_id: "" };
  if (st.isNew) {
    srv = P.newSrv ? P.newSrv.value : srv;
    if (!srv) { P.comp.setNote("Pick a server first.", true); return; }
  } else if (st.placeholder) {
    if (st.msg) body.conversation_id = st.msg.conversation_id;
  } else if (st.inc) {
    const conv = st.inc.kind === "operator" ? lastConv(st.own) : "";
    if (conv) body.conversation_id = conv;
    else body.incident_id = Number(st.inc.id);
  } else return;
  P.busy = true; P.comp.send.disabled = true; P.comp.setNote("sending…");
  const key = P.key;
  try {
    const m = await api("POST", `/api/servers/${enc(srv)}/messages`, body);
    delete S.drafts[key];
    if (P.key !== key) return;
    P.comp.ta.value = ""; P.comp.ta.style.height = "auto";
    P.comp.setNote("enter to send · shift+enter newline");
    if (st.isNew) {
      const ctx = parseHash().srv;
      location.hash = taskHash(ctx, srv, "m" + m.id);
      return;
    }
    if (S.timerFn) S.timerFn();
    st.extra = (st.extra || []).concat(m);
    st.chatSig = "";
    await panelRefresh(false, true);
  } catch (e) {
    if (P.key === key) P.comp.setNote(e.status === 0 ? "Couldn't reach the hub; your message is still here. Try again." : "Not sent: " + e.message, true);
  } finally {
    P.busy = false;
    if (P.key === key) P.comp.send.disabled = !P.comp.ta.value.trim();
  }
}
function lastConv(own) {
  const l = (own || []).filter((m) => m.conversation_id);
  return l.length ? l[l.length - 1].conversation_id : "";
}

function paintNew() {
  const st = P.st;
  const enrolled = S.servers.filter((s) => s.enrolled && !s.revoked);
  P.dot.className = "tdot c-blue";
  const sel = h("select", { class: "sel", "aria-label": "Server" }, enrolled.map((s) => h("option", { value: s.id, selected: s.id === st.srv }, s.name)));
  P.newSrv = sel;
  const sync = () => {
    const s = S.servers.find((x) => x.id === sel.value);
    P.comp.setChip("kodeblue@" + (s ? s.name : "?"));
    const ok = s && (s.status || {}).accepts_messages !== false;
    P.comp.setNote(!s ? "No connected server." : ok ? "enter to send · shift+enter newline" : "This server has hub messages disabled (hub.accept_messages = false).", !ok);
  };
  sel.addEventListener("change", sync);
  clear(P.hd).appendChild(h("div", { class: "tp-hd-in" },
    h("div", { class: "hrow" }, h("span", { class: "srvchip" }, ic("server", 13)), enrolled.length ? sel : h("span", { class: "muted" }, "no connected servers"),
      h("span", { class: "fg" }, "new operator case")),
    h("div", { class: "hrow2" }, h("span", { class: "muted" }, "The agent on the server starts a fresh session with kodeblue's tools; containment still follows the server's policy."))));
  clear(P.chat).appendChild(h("div", { class: "tp-empty" },
    h("p", null, "~ No messages yet."),
    h("p", null, "Ask what happened, ask it to check something, or tell it to watch for something or stop alerting on a known change."),
    h("p", { class: "muted" }, "examples:"),
    h("ul", null, ["What changed on this server in the last 24 hours?", "Is anything listening on a new port?", "Stop alerting on the nightly backup cron, it is expected."].map((x) =>
      h("li", null, h("button", { class: "eg", type: "button", on: { click: () => { P.comp.ta.value = x; P.comp.ta.dispatchEvent(new Event("input")); P.comp.ta.focus(); } } }, x)))),
    h("span", { class: "cursor" })));
  sync();
  setTimeout(() => P.comp.ta.focus(), 50);
}

async function panelRefresh(first, force) {
  const st = P.st;
  const key = P.key;
  if (!P.el || st.isNew) return;
  if (st.loading) { if (force) st.again = true; return; }
  st.loading = true;
  try {
    const msgs = await api("GET", `/api/servers/${enc(st.srv)}/messages`).catch((e) => { if (e.status === 404) throw e; return st.msgs || []; });
    if (P.key !== key) return;
    st.msgs = msgs || [];
    if (st.placeholder) return await refreshPlaceholder(key);
    let rec = null;
    try { rec = await api("GET", `/api/servers/${enc(st.srv)}/records/incident/${enc(st.id)}`); }
    catch (e) { if (e.status === 404) { notFound("This case is not on the hub (yet). It may have been pruned, or the server has not synced it."); return; } if (st.inc) return; throw e; }
    if (P.key !== key) return;
    const inc = parse(rec);
    st.inc = inc;
    st.own = ownMessages(inc, st.msgs).concat((st.extra || []).filter((x) => !st.msgs.some((m) => m.id === x.id)));
    const pending = st.own.some((m) => m.status === "queued" || m.status === "delivered");
    const needSess = inc.session_id && (first || force || !st.sess || (st.sess && st.sess.running) || pending || rec.updated_at !== st.recAt || (st.tick = (st.tick || 0) + 1) % 4 === 0);
    if (needSess) {
      const s = await api("GET", `/api/servers/${enc(st.srv)}/records/session/${enc(inc.session_id)}`).catch(() => null);
      if (P.key !== key) return;
      st.sess = s ? parse(s) : st.sess || null;
    }
    st.recAt = rec.updated_at;
    paintHeader(inc);
    const [notes, pend] = await Promise.all([taskNotes(st.srv, inc.id),
      recs(st.srv, "pending_action", "?limit=200").catch(() => null)]);
    if (P.key !== key) return;
    st.decs = st.msgs.filter((m) => m.decision && String(m.incident_id) === String(inc.id)).sort((a, b) => a.id - b.id);
    if (pend) st.pend = pend.map(parse).filter((a) => String(a.incident_id) === String(inc.id));
    // Follow a fresh ruling closely; one the server has not answered in
    // 30 s (offline, busy) goes back to the 5 s poll.
    st.decOpen = st.decs.some((m) => decOpen(m) && Date.now() - (validTime(m.created_at) || 0) < 30000);
    paintApprovals();
    paintChat(inc, st.sess, st.own, notes, st.decs, st.srv);
    paintExt();
  } catch (e) {
    if (e.status !== 401 && P.key === key && first) notFound(e.message);
  } finally {
    st.loading = false;
    if (st.again && P.key === key) { st.again = false; setTimeout(() => panelRefresh(false, true)); }
    // A ruling takes the server about a second: follow it closely rather
    // than on the 5 s poll.
    else if (st.decOpen && P.key === key && !st.fast && !document.hidden) st.fast = setTimeout(() => { st.fast = null; if (P.key === key) panelRefresh(false, true); }, 1000);
  }
}
function notFound(text) {
  P.dot.className = "tdot";
  clear(P.hd);
  clear(P.chat).appendChild(h("div", { class: "tp-empty" }, h("p", null, "~ " + text)));
}

async function refreshPlaceholder(key) {
  const st = P.st;
  const m = st.msgs.find((x) => "m" + x.id === st.id);
  if (!m) { notFound("This message is no longer on the hub."); return; }
  st.msg = m;
  // Once the agent's new task has synced, the placeholder turns into it.
  let t = null;
  if (S.board) {
    const model = S.model || boardModel(S.board);
    t = model.tasks.find((x) => x._srv === m.server_id && ((m.session_id && x.session_id === m.session_id) || titleMatches(x, m)));
  }
  if (!t && (m.session_id || m.status === "delivered")) {
    try {
      const d = await api("GET", "/api/tasks?server=" + enc(m.server_id) + "&limit=60");
      const model = boardModel(d);
      t = model.tasks.find((x) => (m.session_id && x.session_id === m.session_id) || titleMatches(x, m));
    } catch { /* keep the placeholder */ }
  }
  if (P.key !== key) return;
  if (t) {
    if (S.drafts[key]) S.drafts[m.server_id + ":" + t.id] = S.drafts[key];
    location.replace(taskHash(parseHash().srv, m.server_id, t.id));
    return;
  }
  const pending = m.status === "queued" || m.status === "delivered";
  P.dot.className = "tdot " + (pending ? "c-orange pulse" : "c-red");
  const sig = JSON.stringify(m);
  if (st.hdSig !== sig) {
    st.hdSig = sig;
    clear(P.hd).appendChild(h("div", { class: "tp-hd-in" },
      h("div", { class: "hrow" }, h("span", { class: "srvchip" }, ic("server", 13), serverName(m.server_id)), h("span", { class: "htitle" }, m.body)),
      h("div", { class: "hrow2" }, kindBadge("operator"), statusBadge(m.status), h("span", { class: "muted" }, "sent " + when(m.created_at) + " by " + m.author))));
    P.comp.setChip("kodeblue@" + serverName(m.server_id));
  }
  if (st.chatSig === sig) return;
  st.chatSig = sig;
  const box = P.chat;
  add(clear(box), [opBubble(m.author, m.body, m.created_at), msgState(m), pending ? working(m.status === "queued" ? "waiting for the server to pick up the message…" : "the agent is opening a new case…") : null]);
  box.scrollTop = box.scrollHeight;
}

// ownMessages are the operator messages that belong to a task.
function ownMessages(inc, msgs) {
  const convs = new Set();
  for (const m of msgs) if (inc.session_id && m.session_id === inc.session_id) convs.add(m.conversation_id);
  if (inc.kind === "operator" && !convs.size) {
    const t = Object.assign({}, inc, { _srv: P.st.srv });
    const first = msgs.slice().sort((a, b) => a.id - b.id).find((m) => !m.incident_id && titleMatches(t, m));
    if (first) convs.add(first.conversation_id);
  }
  return msgs.filter((m) => !m.decision && !m.command).filter((m) => (m.incident_id && String(m.incident_id) === String(inc.id)) || (inc.session_id && m.session_id === inc.session_id) || convs.has(m.conversation_id))
    .sort((a, b) => a.id - b.id);
}

function paintHeader(inc) {
  const st = P.st;
  const live = (st.sess && st.sess.running) || inc.status === "investigating" || (st.own || []).some((m) => m.status === "queued" || m.status === "delivered");
  P.dot.className = "tdot " + (live ? "c-orange pulse" : column(inc) === "done" ? "c-green" : "c-red");
  const name = serverName(st.srv);
  P.comp.setChip("kodeblue@" + name);
  const s = S.servers.find((x) => x.id === st.srv);
  if (s && (s.status || {}).accepts_messages === false) P.comp.setNote("This server has hub messages disabled (hub.accept_messages = false).", true);
  const sig = JSON.stringify([inc.title, inc.kind, inc.severity, inc.status, inc.verdict, inc.confidence, inc.cost_usd, inc.updated_at, name, live]);
  if (st.hdSig === sig) return;
  st.hdSig = sig;
  clear(P.hd).appendChild(h("div", { class: "tp-hd-in" },
    h("div", { class: "hrow" }, h("a", { class: "srvchip", href: "#/s/" + enc(st.srv) + "/overview", title: "Open server" }, ic("server", 13), name),
      h("span", { class: "htitle", title: inc.title }, inc.title), h("span", { class: "hid" }, "#" + inc.id)),
    h("div", { class: "hrow2" }, kindBadge(inc.kind), sevBadge(inc.severity), statusBadge(inc.status), verdictBadge(inc.verdict),
      inc.confidence ? h("span", { class: "badge", title: inc.kind === "review" ? "self-evaluation score" : "agent's confidence in its verdict" },
        inc.kind === "review" ? `score ${Math.round(inc.confidence * 10)}/10` : `confidence ${Math.round(inc.confidence * 100)}%`) : null,
      h("span", { class: "muted" }, usd(inc.cost_usd)),
      h("span", { class: "muted" }, "opened " + when(inc.created_at) + " · updated " + ago(inc.updated_at)))));
}

const OP_RE = /^OPERATOR MESSAGE from (.+?) via the kodeblue hub \(authenticated; message #(\d+)\):\n\n([\s\S]*)$/;
// taskNotes are the Slack notifications kodeblue sent about one task. Hubs
// without notification support simply show none.
async function taskNotes(srv, id) {
  if (S.noNotes) return [];
  try {
    const l = await api("GET", "/api/notifications?server_id=" + enc(srv) + "&limit=200");
    return (l || []).filter((n) => String(n.incident_id) === String(id));
  } catch (e) {
    if (e.status === 404) S.noNotes = true;
    return P.st.notes || [];
  }
}
function paintChat(inc, sess, own, notes, decs, srvId) {
  const st = P.st;
  st.notes = notes = notes || [];
  decs = decs || [];
  const turns = (sess && sess.turns) || [];
  const sig = JSON.stringify([turns.length, sess && sess.updated_at, sess && sess.running, own.map((m) => [m.id, m.status, m.session_id, m.reply ? m.reply.length : 0]), inc.status, [...S.open].length,
    notes.map((n) => [n.id, n.status, n.attempts]), decs.map((m) => [m.id, m.status])]);
  if (st.chatSig === sig) return;
  st.chatSig = sig;
  const box = P.chat;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const top = box.scrollTop;
  const seen = new Set();
  const byId = new Map(own.map((m) => [String(m.id), m]));
  const items = [];
  const times = []; // when each item happened, for placing Slack notifications in time order
  const push = (node, at) => { items.push(node); times.push(validTime(at)); };
  turns.forEach((tu, n) => {
    const k = `${(sess && sess.session_id) || inc.session_id}:${n}`;
    if (tu.role === "user") {
      const m = OP_RE.exec(tu.text || "");
      if (m) {
        seen.add(m[2]);
        const rec = byId.get(m[2]);
        push(opBubble(m[1], rec ? rec.body : m[3], tu.at, rec ? null : m[3]), tu.at);
      } else push(briefBubble(tu.text, k, n === 0 ? "kodeblue brief" : "kodeblue", tu.at), tu.at);
      return;
    }
    push(agentTurn(tu, k), tu.at);
  });
  for (const m of own) {
    if (seen.has(String(m.id))) {
      if (m.status === "failed" || m.status === "refused") push(msgState(m), m.replied_at || m.created_at);
      continue;
    }
    push(opBubble(m.author, m.body, m.created_at), m.created_at);
    if (m.status === "done" && m.reply) push(h("div", { class: "turn" }, md(m.reply, "agent"), h("div", { class: "tmeta" }, "reply · " + clock(m.replied_at), m.cost_usd ? " · " + usd(m.cost_usd) : "", " · transcript not synced yet")), m.replied_at);
    else push(msgState(m), m.created_at);
  }
  // Notifications and approve/deny rulings go after the last item that
  // happened before them.
  const events = notes.map((n) => [validTime(n.at), noteEvent(n)]).concat(decs.map((m) => [validTime(m.created_at), decisionEvent(m)]));
  for (const [at, node] of events.sort((a, b) => (a[0] || 0) - (b[0] || 0))) {
    let i = items.length;
    if (at) { i = times.findIndex((t) => t && t > at); if (i < 0) i = items.length; }
    items.splice(i, 0, node);
    times.splice(i, 0, at);
  }
  const pend = own.find((m) => m.status === "queued" || m.status === "delivered");
  if (pend && pend.status === "delivered" && sess && sess.running) items.push(workingStoppable(sess, inc, srvId, "agent is working on your message…"));
  else if (pend) items.push(working(pend.status === "queued" ? "message queued; waiting for the server to pick it up…" : "agent is working on your message…"));
  else if ((sess && sess.running) || inc.status === "investigating") items.push(workingStoppable(sess, inc, srvId, sess ? "agent is working…" : "agent is starting…"));
  if (!turns.length && !own.length) items.unshift(h("div", { class: "tp-empty" }, h("p", null, inc.session_id ? "~ Transcript not synced yet." : "~ No agent session for this case."),
    inc.summary ? md(inc.summary) : null));
  add(clear(box), items);
  if (st.first || atBottom) box.scrollTop = box.scrollHeight; else box.scrollTop = top;
  st.first = false;
}
function decisionEvent(m) {
  const open = decOpen(m);
  const bad = m.status === "failed" || m.status === "refused";
  const verb = m.decision === "approve" ? "approved" : "denied";
  return h("div", { class: "turn" }, h("div", { class: "sysev dec" + (bad ? " bad" : m.decision === "approve" ? " ok" : "") }, ic("shield", 12),
    h("span", null, (m.author || "operator") + " " + verb + " containment"),
    h("span", { class: "sep" }, "·"), h("span", { class: "sev-title" }, m.body.replace(/^(Approve|Deny) containment /, "")),
    h("span", { class: "sep" }, "·"), h("span", { class: bad ? "err" : "" }, open ? (m.status === "queued" ? "waiting for the server…" : "the server is handling it…") : m.reply || m.status),
    h("span", { class: "ut" }, clock(m.replied_at && !open ? m.replied_at : m.created_at))));
}

// ---------- learning ----------
// learningControls: Run learner / Relearn for one server, the command in
// flight, or (for servers that keep learning local) the CLI command.
function learningControls(srv, cmds, after) {
  const st = srv.status || {};
  if (!srv.enrolled || srv.revoked || !st.phase) return "—";
  const open = cmds.find((m) => m.status === "queued" || m.status === "delivered");
  if (open) return h("div", { class: "appr-st" }, h("span", { class: "pulse" }), `${open.author} asked to ${open.command}; ${open.status === "queued" ? "waiting for the server…" : "the server is starting it…"}`);
  const last = cmds[cmds.length - 1];
  const lastNote = last ? h("div", { class: "small " + (last.status === "done" ? "muted" : "c-red") },
    `${last.author}: ${last.command}${last.status === "done" ? "" : " " + last.status} ${ago(last.replied_at || last.created_at)}`, last.reply ? " — " + last.reply : "") : null;
  const prog = baselineText(st);
  if (st.phase === "learning" && (prog || !modelSet(st))) {
    const next = modelSet(st) ? "The learning session follows, with " + learnerModel(st) + "." : modelOnItsWay(st) ? "The hub's model is on its way to the server." : "The learning session waits for a model.";
    return h("div", { class: "stack" }, h("div", { class: "appr-st" }, h("span", { class: "pulse" }), (prog ? "Collecting the baseline: " + prog + ". " : "Collecting the baseline. ") + next), lastNote);
  }
  if (st.learning || st.phase === "learning") return h("div", { class: "stack" }, h("div", { class: "appr-st" }, h("span", { class: "pulse" }), "Learning now: the board shows the learning run."), lastNote);
  if (!st.accepts_learning) {
    return h("div", { class: "appr-cli" }, lastNote, h("span", { class: "faint small" }, "This server starts learning on its CLI only (older kodeblue, or hub.accept_learning = false):"),
      h("code", { class: "copyable" }, "kodeblue relearn && systemctl restart kodeblue"));
  }
  const go = async (mode, btn) => {
    const ok = mode === "learn"
      ? await ask("Run the learner on " + srv.name + "?", [
        h("p", null, "The learner agent reviews the baseline kodeblue already has and writes or updates the server profile, definitions, monitors and skills. Detection keeps running."),
        h("p", { class: "muted small" }, "It uses the learner model (" + ((st.models || {}).learner || st.agent_model || "?") + ") and counts against the server's daily budget.")], "Run learner")
      : await ask("Relearn " + srv.name + "?", [
        h("p", null, "kodeblue collects the baseline again and treats everything the server runs during that window as normal, then runs the learner (if models are on)."),
        h("p", null, h("b", null, "Do this after planned changes, not while you suspect a compromise:"), " anything malicious running now would be learned as normal."),
        h("p", { class: "muted small" }, "The run is announced through configured notification destinations.")], "Relearn", true);
    if (!ok) return;
    btn.disabled = true;
    try {
      await api("POST", `/api/servers/${enc(srv.id)}/learn`, { mode });
      toast(mode === "learn" ? "Learner requested on " + srv.name : "Relearn requested on " + srv.name);
      if (after) after();
    } catch (e) {
      btn.disabled = false;
      toast("Not sent: " + e.message, true);
    }
  };
  const learn = h("button", { class: "btn small", type: "button", disabled: !st.models_enabled, title: st.models_enabled ? "Run the learner agent on the current baseline" : "The learner needs models: pick them in Settings" }, ic("bot", 12), "Run learner");
  const relearn = h("button", { class: "btn small", type: "button", title: "Collect the baseline again, then run the learner" }, ic("refresh", 12), "Relearn");
  learn.addEventListener("click", () => go("learn", learn));
  relearn.addEventListener("click", () => go("relearn", relearn));
  return h("div", { class: "appr-act" }, lastNote, h("div", { class: "btns" }, learn, relearn));
}

// ---------- upgrades ----------
// Upgrades are always started by an operator: one click per server (or
// Update all, which confirms the list first). The hub names its own version;
// the server downloads that release itself, checks it against the release's
// SHA256SUMS and installs it once no learning or agent session runs.
const hubVersion = () => (S.info && S.info.version) || "";
const relVer = (v) => { const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(v || "")); return m ? m.slice(1).map(Number) : null; };
function newerVer(a, b) {
  const x = relVer(a), y = relVer(b);
  if (!x || !y || !/^v\d+\.\d+\.\d+$/.test(a)) return false;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i];
  return false;
}
function updateAvailable(srv) {
  const st = srv.status || {};
  const up = st.upgrade;
  return srv.enrolled && !srv.revoked && newerVer(hubVersion(), st.version || srv.version) && !(up && up.to === hubVersion() && (up.state === "waiting" || up.state === "installing"));
}
// Hub upgrades arrived in v0.1.7: an older server upgrades with the install command.
const hubUpgrades = (srv) => !!(srv.status || {}).accepts_upgrades;
async function requestUpgrade(srv) {
  try {
    await api("POST", `/api/servers/${enc(srv.id)}/upgrade`, {});
    return null;
  } catch (e) { return e.message; }
}
const upgradeSteps = () => [
  h("p", null, "Each server downloads kodeblue " + hubVersion() + " from its release URL (GitHub unless its config says otherwise), checks it against the release's SHA256SUMS, and installs it once no learning or agent session runs on it."),
  h("p", null, "The install keeps the server's config, keys and state, opens a 10-minute maintenance window for the binary swap, and restarts kodeblue. Detection pauses for the few seconds of the restart."),
  h("p", { class: "muted small" }, "Logged in the audit log; on the server: journalctl -u kodeblue-upgrade.")];
function upgradeControls(srv, cmds, after) {
  const st = srv.status || {};
  const cur = st.version || srv.version || "";
  const hv = hubVersion();
  if (!srv.enrolled || srv.revoked || !st.phase) return cur || "—";
  const ver = h("span", { class: "mono" }, cur || "—");
  const open = cmds.find((m) => m.status === "queued" || m.status === "delivered");
  if (open) return h("div", { class: "stack" }, ver, h("div", { class: "appr-st" }, h("span", { class: "pulse" }), `${open.author} asked to upgrade to ${open.body}; ${open.status === "queued" ? "waiting for the server…" : "the server is taking it…"}`));
  const up = st.upgrade;
  const last = cmds[cmds.length - 1];
  let note = null;
  if (up && up.state === "waiting") note = h("div", { class: "appr-st" }, h("span", { class: "pulse" }), `Upgrade to ${up.to} asked by ${String(up.by || "").replace(/^hub:/, "")}: ${up.detail || "starting…"}`);
  else if (up && up.state === "installing") note = h("div", { class: "appr-st" }, h("span", { class: "pulse" }), `Installing ${up.to}: ${up.detail || "…"}`);
  else if (last && last.status !== "done" && (!up || new Date(last.created_at) > new Date(up.at))) note = h("div", { class: "small c-red" }, `${last.author}: upgrade ${last.status} ${ago(last.replied_at || last.created_at)}`, last.reply ? " — " + last.reply : "");
  else if (up && up.state === "failed") note = h("div", { class: "small c-red" }, `Upgrade to ${up.to} failed ${ago(up.at)}: ${up.detail || "no detail"}`);
  else if (up && up.state === "done" && up.to === cur) note = h("div", { class: "small muted" }, `Upgraded from ${up.from || "?"} ${ago(up.at)} (${String(up.by || "").replace(/^hub:/, "")})`);
  const busy = up && (up.state === "waiting" || up.state === "installing");
  if (busy || !newerVer(hv, cur)) return h("div", { class: "stack" }, ver, note, !busy && relVer(hv) && !newerVer(hv, cur) ? h("span", { class: "faint small" }, "Up to date with the hub (" + hv + ").") : null);
  if (!hubUpgrades(srv)) {
    const cli = newerVer("v0.1.7", cur) ? "Rerun the install command without --token (Install command above shows it)." : "sudo kodeblue upgrade " + hv;
    return h("div", { class: "appr-cli" }, ver, note, h("span", { class: "faint small" }, `The hub runs ${hv}. This server upgrades on the server only (kodeblue before v0.1.7, or hub.accept_upgrades = false):`),
      h("code", { class: "copyable" }, cli));
  }
  const btn = h("button", { class: "btn small", type: "button", title: "Upgrade kodeblue on this server to " + hv }, ic("refresh", 12), "Update to " + hv);
  btn.addEventListener("click", async () => {
    if (!await ask(`Update ${srv.name} to ${hv}?`, [h("p", null, `${srv.name} runs ${cur}.`), ...upgradeSteps()], "Update")) return;
    btn.disabled = true;
    const err = await requestUpgrade(srv);
    if (err) { btn.disabled = false; toast("Not sent: " + err, true); return; }
    toast("Update requested on " + srv.name);
    if (after) after();
  });
  return h("div", { class: "appr-act" }, ver, note, h("div", { class: "btns" }, btn));
}
async function updateAll(servers, after) {
  const hv = hubVersion();
  if (!await ask(`Update ${servers.length} server${servers.length > 1 ? "s" : ""} to ${hv}?`, [
    h("ul", null, servers.map((s) => h("li", null, `${s.name}: ${(s.status || {}).version || s.version}`))), ...upgradeSteps()], "Update all")) return;
  const failed = [];
  for (const s of servers) { const err = await requestUpgrade(s); if (err) failed.push(s.name + ": " + err); }
  if (failed.length) toast("Not sent to " + failed.join("; "), true);
  else toast(`Update requested on ${servers.length} server${servers.length > 1 ? "s" : ""}`);
  if (after) after();
}

// ---------- containment approvals ----------
function acceptsApprovals(srvId) {
  const s = S.servers.find((x) => x.id === srvId);
  return !!(s && s.enrolled && !s.revoked && (s.status || {}).accepts_approvals);
}
const actTarget = (a) => Object.entries(a.params || {}).map(([k, v]) => k + "=" + v).join(" ");
// approvalControls: Approve/Deny for one pending request, its in-flight
// ruling, or (for servers that keep approval local) the CLI commands.
function approvalControls(srvId, a, decs, after) {
  const open = (decs || []).find((m) => m.request_id === a.id && decOpen(m));
  if (open) return h("div", { class: "appr-st" }, h("span", { class: "pulse" }), `${open.author} sent ${open.decision}; ${open.status === "queued" ? "waiting for the server…" : "the server is handling it…"}`);
  const last = (decs || []).filter((m) => m.request_id === a.id).pop();
  const lastNote = last && (last.status === "failed" || last.status === "refused") ? h("div", { class: "small c-red" }, `${last.decision} ${last.status}: ${last.reply || ""}`) : null;
  if (!acceptsApprovals(srvId)) {
    return h("div", { class: "appr-cli" }, lastNote, h("span", { class: "faint small" }, "This server takes approvals on its CLI only:"),
      h("code", { class: "copyable" }, `kodeblue respond approve ${a.id}`), h("code", { class: "copyable" }, `kodeblue respond deny ${a.id}`));
  }
  const go = async (decision, btn) => {
    const name = serverName(srvId);
    const ok = await ask(decision === "approve" ? "Approve containment?" : "Deny containment?",
      [h("p", null, decision === "approve" ? `kodeblue on ${name} will run ` : `kodeblue on ${name} will drop the request for `, h("b", null, a.action),
        actTarget(a) ? [" on ", h("code", null, actTarget(a))] : null, decision === "approve" ? ", through its root helper and under the server's own response policy." : ". Nothing on the host changes."),
      a.justification ? h("p", { class: "muted small" }, "Agent's reason: " + a.justification) : null],
      decision === "approve" ? "Approve and run" : "Deny", decision === "approve");
    if (!ok) return;
    btn.disabled = true;
    try {
      await api("POST", `/api/servers/${enc(srvId)}/actions/${enc(a.id)}/decision`, { decision });
      toast(decision === "approve" ? `Approved ${a.action}; sent to ${name}` : `Denied ${a.action}`);
      if (after) after();
    } catch (e) {
      btn.disabled = false;
      toast("Not sent: " + e.message, true);
    }
  };
  const yes = h("button", { class: "btn small primary", type: "button" }, ic("check", 12), "Approve");
  const no = h("button", { class: "btn small", type: "button" }, ic("ban", 12), "Deny");
  yes.addEventListener("click", () => go("approve", yes));
  no.addEventListener("click", () => go("deny", no));
  return h("div", { class: "appr-act" }, lastNote, h("div", { class: "btns" }, yes, no));
}
// Rulings on their way to the server, and rulings it carried out (the
// request leaves the pending list on the server's next sync; it is settled now).
// A ruling delivered 5 minutes ago without a reply is lost (the hub takes a
// new one then, see DecisionReplyWait).
const decOpen = (m) => m.status === "queued" || (m.status === "delivered" && Date.now() - (validTime(m.delivered_at) || 0) < 300000);
const decidedDone = (m) => !!m && m.decision && m.status === "done";
async function approveAll(srvId, list, after, btn) {
  const name = serverName(srvId);
  btn.disabled = true;
  try { await approveAllRun(srvId, list, after, name); } finally { btn.disabled = false; }
}
async function approveAllRun(srvId, list, after, name) {
  const ok = await ask(`Approve all ${list.length} containment actions?`,
    [h("p", null, `kodeblue on ${name} will run these through its root helper, under the server's own response policy:`),
      h("ul", { class: "appr-list" }, list.map((a) => h("li", null, h("b", null, a.action), actTarget(a) ? [" ", h("code", null, actTarget(a))] : null)))],
    `Approve and run ${list.length}`, true);
  if (!ok) return;
  const res = await Promise.allSettled(list.map((a) => api("POST", `/api/servers/${enc(srvId)}/actions/${enc(a.id)}/decision`, { decision: "approve" })));
  const bad = res.filter((r) => r.status === "rejected");
  if (bad.length) toast(`${list.length - bad.length} of ${list.length} sent; not sent: ${bad[0].reason.message}`, true);
  else toast(`Approved ${list.length} actions; sent to ${name}`);
  if (after) after();
}
function paintApprovals() {
  const st = P.st;
  const decs = st.decs || [];
  const list = (st.pend || []).filter((a) => !decidedDone(decs.filter((m) => m.request_id === a.id).pop()));
  const foldKey = `kb.apprFold:${st.srv}:${st.id}`;
  // A fold remembers the requests it hid: a new request opens it again.
  const folded = (store(foldKey) || "").split(",").filter(Boolean);
  const fold = list.length > 0 && list.every((a) => folded.includes(a.id));
  const sig = JSON.stringify([list.map((a) => a.id), decs.map((m) => [m.id, m.status]), acceptsApprovals(st.srv), fold]);
  if (st.apprSig === sig) return;
  st.apprSig = sig;
  P.appr.hidden = !list.length;
  P.appr.classList.toggle("fold", fold);
  clear(P.appr);
  if (!list.length) return;
  const after = () => { st.apprSig = ""; st.chatSig = ""; panelRefresh(false, true); if (S.timerFn) S.timerFn(); };
  const toggle = () => { store(foldKey, fold ? "" : list.map((a) => a.id).join(",")); st.apprSig = ""; paintApprovals(); };
  const open = list.filter((a) => !decs.some((m) => m.request_id === a.id && decOpen(m)));
  const all = acceptsApprovals(st.srv) && open.length > 1
    ? h("button", { class: "btn small primary", type: "button", on: { click: (e) => { e.stopPropagation(); approveAll(st.srv, open, after, e.currentTarget); } } }, ic("check", 12), `Approve all (${open.length})`)
    : null;
  const sent = list.length - open.length;
  add(P.appr, [h("div", { class: "appr-hd", role: "button", tabindex: "0", "aria-expanded": String(!fold), title: fold ? "Show the requests" : "Hide the requests",
    on: { click: toggle, keydown: (e) => { if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggle(); } } } },
    ic(fold ? "chevRight" : "chevDown", 13), ic("shield", 13), h("span", null, `Waiting for your approval (${list.length})`),
    sent ? h("span", { class: "appr-st" }, h("span", { class: "pulse" }), `${sent} on the way to the server`) : null,
    h("div", { class: "sp" }),
    fold ? null : h("span", { class: "faint small appr-sub" }, "the agent asked for this under the server's recommend policy"), all),
  fold ? null : list.map((a) => h("div", { class: "appr-i" },
    h("div", { class: "appr-l" }, h("div", null, h("span", { class: "badge b-warn" }, a.action), " ", h("code", { class: "atgt" }, actTarget(a))),
      a.justification ? h("div", { class: "small muted appr-why", title: "Show all", on: { click: (e) => e.currentTarget.classList.toggle("open") } }, a.justification) : null),
    approvalControls(st.srv, a, decs, after)))]);
}

function noteEvent(n) {
  const bad = n.status === "failed";
  return h("div", { class: "turn" }, h("div", { class: "sysev" + (bad ? " bad" : "") }, ic("bell", 12),
    h("span", null, n.status === "skipped" ? "Not posted (skipped)" : n.status === "pending" ? "Delivering notification…" : bad ? "Notification delivery failed" : "Notification delivered"),
    h("span", { class: "sep" }, "·"), h("span", { class: "sev-" + (SEV.includes(n.severity) ? n.severity : "info") }, n.severity || "info"),
    h("span", { class: "sep" }, "·"), h("span", { class: "sev-title" }, n.title || n.kind || "notification"),
    bad && n.error ? h("span", { class: "err" }, "(" + n.error + ")") : null,
    h("span", { class: "ut" }, clock(n.at))));
}
function opBubble(author, body, at, ctx) {
  return h("div", { class: "turn" }, h("div", { class: "ubox" },
    h("div", { class: "ulbl" }, h("span", { class: "c-green" }, ">"), h("span", null, author || "operator"), at ? h("span", { class: "ut" }, clock(at)) : null),
    h("div", { class: "utext" }, body)));
}
function briefBubble(text, key, label, at) {
  const long = (text || "").split("\n").length > 8 || (text || "").length > 700;
  const open = S.open.has(key + ":b");
  const body = h("div", { class: "utext" + (long && !open ? " clip" : "") }, text);
  const tog = long ? h("button", { class: "more", type: "button", on: { click: () => { if (S.open.has(key + ":b")) S.open.delete(key + ":b"); else S.open.add(key + ":b"); body.classList.toggle("clip"); tog.textContent = body.classList.contains("clip") ? "show full brief" : "show less"; } } },
    open ? "show less" : "show full brief") : null;
  return h("div", { class: "turn" }, h("div", { class: "ubox brief" },
    h("div", { class: "ulbl" }, h("span", { class: "c-blue" }, ">"), h("span", null, label), at ? h("span", { class: "ut" }, clock(at)) : null), body, tog));
}
function msgState(m) {
  if (m.status === "failed" || m.status === "refused") {
    return h("div", { class: "turn" }, h("div", { class: "sys bad" }, "[" + m.status + "] ", m.reply || (m.status === "refused" ? "the server refused the message" : "the agent could not answer")));
  }
  return null;
}
// workingStoppable is the live indicator plus a Stop button that aborts the
// running session (operator safety brake). It stays "stopping…" across
// redraws until the session ends.
function workingStoppable(sess, inc, srvId, text) {
  const sid = (sess && sess.id) || inc.session_id;
  const canStop = srvId && sid && S.me;
  const asked = canStop && S.stopping.has(sid);
  const stop = canStop ? h("button", { class: "btn danger small", disabled: asked, on: { click: async (e) => {
    const b = e.currentTarget; b.disabled = true; b.textContent = "stopping…";
    S.stopping.add(sid);
    try { await api("POST", `/api/servers/${enc(srvId)}/stop-session`, { session_id: sid, incident_id: inc.id }); }
    catch (err) { S.stopping.delete(sid); b.disabled = false; b.textContent = "Stop"; toast((err && err.message) || "stop failed", true); }
  } } }, asked ? "stopping…" : "Stop") : null;
  return h("div", { class: "turn" }, h("div", { class: "working" }, h("span", { class: "dots" }, "..."), h("span", null, text), h("span", { class: "cursor" }), stop));
}

function working(text) {
  return h("div", { class: "turn" }, h("div", { class: "working" }, h("span", { class: "dots" }, "..."), h("span", null, text), h("span", { class: "cursor" })));
}
function agentTurn(tu, key) {
  const parts = [];
  if (tu.reasoning) {
    const open = S.open.has(key + ":r");
    const body = h("div", { class: "think-bd" }, tu.reasoning);
    const preview = h("span", { class: "think-pv" }, tu.reasoning.replace(/\s+/g, " ").slice(0, 140));
    const box = h("div", { class: "think" + (open ? " open" : "") },
      h("button", { class: "think-hd", type: "button", "aria-expanded": String(open), on: { click: () => {
        const o = !box.classList.contains("open");
        box.classList.toggle("open", o);
        box.firstChild.setAttribute("aria-expanded", String(o));
        if (o) S.open.add(key + ":r"); else S.open.delete(key + ":r");
      } } }, ic("terminal", 12), h("span", { class: "think-l" }, "Thinking"), preview, ic("chevRight", 13, "chev")), body);
    parts.push(box);
  }
  if (tu.text) parts.push(md(tu.text, "agent"));
  for (const [j, x] of (tu.tools || []).entries()) parts.push(toolCall(x, key + ":t" + j));
  parts.push(h("div", { class: "tmeta" }, clock(tu.at), tu.cost_usd ? " · " + usd(tu.cost_usd) : ""));
  return h("div", { class: "turn" }, parts);
}
function argSummary(name, args) {
  let a = args;
  try { a = typeof args === "string" ? JSON.parse(args) : args; } catch { return String(args || ""); }
  if (!a || typeof a !== "object") return String(a || "");
  for (const k of ["command", "cmd", "path", "query", "pattern", "url", "name", "id", "title", "unit"]) if (a[k] !== undefined && typeof a[k] !== "object") return String(a[k]);
  const first = Object.values(a).find((v) => typeof v === "string");
  return first || (Object.keys(a).length ? JSON.stringify(a) : "");
}
function toolCall(x, key) {
  const open = S.open.has(key);
  const state = x.is_error ? "err" : x.result ? "ok" : "run";
  const body = h("div", { class: "tool-bd" },
    h("div", { class: "tlbl" }, "args:"), h("pre", null, prettyJSON(x.args || "{}")),
    x.result ? [h("div", { class: "tlbl" }, "result:"), h("pre", { class: x.is_error ? "err" : "" }, x.result)] : h("div", { class: "muted" }, "No result yet."));
  const name = String(x.name || "tool").replace(/^mcp__kodeblue__/, "");
  const box = h("div", { class: "tool t-" + state + (open ? " open" : "") },
    h("button", { class: "tool-hd", type: "button", on: { click: () => {
      const o = !box.classList.contains("open");
      box.classList.toggle("open", o);
      if (o) S.open.add(key); else S.open.delete(key);
    } } }, ic("chevRight", 12, "chev"), ic(/exec|shell|bash|command/.test(name) ? "terminal" : "wrench", 12, "c-cyan"),
      h("span", { class: "tname" }, name), h("span", { class: "targ" }, argSummary(name, x.args)),
      h("span", { class: "tst" }, state === "ok" ? "✓" : state === "err" ? "✗" : "running...")), body);
  return box;
}

async function paintExt() {
  const st = P.st;
  if (!P.el || !P.ext || st.isNew || st.placeholder || !st.inc) return;
  const inc = st.inc;
  const key = P.key;
  let node;
  const title = { overview: "Overview", findings: "Findings", containment: "Containment", details: "Details" }[P.ext];
  if (P.ext === "overview") {
    const sig = JSON.stringify([inc.summary, inc.self_eval, inc.report, inc.status]);
    if (st.extSig === "o" + sig) return;
    st.extSig = "o" + sig;
    node = [
      inc.status === "needs_human" && inc.kind === "coverage" ? h("div", { class: "callout" }, h("div", { class: "lbl" }, "Coverage gap"),
        "kodeblue cannot monitor this service well enough. The report says which checks are missing and why. Create the monitors (Relearn, or ask the agent in the chat) or change how kodeblue runs; the case resolves by itself once they are covered.") :
      inc.status === "needs_human" ? h("div", { class: "callout" }, h("div", { class: "lbl" }, "Needs a human"),
        "The agent could not close this on its own. Review the report, then message the agent in the chat, approve or deny any containment it asked for, or act on the server (",
        h("code", null, "kodeblue ack <finding>"), ").") : null,
      inc.summary ? h("div", { class: "xsec" }, h("h4", null, "summary"), md(inc.summary)) : null,
      inc.self_eval ? h("div", { class: "callout eval" }, h("div", { class: "lbl" }, inc.kind === "review" ? "Reviewer self-evaluation" : "Agent self-evaluation"), md(inc.self_eval)) : null,
      inc.report ? h("div", { class: "xsec" }, h("h4", null, "report"), md(inc.report)) : null,
      !inc.summary && !inc.report && !inc.self_eval ? h("div", { class: "empty" }, inc.status === "investigating" ? "The agent writes its summary, report and self-evaluation when it finishes." : "No report for this case.") : null];
  } else if (P.ext === "findings" || P.ext === "containment") {
    const q = "?limit=50&q=" + enc(`"incident_id":${inc.id},`);
    let data;
    try {
      data = P.ext === "findings" ? [await recs(st.srv, "finding", q)] : await Promise.all([recs(st.srv, "action", q), recs(st.srv, "pending_action", q)]);
    } catch { return; }
    if (P.key !== key) return;
    const sig = P.ext + JSON.stringify(data) + JSON.stringify((st.decs || []).map((m) => [m.id, m.status]));
    if (st.extSig === sig) return;
    st.extSig = sig;
    if (P.ext === "findings") {
      const fl = data[0].map(parse).filter((f) => f.incident_id === inc.id);
      node = fl.length ? findingTable(fl, true) : h("div", { class: "empty" }, "No findings are attached to this case.");
    } else {
      const al = data[0].map(parse).filter((a) => a.incident_id === inc.id);
      const pl = data[1].map(parse).filter((a) => a.incident_id === inc.id);
      node = [pl.length ? h("div", { class: "xsec" }, h("h4", null, `waiting for approval (${pl.length})`),
        h("div", { class: "note mb" }, "An agent asked for these under the server's recommend policy. Approving runs the action on the server, under its own policy."),
        actionCards(pl, true, st.srv, st.decs, () => { st.extSig = ""; st.apprSig = ""; panelRefresh(false, true); })) : null,
      h("div", { class: "xsec" }, h("h4", null, "actions taken"), al.length ? actionCards(al) : h("div", { class: "empty" }, "No containment actions for this case."))];
    }
  } else {
    const sess = st.sess;
    const turns = (sess && sess.turns) || [];
    const tools = turns.reduce((a, t) => a + (t.tools || []).length, 0);
    const sig = JSON.stringify([inc, turns.length, tools, sess && sess.running]);
    if (st.extSig === "d" + sig) return;
    st.extSig = "d" + sig;
    node = h("dl", { class: "kv" },
      h("dt", null, "server"), h("dd", null, h("a", { href: "#/s/" + enc(st.srv) + "/overview" }, serverName(st.srv))),
      h("dt", null, "kind"), h("dd", null, inc.kind),
      h("dt", null, "status"), h("dd", null, statusBadge(inc.status)),
      h("dt", null, "severity"), h("dd", null, sevBadge(inc.severity)),
      h("dt", null, "verdict"), h("dd", null, verdictBadge(inc.verdict) || "—"),
      h("dt", null, "cost"), h("dd", null, usd(inc.cost_usd)),
      h("dt", null, "opened"), h("dd", null, when(inc.created_at)),
      h("dt", null, "updated"), h("dd", null, when(inc.updated_at)),
      h("dt", null, "session"), h("dd", { class: "mono" }, inc.session_id || "—", sess && sess.running ? h("span", { class: "badge b-accent" }, "live") : null),
      h("dt", null, "run"), h("dd", { class: "mono" }, inc.run_id || "—"),
      h("dt", null, "turns"), h("dd", null, turns.length + " turns · " + tools + " tool calls"),
      h("dt", null, "messages"), h("dd", null, String((st.own || []).length)));
  }
  clear(P.extEl).append(h("div", { class: "ext-hd" }, h("span", { class: "tt" }, title), h("div", { class: "sp" }),
    h("button", { class: "ibtn", type: "button", "aria-label": "Close", on: { click: () => { P.ext = null; store("kb.ext", "none"); paintRail(); } } }, ic("x", 13))),
  h("div", { class: "ext-bd" }, node));
}

// ---------- dialogs ----------
function modal(title, bodyKids, footKids, onClose) {
  const close = () => {
    if (!scrim.isConnected) return;
    scrim.remove();
    document.removeEventListener("keydown", onKey);
    if (onClose) onClose();
  };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const scrim = h("div", { class: "scrim", on: { click: (e) => { if (e.target === scrim) close(); } } },
    h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title },
      h("div", { class: "hd" }, h("h2", null, title), h("button", { class: "ibtn", type: "button", "aria-label": "Close", on: { click: close } }, ic("x", 14))),
      h("div", { class: "bd" }, bodyKids),
      h("div", { class: "ft" }, footKids, h("button", { class: "btn", type: "button", on: { click: close } }, "Close"))));
  document.body.appendChild(scrim);
  document.addEventListener("keydown", onKey);
  scrim.close = close;
  return scrim;
}
// ask shows an in-page confirmation and resolves true/false.
function ask(title, text, okLabel, danger) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const ok = h("button", { class: "btn " + (danger ? "danger solid" : "primary"), type: "button", on: { click: () => { finish(true); m.close(); } } }, okLabel);
    const m = modal(title, [h("div", null, text)], [ok], () => finish(false));
    ok.focus();
  });
}
function installView(res) {
  const cmd = h("div", { class: "cmd" }, res.install_command);
  return [
    h("div", { class: "note" }, "Run this on the server, as root or as a user with sudo (Ubuntu/Debian/RHEL with systemd, amd64 or arm64):"),
    cmd,
    h("div", { class: "btns" }, h("button", { class: "btn small", type: "button", on: { click: async () => { try { await navigator.clipboard.writeText(res.install_command); toast("Copied"); } catch { toast("Copy failed; select the command and copy it", true); } } } }, ic("copy", 12), "Copy command")),
    h("div", { class: "note" }, h("ul", null,
      h("li", null, "The token is single-use and expires ", when(res.expires), ". The server trades it for its own API key, so the token is worthless afterwards."),
      h("li", null, "The server only connects out to this hub. Nothing on the server listens for the hub."),
      h("li", null, S.info && S.info.fleet_model ? "The fleet's default model (" + S.info.fleet_model + ") and its key are handed over at enrollment; the per-agent models follow on the first sync." : "No default model is picked on the hub yet, so the installer asks for an endpoint. Add a model connection and pick a default model under Settings to skip that. Without a model the server still watches, but its learning waits until you add one."),
      h("li", null, "Containment starts in recommend mode: agents ask, and an operator approves here or on the server."))),
  ];
}
function addServerDialog() {
  const name = h("input", { type: "text", placeholder: "e.g. web-1 (prod)", class: "full", maxlength: 80 });
  const contain = h("input", { type: "checkbox" });
  const area = h("div", { class: "stack" }, h("label", { class: "field" }, "Server name", name),
    h("label", { class: "chk" }, contain, h("span", null, "Let the hub switch this server to Contain ",
      h("span", { class: "faint small block" }, "Adds --hub-max-mode contain: from Settings, an operator can then turn on containment actions that run without approval. The server starts in recommend mode either way."))));
  const go = h("button", { class: "btn primary", type: "button", on: { click: async () => {
    if (!name.value.trim()) { name.focus(); return; }
    go.disabled = true;
    try {
      const r = await api("POST", "/api/servers", { name: name.value, hub_contain: contain.checked });
      clear(area); add(area, installView(r));
      go.remove();
      S.serversAt = 0;
    } catch (e) { toast(e.message, true); go.disabled = false; }
  } } }, "Create install command");
  name.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });
  modal("Add a server", [area], [go], () => { S.viewKey = ""; route(); });
  name.focus();
}
async function reinstall(srv) {
  if (srv.enrolled && !(await ask("New install token", "Create a new one-time install token for " + srv.name + "? When it is used, the server's current key stops working (use it to reinstall or rotate the key).", "Create token"))) return;
  try { const r = await api("POST", `/api/servers/${enc(srv.id)}/enroll-token`, {}); modal("Install / re-enroll " + srv.name, installView(r), [], () => { S.viewKey = ""; route(); }); }
  catch (e) { toast(e.message, true); }
}
async function revoke(srv) {
  if (!(await ask("Revoke key", "Revoke " + srv.name + "'s key? It stops reporting to the hub until it is re-enrolled. Monitoring on the server keeps running.", "Revoke", true))) return;
  try { await api("POST", `/api/servers/${enc(srv.id)}/revoke`, {}); S.serversAt = 0; S.viewKey = ""; route(); } catch (e) { toast(e.message, true); }
}
async function del(srv) {
  if (!(await ask("Delete server", "Delete " + srv.name + " and everything the hub stored for it? This cannot be undone. kodeblue on the server is not uninstalled; its key stops working.", "Delete", true))) return;
  try { await api("DELETE", `/api/servers/${enc(srv.id)}`); S.serversAt = 0; location.hash = "#/"; } catch (e) { toast(e.message, true); }
}

// ---------- page helpers ----------
function panel(title, bd, extra, color) {
  return h("section", { class: "panel" }, h("div", { class: "hd" }, h("span", { class: "cdot c-" + (color || "blue") }), h("h2", null, title), extra || null), bd);
}
function stat(k, v, s, color) { return h("div", { class: "panel stat" }, h("div", { class: "k" }, k), h("div", { class: "v" + (color ? " c-" + color : "") }, String(v)), h("div", { class: "s" }, s)); }
function sync(target, node) { clear(target); target.appendChild(node); }
// unchanged reports whether a view's data is identical to its last render, so
// auto-refresh never rebuilds the page under the operator's cursor for nothing.
function unchanged(body, key, data) {
  const sig = key + "|" + JSON.stringify(data);
  if (body.dataset.sig === sig && body.firstChild) return true;
  body.dataset.sig = sig;
  return false;
}

// ---------- fleet (servers) ----------
async function vFleet(main) {
  const body = h("div", { class: "stack" }, h("div", { class: "empty" }, "Loading…"));
  const fq = h("input", { type: "search", placeholder: "Search servers…", "aria-label": "Search servers", autocomplete: "off", spellcheck: "false", value: S.cache.fleetQ || "" });
  const filter = () => {
    const q = (S.cache.fleetQ || "").trim().toLowerCase();
    let n = 0;
    body.querySelectorAll("tr[data-q]").forEach((tr) => { tr.hidden = !!q && !tr.dataset.q.includes(q); if (!tr.hidden) n++; });
    const none = body.querySelector(".fnone");
    if (none) none.hidden = n > 0 || !q;
  };
  fq.addEventListener("input", () => { S.cache.fleetQ = fq.value; filter(); });
  main.append(h("div", { class: "toolbar" }, h("h1", null, "Servers"), h("div", { class: "fsearch" }, ic("search", 14, "c-muted"), fq), h("div", { class: "sp" }),
    h("button", { class: "btn primary", type: "button", on: { click: addServerDialog } }, ic("plus", 14), "Add server")), body);
  const draw = async () => {
    let fleet;
    try { fleet = await loadServers(true); } catch { return; }
    if (unchanged(body, "fleet", fleet)) return;
    clear(body);
    const online = fleet.filter((s) => s.online).length;
    let open = 0, human = 0, spend = 0, live = 0;
    for (const s of fleet) {
      for (const n of Object.values(s.counts.open_incidents || {})) open += n;
      human += s.counts.needs_human + s.counts.needs_ack + s.counts.pending_actions;
      live += s.counts.investigating;
      spend += (s.status && s.status.spend_today_usd) || 0;
    }
    body.appendChild(h("div", { class: "grid g4" },
      stat("Servers online", `${online} / ${fleet.length}`, !fleet.length ? "none added yet" : fleet.length - online ? `${fleet.length - online} offline or not enrolled` : "all reporting", "green"),
      stat("Open incidents", open, live ? `${live} being investigated now` : "none being investigated", "orange"),
      stat("Waiting on a human", human, "verdicts, acks and approvals", "red"),
      stat("Model spend today", usd(spend), "all servers", "blue")));
    if (!fleet.length) {
      body.appendChild(h("div", { class: "panel" }, h("div", { class: "empty" },
        h("h2", null, "No servers yet"),
        h("p", { class: "muted" }, "Add a server to get a one-line install command. The server connects out to this hub with its own key."),
        h("button", { class: "btn primary", type: "button", on: { click: addServerDialog } }, ic("plus", 14), "Add server"))));
      return;
    }
    const outdated = fleet.filter((s) => s.online && updateAvailable(s) && hubUpgrades(s));
    const oldAgents = fleet.filter((s) => s.online && updateAvailable(s) && !hubUpgrades(s));
    if (outdated.length || oldAgents.length) {
      body.appendChild(h("div", { class: "callout" }, h("div", { class: "lbl" }, "kodeblue " + hubVersion() + " is available"),
        outdated.length ? [`${outdated.map((s) => s.name).join(", ")} can be updated from here. `,
          h("button", { class: "btn small", type: "button", on: { click: () => updateAll(outdated, () => { body.dataset.sig = ""; draw(); }) } }, ic("refresh", 12), "Update " + (outdated.length > 1 ? "all " + outdated.length : outdated[0].name))] : null,
        oldAgents.length ? h("div", { class: "faint small" }, `${oldAgents.map((s) => s.name).join(", ")} run${oldAgents.length > 1 ? "" : "s"} a kodeblue before v0.1.7 (or keep${oldAgents.length > 1 ? "" : "s"} upgrades local): upgrade on the server with the install command without --token.`) : null));
    }
    const waiting = fleet.filter((s) => s.enrolled && !s.revoked && learnWaits(s.status || {}) && !modelSet(s.status || {}) && !modelOnItsWay(s.status || {}));
    if (waiting.length) {
      body.appendChild(h("div", { class: "callout warn" }, h("div", { class: "lbl" }, "Learning is waiting for a model"),
        `${waiting.map((s) => s.name).join(", ")} cannot run the learning session or the vulnerability assessment without a model. Detection watches meanwhile. `,
        S.info && S.info.fleet_model
          ? "The hub has a Default model; a server that keeps its own model (accept_settings = false) needs one set on it with sudo kodeblue inference."
          : ["Add a model connection and pick a default model in ", h("a", { href: "#/settings" }, "Settings"), "; learning starts on its own."]));
    }
    const rows = fleet.map((s) => {
      const st = s.status || {};
      const sev = s.counts.open_incidents || {};
      const budget = st.daily_budget_usd || 0;
      const need = s.counts.needs_human + s.counts.needs_ack + s.counts.pending_actions;
      const bar = budget ? h("div", { class: "bar" + (pct(st.spend_today_usd, budget) > 80 ? " hot" : ""), title: pct(st.spend_today_usd, budget) + "% of daily budget" }, h("i")) : null;
      if (bar) bar.firstChild.style.width = pct(st.spend_today_usd, budget) + "%";
      return h("tr", { class: "click", "data-q": [s.name, s.hostname, s.id, s.last_ip, st.os].filter(Boolean).join(" ").toLowerCase(), on: { click: () => (location.hash = "#/s/" + enc(s.id)) } },
        h("td", null, h("div", { class: "srow" },
          h("span", { class: "dot " + (s.online ? "on" : s.enrolled ? "off" : ""), title: s.online ? "online" : s.enrolled ? "offline" : "not enrolled" }),
          h("div", null, h("div", { class: "fg strong" }, s.name), h("div", { class: "faint small" }, s.hostname || (s.enroll_pending ? "waiting for install" : s.revoked ? "key revoked" : "—"))))),
        h("td", null, s.enrolled ? phaseBadge(st.phase) : h("span", { class: "badge" }, s.revoked ? "revoked" : "not enrolled"),
          s.enrolled && baselineText(st) ? h("div", { class: "faint small", title: "baseline " + baselineText(st) }, `baseline ${st.baseline_sweep}/${st.baseline_sweeps}`) : null),
        h("td", null, st.response_mode ? modeBadge(st.response_mode) : "—"),
        h("td", null, h("div", { class: "sev-strip" },
          SEV.filter((k) => sev[k]).map((k) => h("span", { class: "badge b-" + k }, sev[k] + " " + k)),
          s.counts.investigating ? h("span", { class: "badge b-accent" }, h("span", { class: "pulse" }), s.counts.investigating + " live") : null,
          Object.keys(sev).length ? null : h("span", { class: "faint" }, "none"))),
        h("td", null, need ? h("span", { class: "badge b-warn" }, String(need)) : s.counts.rules_waiting ? null : h("span", { class: "faint" }, "0"),
          s.counts.rules_waiting ? h("a", { class: "badge b-warn" + (need ? " ml" : ""), href: `#/s/${enc(s.id)}/autoblock`, title: "auto-block rules waiting for approval", on: { click: (e) => e.stopPropagation() } },
            s.counts.rules_waiting + " auto-block") : null),
        h("td", null, s.counts.monitors, s.counts.failing_monitors ? h("span", { class: "badge b-bad ml" }, s.counts.failing_monitors + " failing") : null),
        h("td", null, h("a", { class: "sev-strip", href: `#/s/${enc(s.id)}/vulnerabilities`, title: "Open the server's vulnerabilities", on: { click: (e) => e.stopPropagation() } },
          VSEV.filter((k) => (s.counts.open_vulnerabilities || {})[k]).map((k) => h("span", { class: "badge b-" + k }, s.counts.open_vulnerabilities[k] + " " + k)),
          openVulns(s.counts) ? null : h("span", { class: "faint" }, s.counts.services ? "none open" : "—"))),
        h("td", null, h("div", { class: "small" }, usd(st.spend_today_usd), budget ? h("span", { class: "faint" }, " / " + usd(budget)) : null), bar),
        h("td", { class: "nowrap muted small" }, s.enrolled ? ago(s.last_seen) : "—"));
    });
    body.appendChild(h("div", { class: "panel" }, h("div", { class: "bd flush tbl-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Server", "Phase", "Policy", "Open incidents", "Needs you", "Monitors", "Vulnerabilities", "Spend today", "Last seen"].map((t) => h("th", null, t)))),
      h("tbody", null, rows))), h("div", { class: "empty fnone", hidden: true }, "No servers match your search.")));
    filter();
  };
  await draw();
  setTimer(draw, 10000);
}

// ----- overview
async function vOverview(srv, body) {
  const st = srv.status || {};
  const [inc, jr, msgs] = await Promise.all([recs(srv.id, "incident", "?limit=60"), recs(srv.id, "journal", "?limit=25"),
    api("GET", `/api/servers/${enc(srv.id)}/messages`).catch(() => [])]);
  const allCmds = (msgs || []).filter((m) => m.command).sort((a, b) => a.id - b.id);
  const cmds = allCmds.filter((m) => m.command === "learn" || m.command === "relearn");
  const upCmds = allCmds.filter((m) => m.command === "upgrade");
  if (unchanged(body, "overview", [srv, inc, jr, allCmds, hubVersion()])) return;
  const incidents = inc.map(parse);
  const open = incidents.filter((i) => i.kind === "incident" && i.status !== "resolved");
  const live = incidents.filter((i) => i.status === "investigating");
  const budget = st.daily_budget_usd || 0;
  const purposes = Object.entries(st.spend_by_purpose || {}).sort((a, b) => b[1] - a[1]);
  const base = Object.entries(st.baseline || {}).sort((a, b) => b[1] - a[1]);
  const node = h("div", { class: "stack" },
    srv.enrolled && !st.phase ? h("div", { class: "callout" }, h("div", { class: "lbl" }, "Not reporting yet"),
      "This server enrolled ", ago(srv.enrolled_at), " but has not sent a report. If kodeblue is running there, check ", h("code", null, "journalctl -u kodeblue"), " for hub errors (network, pin, revoked key).") : null,
    !srv.enrolled && !srv.revoked ? h("div", { class: "callout" }, h("div", { class: "lbl" }, "Not installed yet"),
      "Use ", h("strong", null, "Install command"), " above and run it on the server.") : null,
    h("div", { class: "grid g4" },
      stat("Open incidents", open.length, live.length ? `${live.length} agent session${live.length > 1 ? "s" : ""} running` : "no agent running", "orange"),
      stat("Spend today", usd(st.spend_today_usd), budget ? `${pct(st.spend_today_usd, budget)}% of ${usd(budget)} budget` : "", "blue"),
      stat("Spend 7 days", usd(st.spend_7d_usd), `${(st.tokens_today || 0).toLocaleString()} tokens today`, "purple"),
      stat("Baseline items", base.reduce((a, b) => a + b[1], 0).toLocaleString(), st.learned_at ? "learned " + when(st.learned_at) : "still learning", "green")),
    live.length ? panel("Agents working right now", h("div", { class: "bd flush" }, h("ul", { class: "list-plain" },
      live.map((i) => h("li", null, h("span", { class: "pulse" }), " ",
        h("a", { href: `#/s/${enc(srv.id)}/t/${i.id}` }, `#${i.id} ${i.title}`), " ", h("span", { class: "faint small" }, i.kind))))), null, "orange") : null,
    h("div", { class: "split" },
      h("div", { class: "stack" },
        panel("Server", h("div", { class: "bd" }, h("dl", { class: "kv" },
          h("dt", null, "Phase"), h("dd", null, phaseBadge(st.phase), st.maintenance_until ? h("span", { class: "faint small" }, " until " + when(st.maintenance_until)) : null),
          h("dt", null, "Response"), h("dd", null, st.response_mode || "—"),
          h("dt", null, "Models"), h("dd", null, !st.phase ? "—" : st.models_enabled ? `${st.triage_model} (triage) · ${st.agent_model} (agents)` : "disabled (no inference key, or the agent engine is not running)"),
          h("dt", null, "Heartbeat"), h("dd", null, ago(st.heartbeat)),
          h("dt", null, "Learned"), h("dd", null, when(st.learned_at)),
          h("dt", null, "Learning"), h("dd", null, learningControls(srv, cmds, () => { body.dataset.sig = ""; vOverview(srv, body); })),
          h("dt", null, "kodeblue"), h("dd", null, upgradeControls(srv, upCmds, () => { body.dataset.sig = ""; vOverview(srv, body); })),
          h("dt", null, "Last review"), h("dd", null, when(st.last_review_at)),
          h("dt", null, "Messages"), h("dd", null, !st.phase ? "—" : st.accepts_messages ? "accepted from the hub" : "disabled on the server"),
          h("dt", null, "Kernel"), h("dd", { class: "mono" }, st.kernel || "—")))),
        vulnSummary(srv),
        panel("Model spend today by purpose", h("div", { class: "bd" }, purposes.length ? h("dl", { class: "kv" }, purposes.map(([k, v]) => [h("dt", null, k), h("dd", null, usd(v))])) : h("div", { class: "faint" }, "Nothing spent today.")), null, "purple"),
        panel("What kodeblue learned is normal", h("div", { class: "bd" }, base.length ? h("dl", { class: "kv" }, base.map(([k, v]) => [h("dt", null, k), h("dd", null, v.toLocaleString())])) : h("div", { class: "faint" }, "No baseline yet.")), null, "green")),
      h("div", { class: "stack" },
        panel("Server profile (written by the learning agent)", h("div", { class: "bd" }, st.profile ? md(st.profile) : h("div", { class: "faint" }, "Not written yet. The learner writes it at the end of the learning phase.")), null, "cyan"),
        panel("Open incidents", h("div", { class: "bd flush" }, open.length ? incidentTable(srv, open) : h("div", { class: "empty" }, "No open incidents.")), h("a", { href: "#/s/" + enc(srv.id), class: "small" }, "Board"), "red"),
        panel("Latest activity", h("div", { class: "bd flush" }, journalList(jr.map(parse))), h("a", { href: `#/s/${enc(srv.id)}/activity`, class: "small" }, "All activity"), "yellow"))));
  sync(body, node);
}

// vulnSummary is the Overview's pointer to the Vulnerabilities tab.
function vulnSummary(srv) {
  const c = srv.counts || {}, sw = (srv.status || {}).software || {};
  const ov = c.open_vulnerabilities || {};
  const n = openVulns(c);
  return panel("Vulnerabilities", h("div", { class: "bd stack" },
    h("div", { class: "btns" }, n ? VSEV.filter((k) => ov[k]).map((k) => h("span", { class: "badge b-" + k }, ov[k] + " " + k)) : h("span", { class: "c-green" }, "none open"),
      sw.security_updates ? h("span", { class: "badge b-high" }, sw.security_updates + " security update" + (sw.security_updates > 1 ? "s" : "") + " waiting") : null)),
  h("a", { href: `#/s/${enc(srv.id)}/vulnerabilities`, class: "small" }, "All vulnerabilities"), n ? (worstVuln(c) ? "red" : "orange") : "green");
}

// softwarePanel shows the daily software check: how up to date the server
// is and the new CVEs naming its software. The reviewer confirms each one
// against the installed version; confirmed ones are on the Vulnerabilities tab.
const FEED_SOURCES = { nvd: "NIST NVD", cisa_kev: "CISA known exploited" };
function softwarePanel(srv, sw) {
  if (!sw) return panel("Software and new CVEs", h("div", { class: "bd faint" }, "Not reported yet: the server checks once a day (kodeblue v0.1.5 or newer)."), null, "blue");
  const feed = sw.feed || {};
  const today = new Date().toISOString().slice(0, 10);
  const days = sw.support_ends ? Math.round((Date.parse(sw.support_ends) - Date.now()) / 864e5) : null;
  const support = !sw.support_ends ? "—" : days < 0 ? h("span", { class: "badge b-high" }, "support ended " + sw.support_ends)
    : days < 90 ? h("span", { class: "badge b-medium" }, `ends ${sw.support_ends} (${days} days)`) : `until ${sw.support_ends}`;
  const sources = (feed.sources || []).length ? feed.sources.map((k) => FEED_SOURCES[k] || k).join(" · ") : "off";
  const off = (feed.allowed || []).filter((k) => !(feed.sources || []).includes(k));
  const matches = feed.matches || [];
  const checked = !!sw.checked_at;
  return panel("Software and new CVEs", h("div", { class: "bd stack" },
    h("dl", { class: "kv" },
      checked ? null : [h("dt", null, "Versions"), h("dd", { class: "faint" }, "not checked yet: the server checks at start and then once a day")],
      checked ? h("dt", null, "OS") : null, checked ? h("dd", null, sw.os || "—", " ", h("span", { class: "faint small" }, "support "), support) : null,
      checked ? h("dt", null, "Updates") : null, checked ? h("dd", null, sw.security_updates ? h("span", { class: "badge b-high" }, sw.security_updates + " security") : h("span", { class: "faint" }, "no security updates"),
        " ", h("span", { class: "faint small" }, `${sw.updates || 0} in all`), sw.reboot_required ? h("span", { class: "badge b-medium ml" }, "reboot pending") : null,
        sw.lists_updated ? h("span", { class: "faint small" }, " · lists " + ago(sw.lists_updated)) : null) : null,
      checked ? h("dt", null, "Checked") : null, checked ? h("dd", null, ago(sw.checked_at)) : null,
      h("dt", null, "CVE feed"), h("dd", null, sources, off.length ? h("span", { class: "faint small" }, " (off on the hub: " + off.map((k) => FEED_SOURCES[k] || k).join(", ") + ")") : null,
        feed.last_pull ? h("span", { class: "faint small" }, " · pulled " + ago(feed.last_pull)) : null,
        feed.failures ? h("span", { class: "badge b-warn ml", title: "The server retries with a growing pause; see its journal." }, feed.failures + " failed pulls") : null),
      h("dt", null, "Matches (30 days)"), h("dd", null, String(feed.total || 0), " ", h("span", { class: "faint small" }, "naming software here; the reviewer checks the installed versions"))),
    matches.length ? h("div", { class: "tbl-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["CVE", "Severity", "Matched", "Found"].map((t) => h("th", null, t)))),
      h("tbody", null, matches.slice(0, 10).map((m) => h("tr", null,
        h("td", { class: "nowrap" }, h("a", { href: "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(m.id), target: "_blank", rel: "noopener noreferrer" }, m.id),
          m.kev ? h("span", { class: "badge b-critical ml", title: "CISA lists it as exploited in the wild" }, "exploited") : null),
        h("td", null, m.severity ? h("span", { class: "badge b-" + (VSEV.includes(m.severity) ? m.severity : "low") }, (m.score ? m.score.toFixed(1) + " " : "") + m.severity) : h("span", { class: "faint" }, "—")),
        h("td", null, h("div", { title: m.summary || "" }, m.term), h("div", { class: "faint small" }, m.from)),
        h("td", { class: "nowrap faint small" }, (m.found_at || "").slice(0, 10) === today ? "today" : ago(m.found_at))))))) : null,
    h("div", { class: "faint small" }, "Turn the feed and its sources on or off under ", h("a", { href: `#/s/${enc(srv.id)}/settings` }, "Settings"), " → Vulnerability feed.")), null, "blue");
}

function incidentTable(srv, list) {
  return h("div", { class: "tbl-wrap" }, h("table", null,
    h("thead", null, h("tr", null, ["#", "Case", "Severity", "Status", "Verdict", "Cost", "Opened"].map((t) => h("th", { class: t === "Cost" ? "num" : "" }, t)))),
    h("tbody", null, list.map((i) => h("tr", { class: "click", on: { click: () => (location.hash = `#/s/${enc(srv.id)}/t/${i.id}`) } },
      h("td", { class: "faint" }, i.id),
      h("td", null, h("div", { class: "trunc", title: i.title }, i.status === "investigating" ? h("span", { class: "pulse" }) : null, i.title),
        h("div", { class: "faint small" }, i.kind !== "incident" ? i.kind + " · " : "", ago(i.created_at))),
      h("td", null, sevBadge(i.severity)),
      h("td", null, statusBadge(i.status)),
      h("td", null, verdictBadge(i.verdict)),
      h("td", { class: "num small" }, usd(i.cost_usd)),
      h("td", { class: "nowrap small muted" }, when(i.created_at)))))));
}
function journalList(entries) {
  if (!entries.length) return h("div", { class: "empty" }, "No activity yet.");
  return h("ul", { class: "list-plain" }, entries.map((j) => h("li", { class: "small" },
    h("span", { class: "faint nowrap" }, when(j.at)), " ",
    h("span", { class: "badge" }, j.actor), " ", h("strong", null, j.action), " ", h("span", { class: "muted" }, j.detail))));
}

// ----- findings
function findingTable(list, compact) {
  const cols = compact ? ["#", "Finding", "Status"] : ["#", "Finding", "Sev", "Status", "Triage", "Seen", "When"];
  return h("div", { class: "tbl-wrap" }, h("table", null,
    h("thead", null, h("tr", null, cols.map((t) => h("th", null, t)))),
    h("tbody", null, list.map((f) => {
      const key = "f" + f.id;
      const row = h("tr", { class: "click", on: { click: () => { S.open.has(key) ? S.open.delete(key) : S.open.add(key); ex.hidden = !S.open.has(key); } } },
        h("td", { class: "faint" }, f.id),
        h("td", null, h("div", { class: compact ? "" : "trunc", title: f.title }, f.title), h("div", { class: "faint small mono" }, f.rule, compact ? " · ×" + f.occurrences : "")),
        compact ? null : h("td", null, sevBadge(f.severity)),
        h("td", null, compact ? [sevBadge(f.severity), " "] : null, statusBadge(f.status)),
        compact ? null : h("td", null, verdictBadge(f.verdict), f.verdict_reason ? h("div", { class: "small muted clamp", title: "click the row for the full text" }, f.verdict_reason) : null),
        compact ? null : h("td", { class: "num" }, f.occurrences), compact ? null : h("td", { class: "nowrap small muted" }, ago(f.created_at)));
      const ex = h("tr", { hidden: !S.open.has(key), class: "ex" }, h("td", { colspan: cols.length },
        f.verdict_reason ? h("div", { class: "small mb" }, verdictBadge(f.verdict), " ", f.verdict_reason) : null,
        h("div", { class: "stack" }, f.detail ? h("div", { class: "small" }, f.detail) : null,
          f.item_id ? h("div", { class: "small" }, h("span", { class: "faint" }, "item "), h("code", null, f.item_id)) : null,
          h("pre", { class: "out json" }, prettyJSON(f.evidence || {})),
          f.status === "needs_ack" ? h("div", { class: "small" }, "Acknowledge on the server if legitimate: ", h("code", null, `kodeblue ack ${f.id}`)) : null)));
      return [row, ex];
    }))));
}
async function vFindings(srv, body) {
  const status = S.cache.findStatus || "";
  const q = h("input", { type: "search", placeholder: "Search findings…", value: S.cache.findQ || "" });
  const list = (await recs(srv.id, "finding", "?limit=400" + (S.cache.findQ ? "&q=" + enc(S.cache.findQ) : ""))).map(parse)
    .filter((f) => !status || f.status === status);
  const statuses = ["", "needs_ack", "escalated", "incident", "benign", "digest", "closed", "new"];
  const sel = h("select", { on: { change: () => { S.cache.findStatus = sel.value; vFindings(srv, body); } } },
    statuses.map((s) => h("option", { value: s, selected: s === status }, s ? s.replace(/_/g, " ") : "all statuses")));
  q.addEventListener("keydown", (e) => { if (e.key === "Enter") { S.cache.findQ = q.value; vFindings(srv, body); } });
  const verdicts = {};
  for (const f of list) if (f.verdict) verdicts[f.verdict] = (verdicts[f.verdict] || 0) + 1;
  sync(body, h("div", { class: "stack" },
    h("div", { class: "note" }, "Findings are what the sensors flagged after the deterministic filters. The triage model's verdict and its one-line reasoning are shown for each; benign ones at high confidence were absorbed into the baseline."),
    h("div", { class: "toolbar" }, q, sel, h("div", { class: "sp" }),
      Object.entries(verdicts).map(([k, n]) => h("span", { class: "small muted" }, verdictBadge(k), " ", n))),
    h("div", { class: "panel" }, h("div", { class: "bd flush" }, list.length ? findingTable(list) : h("div", { class: "empty" }, "No findings.")))));
}

// ----- monitors
// ----- containment rules: what kodeblue does on its own, once approved
const RULE_ST = { proposed: "b-warn", active: "b-ok", paused: "", expired: "", rejected: "", deleted: "" };
function ruleStatus(r) {
  if (r.pending_change) return h("span", { class: "badge b-warn", title: "a changed version waits for approval; the approved one keeps acting until then" }, r.status + " · change waiting");
  return h("span", { class: "badge " + (RULE_ST[r.status] || "") }, r.status === "proposed" ? "waiting for approval" : r.status);
}
function ruleSummary(r) {
  const scope = Object.entries(r.scope || {}).map(([k, v]) => (k === "cidr" ? "inside " : "under ") + v).join(", ");
  const verb = { block_ip: "block the address", quarantine_file: "quarantine the file" }[r.action] || r.action;
  const from = r.when && r.when.field ? ` from ${r.when.field}` : "";
  return `On every ${(r.when || {}).rule} finding, ${verb}${from}${scope ? " " + scope : ""}; at most ${r.max_per_hour}/hour, for ${r.days} days after approval.`;
}
async function ruleCommand(srv, r, command, note, after) {
  try {
    await api("POST", `/api/servers/${enc(srv.id)}/rules/${enc(r.id)}`, { command, hash: r.hash, note });
    toast({ rule_approve: "Approval sent", rule_reject: "Rejected", rule_pause: "Pause sent", rule_delete: "Delete sent" }[command] + "; the server applies it within seconds");
    setTimeout(after, 4000);
  } catch (e) { toast(e.message, true); }
}
function ruleNoteDialog(srv, r, command, title, label, placeholder, okLabel, after) {
  const why = h("textarea", { class: "full", rows: 3, placeholder });
  const go = h("button", { class: "btn " + (command === "rule_delete" ? "danger solid" : "primary"), type: "button", on: { click: async () => {
    if (command !== "rule_delete" && !why.value.trim()) { why.focus(); return; }
    m.close();
    await ruleCommand(srv, r, command, why.value, after);
  } } }, okLabel);
  const m = modal(title, [h("div", { class: "stack" }, h("div", { class: "strong" }, r.title), h("label", { class: "field" }, label, why))], [go]);
  why.focus();
}
function ruleDetail(r) {
  const w = r.when || {};
  return h("dl", { class: "kv" },
    h("dt", null, "Answers"), h("dd", null, h("code", null, w.rule)),
    w.field ? [h("dt", null, "Target from"), h("dd", null, h("code", null, w.field))] : null,
    w.extract ? [h("dt", null, "Extracted with"), h("dd", null, h("code", null, w.extract))] : null,
    h("dt", null, "Action"), h("dd", null, r.action, Object.entries(r.scope || {}).map(([k, v]) => h("span", { class: "faint" }, ` · ${k} `, h("code", null, v)))),
    h("dt", null, "Limits"), h("dd", null, `${r.max_per_hour} per hour · ${r.days} days after approval`),
    h("dt", null, "Proposed"), h("dd", null, `${r.proposed_by || "?"} ${when(r.proposed_at)}`),
    r.approved_by ? [h("dt", null, "Approved"), h("dd", null, `${r.approved_by} ${when(r.approved_at)} · expires ${when(r.expires_at)}`)] : null,
    r.changed_by ? [h("dt", null, "Changed"), h("dd", null, `${r.status} by ${r.changed_by} ${when(r.changed_at)}`, r.note ? h("div", { class: "faint" }, r.note) : null)] : null,
    h("dt", null, "Content"), h("dd", { class: "mono faint small" }, r.hash));
}
function approveRuleDialog(srv, r, after) {
  if (!(srv.status || {}).accepts_rule_approvals) {
    modal("Approve on the server", [h("div", { class: "stack" },
      h("div", { class: "strong" }, r.title),
      h("div", { class: "callout warn" }, ruleSummary(r)),
      h("div", null, "An approved rule acts without asking, so this server takes the approval from the hub only when its root allowed automatic actions from the hub ([response] hub_max_mode = \"contain\", and hub.accept_approvals). Approve it on the server:"),
      h("div", { class: "cmd" }, "sudo kodeblue rules approve " + r.id))], []);
    return;
  }
  const go = h("button", { class: "btn primary", type: "button", on: { click: async () => { m.close(); await ruleCommand(srv, r, "rule_approve", "", after); } } }, "Approve rule");
  const m = modal("Approve auto-block rule", [h("div", { class: "stack" },
    h("div", { class: "strong" }, r.title),
    r.pending_change ? h("div", { class: "small strong c-orange" }, "This is a changed version of an active rule. Approving makes this version active:") : null,
    h("div", { class: "callout warn" }, ruleSummary(r)),
    r.current ? h("div", { class: "small muted" }, "It replaces: " + ruleSummary(r.current)) : null,
    (r.when || {}).extract ? h("div", { class: "small c-orange" }, "Targets are taken from log text, which a client can write (a forwarded-for header, a user agent). Check the pattern only matches what the server itself records.") : null,
    h("div", null, h("div", { class: "small faint" }, "Why the agent proposes it"), md(r.why || "—")),
    ruleDetail(r),
    h("div", { class: "small muted" }, "Once approved, kodeblue takes this action by itself on every match, without asking, in any response mode except off. Protected addresses and paths are still refused, and you can pause it at any time."))], [go]);
}
const RULE_ORDER = { proposed: 0, active: 1, paused: 2, expired: 3, rejected: 4, deleted: 5 };
const ruleRank = (r) => (r.pending_change ? -1 : RULE_ORDER[r.status] ?? 6);
// rulesPanel: msgs are the server's rule commands, newest first, so a ruling
// on its way shows instead of the buttons, and a refusal says why.
function rulesPanel(srv, list, after, msgs) {
  list = list.slice().sort((a, b) => ruleRank(a) - ruleRank(b) || String(a.id).localeCompare(String(b.id)));
  const live = list.filter((r) => !["rejected", "deleted"].includes(r.status));
  const old = list.length - live.length;
  const shown = S.open.has("rules-old") ? list : live;
  const waiting = list.filter((r) => r.status === "proposed" || r.pending_change).length;
  const active = list.filter((r) => r.status === "active").length;
  const extra = h("span", { class: "hd-x" }, waiting ? h("span", { class: "badge b-warn" }, waiting + " waiting for you") : null,
    old ? h("button", { class: "btn small ghost", type: "button", on: { click: () => { S.open.has("rules-old") ? S.open.delete("rules-old") : S.open.add("rules-old"); after(); } } },
      S.open.has("rules-old") ? "Hide rejected and deleted" : `Show rejected and deleted (${old})`) : null);
  const cols = ["Rule", "Status", "Fired", "Last fired", "Expires"];
  return panel(`Auto-block rules (${active} active)`, h("div", { class: "bd flush tbl-wrap" }, shown.length ? h("table", null,
    h("thead", null, h("tr", null, cols.map((t, i) => h("th", { class: i === 2 ? "num" : "" }, t)))),
    h("tbody", null, shown.map((r) => {
      const key = "cr" + r.id;
      const mine = (msgs || []).filter((m) => m.request_id === r.id);
      const open = mine.find(decOpen);
      const last = mine[0];
      const btns = [];
      if (r.status === "proposed" || r.pending_change || r.status === "paused" || r.status === "expired")
        btns.push(h("button", { class: "btn small primary", type: "button", on: { click: () => approveRuleDialog(srv, r, after) } }, ic("check", 12), r.status === "proposed" || r.pending_change ? "Approve" : r.status === "paused" ? "Resume" : "Renew"));
      if (r.status === "proposed" || r.pending_change)
        btns.push(h("button", { class: "btn small", type: "button", on: { click: () => ruleNoteDialog(srv, r, "rule_reject", "Reject " + r.id, "Why not", "e.g. these addresses include our office VPN", "Reject", after) } }, "Reject"));
      if (r.status === "active")
        btns.push(h("button", { class: "btn small", type: "button", on: { click: () => ruleNoteDialog(srv, r, "rule_pause", "Pause " + r.id, "Why pause it", "e.g. it blocked a partner's scanner", "Pause rule", after) } }, ic("pause", 12), "Pause"));
      if (!["deleted", "rejected"].includes(r.status) && r.approved_by && acceptsApprovals(srv.id))
        btns.push(h("button", { class: "btn small danger", type: "button", on: { click: () => ruleNoteDialog(srv, r, "rule_delete", "Delete " + r.id, "Note (optional)", "", "Delete rule", after) } }, ic("trash", 12), "Delete"));
      const ex = h("tr", { hidden: !S.open.has(key), class: "ex" }, h("td", { colspan: cols.length }, h("div", { class: "stack" },
        h("div", null, h("div", { class: "small faint" }, "Why"), md(r.why || "—")), ruleDetail(r))));
      const row = h("tr", { class: "click" + (r.status === "proposed" || r.pending_change ? " attn" : ""), on: { click: (e) => { if (e.target.closest("button")) return; S.open.has(key) ? S.open.delete(key) : S.open.add(key); ex.hidden = !S.open.has(key); } } },
        h("td", null, h("div", { class: "fg strong" }, r.title), h("div", { class: "small muted" }, ruleSummary(r)),
          open ? h("div", { class: "appr-st", style: "margin-top:6px" }, h("span", { class: "pulse" }), `${open.author} sent ${open.command.replace("rule_", "")}; ${open.status === "queued" ? "waiting for the server…" : "the server is handling it…"}`)
            : btns.length ? h("div", { class: "btns", style: "margin-top:6px" }, btns) : null,
          !open && last && (last.status === "refused" || last.status === "failed") && Date.now() - (validTime(last.replied_at) || 0) < 86400000
            ? h("div", { class: "small c-red", style: "margin-top:4px" }, `${last.command.replace("rule_", "")} by ${last.author} ${last.status}: ${last.reply}`) : null),
        h("td", null, ruleStatus(r)),
        h("td", { class: "num" }, r.fired || 0, r.fired_last_hour ? h("div", { class: "faint small" }, r.fired_last_hour + " last hour") : null),
        h("td", { class: "nowrap small muted" }, validTime(r.last_fired) ? ago(r.last_fired) : "—"),
        h("td", { class: "nowrap small muted" }, validTime(r.expires_at) ? when(r.expires_at) : "—"));
      return [row, ex];
    }))) : h("div", { class: "empty" }, "No auto-block rules yet. When the same attack keeps coming back, the reviewer or responder proposes one here; it acts only after you approve it.")), extra, "red");
}

// vAutoblock: the containment rules, what kodeblue does by itself once a
// person approved it, and the actions they took.
async function vAutoblock(srv, body) {
  const [crules, msgs, acts] = await Promise.all([recs(srv.id, "containment_rule", "?limit=500").then((x) => x.map(parse)),
    api("GET", `/api/servers/${enc(srv.id)}/messages`).then((m) => m.filter((x) => String(x.command || "").startsWith("rule_"))).catch(() => []),
    recs(srv.id, "action", "?limit=500").then((x) => x.map(parse).filter((a) => String(a.requested_by || "").startsWith("rule:")))]);
  const again = () => { if (body.isConnected) vAutoblock(srv, body); };
  // While a ruling is on its way, look again until the server answered.
  if (msgs.some(decOpen)) setTimeout(again, 4000);
  const st = srv.status || {};
  const cur = st.version || srv.version || "";
  const old = newerVer("v0.1.8", cur);
  const at = (a) => validTime(a.done_at) || validTime(a.requested_at) || 0;
  acts.sort((a, b) => at(b) - at(a));
  const live = crules.filter((r) => r.status === "active").length;
  const waiting = crules.filter((r) => r.status === "proposed" || r.pending_change).length;
  const narrow = window.innerWidth < 760;
  sync(body, h("div", { class: "stack" },
    h("div", { class: "grid g4" },
      stat("Active rules", live, live ? "acting on their own" : "nothing acts on its own", live ? "red" : "green"),
      stat("Waiting for you", waiting, waiting ? "approve or reject below" : "no proposals", waiting ? "orange" : "green"),
      stat("Actions by rules", acts.length, acts.length ? "last " + ago(at(acts[0])) : "none yet", "blue"),
      old ? stat("Approve from the hub", "update first", `auto-block arrived in v0.1.8; this server runs ${cur}`, "yellow")
        : stat("Approve from the hub", st.accepts_rule_approvals ? "yes" : "no", st.accepts_rule_approvals ? "this server takes hub approvals"
          : "on the server: sudo kodeblue rules approve", st.accepts_rule_approvals ? "green" : "yellow")),
    h("div", { class: "callout info" }, h("div", { class: "lbl" }, "How auto-block works"),
      "When the same attack keeps coming back, the reviewer or responder agent proposes a rule, such as \"block every address that brute-forces SSH\". ",
      "A proposal does nothing: you read it here and approve or reject it. Once approved, kodeblue takes that one action on every match without asking, within the rule's limits (actions per hour, addresses or paths it may touch) and only until it expires. ",
      "Protected addresses and paths are still refused, and Pause stops a rule at once. In the code and on the server these are called containment rules."),
    rulesPanel(srv, crules, again, msgs),
    panel(`What the rules did (${acts.length})`, h("div", { class: "bd flush" }, acts.length
      ? (narrow ? h("div", { class: "pad pb" }, actionCards(acts, false, srv.id, [], again)) : actionTable(acts, false, srv.id, [], again))
      : h("div", { class: "empty" }, "No rule has acted yet.")), h("a", { href: `#/s/${enc(srv.id)}/activity`, class: "small" }, "All containment actions"), "red")));
}

async function vMonitors(srv, body) {
  const [mons, rules] = await Promise.all([recs(srv.id, "monitor", "?limit=500"), recs(srv.id, "allow_rule", "?limit=500")]);
  const st = srv.status || {};
  const ml = mons.map(parse).sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const rl = rules.map(parse);
  const coll = Object.entries(st.collector_runs || {}).sort();
  sync(body, h("div", { class: "stack" },
    h("div", { class: "note" }, "Monitors watch and raise findings; they never act. Rules that block or quarantine by themselves are on the ",
      h("a", { href: `#/s/${enc(srv.id)}/autoblock` }, "Auto-block"), " tab."),
    panel(`Agent-written monitors (${ml.filter((m) => !m.disabled).length} active)`, h("div", { class: "bd flush tbl-wrap" }, ml.length ? h("table", null,
      h("thead", null, h("tr", null, ["Monitor", "Check", "Status", "Runs", "Fails", "Last run", "By"].map((t, i) => h("th", { class: i === 3 || i === 4 ? "num" : "" }, t)))),
      h("tbody", null, ml.map((m) => {
        const spec = m.spec || {};
        const key = "m" + m.id;
        const ex = h("tr", { hidden: !S.open.has(key), class: "ex" }, h("td", { colspan: 7 }, h("div", { class: "small faint" }, "Spec"), h("pre", { class: "out json" }, prettyJSON(spec)),
          m.last_output ? [h("div", { class: "small faint" }, "Last output"), h("pre", { class: "out" + (m.last_ok ? "" : " err") }, m.last_output)] : null));
        return [h("tr", { class: "click", on: { click: () => { S.open.has(key) ? S.open.delete(key) : S.open.add(key); ex.hidden = !S.open.has(key); } } },
          h("td", null, h("div", { class: "fg strong" }, m.id), spec.description ? h("div", { class: "small muted trunc" }, spec.description) : null),
          h("td", null, h("span", { class: "badge" }, spec.kind || spec.type || "—"), spec.interval_seconds ? h("span", { class: "faint small" }, " every " + spec.interval_seconds + "s") : null),
          h("td", null, m.disabled ? h("span", { class: "badge" }, "disabled") : m.runs === 0 ? h("span", { class: "badge" }, "not run") : m.last_ok ? h("span", { class: "badge b-ok" }, "ok") : h("span", { class: "badge b-bad" }, "failing")),
          h("td", { class: "num" }, m.runs), h("td", { class: "num" }, m.fails), h("td", { class: "nowrap small muted" }, ago(m.last_run)), h("td", { class: "small muted" }, m.created_by)), ex];
      }))) : h("div", { class: "empty" }, "No monitors yet. The learning agent writes them for this server.")), null, "cyan"),
    h("div", { class: "grid g2" },
      panel("Built-in sensors (sweeps run)", h("div", { class: "bd" }, coll.length ? h("dl", { class: "kv" }, coll.map(([k, v]) => [h("dt", null, k), h("dd", null, v.toLocaleString() + " sweeps")])) : h("div", { class: "faint" }, "No sweeps yet.")), null, "green"),
      panel(`Allow rules (${rl.length})`, h("div", { class: "bd flush tbl-wrap" }, rl.length ? h("table", null,
        h("thead", null, h("tr", null, ["Pattern", "Reason", "Hits", "By"].map((t) => h("th", null, t)))),
        h("tbody", null, rl.map((r) => h("tr", null,
          h("td", null, h("div", { class: "small faint" }, r.collector, r.rule ? " · " + r.rule : ""), h("code", null, r.key_pattern)),
          h("td", { class: "small" }, r.reason, r.expires_at && !String(r.expires_at).startsWith("0001") ? h("div", { class: "faint" }, "expires " + when(r.expires_at)) : null),
          h("td", { class: "num" }, r.hits), h("td", { class: "small muted" }, r.created_by))))) : h("div", { class: "empty" }, "No allow rules.")), null, "yellow"))));
}

// ----- services and vulnerabilities
const VSEV = ["critical", "high", "medium", "low"];
const openVulns = (c) => Object.values((c && c.open_vulnerabilities) || {}).reduce((a, b) => a + b, 0);
const worstVuln = (c) => VSEV.slice(0, 2).some((s) => ((c && c.open_vulnerabilities) || {})[s] > 0);
const vulnRank = (v) => (v.status === "open" ? 0 : v.status === "accepted" ? 1 : 2) * 10 + Math.max(0, VSEV.indexOf(v.severity));
function vulnStatus(v) {
  const cls = { open: "b-warn", resolved: "b-ok", accepted: "" }[v.status] || "";
  return h("span", { class: "badge " + cls, title: v.status_note || null }, v.status === "accepted" ? "risk accepted" : v.status);
}
function vulnCheck(v) {
  if (!v.check) return h("span", { class: "faint small", title: "an agent confirms the fix, or a human accepts the risk" }, "no check");
  if (!validTime(v.checked_at)) return h("span", { class: "faint small" }, "not run");
  return h("span", { class: "small " + (v.check_ok ? "c-green" : "c-red"), title: v.check_output || null }, v.check_ok ? "passes" : "fails", h("span", { class: "faint" }, " · " + ago(v.checked_at)));
}
async function vulnCommand(srv, v, command, note, after) {
  try {
    await api("POST", `/api/servers/${enc(srv.id)}/vulnerabilities/${enc(v.id)}`, { command, note });
    toast({ vuln_accept: "Risk accepted", vuln_reopen: "Reopened", vuln_recheck: "Recheck sent" }[command] + "; the server applies it within seconds");
    setTimeout(after, 4000);
  } catch (e) { toast(e.message, true); }
}
function acceptDialog(srv, v, after) {
  const why = h("textarea", { class: "full", rows: 3, placeholder: "e.g. intentionally vulnerable training target; compensated by the WAF in front of it" });
  const go = h("button", { class: "btn primary", type: "button", on: { click: async () => {
    if (!why.value.trim()) { why.focus(); return; }
    m.close();
    await vulnCommand(srv, v, "vuln_accept", why.value, after);
  } } }, "Accept risk");
  const m = modal("Accept the risk of " + v.id, [h("div", { class: "stack" }, h("div", null, v.title),
    h("label", { class: "field" }, "Why the team keeps this risk", why))], [go]);
  why.focus();
}
// vulnTable lists vulnerabilities; withService adds the service each is in,
// for the server-wide list.
function vulnTable(srv, list, after, withService) {
  const cols = withService ? ["Vulnerability", "Service", "Sev", "Status", "Check", "Found"] : ["Vulnerability", "Sev", "Status", "Check", "Found"];
  return h("div", { class: "tbl-wrap" }, h("table", null,
    h("thead", null, h("tr", null, cols.map((t) => h("th", null, t)))),
    h("tbody", null, list.map((v) => {
      const key = "v" + v.id;
      const row = h("tr", { class: "click", on: { click: () => { S.open.has(key) ? S.open.delete(key) : S.open.add(key); ex.hidden = !S.open.has(key); } } },
        h("td", null, h("div", { class: "fg strong" }, v.title),
          h("div", { class: "faint small mono" }, v.id, v.category ? " · " + v.category : "", (v.cves || []).length ? " · " + v.cves.join(", ") : "")),
        withService ? h("td", { class: "small" }, v.service || h("span", { class: "faint" }, "host")) : null,
        h("td", null, sevBadge(v.severity)),
        h("td", null, vulnStatus(v)),
        h("td", { class: "nowrap" }, vulnCheck(v)),
        h("td", { class: "nowrap small muted" }, ago(v.created_at)));
      const btns = [];
      if (v.status !== "accepted") btns.push(h("button", { class: "btn small", type: "button", on: { click: () => acceptDialog(srv, v, after) } }, "Accept risk"));
      if (v.status !== "open") btns.push(h("button", { class: "btn small", type: "button", on: { click: () => vulnCommand(srv, v, "vuln_reopen", "", after) } }, "Reopen"));
      if (v.check) btns.push(h("button", { class: "btn small", type: "button", on: { click: () => vulnCommand(srv, v, "vuln_recheck", "", after) } }, "Recheck now"));
      const ex = h("tr", { hidden: !S.open.has(key), class: "ex" }, h("td", { colspan: cols.length }, h("div", { class: "stack" },
        h("div", null, h("div", { class: "small faint" }, "Evidence"), h("pre", { class: "out" }, v.evidence || "—")),
        h("div", null, h("div", { class: "small faint" }, "How to fix it"), md(v.remediation || "—")),
        v.check ? h("div", null, h("div", { class: "small faint" }, "Check (passes once fixed)"), h("pre", { class: "out json" }, prettyJSON(v.check)),
          v.check_output ? h("pre", { class: "out" + (v.check_ok ? "" : " err") }, v.check_output) : null) : null,
        v.status_note ? h("div", { class: "small" }, h("span", { class: "faint" }, v.status.replace(/_/g, " ") + " by " + (v.status_by || "?") + ": "), v.status_note) : null,
        h("div", { class: "small faint" }, "found by " + (v.found_by || "?") + " " + when(v.created_at), validTime(v.resolved_at) ? " · resolved " + when(v.resolved_at) : ""),
        btns.length ? h("div", { class: "btns" }, btns) : null)));
      return [row, ex];
    }))));
}
function checkChips(svc) {
  const checks = svc.checks || [];
  if (!checks.length) return h("span", { class: "faint small" }, svc.role === "system" ? "OS plumbing: the built-in sensors watch it" : "no checks needed");
  return h("div", { class: "checks" }, checks.map((c) => {
    const ok = (c.covered_by || []).length > 0;
    return h("span", { class: "badge " + (ok ? "b-ok" : "b-bad"), title: ok ? "covered by " + c.covered_by.join(", ") : "missing: " + c.need }, ok ? ic("check", 10) : ic("x", 10), c.check);
  }));
}
function servicePanel(srv, svc, vulns, after) {
  const ports = (svc.listen || []).map((p) => `${p.proto}/${p.port}` + (p.address && !["0.0.0.0", "::"].includes(p.address) ? " on " + p.address : ""));
  const open = vulns.filter((v) => v.status === "open").length;
  const meta = h("div", { class: "small muted" },
    h("span", { class: "badge" }, svc.role || "service"), " ", h("span", { class: "badge" + (svc.state === "running" ? " b-ok" : "") }, svc.state || "?"),
    ports.length ? " · " + ports.join(", ") : "", (svc.exes || []).length ? " · " : "", (svc.exes || []).map((e, i) => [i ? ", " : "", h("code", null, e)]),
    svc.container ? " · container " + svc.container : "", svc.note ? h("div", { class: "faint" }, svc.note) : null);
  const extra = h("span", { class: "hd-x" }, open ? h("span", { class: "badge b-warn" }, open + " open") : null,
    svc.case ? h("a", { class: "small", href: `#/s/${enc(srv.id)}/t/${svc.case}` }, " coverage case #" + svc.case) : null);
  return panel(svc.name, h("div", { class: "bd stack" }, meta,
    h("div", null, h("div", { class: "small faint" }, "Monitoring coverage"), checkChips(svc)),
    h("div", null, h("div", { class: "small faint" }, "Vulnerabilities"), vulns.length ? vulnTable(srv, vulns, after) : h("div", { class: "faint small" }, svc.role === "system" ? "None recorded." : "None found yet."))),
  extra, (svc.missing || []).length ? "red" : open ? "orange" : "green");
}
// vVulnerabilities is everything known to be weak on the server in one list,
// the hub's view of the server's VULNERABILITIES.md. The filters redraw only
// the list, so the search box keeps its focus.
const VULN_ST = [["open", "Open"], ["accepted", "Risk accepted"], ["resolved", "Fixed"], ["", "All"]];
async function vVulnerabilities(srv, body) {
  const vv = await recs(srv.id, "vulnerability", "?limit=1000");
  const st = srv.status || {};
  if (unchanged(body, "vulnerabilities", [vv, st.software])) return;
  const after = () => { body.dataset.sig = ""; vVulnerabilities(srv, body); };
  const vulns = vv.map(parse).sort((a, b) => vulnRank(a) - vulnRank(b) || String(a.id).localeCompare(String(b.id)));
  const open = vulns.filter((v) => v.status === "open");
  const by = (sev) => open.filter((v) => v.severity === sev).length;
  const f = S.cache.vulnF || (S.cache.vulnF = { status: "open", sev: "", svc: "", q: "" });
  const n = (s) => (s ? vulns.filter((v) => v.status === s).length : vulns.length);
  const statusSel = h("select", { "aria-label": "Status" }, VULN_ST.map(([k, l]) => h("option", { value: k, selected: f.status === k }, `${l} (${n(k)})`)));
  const sevSel = h("select", { "aria-label": "Severity" }, h("option", { value: "" }, "Any severity"), VSEV.map((k) => h("option", { value: k, selected: f.sev === k }, k)));
  const svcs = [...new Set(vulns.map((v) => v.service || ""))].sort();
  const svcSel = h("select", { "aria-label": "Service" }, h("option", { value: "" }, "Every service"),
    svcs.map((k) => h("option", { value: k || "-", selected: f.svc === (k || "-") }, k || "host")));
  const q = h("input", { type: "search", placeholder: "Search title, CVE, id…", "aria-label": "Search vulnerabilities", autocomplete: "off", spellcheck: "false", value: f.q });
  const list = h("div");
  const draw = () => {
    const qq = f.q.trim().toLowerCase();
    const shown = vulns.filter((v) => (!f.status || v.status === f.status) && (!f.sev || v.severity === f.sev) &&
      (!f.svc || (v.service || "-") === f.svc) &&
      (!qq || [v.title, v.id, v.service, v.category, ...(v.cves || [])].some((x) => String(x || "").toLowerCase().includes(qq))));
    clear(list);
    list.appendChild(shown.length ? vulnTable(srv, shown, after, true)
      : h("div", { class: "empty" }, vulns.length ? "Nothing matches these filters." : "No vulnerabilities recorded yet. The assessment runs after learning, then the reviewer and the daily CVE feed add to it."));
  };
  statusSel.addEventListener("change", () => { f.status = statusSel.value; draw(); });
  sevSel.addEventListener("change", () => { f.sev = sevSel.value; draw(); });
  svcSel.addEventListener("change", () => { f.svc = svcSel.value; draw(); });
  q.addEventListener("input", () => { f.q = q.value; draw(); });
  draw();
  sync(body, h("div", { class: "stack" },
    h("div", { class: "grid g4" },
      stat("Open", open.length, VSEV.map((s) => by(s) ? by(s) + " " + s : "").filter(Boolean).join(" · ") || "none open", open.length ? (by("critical") || by("high") ? "red" : "orange") : "green"),
      stat("Critical or high", by("critical") + by("high"), "fix these first", by("critical") + by("high") ? "red" : "green"),
      stat("Fixed or accepted", vulns.length - open.length, n("resolved") + " fixed, " + n("accepted") + " accepted", "green"),
      stat("Security updates", (st.software || {}).security_updates || 0, (st.software || {}).checked_at ? "waiting to install · checked " + ago(st.software.checked_at) : "not checked yet", (st.software || {}).security_updates ? "orange" : "green")),
    h("div", { class: "note" }, "Everything known to be weak on this server: what the vulnerability assessment, the reviewer and the CVE feed confirmed. Open one for its evidence and how to fix it. On the server the same list is in ",
      h("code", null, "/var/lib/kodeblue/workspace/VULNERABILITIES.md"), " and ", h("code", null, "sudo kodeblue vulnerabilities"), "."),
    panel(`Vulnerabilities (${vulns.length})`, h("div", { class: "bd stack" }, h("div", { class: "toolbar" }, h("div", { class: "fsearch" }, ic("search", 14, "c-muted"), q), statusSel, sevSel, svcSel), list), null, "orange"),
    softwarePanel(srv, st.software)));
}

async function vServices(srv, body) {
  const [sv, vv] = await Promise.all([recs(srv.id, "service", "?limit=500"), recs(srv.id, "vulnerability", "?limit=1000")]);
  if (unchanged(body, "services", [sv, vv])) return;
  const after = () => { body.dataset.sig = ""; vServices(srv, body); };
  const svcs = sv.map(parse).sort((a, b) => (a.role === "system") - (b.role === "system") || String(a.name).localeCompare(String(b.name)));
  const vulns = vv.map(parse).sort((a, b) => vulnRank(a) - vulnRank(b) || String(a.id).localeCompare(String(b.id)));
  const names = new Set(svcs.map((s) => s.name));
  const of = (name) => vulns.filter((v) => v.service === name);
  const other = vulns.filter((v) => !names.has(v.service));
  const open = vulns.filter((v) => v.status === "open");
  const gaps = svcs.filter((s) => (s.missing || []).length);
  const by = (sev) => open.filter((v) => v.severity === sev).length;
  const node = h("div", { class: "stack" },
    h("div", { class: "grid g4" },
      stat("Services", svcs.length, svcs.filter((s) => s.role !== "system").length + " workload", "blue"),
      stat("Fully monitored", svcs.length - gaps.length, gaps.length ? gaps.length + " missing a check" : "every check covered", gaps.length ? "red" : "green"),
      stat("Open vulnerabilities", open.length, VSEV.map((s) => by(s) ? by(s) + " " + s : "").filter(Boolean).join(" · ") || "none open", open.length ? (by("critical") || by("high") ? "red" : "orange") : "green"),
      stat("Fixed or accepted", vulns.length - open.length, vulns.filter((v) => v.status === "resolved").length + " fixed, " + vulns.filter((v) => v.status === "accepted").length + " accepted", "green")),
    !svcs.length ? h("div", { class: "empty" }, "No service inventory yet. kodeblue takes it after learning, then every 10 minutes.") : null,
    svcs.map((s) => servicePanel(srv, s, of(s.name), after)),
    other.length ? panel("Host and other", h("div", { class: "bd" }, vulnTable(srv, other, after)), null, "purple") : null);
  sync(body, node);
}

// ----- self-evaluation
async function vEvaluation(srv, body) {
  const st = srv.status || {};
  const inc = (await recs(srv.id, "incident", "?limit=400")).map(parse);
  const reviews = inc.filter((i) => i.kind === "review").sort((a, b) => b.id - a.id);
  const latest = reviews.find((r) => r.self_eval);
  const evals = inc.filter((i) => i.kind === "incident" && i.self_eval).sort((a, b) => b.id - a.id);
  const verdicts = {};
  for (const i of inc.filter((i) => i.kind === "incident" && i.verdict)) verdicts[i.verdict] = (verdicts[i.verdict] || 0) + 1;
  const decided = Object.values(verdicts).reduce((a, b) => a + b, 0);
  const noise = (verdicts.false_positive || 0);
  const fs = st.finding_stats_7d || {};
  const rules = Object.entries(fs).map(([rule, m]) => [rule, m, Object.values(m).reduce((a, b) => a + b, 0)]).sort((a, b) => b[2] - a[2]);
  const avgConf = evals.length ? evals.reduce((a, i) => a + (i.confidence || 0), 0) / evals.length : 0;
  sync(body, h("div", { class: "stack" },
    h("div", { class: "grid g4" },
      stat("Latest self-score", latest ? `${Math.round(latest.confidence * 10)}/10` : "—", latest ? "review #" + latest.id + " · " + when(latest.updated_at) : "after the first daily review", "purple"),
      stat("Incidents judged", decided, Object.entries(verdicts).map(([k, n]) => `${n} ${k.replace(/_/g, " ")}`).join(" · ") || "none yet", "blue"),
      stat("False-positive rate", decided ? Math.round((noise / decided) * 100) + "%" : "—", "incidents the agent called false positive", "yellow"),
      stat("Avg. agent confidence", evals.length ? Math.round(avgConf * 100) + "%" : "—", `over ${evals.length} incident self-evaluations`, "green")),
    latest ? panel(`Reviewer self-evaluation — review #${latest.id}`, h("div", { class: "bd" }, h("div", { class: "callout eval" }, h("div", { class: "lbl" }, "How kodeblue thinks it did"), md(latest.self_eval))),
      h("a", { href: `#/s/${enc(srv.id)}/t/${latest.id}` }, "Open review"), "purple") :
      panel("Reviewer self-evaluation", h("div", { class: "bd faint" }, "The periodic reviewer writes one each run (default daily): what worked, false positives and why, what was missed, and cost against budget."), null, "purple"),
    panel("Per-incident self-evaluations", h("div", { class: "bd flush" }, evals.length ? h("ul", { class: "list-plain" }, evals.slice(0, 40).map((i) =>
      h("li", null, h("div", { class: "btns" }, h("a", { href: `#/s/${enc(srv.id)}/t/${i.id}` }, `#${i.id} ${i.title}`),
        verdictBadge(i.verdict), i.confidence ? h("span", { class: "badge" }, `confidence ${Math.round(i.confidence * 100)}%`) : null),
        h("div", { class: "small mt" }, md(i.self_eval))))) : h("div", { class: "empty" }, "No incident self-evaluations yet.")), null, "blue"),
    panel("Detection quality, last 7 days (findings by rule and outcome)", h("div", { class: "bd flush tbl-wrap" }, rules.length ? h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Rule"), h("th", { class: "num" }, "Total"), h("th", null, "Outcomes"))),
      h("tbody", null, rules.map(([rule, m, n]) => h("tr", null, h("td", { class: "mono" }, rule), h("td", { class: "num" }, n),
        h("td", null, h("div", { class: "btns" }, Object.entries(m).map(([k, v]) => h("span", { class: "small" }, statusBadge(k), " ", v)))))))) : h("div", { class: "empty" }, "No findings in the last 7 days.")), null, "green"),
    reviews.length > 1 ? panel("Review history", h("div", { class: "bd flush" }, incidentTable(srv, reviews)), null, "purple") : null));
}

// ----- activity
async function vActivity(srv, body) {
  const q = h("input", { type: "search", placeholder: "Filter activity…", value: S.cache.actQ || "" });
  q.addEventListener("keydown", (e) => { if (e.key === "Enter") { S.cache.actQ = q.value; vActivity(srv, body); } });
  const [jr, acts, pend, msgs] = await Promise.all([
    recs(srv.id, "journal", "?limit=400" + (S.cache.actQ ? "&q=" + enc(S.cache.actQ) : "")),
    recs(srv.id, "action", "?limit=200"), recs(srv.id, "pending_action", "?limit=200"),
    api("GET", `/api/servers/${enc(srv.id)}/messages`).catch(() => [])]);
  const pl = pend.map(parse);
  const decs = (msgs || []).filter((m) => m.decision).sort((a, b) => a.id - b.id);
  const again = () => { if (body.isConnected) vActivity(srv, body); };
  // Follow an in-flight ruling until the server answers.
  if (decs.some(decOpen)) {
    const follow = () => { if (!body.isConnected) return; if (document.activeElement && document.activeElement.tagName === "INPUT" && body.contains(document.activeElement)) setTimeout(follow, 3000); else again(); };
    setTimeout(follow, 3000);
  }
  const narrow = window.innerWidth < 760; // tables are unreadable on a phone; cards fit
  const actions = (l, p) => narrow ? h("div", { class: "pad pb" }, actionCards(l, p, srv.id, decs, again)) : actionTable(l, p, srv.id, decs, again);
  sync(body, h("div", { class: "stack" },
    pl.length ? panel(`Containment waiting for approval (${pl.length})`, h("div", { class: "bd flush" }, h("div", { class: "note pad" },
      acceptsApprovals(srv.id) ? "Policy on this server is recommend: an agent asked for these. Approving runs the action on the server through its root helper, under the server's own policy."
        : "Policy on this server is recommend: an agent asked for these. This server takes approvals on its own CLI only (older kodeblue, or hub.accept_approvals = false)."),
    actions(pl, true)), null, "orange") : null,
    panel("Containment actions taken", h("div", { class: "bd flush" }, acts.length ? actions(acts.map(parse)) : h("div", { class: "empty" }, "No containment actions.")), null, "red"),
    panel("Journal", h("div", { class: "bd flush" }, h("div", { class: "toolbar pad" }, q), journalList(jr.map(parse))), null, "blue")));
}
function actionTable(list, pending, srvId, decs, after) {
  return h("div", { class: "tbl-wrap" }, h("table", null,
    h("thead", null, h("tr", null, ["Id", "Action", "Target", "Why", pending ? "Decision" : "Result", "When"].map((t) => h("th", null, t)))),
    h("tbody", null, list.map((a) => h("tr", null,
      h("td", { class: "mono small" }, a.id), h("td", null, h("span", { class: "badge" }, a.action), a.incident_id ? h("div", { class: "faint small" }, "incident #" + a.incident_id) : null),
      h("td", { class: "mono small" }, Object.entries(a.params || {}).map(([k, v]) => k + "=" + v).join(" ")),
      h("td", { class: "small why" }, a.justification),
      h("td", { class: "small" }, pending ? approvalControls(srvId, a, decs, after) : [statusBadge(a.status), " ", h("span", { class: "muted" }, a.result || ""),
        a.status === "done" && a.action !== "kill_process" ? h("div", { class: "faint" }, "undo: ", h("code", null, `kodeblue respond undo ${a.id}`)) : null]),
      h("td", { class: "nowrap small muted" }, ago(a.done_at && !String(a.done_at).startsWith("0001") ? a.done_at : a.requested_at)))))));
}

// actionCards is actionTable for the narrow task-panel side panel.
function actionCards(list, pending, srvId, decs, after) {
  return h("div", { class: "acards" }, list.map((a) => h("div", { class: "acard" },
    h("div", { class: "ahd" }, h("span", { class: "badge" + (pending ? " b-warn" : "") }, a.action), pending ? null : statusBadge(a.status), h("div", { class: "sp" }),
      h("span", { class: "faint small" }, ago(a.done_at && !String(a.done_at).startsWith("0001") ? a.done_at : a.requested_at))),
    Object.keys(a.params || {}).length ? h("div", { class: "mono small atgt" }, Object.entries(a.params || {}).map(([k, v]) => k + "=" + v).join(" ")) : null,
    a.justification ? h("div", { class: "small muted" }, a.justification) : null,
    pending ? approvalControls(srvId, a, decs, after) :
      [a.result ? h("div", { class: "small muted" }, a.result) : null,
        a.status === "done" && a.action !== "kill_process" ? h("div", { class: "small faint" }, "undo: ", h("code", null, `kodeblue respond undo ${a.id}`)) : null])));
}

// ----- knowledge
async function vKnowledge(srv, body, item) {
  const [reports, skills, defs] = await Promise.all([recs(srv.id, "report", "?limit=300"), recs(srv.id, "skill", "?limit=300"), recs(srv.id, "definition", "?limit=300")]);
  const groups = [["Reports", "report", reports], ["Skills", "skill", skills], ["Definitions", "definition", defs]];
  let sel = null;
  if (item) {
    const [k, ...rest] = item.split(":");
    const id = rest.join(":");
    for (const [, kind, l] of groups) if (kind === k) sel = l.find((r) => r.id === id);
  }
  const nav = h("div", { class: "panel" }, groups.map(([title, kind, l]) => [h("div", { class: "hd" }, h("span", { class: "cdot c-cyan" }), h("h2", null, `${title} (${l.length})`)),
    h("div", { class: "convs" }, l.sort((a, b) => a.id.localeCompare(b.id)).map((r) => h("a", { class: sel === r ? "on" : "", href: `#/s/${enc(srv.id)}/knowledge/${enc(kind + ":" + r.id)}` },
      h("div", { class: "t" }, r.id), h("div", { class: "s" }, "modified " + ago(parse(r).modified))))),
    l.length ? null : h("div", { class: "empty small" }, "none")]));
  const view = sel ? panel(sel.id, h("div", { class: "bd" }, md(parse(sel).content))) :
    h("div", { class: "panel" }, h("div", { class: "empty" }, "What the agents wrote on this server: incident and review reports, the skills they created, and the definitions of normal behavior they maintain."));
  sync(body, h("div", { class: "kgrid" }, nav, view));
}

// ---------- notifications ----------
function noteStatus(n) {
  const cls = { delivered: "b-ok", pending: "b-warn", failed: "b-bad", skipped: "" }[n.status] || "";
  return h("span", { class: "badge " + cls, title: n.attempts ? n.attempts + " attempt" + (n.attempts === 1 ? "" : "s") : null }, n.status || "?",
    n.attempts > 1 ? " ×" + n.attempts : "");
}
async function vNotifications(srv, main) {
  const status = h("select", { "aria-label": "Delivery status" }, ["", "delivered", "pending", "failed", "skipped"].map((s) =>
    h("option", { value: s, selected: (S.cache.noteStatus || "") === s }, s || "all statuses")));
  const body = h("div", { class: "stack" }, h("div", { class: "empty" }, "Loading…"));
  status.addEventListener("change", () => { S.cache.noteStatus = status.value; body.dataset.sig = ""; draw(); });
  main.append(h("div", { class: "toolbar" }, srv ? null : h("h1", null, "Notifications"),
    h("span", { class: "muted small" }, "What kodeblue sent to notification destinations" + (srv ? " from " + srv.name : " across the fleet") + ", newest first."),
    h("div", { class: "sp" }), status, h("a", { class: "btn small", href: "#/settings" }, ic("sliders", 12), "Notification settings")), body);
  const draw = async () => {
    let list;
    try { list = await api("GET", "/api/notifications?limit=200" + (srv ? "&server_id=" + enc(srv.id) : "")); }
    catch (e) {
      if (e.status === 401) return;
      if (unchanged(body, "err", e.message)) return;
      sync(body, h("div", { class: "panel" }, h("div", { class: "empty" }, e.status === 404 ? "This hub does not deliver notifications yet." : "Could not load notifications: " + e.message)));
      return;
    }
    list = (list || []).filter((n) => !S.cache.noteStatus || n.status === S.cache.noteStatus);
    if (unchanged(body, "notes", list)) return;
    if (!list.length) {
      sync(body, h("div", { class: "panel" }, h("div", { class: "empty" }, S.cache.noteStatus ? "No " + S.cache.noteStatus + " notifications." : "No notifications sent yet.")));
      return;
    }
    sync(body, h("div", { class: "panel" }, h("div", { class: "nlist" }, list.map((n) => {
      const key = "n" + n.id;
      const fields = Object.entries(n.fields || {});
      const more = h("div", { class: "nmore", hidden: !S.open.has(key) },
        n.body ? h("div", { class: "nbody" }, n.body) : null,
        fields.length ? h("dl", { class: "kv" }, fields.map(([k, v]) => [h("dt", null, k), h("dd", null, typeof v === "object" ? JSON.stringify(v) : String(v))])) : null,
        h("div", { class: "faint small" }, "kind ", n.kind || "—", " · ", n.attempts || 0, " attempt", n.attempts === 1 ? "" : "s",
          n.delivered_at && validTime(n.delivered_at) ? " · delivered " + when(n.delivered_at) : ""));
      const row = h("div", { class: "nrow" + (n.status === "failed" ? " failed" : ""), role: "button", tabindex: "0", "aria-expanded": String(S.open.has(key)) },
        h("div", { class: "nmain" },
          h("div", { class: "nhd" }, sevBadge(n.severity), h("span", { class: "ntitle" }, n.title || n.kind || "notification")),
          n.body ? h("div", { class: "nprev" }, n.body) : null,
          h("div", { class: "nmeta" },
            srv ? null : h("a", { class: "srvn", href: "#/s/" + enc(n.server_id) + "/notifications", on: { click: (e) => e.stopPropagation() } }, ic("server", 11), h("span", null, n.server_name || serverName(n.server_id))),
            n.incident_id ? h("a", { href: taskHash(srv ? srv.id : null, n.server_id, n.incident_id), on: { click: (e) => e.stopPropagation() } }, "case #" + n.incident_id) : null,
            h("span", { class: "faint", title: when(n.at) }, ago(n.at)))),
        h("div", { class: "nside" }, noteStatus(n), n.status === "failed" && n.error ? h("div", { class: "nerr", title: n.error }, n.error) : null),
        more);
      const toggle = () => { if (S.open.has(key)) S.open.delete(key); else S.open.add(key); more.hidden = !S.open.has(key); row.setAttribute("aria-expanded", String(!more.hidden)); };
      row.addEventListener("click", (e) => { if (!e.target.closest("a")) toggle(); });
      row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      return row;
    }))));
  };
  await draw();
  setTimer(draw, 10000);
}

// ---------- settings ----------
async function vSettings(main) {
  const body = h("div", { class: "stack narrow" });
  main.append(h("div", { class: "toolbar" }, h("h1", null, "Settings")), body);
  const status = h("span", { class: "badge" }, "…");
  const url = h("input", { type: "password", class: "full", autocomplete: "off", spellcheck: "false", placeholder: "https://hooks.slack.com/services/…", "aria-label": "Slack incoming webhook URL" });
  const save = h("button", { class: "btn primary", type: "button" }, "Save webhook");
  const clr = h("button", { class: "btn danger", type: "button" }, "Clear");
  const sev = h("select", { class: "sel", "aria-label": "Minimum severity" }, ["info", "low", "medium", "high", "critical"].map((s) => h("option", { value: s }, s)));
  const test = h("button", { class: "btn", type: "button" }, ic("send", 12), "Send test message");
  const msg = h("div", { class: "smsg", role: "status" });
  const say = (text, bad) => { msg.textContent = text; msg.className = "smsg " + (bad ? "bad" : "ok"); };
  let cur = null;
  const paint = (s) => {
    cur = s;
    status.className = "badge " + (s.configured ? "b-ok" : "");
    status.textContent = s.configured ? "configured" : "not configured";
    clr.hidden = !s.configured;
    test.disabled = !s.configured;
    test.title = s.configured ? "" : "Save a webhook first";
    if (s.min_severity) sev.value = s.min_severity;
    url.placeholder = s.configured ? "Enter a new URL to replace the stored one" : "https://hooks.slack.com/services/…";
  };
  const busy = async (btn, fn) => {
    btn.disabled = true;
    try { await fn(); } catch (e) { if (e.status !== 401) say(e.status === 0 ? "Can't reach the hub." : e.message, true); }
    finally { btn.disabled = false; if (cur) paint(cur); }
  };
  save.addEventListener("click", () => busy(save, async () => {
    const v = url.value.trim();
    if (!v) { say("Paste the incoming-webhook URL first.", true); url.focus(); return; }
    paint(await api("PUT", "/api/settings/slack", { webhook_url: v }));
    url.value = "";
    say("Webhook saved. Use “Send test message” to check it.");
  }));
  url.addEventListener("keydown", (e) => { if (e.key === "Enter") save.click(); });
  clr.addEventListener("click", async () => {
    if (!(await ask("Clear Slack webhook", "Remove the stored webhook? kodeblue stops posting to Slack until a new one is saved; notifications are still listed on the hub.", "Clear", true))) return;
    busy(clr, async () => { paint(await api("PUT", "/api/settings/slack", { webhook_url: "" })); say("Webhook cleared."); });
  });
  sev.addEventListener("change", () => busy(sev, async () => { paint(await api("PUT", "/api/settings/slack", { min_severity: sev.value })); say("Minimum severity set to " + sev.value + "."); }));
  test.addEventListener("click", () => busy(test, async () => {
    say("Sending…");
    const r = await api("POST", "/api/settings/slack/test", {});
    if (r && r.ok) say("Test message delivered to Slack."); else say("Test failed: " + ((r && r.error) || "unknown error"), true);
  }));
  const agents = h("div", { class: "stack" });
  const telegram = h("div");
  body.append(agents,
    panel("Slack", h("div", { class: "bd stack" },
      h("div", { class: "setrow" }, h("span", { class: "fg" }, "Incoming webhook"), status),
      h("div", { class: "note" }, "The hub posts kodeblue's notifications (incidents, needs-human, containment requests, reviews) to this Slack incoming webhook. The stored URL is a secret and is never shown again; paste a new one to replace it."),
      h("label", { class: "field" }, "Webhook URL", url),
      h("div", { class: "btns" }, save, clr),
      h("div", { class: "setrow" }, h("label", { class: "field inline" }, "Minimum severity", sev),
        h("span", { class: "note" }, "Notifications below this severity are listed on the hub but not posted.")),
      h("div", { class: "btns" }, test, h("a", { class: "small", href: "#/notifications" }, "Notification history")),
      msg), null, "purple"),
    telegram,
    panel("Hub", h("div", { class: "bd" }, h("dl", { class: "kv" },
      h("dt", null, "Signed in as"), h("dd", null, S.me ? S.me.name : "—"),
      h("dt", null, "Operators"), h("dd", null, h("code", null, "kodeblue-hub user add <name>")),
      h("dt", null, "Audit"), h("dd", null, h("a", { href: "#/audit" }, "Audit log"))))));
  vTelegramSettings(telegram);
  fleetAgents(agents);
  try { paint(await api("GET", "/api/settings/slack")); }
  catch (e) {
    if (e.status === 401) return;
    status.textContent = "unavailable";
    [url, save, clr, sev, test].forEach((x) => { x.disabled = true; });
    say(e.status === 404 ? "This hub does not support Slack settings yet." : "Could not load Slack settings: " + e.message, true);
  }
}

async function vTelegramSettings(main) {
  const body = h("div", { class: "stack narrow" });
  main.append(body);
  const status = h("span", { class: "badge" }, "…");
  const url = h("input", { type: "password", class: "full", autocomplete: "off", spellcheck: "false", placeholder: "BotFather token", "aria-label": "Telegram bot token" });
  const chat = h("input", { class: "full", autocomplete: "off", spellcheck: "false", placeholder: "-1001234567890 or @channelusername", "aria-label": "Telegram chat ID" });
  const save = h("button", { class: "btn primary", type: "button" }, "Save Telegram");
  const clr = h("button", { class: "btn danger", type: "button" }, "Clear");
  const sev = h("select", { class: "sel", "aria-label": "Minimum severity" }, ["info", "low", "medium", "high", "critical"].map((s) => h("option", { value: s }, s)));
  const test = h("button", { class: "btn", type: "button" }, ic("send", 12), "Send test message");
  const msg = h("div", { class: "smsg", role: "status" });
  const say = (text, bad) => { msg.textContent = text; msg.className = "smsg " + (bad ? "bad" : "ok"); };
  let cur = null;
  const paint = (s) => {
    cur = s;
    chat.value = s.chat_id || "";
    status.className = "badge " + (s.configured ? "b-ok" : "");
    status.textContent = s.configured ? "configured" : "not configured";
    test.disabled = !s.configured;
    test.title = s.configured ? "" : "Save a bot token and chat ID first";
    if (s.min_severity) sev.value = s.min_severity;
    url.placeholder = s.configured ? "Leave blank to keep the stored token" : "BotFather token";
  };
  const busy = async (btn, fn) => {
    btn.disabled = true;
    try { await fn(); } catch (e) { if (e.status !== 401) say(e.status === 0 ? "Can't reach the hub." : e.message, true); }
    finally { btn.disabled = false; if (cur) paint(cur); }
  };
  save.addEventListener("click", () => busy(save, async () => {
    const v = url.value.trim();
    if (!chat.value.trim() || (!v && !(cur && cur.configured))) { say("Enter a bot token and chat ID first.", true); url.focus(); return; }
    paint(await api("PUT", "/api/settings/telegram", { ...(v ? { bot_token: v } : {}), chat_id: chat.value.trim() }));
    url.value = "";
    say("Telegram saved. Use “Send test message” to check it.");
  }));
  url.addEventListener("keydown", (e) => { if (e.key === "Enter") save.click(); });
  clr.addEventListener("click", async () => {
    if (!(await ask("Clear Telegram bot token", "Remove the stored bot token? kodeblue stops posting to Telegram until a new one is saved; notifications are still listed on the hub.", "Clear", true))) return;
    busy(clr, async () => { paint(await api("PUT", "/api/settings/telegram", { bot_token: "", chat_id: "" })); say("Telegram cleared."); });
  });
  sev.addEventListener("change", () => busy(sev, async () => { paint(await api("PUT", "/api/settings/telegram", { min_severity: sev.value })); say("Minimum severity set to " + sev.value + "."); }));
  test.addEventListener("click", () => busy(test, async () => {
    say("Sending…");
    const r = await api("POST", "/api/settings/telegram/test", {});
    if (r && r.ok) say("Test message delivered to Telegram."); else say("Test failed: " + ((r && r.error) || "unknown error"), true);
  }));
  body.append(
    panel("Telegram", h("div", { class: "bd stack" },
      h("div", { class: "setrow" }, h("span", { class: "fg" }, "Bot notifications"), status),
      h("div", { class: "note" }, "Create a bot with @BotFather. Start it privately, or add it to your group or channel with permission to send messages. Enter the destination chat ID or public channel username. The bot token is secret and never shown again. Notifications are one-way; replies do not run commands."),
      h("label", { class: "field" }, "Bot token", url),
      h("label", { class: "field" }, "Chat ID", chat),
      h("div", { class: "btns" }, save, clr),
      h("div", { class: "setrow" }, h("label", { class: "field inline" }, "Minimum severity", sev),
        h("span", { class: "note" }, "Notifications below this severity are listed on the hub but not posted.")),
      h("div", { class: "btns" }, test, h("a", { class: "small", href: "#/notifications" }, "Notification history")),
      msg), null, "purple"));
  try { paint(await api("GET", "/api/settings/telegram")); }
  catch (e) {
    if (e.status === 401) return;
    status.textContent = "unavailable";
    [url, chat, save, clr, sev, test].forEach((x) => { x.disabled = true; });
    say(e.status === 404 ? "This hub does not support Telegram settings yet." : "Could not load Telegram settings: " + e.message, true);
  }
}


// ---------- agent settings (fleet and per server) ----------
// Operators pick the model endpoint, a model per agent role, extra
// instructions per agent and a rule per containment action. The fleet has
// one set; a server can override single entries. Empty means "not set here".
const ROLE_NAMES = { default: "Default (every agent)", triage: "Triage", learner: "Learner", responder: "Responder (incidents)", reviewer: "Reviewer",
  operator: "Operator (hub chats)", critical: "Critical incidents", all: "All agents" };
const ACTION_NAMES = { block_ip: "Block an IP", disable_ssh_key: "Disable an SSH key", kill_process: "Kill a process", lock_user: "Lock a user",
  quarantine_file: "Quarantine a file", stop_unit: "Stop a service" };
const RULES = [["approve", "Needs approval"], ["auto", "Automatic"], ["off", "Off (recommend only)"]];
const MODES = [["off", "Off (recommend only)"], ["recommend", "Recommend (approve each action)"], ["contain", "Contain (act at once)"]];
const modeRank = (m) => MODES.findIndex(([v]) => v === m);
const roleName = (r) => ROLE_NAMES[r] || r;
const actionName = (a) => ACTION_NAMES[a] || String(a).replace(/_/g, " ");
const ruleName = (r) => (RULES.find((x) => x[0] === r) || [r, r])[1];
const utf8Len = (s) => new TextEncoder().encode(s).length; // the hub counts bytes

// statusLine is the quiet one-line result under a form: ok, bad or neutral.
function statusLine() {
  const el = h("div", { class: "smsg", role: "status" });
  return { el, say: (text, kind) => { el.textContent = text; el.className = "smsg" + (kind ? " " + kind : ""); } };
}
async function busyBtn(btn, line, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { if (e.status !== 401) line.say(e.status === 0 ? "Can't reach the hub." : e.message, "bad"); }
  finally { btn.disabled = false; }
}
// values turns [[key, input]] into the non-empty {key: value} the hub stores.
function values(rows) {
  const out = {};
  for (const [k, el] of rows) { const v = el.value.trim(); if (v) out[k] = v; }
  return out;
}

// ----- model connections and the model browser
const KIND_NAMES = { "inference-manager": "Inference manager", openrouter: "OpenRouter", "openai-compatible": "OpenAI-compatible" };
const kindName = (k) => KIND_NAMES[k] || k;
// origin is a URL's scheme, host and port ("" when it does not parse).
const origin = (u) => { try { return new URL(u).origin; } catch { return ""; } };

// catalog is one page's view of the connections and their models. The
// model list loads once and again after a connection changes.
function catalog(conns) {
  let p = null;
  const c = {
    conns: conns || [],
    models: (force) => {
      if (!p || force) p = api("GET", "/api/settings/models").catch((e) => ({ models: [], errors: {}, error: e.status === 401 ? "" : e.message }));
      return p;
    },
    name: (id) => {
      if (!id) return "server's own endpoint";
      const x = c.conns.find((k) => k.id === id);
      return x ? x.name || x.id : id + " (removed)";
    },
    label: (r) => r.model + " · " + c.name(r.connection) + (r.provider && r.provider !== "openrouter" ? " (" + r.provider + ")" : ""),
  };
  return c;
}
function modelDesc(m) {
  const n = (v) => String(Number((Number(v) || 0).toFixed(v < 1 ? 3 : 2)));
  const ctx = (c) => (c >= 1e6 ? n(c / 1e6) + "M" : Math.round(c / 1000) + "k") + " context";
  return [m.name && m.name !== m.id ? m.name : null, m.context_length ? ctx(m.context_length) : null,
    m.prompt_usd_per_mtok || m.completion_usd_per_mtok ? `$${n(m.prompt_usd_per_mtok)} in / $${n(m.completion_usd_per_mtok)} out per Mtok` : null].filter(Boolean).join(" · ");
}

// pickModel is the model browser: every connection's models in one
// searchable list, plus a free-form model id. Resolves to a ref or null.
function pickModel(title, cur, cat) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const q = h("input", { type: "search", class: "full", placeholder: "Search models, e.g. kimi, claude, glm", spellcheck: "false", autocomplete: "off", "aria-label": "Search models" });
    const connSel = h("select", { class: "sel", "aria-label": "Connection" }, h("option", { value: "" }, "All connections"),
      cat.conns.map((c) => h("option", { value: c.id }, c.name || c.id)));
    const list = h("div", { class: "mlist", role: "listbox", "aria-label": "Models" });
    // Agents call tools; a model the catalog says cannot is hidden unless asked for.
    const showNoTools = h("input", { type: "checkbox" });
    const noToolsBox = h("label", { class: "small faint", hidden: true }, showNoTools, " show models without tool calls");
    const info = h("div", { class: "faint small" }, "Loading models…");
    const errs = h("div", { class: "smsg bad", hidden: true });
    // A model id the catalog does not list.
    const ownConn = h("select", { class: "sel", "aria-label": "Connection for the model id" }, cat.conns.map((c) => h("option", { value: c.id, selected: cur && cur.connection === c.id }, c.name || c.id)));
    const ownProv = h("input", { type: "text", class: "full", placeholder: "provider label (inference manager only)", maxlength: 64, spellcheck: "false", autocomplete: "off", value: (cur && cur.provider) || "" });
    const ownId = h("input", { type: "text", class: "full", placeholder: "model id", maxlength: 200, spellcheck: "false", autocomplete: "off", value: (cur && cur.model) || "" });
    const kindOf = (id) => (cat.conns.find((c) => c.id === id) || {}).kind;
    const showProv = () => { ownProv.hidden = kindOf(ownConn.value) !== "inference-manager"; };
    ownConn.addEventListener("change", showProv);
    const use = h("button", { class: "btn small", type: "button" }, "Use this id");
    const pick = (r) => { finish(r); m.close(); };
    use.addEventListener("click", () => {
      const id = ownId.value.trim();
      if (!id || /\s/.test(id)) { ownId.focus(); return; }
      pick({ connection: ownConn.value, provider: kindOf(ownConn.value) === "inference-manager" ? ownProv.value.trim().toLowerCase() : "", model: id });
    });
    let all = [];
    const render = () => {
      const words = q.value.toLowerCase().split(/\s+/).filter(Boolean);
      const hits = all.filter((x) => (!connSel.value || x.connection === connSel.value) && (showNoTools.checked || !x.no_tools) &&
        words.every((w) => (x.id + " " + (x.name || "") + " " + (x.provider || "") + " " + cat.name(x.connection)).toLowerCase().includes(w)));
      const shown = hits.slice(0, 200);
      clear(list);
      add(list, shown.map((x) => {
        const on = cur && cur.connection === x.connection && cur.model === x.id;
        return h("button", { class: "mrow" + (on ? " on" : ""), type: "button", role: "option", "aria-selected": on ? "true" : "false",
          on: { click: () => pick({ connection: x.connection, provider: x.provider || "", model: x.id }) } },
        h("span", { class: "mrow-id mono" }, x.id),
        h("span", { class: "mrow-tags" }, x.no_tools ? h("span", { class: "badge b-warn", title: "kodeblue's agents need tool calls" }, "no tool calls") : null,
          h("span", { class: "badge" }, cat.name(x.connection)), x.provider ? h("span", { class: "badge" }, x.provider) : null),
        h("span", { class: "mrow-d faint small" }, modelDesc(x)));
      }));
      info.textContent = !all.length ? "No models listed. Enter a model id below." : hits.length > shown.length
        ? `Showing ${shown.length} of ${hits.length} matches: refine the search.` : `${hits.length} model${hits.length === 1 ? "" : "s"}`;
    };
    q.addEventListener("input", render);
    showNoTools.addEventListener("change", render);
    connSel.addEventListener("change", render);
    const m = modal(title, [
      h("div", { class: "setrow" }, h("div", { class: "grow" }, q), connSel),
      errs, list, h("div", { class: "setrow" }, info, h("div", { class: "grow" }), noToolsBox),
      h("details", { class: "fleet-i", open: !!(cur && cur.model) || null }, h("summary", null, "Use a model id that is not listed"),
        h("div", { class: "stack" }, h("div", { class: "setrow" }, ownConn, h("div", { class: "grow" }, ownId)), ownProv, h("div", { class: "btns" }, use))),
    ], [], () => finish(null));
    m.querySelector(".modal").classList.add("wide");
    showProv();
    q.focus();
    cat.models().then((r) => {
      all = (r && r.models) || [];
      const hidden = all.filter((x) => x.no_tools).length;
      noToolsBox.hidden = !hidden;
      noToolsBox.lastChild.textContent = ` show ${hidden} model${hidden === 1 ? "" : "s"} without tool calls`;
      const e = Object.entries((r && r.errors) || {});
      errs.hidden = !e.length && !(r && r.error);
      errs.textContent = (r && r.error) || e.map(([id, msg]) => cat.name(id) + ": " + msg).join(" · ");
      render();
    });
  });
}

// modelField shows a role's model and opens the browser to change it.
function modelField(ref, label, cat) {
  let cur = ref && ref.model ? { ...ref } : null, ph = "";
  const txt = h("span", { class: "mf-txt" });
  const btn = h("button", { class: "mf", type: "button", "aria-label": label + ": choose a model" }, txt, ic("chevDown", 12));
  const clr = h("button", { class: "ibtn", type: "button", "aria-label": "Clear the model for " + label, title: "Clear" }, ic("x", 12));
  const el = h("div", { class: "mfield" }, btn, clr);
  const paint = () => { txt.textContent = cur ? cat.label(cur) : ph; txt.classList.toggle("faint", !cur); clr.hidden = !cur; };
  const changed = () => { paint(); el.dispatchEvent(new Event("change", { bubbles: true })); };
  btn.addEventListener("click", async () => {
    if (!cat.conns.length) { toast("Add a model connection first", true); return; }
    const r = await pickModel(label, cur, cat);
    if (r) { cur = r; changed(); }
    btn.focus();
  });
  clr.addEventListener("click", () => { cur = null; changed(); });
  paint();
  return { el, get: () => cur, set: (r) => { cur = r && r.model ? { ...r } : null; paint(); }, placeholder: (t) => { ph = t; paint(); } };
}
// refs turns [[role, field]] into the {role: ref} the hub stores.
function refs(rows) {
  const out = {};
  for (const [role, f] of rows) { const r = f.get(); if (r) out[role] = r; }
  return out;
}

// connectionDialog adds a connection (conn null) or edits one.
function connectionDialog(conn, orUrl) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const kinds = ["inference-manager", "openrouter", "openai-compatible"];
    const radios = kinds.map((k) => h("input", { type: "radio", name: "conn-kind", value: k, checked: conn ? conn.kind === k : k === "openrouter", disabled: !!conn }));
    const kind = () => (radios.find((r) => r.checked) || {}).value;
    const name = h("input", { type: "text", class: "full", maxlength: 64, value: conn ? conn.name || "" : "", placeholder: "e.g. OpenRouter, Production gateway" });
    const base = h("input", { type: "url", class: "full", spellcheck: "false", autocomplete: "off", value: conn ? conn.base_url : "" });
    const key = h("input", { type: "password", class: "full", autocomplete: "new-password", spellcheck: "false",
      placeholder: conn && conn.has_key ? "Leave empty to keep the stored key" : "Paste the API key" });
    const help = h("div", { class: "note" });
    const baseField = h("label", { class: "field" }, "Base URL", base);
    const msg = statusLine();
    const paint = () => {
      const k = kind();
      baseField.hidden = k === "openrouter";
      base.placeholder = k === "inference-manager" ? "https://inference.example.com" : "https://api.example.com";
      clear(help).append(...{
        "inference-manager": ["A gateway that serves models from several vendors and lists each model's vendor in ", h("code", null, "/v1/models"), "."],
        openrouter: ["kodeblue calls ", h("code", null, orUrl), ". Create a key at ", h("a", { href: "https://openrouter.ai/keys", target: "_blank", rel: "noopener noreferrer" }, "openrouter.ai/keys"), "."],
        "openai-compatible": ["Any API that serves ", h("code", null, "{base}/v1/chat/completions"), " and ", h("code", null, "{base}/v1/models"), ": vLLM, Ollama, LiteLLM, a cloud vendor…"],
      }[k]);
      if (!conn && !name.dataset.typed) name.value = kindName(k);
    };
    name.addEventListener("input", () => { name.dataset.typed = "1"; });
    radios.forEach((r) => r.addEventListener("change", paint));
    const save = h("button", { class: "btn primary", type: "button" }, conn ? "Save" : "Add connection");
    save.addEventListener("click", () => busyBtn(save, msg, async () => {
      const k = kind();
      const url = k === "openrouter" ? (conn ? conn.base_url : orUrl) : base.value.trim();
      if (!url) { msg.say("Enter the base URL.", "bad"); base.focus(); return; }
      if (!conn && !key.value.trim()) { msg.say("Paste the API key.", "bad"); key.focus(); return; }
      // A stored key never follows the connection to a new host (the hub
      // refuses it too); a path change on the same host keeps it.
      if (conn && conn.has_key && !key.value.trim() && origin(url) !== origin(conn.base_url)) {
        msg.say("The endpoint moved to another host: enter its API key again. The stored key was saved for " + conn.base_url + " and never follows a connection to a new host.", "bad");
        key.focus();
        return;
      }
      const body = { kind: k, name: name.value.trim(), base_url: url, api_key: key.value.trim() };
      const r = conn ? await api("PUT", "/api/settings/connections/" + enc(conn.id), body) : await api("POST", "/api/settings/connections", body);
      finish(r);
      m.close();
    }));
    const m = modal(conn ? "Edit connection" : "Add model connection", [
      h("div", { class: "choice", role: "radiogroup", "aria-label": "Connection type" }, kinds.map((k, i) => h("label", null, radios[i], kindName(k)))),
      help,
      h("label", { class: "field" }, "Name", name),
      baseField,
      h("label", { class: "field" }, "API key", key),
      msg.el,
    ], [save], () => finish(null));
    paint();
    (conn ? name : radios.find((r) => r.checked)).focus();
  });
}

// connectionsPanel lists the fleet's connections. onChange runs after any
// change with the new list.
function connectionsPanel(cat, orUrl, onChange, onAdded) {
  const rows = h("div", { class: "mconns" });
  const msg = statusLine();
  const set = (list) => { cat.conns.splice(0, cat.conns.length, ...(list || [])); paint(); cat.models(true); onChange(); };
  const paint = () => {
    clear(rows);
    if (!cat.conns.length) {
      rows.append(h("div", { class: "note" }, "No connections yet. Without one, each server uses the model endpoint in its own kodeblue.toml."));
      return;
    }
    add(rows, cat.conns.map((c) => {
      const res = h("span", { class: "faint small" });
      const test = h("button", { class: "btn small", type: "button" }, "Test");
      const edit = h("button", { class: "btn small", type: "button" }, "Edit");
      const rm = h("button", { class: "btn small danger", type: "button" }, "Remove");
      test.addEventListener("click", async () => {
        test.disabled = true;
        res.className = "faint small";
        res.textContent = "Testing…";
        try {
          const r = await api("POST", "/api/settings/connections/" + enc(c.id) + "/test");
          res.className = "small " + (r.ok ? "c-green" : "c-red");
          res.textContent = r.ok ? `OK: ${r.models} models` : r.error;
        } catch (e) { res.className = "small c-red"; res.textContent = e.message; }
        finally { test.disabled = false; }
      });
      edit.addEventListener("click", async () => {
        const r = await connectionDialog(c, orUrl);
        if (r) { set(r.connections); msg.say("Saved. Servers using it pick the change up on their next sync.", "ok"); }
      });
      rm.addEventListener("click", async () => {
        if (!(await ask("Remove connection", ["Remove ", h("b", null, c.name || c.id), " and its key from the hub?"], "Remove", true))) return;
        busyBtn(rm, msg, async () => { const r = await api("DELETE", "/api/settings/connections/" + enc(c.id)); set(r.connections); msg.say("Connection removed.", "ok"); });
      });
      return h("div", { class: "mconn" },
        h("div", { class: "mconn-main" },
          h("div", { class: "setrow" }, h("b", null, c.name || c.id), h("span", { class: "badge" }, kindName(c.kind)),
            h("span", { class: "badge " + (c.has_key ? "b-ok" : "b-warn") }, c.has_key ? "key stored" : "no key")),
          h("div", { class: "mono small faint" }, c.base_url),
          h("div", { class: "small faint" }, c.used_by && c.used_by.length ? "Used by: " + c.used_by.join(", ") : "Not picked for any model yet"),
          res),
        h("div", { class: "btns" }, test, edit, rm));
    }));
  };
  const addBtn = h("button", { class: "btn primary", type: "button" }, ic("plus", 12), "Add connection");
  addBtn.addEventListener("click", async () => {
    const r = await connectionDialog(null, orUrl);
    if (!r) return;
    set(r.connections);
    msg.say("Connection added. Pick its models under Agent models.", "ok");
    if (onAdded) onAdded(msg);
  });
  paint();
  return { el: panel("Model connections", h("div", { class: "bd stack" },
    h("div", { class: "note" }, "Endpoints the agents reach models through. Connect several, an inference manager, OpenRouter and any OpenAI-compatible API, and pick a model from any of them per agent. Keys stay on the hub and go only to servers whose agents use that connection."),
    rows, h("div", { class: "btns" }, addBtn), msg.el), null, "blue"), refresh: (list) => set(list) };
}
function ruleSelect(value, first, label) {
  return h("select", { class: "sel", "aria-label": label }, h("option", { value: "" }, first),
    RULES.map(([v, l]) => h("option", { value: v, selected: v === value }, l)));
}
// instrBox is a textarea for one agent's instructions, with a size counter.
function instrBox(value, max, label) {
  const ta = h("textarea", { class: "ta", rows: 3, maxlength: max, "aria-label": label }, value || "");
  const n = h("span", { class: "faint small" });
  const upd = () => { const len = utf8Len(ta.value); n.textContent = len.toLocaleString() + " / " + max.toLocaleString(); n.classList.toggle("c-red", len > max); };
  ta.addEventListener("input", upd);
  upd();
  return { ta, n, el: (extra) => h("div", { class: "fblock" }, h("div", { class: "fhd" }, h("span", { class: "fg" }, label), h("div", { class: "sp" }), n), ta, extra || null) };
}
function approvalNote() {
  return h("div", { class: "note" }, "These rules can only make a server stricter than its own policy. “Automatic” only works on servers running contain (set in their root-owned ",
    h("code", null, "/etc/kodeblue/kodeblue.toml"), ", or switched to it here where that file allows); in the default recommend mode every action still needs approval.");
}

// fleetAgents fills the fleet half of the Settings view: model
// connections, then agent models, instructions and approvals (saved together).
async function fleetAgents(box) {
  let d;
  try { d = await api("GET", "/api/settings/agents"); }
  catch (e) {
    if (e.status === 401) return;
    box.appendChild(panel("Agents", h("div", { class: "bd" }, h("div", { class: "smsg bad" },
      e.status === 404 ? "This hub does not support agent settings yet." : "Could not load agent settings: " + e.message))));
    return;
  }
  const schema = d.schema || {};
  const fleet = d.fleet || {};
  const cat = catalog(d.connections);
  const orUrl = schema.openrouter_url || "https://openrouter.ai/api";

  const fm = fleet.models || {}, fi = fleet.instructions || {}, fa = fleet.approvals || {};
  const max = schema.max_instructions || 8000;
  const models = (schema.model_roles || []).map((role) => [role, modelField(fm[role], roleName(role), cat)]);
  const defF = (models.find(([r]) => r === "default") || [])[1];
  // An empty role uses Default; an empty Default leaves each server's own.
  const placeholders = () => {
    const def = defF && defF.get();
    for (const [role, f] of models) {
      f.placeholder(role === "default" ? "each server's own model" : role === "critical" ? "uses Responder" : def ? "uses Default: " + cat.label(def) : "uses Default");
    }
  };
  const conns = connectionsPanel(cat, orUrl, () => {
    placeholders();
    for (const [, f] of models) f.set(f.get()); // repaint connection names
    api("GET", "/api/me").then((r) => (S.info = r)).catch(() => {});
  }, async (msg) => {
    // A fresh hub's first connection: nothing uses the key until a Default
    // is picked, so ask now; adding a key is then all it needs before Add
    // server. Only the Default is saved, from the stored settings, so other
    // edits on this page stay unsaved.
    if (!defF || defF.get() || cat.conns.length !== 1) return;
    const r = await pickModel("Model for every agent", null, cat);
    if (!r) { msg.say("Connection added. Pick a Default model under Agent models so servers use it.", "ok"); return; }
    try {
      const cur = (await api("GET", "/api/settings/agents")).fleet || {};
      if ((cur.models || {}).default) { msg.say("Connection added. Another operator already picked a Default model; reload to see it.", "ok"); return; }
      const res = await api("PUT", "/api/settings/agents", { models: { ...(cur.models || {}), default: r }, instructions: cur.instructions || {}, approvals: cur.approvals || {}, response_mode: cur.response_mode || "" });
      defF.set(((res.fleet || {}).models || {}).default || r);
      placeholders();
      api("GET", "/api/settings/connections").then((x) => conns.refresh(x.connections)).catch(() => {});
      msg.say("Connection added; " + cat.label(r) + " is the Default model for every agent.", "ok");
    } catch (e) {
      msg.say("Connection added, but the Default model was not saved: " + e.message + ". Pick it under Agent models.", "bad");
    }
  });
  const instr = (schema.instruction_roles || []).map((role) => [role, instrBox(fi[role], max, roleName(role))]);
  const appr = (schema.actions || []).map((a) => [a, ruleSelect(fa[a], "Server policy (default)", actionName(a))]);
  const agSave = h("button", { class: "btn primary", type: "button" }, "Save agent settings");
  const agMsg = statusLine();
  const fill = (f) => {
    for (const [role, el] of models) el.set((f.models || {})[role]);
    for (const [role, b] of instr) { b.ta.value = (f.instructions || {})[role] || ""; b.ta.dispatchEvent(new Event("input")); }
    for (const [a, el] of appr) el.value = (f.approvals || {})[a] || "";
    placeholders();
  };
  agSave.addEventListener("click", () => busyBtn(agSave, agMsg, async () => {
    const r = await api("PUT", "/api/settings/agents", { models: refs(models), instructions: values(instr.map(([k, b]) => [k, b.ta])), approvals: values(appr), response_mode: fleet.response_mode || "" });
    fill(r.fleet || {});
    agMsg.say("Saved. Servers that take hub settings pick these up on their next sync.", "ok");
    api("GET", "/api/settings/connections").then((x) => conns.refresh(x.connections)).catch(() => {});
  }));
  const agents = h("div", { class: "stack" },
    panel("Agent models", h("div", { class: "bd stack" },
      h("div", { class: "note" }, "The model each agent uses on every server, from any connection. An empty role uses Default; critical incidents use the Responder's model unless set. Servers can override single roles on their Settings tab."),
      h("div", { class: "frows" }, models.map(([role, f]) => h("div", { class: "frow" }, h("span", { class: "frow-l" }, roleName(role)), f.el)))), null, "cyan"),
    panel("Agent instructions", h("div", { class: "bd stack" },
      h("div", { class: "note" }, "Extra instructions added after each agent's built-in prompt: “All agents” first, then the agent's own."),
      instr.map(([, b]) => b.el())), null, "green"),
    panel("Containment approvals", h("div", { class: "bd stack" },
      approvalNote(),
      h("div", { class: "frows" }, appr.map(([a, el]) => h("div", { class: "frow" }, h("span", { class: "frow-l" }, actionName(a)), el)))), null, "orange"),
    h("div", { class: "savebar" }, agSave, agMsg.el));
  agents.addEventListener("input", () => agMsg.say("Unsaved changes"));
  agents.addEventListener("change", () => { agMsg.say("Unsaved changes"); placeholders(); });

  // Server settings beyond the agents: saved on their own, so the agent
  // settings form above is unaffected.
  const tun = tuningForm(schema.tunings, fleet.tuning || {});
  tun.paint(() => "each server's own", null);
  const prot = protectForm(fleet, null);
  const svSave = h("button", { class: "btn primary", type: "button" }, "Save server settings");
  const svMsg = statusLine();
  svSave.addEventListener("click", () => busyBtn(svSave, svMsg, async () => {
    await api("PUT", "/api/settings/agents", { tuning: tun.values(), ...prot.values() });
    svMsg.say("Saved. Servers that take hub settings pick these up on their next sync.", "ok");
  }));
  const servers = h("div", { class: "stack" },
    panel("Server settings", h("div", { class: "bd stack" },
      h("div", { class: "note" }, "Budget, schedule, detection noise, notifications and the hub link for every server. An empty field leaves each server's own value from its ",
        h("code", null, "/etc/kodeblue/kodeblue.toml"), ". A server's Settings tab can override single values. Each value has bounds, and a server never takes a daily budget above its own ",
        h("code", null, "[budget] hub_max_daily_usd"), " ($20 unless set)."),
      tun.el), null, "purple"),
    panel("Protected users, IPs and services", h("div", { class: "bd stack" }, prot.el), null, "red"),
    h("div", { class: "savebar" }, svSave, svMsg.el));
  servers.addEventListener("input", () => svMsg.say("Unsaved changes"));
  servers.addEventListener("change", () => svMsg.say("Unsaved changes"));

  box.append(conns.el, agents, servers);
  placeholders();
}

// ----- server tuning and protections (fleet Settings and a server's tab)
// tuningForm has one field per server setting the hub may set (the hub's
// schema lists them with their bounds), grouped as on the server. An empty
// field inherits; hint(t) says what from. fmtTuning shows a value.
const fmtTuning = (t, v) => v === undefined || v === "" ? "" : t.kind === "usd" ? "$" + v : t.kind === "bool" ? (v === "true" ? "yes" : "no") : String(v);
// Settings a hub may only tighten (hubproto.Tuning.Only).
const TUNE_ONLY = {
  lower: "Only tightens: a server keeps its own value when it is lower (or off).",
  raise: "Only tightens: a server keeps its own value when it is higher.",
};
function tuningForm(defs, vals) {
  const fields = (defs || []).map((t) => {
    let el;
    if (t.kind === "bool" || t.kind === "severity") {
      const opts = t.kind === "bool" ? [["true", "Yes"], ["false", "No"]] : ["info", "low", "medium", "high", "critical"].map((v) => [v, v]);
      el = h("select", { class: "sel", "aria-label": t.label }, h("option", { value: "" }, ""), opts.map(([v, l]) => h("option", { value: v, selected: v === vals[t.key] }, l)));
    } else {
      el = h("input", { type: "number", class: "full num", min: t.min, max: t.max, step: t.kind === "usd" ? "0.01" : "1", "aria-label": t.label, value: vals[t.key] || "" });
    }
    return { t, el, now: h("span", { class: "frow-now faint small mono" }) };
  });
  const groups = [...new Set(fields.map((f) => f.t.group))];
  return {
    el: h("div", { class: "stack" }, groups.map((g) => h("div", { class: "fblock" }, h("div", { class: "fhd strong" }, g),
      h("div", { class: "frows" }, fields.filter((f) => f.t.group === g).map((f) => {
        const help = [f.t.help, TUNE_ONLY[f.t.only]].filter(Boolean).join(" ");
        return h("div", { class: "frow c3", title: help || null },
          h("span", { class: "frow-l" }, f.t.label, help ? h("span", { class: "faint small block" }, help) : null), f.el, f.now);
      }))))),
    // hint(t) is what an empty field means; reported is what the server runs.
    paint(hint, reported) {
      for (const f of fields) {
        const hv = hint(f.t);
        if (f.el.tagName === "SELECT") f.el.options[0].textContent = hv;
        else f.el.placeholder = hv;
        const r = reported && reported[f.t.key];
        f.now.textContent = r !== undefined && r !== "" ? "now: " + fmtTuning(f.t, r) : "";
      }
    },
    values() {
      const out = {};
      for (const f of fields) { const v = String(f.el.value).trim(); if (v) out[f.t.key] = v; }
      return out;
    },
  };
}
// protectForm: protected users, IPs and services the hub adds (one per
// line), and a lower containment rate limit.
function protectForm(cur, fleetCur) {
  const box = (label, v) => h("textarea", { class: "ta", rows: 2, spellcheck: "false", "aria-label": label, placeholder: "one per line" }, (v || []).join("\n"));
  const users = box("Protected users", cur.protected_users), ips = box("Protected IPs", cur.protected_ips), units = box("Protected services", cur.protected_units);
  const rate = h("input", { type: "number", class: "full num", min: 1, max: 1000, step: 1, "aria-label": "Containment actions per hour", value: cur.max_actions_per_hour || "" });
  rate.placeholder = fleetCur && fleetCur.max_actions_per_hour ? "inherits fleet: " + fleetCur.max_actions_per_hour : "the server's own limit";
  const fleetNote = (l) => fleetCur && (l || []).length ? h("div", { class: "faint small" }, "The fleet adds: " + l.join(", ")) : null;
  const lines = (ta) => ta.value.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
  return {
    el: h("div", { class: "stack" },
      h("div", { class: "note" }, "Added to each server's own protected lists in its root-owned ", h("code", null, "/etc/kodeblue/kodeblue.toml"),
        ", never in place of them: agents may not lock these users, block these IPs (or CIDRs) or stop these services. The limit can only lower the server's own."),
      h("div", { class: "frows" },
        h("div", { class: "frow" }, h("span", { class: "frow-l" }, "Users"), h("div", null, users, fleetNote(fleetCur && fleetCur.protected_users))),
        h("div", { class: "frow" }, h("span", { class: "frow-l" }, "IPs and CIDRs"), h("div", null, ips, fleetNote(fleetCur && fleetCur.protected_ips))),
        h("div", { class: "frow" }, h("span", { class: "frow-l" }, "Services"), h("div", null, units, fleetNote(fleetCur && fleetCur.protected_units))),
        h("div", { class: "frow" }, h("span", { class: "frow-l" }, "Containment actions per hour"), rate))),
    values: () => ({ protected_users: lines(users), protected_ips: lines(ips), protected_units: lines(units), max_actions_per_hour: Number(rate.value) || 0 }),
  };
}

// ----- per-server settings tab
async function vServerSettings(srv, body) {
  let paintApplied = null;
  const draw = async (flash) => {
    let d;
    try { d = await api("GET", `/api/servers/${enc(srv.id)}/settings`); }
    catch (e) {
      if (e.status === 401) return;
      sync(body, h("div", { class: "panel" }, h("div", { class: "empty" }, e.status === 404 ? "This hub does not support per-server settings yet." : "Could not load settings: " + e.message)));
      return;
    }
    const schema = d.schema || {};
    const own = d.server || {}, fleet = d.fleet || {};
    const om = own.models || {}, oi = own.instructions || {}, oa = own.approvals || {};
    const fm = fleet.models || {}, fi = fleet.instructions || {}, fa = fleet.approvals || {};
    const max = schema.max_instructions || 8000;
    const cat = catalog(d.connections);
    const state = h("div", { class: "bd stack" });
    const models = (schema.model_roles || []).map((role) => [role, modelField(om[role], roleName(role), cat)]);
    const now = {};
    const defF = (models.find(([r]) => r === "default") || [])[1];
    // The placeholder is what the role gets without an override here.
    const placeholders = () => {
      const def = (defF && defF.get()) || fm.default;
      for (const [role, f] of models) {
        const v = role === "default" ? fm.default : fm[role] || (role === "critical" ? null : def);
        f.placeholder(v ? "inherits " + cat.label(v) : role === "critical" ? "inherits Responder" : "the server's own model");
      }
    };
    placeholders();
    const instr = (schema.instruction_roles || []).map((role) => [role, instrBox(oi[role], max, roleName(role))]);
    const appr = (schema.actions || []).map((a) => [a, ruleSelect(oa[a], "Inherit fleet (" + (fa[a] ? ruleName(fa[a]).replace(/ \(.*\)$/, "") : "server policy") + ")", actionName(a))]);
    const badges = {};
    const ft = fleet.tuning || {};
    const tun = tuningForm(schema.tunings, own.tuning || {});
    const tunHint = (t) => ft[t.key] ? "inherits fleet: " + fmtTuning(t, ft[t.key]) : "the server's own";
    const prot = protectForm(own, fleet);
    const modeNote = h("div", { class: "callout warn", hidden: true });
    // Response mode: the hub switches it up to the server's root ceiling.
    const modeOpts = MODES.map(([v, l]) => h("option", { value: v, selected: v === own.response_mode }, l));
    const modeOwn = h("option", { value: "" }, fleet.response_mode ? "Inherit fleet (" + fleet.response_mode + ")" : "Server's own policy");
    const modeSel = h("select", { class: "sel", "aria-label": "Response mode" }, modeOwn, modeOpts);
    const modeNow = h("span", { class: "frow-now" });
    const modeCap = h("div", { class: "note", hidden: true });
    const save = h("button", { class: "btn primary", type: "button" }, "Save overrides");
    const reset = h("button", { class: "btn danger", type: "button" }, "Clear overrides");
    const msg = statusLine();
    reset.hidden = !Object.keys(om).length && !Object.keys(oi).length && !Object.keys(oa).length && !own.response_mode && !Object.keys(own.tuning || {}).length &&
      !(own.protected_users || []).length && !(own.protected_ips || []).length && !(own.protected_units || []).length && !own.max_actions_per_hour;
    save.addEventListener("click", () => busyBtn(save, msg, async () => {
      await api("PUT", `/api/servers/${enc(srv.id)}/settings`, { models: refs(models), instructions: values(instr.map(([k, b]) => [k, b.ta])), approvals: values(appr), response_mode: modeSel.value,
        tuning: tun.values(), ...prot.values() });
      await draw("Saved. The server picks these up on its next sync.");
    }));
    reset.addEventListener("click", async () => {
      if (!(await ask("Clear overrides", "Remove every override for " + srv.name + "? It goes back to the fleet settings.", "Clear overrides", true))) return;
      busyBtn(reset, msg, async () => {
        await api("PUT", `/api/servers/${enc(srv.id)}/settings`, { models: {}, instructions: {}, approvals: {}, response_mode: "", tuning: {}, protected_users: [], protected_ips: [], protected_units: [], max_actions_per_hour: 0 });
        await draw("Overrides cleared. The server goes back to the fleet settings on its next sync.");
      });
    });
    // paintApplied repaints what the server reports, never the form.
    paintApplied = (x) => {
      const a = x.applied || {}, eff = x.effective || {};
      const reporting = srv.enrolled && !srv.revoked && (srv.status || {}).phase;
      const [cls, label, text] = !reporting ? ["", "not reporting yet", "This server has not reported to the hub yet. Overrides saved here apply once it connects and takes hub settings."]
        : !a.accepts_settings ? ["", "does not take hub settings", null]
          : a.in_sync ? ["b-ok", "applied", "The server runs the settings below."]
            : ["b-warn", "waiting for the server", "The server picks these settings up on its next sync (about 15 seconds) and restarts kodeblue once no agent is working."];
      const ec = eff.connections || [];
      // append() would print a null child as "null"; h() skips them.
      clear(state).append(...[
        h("div", { class: "setrow" }, h("span", { class: "badge " + cls }, label), h("span", { class: "fg" }, reporting && !a.accepts_settings ? "This server does not take settings from the hub." : text)),
        reporting && !a.accepts_settings ? h("div", { class: "note" }, "It runs with ", h("code", null, "[hub] accept_settings = false"), " in ", h("code", null, "/etc/kodeblue/kodeblue.toml"),
          " (or a kodeblue version without hub settings) and keeps its own models, instructions and rules. Overrides saved here apply once it takes hub settings.") : null,
        h("dl", { class: "kv" },
          h("dt", null, "Connections"), h("dd", null, ec.length ? ec.map((c) => (c.name || c.id) + " (" + kindName(c.kind) + ")").join(", ") : "none from the hub; the server uses the endpoint in its own kodeblue.toml"),
          h("dt", null, "Version"), h("dd", { class: "mono small" }, (eff.version || "—") + (a.settings_version && a.settings_version !== eff.version ? " · server has " + a.settings_version : "")),
          h("dt", null, "Fleet"), h("dd", null, h("a", { href: "#/settings" }, "Fleet settings")))].filter(Boolean));
      tun.paint(tunHint, a.tuning);
      const am = a.models || {}, aa = a.actions || {};
      for (const [role, el] of Object.entries(now)) { el.textContent = am[role] ? "now: " + am[role] : ""; el.title = am[role] ? am[role] + " (reported by the server)" : ""; }
      for (const [act, el] of Object.entries(badges)) {
        const r = aa[act];
        el.className = "badge " + ({ auto: "b-bad", approve: "b-warn" }[r] || "");
        el.textContent = r ? { auto: "automatic", approve: "needs approval", off: "off" }[r] || r : "not reported";
        el.title = "the rule this server applies now";
      }
      const mode = a.response_mode, root = a.root_response_mode || "", ceiling = a.response_mode_ceiling || root;
      modeNote.hidden = !reporting || !mode || mode === "contain";
      clear(modeNote).append(h("div", { class: "lbl" }, "Response mode: " + (mode || "?")),
        mode === "off" ? "Containment is off on this server, so no action runs at all." : "This server asks for approval for every action, so “Automatic” has no effect here.");
      clear(modeNow).append(reporting && mode ? modeBadge(mode) : h("span", { class: "faint small" }, "not reported"));
      modeOwn.textContent = (fleet.response_mode ? "Inherit fleet (" + fleet.response_mode + ")" : "Server's own policy") + (root ? " · own: " + root : "");
      for (const o of modeOpts) {
        const above = !!ceiling && modeRank(o.value) > modeRank(ceiling);
        o.disabled = above && o.value !== modeSel.value;
        o.textContent = MODES.find(([v]) => v === o.value)[1] + (above ? " (not allowed by this server)" : "");
      }
      const capped = ceiling && modeSel.value && modeRank(modeSel.value) > modeRank(ceiling);
      modeCap.hidden = !ceiling || ceiling === "contain";
      clear(modeCap).append(capped ? "This server lets the hub choose at most “" + ceiling + "”, so it runs “" + ceiling + "”. " : "This server lets the hub choose at most “" + ceiling + "”. ",
        "To let the hub switch it to contain, its root sets ", h("code", null, "hub_max_mode = \"contain\""), " under ", h("code", null, "[response]"), " in ", h("code", null, "/etc/kodeblue/kodeblue.toml"),
        " (or reruns the installer with ", h("code", null, "--hub-max-mode contain"), ") and restarts kodeblue.");
    };
    sync(body, h("div", { class: "stack narrow" },
      panel("Hub settings for " + srv.name, state, null, "blue"),
      panel("Models", h("div", { class: "bd stack" },
        h("div", { class: "note" }, "Override the model for single roles on this server. Empty fields inherit the fleet setting shown in grey."),
        h("div", { class: "frows" }, models.map(([role, f]) => h("div", { class: "frow c3" }, h("span", { class: "frow-l" }, roleName(role)), f.el,
          now[role] = h("span", { class: "frow-now faint small mono" }))))), null, "cyan"),
      panel("Instructions", h("div", { class: "bd stack" },
        h("div", { class: "note" }, "An override replaces the fleet instructions for that agent on this server. They are added after the agent's built-in prompt."),
        instr.map(([role, b]) => b.el(fi[role] ? h("details", { class: "fleet-i" }, h("summary", null, "Fleet instructions (used when this is empty)"), h("div", { class: "ftext" }, fi[role]))
          : h("div", { class: "faint small" }, "No fleet instructions for this agent.")))), null, "green"),
      panel("Response mode", h("div", { class: "bd stack" },
        h("div", { class: "note" }, "What kodeblue does when it finds an attack on this server. Off: agents only recommend actions in their reports. Recommend: every action waits for an operator's approval. Contain: actions run at once, including monitor reflexes that kill a payload or quarantine a dropped file seconds after it appears. The hub can switch up to what the server's root-owned ",
          h("code", null, "/etc/kodeblue/kodeblue.toml"), " allows (its mode, or hub_max_mode), never above it. Every change is announced through configured notification destinations."),
        h("div", { class: "frows" }, h("div", { class: "frow c3" }, h("span", { class: "frow-l" }, "Mode"), modeSel, modeNow)),
        modeCap), null, "red"),
      panel("Containment approvals", h("div", { class: "bd stack" },
        approvalNote(),
        modeNote,
        h("div", { class: "frows" }, appr.map(([a, el]) => h("div", { class: "frow c3" }, h("span", { class: "frow-l" }, actionName(a)), el,
          h("span", { class: "frow-now" }, badges[a] = h("span", { class: "badge" })))))), null, "orange"),
      panel("Server settings", h("div", { class: "bd stack" },
        h("div", { class: "note" }, "Override single values for this server. Empty fields inherit the fleet's value, or the server's own from its kodeblue.toml; “now” is what the server reports it runs."),
        tun.el), null, "purple"),
      panel("Protected users, IPs and services", h("div", { class: "bd stack" }, prot.el), null, "red"),
      h("div", { class: "savebar" }, save, reset, msg.el)));
    body.querySelector(".narrow").addEventListener("input", () => msg.say("Unsaved changes"));
    body.querySelector(".narrow").addEventListener("change", () => { msg.say("Unsaved changes"); placeholders(); });
    paintApplied(d);
    if (flash) msg.say(flash, "ok");
  };
  await draw();
  // Follow the server's sync state; the form is left alone.
  setTimer(async () => {
    if (!paintApplied || !body.isConnected) return;
    try { paintApplied(await api("GET", `/api/servers/${enc(srv.id)}/settings`)); } catch { /* keep the last state */ }
  }, 8000);
}

// ---------- audit ----------
async function vAudit(main) {
  let list = [];
  try { list = await api("GET", "/api/audit"); } catch (e) { if (e.status === 401) return; main.appendChild(h("div", { class: "empty" }, e.message)); return; }
  main.append(h("div", { class: "toolbar" }, h("h1", null, "Audit log")),
    h("div", { class: "note mb" }, "Everything operators and servers did on the hub: sign-ins, servers added or revoked, enrollments, and every message sent to an agent."),
    h("div", { class: "panel" }, h("div", { class: "bd flush tbl-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["When", "Who", "Action", "Server", "Detail", "IP"].map((t) => h("th", null, t)))),
      h("tbody", null, (list || []).map((a) => h("tr", null, h("td", { class: "nowrap small muted" }, when(a.at)), h("td", null, a.actor), h("td", null, h("span", { class: "badge" + (a.action.includes("failed") ? " b-bad" : "") }, a.action)),
        h("td", { class: "mono small" }, a.server_id ? h("a", { href: "#/s/" + enc(a.server_id) }, serverName(a.server_id)) : ""), h("td", { class: "small" }, a.detail || ""), h("td", { class: "mono small muted" }, a.ip || ""))))))));
}

window.addEventListener("resize", () => applyWidth());
route();
