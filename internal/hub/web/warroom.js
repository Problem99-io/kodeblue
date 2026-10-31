// War room is a drawer above the current page. All source/provider data is
// untrusted and rendered through text nodes; the map has no remote tile server.
"use strict";
const WAR = { open: false, request: 0, hours: "24", server: "", severity: "", query: "", selected: null, eventLimit: 50, camera: { x: 0, y: 0, width: 1000, height: 500 }, data: null, land: null, timer: null };

function mountWarRoom() {
  let tab = document.getElementById("war-tab");
  if (!tab) {
    tab = h("button", { id: "war-tab", class: "war-tab", type: "button", "aria-controls": "war-room", "aria-expanded": "false", on: { click: () => WAR.open ? closeWarRoom() : openWarRoom() } },
      ic("layers", 15), h("span", null, "War room"), ic("chevRight", 12));
    const drawer = h("div", { id: "war-drawer", class: "war-drawer" }, tab);
    document.body.append(drawer);
  }
  tab.hidden = !S.me;
}

function openWarRoom() {
  if (WAR.open || !S.me) return;
  WAR.open = true;
  document.querySelectorAll(".menu").forEach((el) => el.remove());
  const tab = document.getElementById("war-tab");
  const drawer = document.getElementById("war-drawer");
  tab.setAttribute("aria-expanded", "true"); tab.title = "Close war room";
  WAR.background = [...document.body.children].filter((el) => el !== drawer && el.tagName !== "SCRIPT").map((el) => ({ el, inert: el.inert }));
  for (const entry of WAR.background) entry.el.inert = true;
  document.body.classList.add("war-open");
  WAR.backdrop = h("div", { class: "war-backdrop", on: { click: closeWarRoom } });
  WAR.shell = h("section", { id: "war-room", class: "war-shell", role: "dialog", "aria-modal": "true", "aria-labelledby": "war-title" });
  const close = h("button", { class: "ibtn", type: "button", "aria-label": "Close war room", on: { click: closeWarRoom } }, ic("x", 18));
  const range = h("select", { class: "sel", "aria-label": "Activity time range" }, [["1", "Last hour"], ["24", "Last 24 hours"], ["168", "Last 7 days"], ["720", "Last 30 days"]].map(([value, label]) => h("option", { value }, label)));
  range.value = WAR.hours;
  range.addEventListener("change", () => { WAR.hours = range.value; WAR.selected = null; refreshWarRoom(); });
  const servers = h("select", { class: "sel", "aria-label": "Filter source activity by server" }, h("option", { value: "" }, "All servers"), S.servers.map((srv) => h("option", { value: srv.id }, srv.name)));
  servers.value = WAR.server;
  servers.addEventListener("change", () => { WAR.server = servers.value; WAR.selected = null; refreshWarRoom(); });
  const severity = h("select", { class: "sel", "aria-label": "Filter source activity by severity" }, h("option", { value: "" }, "All severities"), ["critical", "high", "medium", "low", "info"].map((s) => h("option", { value: s }, s)));
  severity.value = WAR.severity;
  severity.addEventListener("change", () => { WAR.severity = severity.value; WAR.selected = null; paintWarRoom(); });
  const query = h("input", { type: "search", class: "war-search", placeholder: "Search IP, provider, location…", "aria-label": "Search source activity", value: WAR.query });
  query.addEventListener("input", () => { WAR.query = query.value; WAR.selected = null; paintWarRoom(); });
  WAR.status = h("span", { class: "war-sync", role: "status" }, "Loading activity…");
  WAR.stats = h("div", { class: "war-stats" });
  WAR.map = h("div", { class: "war-map", "aria-label": "World map of source activity" });
  WAR.recent = h("div", { class: "war-recent" });
  WAR.researchHost = h("div", {id:"war-research-panel",class:"war-research-host", hidden:true});
  WAR.researchGraph = null;
  WAR.inspector = h("aside", { class: "war-inspector", "aria-label": "Source and incident details", "aria-live": "polite" });
  WAR.config = h("div", { class: "war-config", hidden: true });
  WAR.notice = h("div", { class: "war-notice", hidden: true, role: "status" });
  const settings = h("button", { class: "btn small", type: "button", "aria-expanded": "false", on: { click: () => { WAR.config.hidden = !WAR.config.hidden; settings.setAttribute("aria-expanded", String(!WAR.config.hidden)); if (!WAR.config.hidden) paintWarSettings(); } } }, ic("sliders", 13), "Enrichment");
  WAR.settingsButton = settings;
  WAR.researchButton=h("button",{class:"btn small",type:"button","aria-expanded":"false","aria-controls":"war-research-panel",on:{click:()=>toggleWarResearch(!WAR.researchOpen)}},ic("layers",13),"Research layer");
  WAR.shell.append(
    h("div", { class: "war-heading" }, h("div", { class: "war-wordmark" }, ic("layers", 20), h("div", null, h("h1", { id: "war-title" }, "War room"), h("div", { class: "small faint" }, "Source activity · evidence · agent council"))), h("div", { class: "sp" }), WAR.status, WAR.researchButton, settings, close),
    h("div", { class: "war-filters" }, range, servers, severity, h("div", { class: "sp" }), query), WAR.config, WAR.notice, WAR.stats,
    h("div", { class: "war-grid" }, h("div", { class: "war-theater" },
      h("div", { class: "war-map-top" }, h("span", null, "SOURCE ORIGINS"), h("span", { class: "war-live" }, h("span", { class: "dot on" }), "Live activity")),
      WAR.map,
      h("div", { class: "war-map-foot" }, h("span", null, "IP locations are approximate; a location may represent a VPN, proxy, or hosting exit."), h("span", null, "Map: Natural Earth")),
      WAR.recent,WAR.researchHost), WAR.inspector));
  WAR.shell.addEventListener("keydown", warKeys);
  document.body.append(WAR.backdrop);
  drawer.append(WAR.shell);
  requestAnimationFrame(() => { if (WAR.open) drawer.classList.add("on"); });
  close.focus();
  const reopenResearch=WAR.researchOpen;WAR.researchOpen=false;if(reopenResearch)toggleWarResearch(true);
  refreshWarRoom();
  WAR.timer = setInterval(() => { if (!document.hidden && WAR.open) refreshWarRoom(); }, 60000);
}

function closeWarRoom() {
  if (!WAR.open) return;
  WAR.open = false; WAR.request++;
  window.KodeBlueResearch?.close();WAR.researchGraph=null;
  clearInterval(WAR.timer);
  for (const entry of WAR.background || []) if (entry.el.isConnected) entry.el.inert = entry.inert;
  WAR.background = [];
  document.body.classList.remove("war-open");
  const shell = WAR.shell, backdrop = WAR.backdrop;
  shell.parentElement.classList.remove("on");
  backdrop.remove();
  setTimeout(() => shell.remove(), 340);
  const tab = document.getElementById("war-tab");
  if (tab) { tab.setAttribute("aria-expanded", "false"); tab.title = "Open war room"; tab.focus(); tab.hidden = !S.me; }
}

function warKeys(e) {
  if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeWarRoom(); }
  if (e.key !== "Tab") return;
  const nodes = [...WAR.shell.querySelectorAll('a,button,input,select,[tabindex="0"]')].filter((el) => !el.disabled && el.getClientRects().length);
  const first = nodes[0], last = nodes[nodes.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}

function toggleWarResearch(enabled,focusPanel=false){
  if(!WAR.open || !WAR.researchHost)return;
  if(WAR.researchOpen===enabled)return;
  WAR.researchOpen=enabled;WAR.researchHost.hidden=!enabled;
  WAR.researchButton.setAttribute("aria-expanded",String(enabled));
  if(!enabled){window.KodeBlueResearch?.close();WAR.researchGraph=null;paintWarRoom();return;}
  WAR.researchHost.textContent="Loading behavioral evidence…";
  let first=true;
  window.KodeBlueResearch.mount(WAR.researchHost,{onGraph:data=>{if(!WAR.open || !WAR.researchOpen)return;WAR.researchGraph=data;paintWarRoom();if(first&&focusPanel)WAR.researchHost.scrollIntoView({block:"start"});first=false;}}).catch(()=>{if(WAR.open && WAR.researchOpen)WAR.researchHost.textContent="Research layer unavailable. Source locations and incidents remain available.";});
}

// Relationships reuse only already available War room locations. No additional
// lookup or change to enrichment consent is caused by enabling this layer.
function paintWarResearchLinks(map,groups){
  if(!WAR.researchOpen || !WAR.researchGraph)return;
  const locations=new Map();
  for(const group of groups){if(!group.located)continue;for(const source of group.sources)locations.set(source.ip,warProject(group.longitude,group.latitude));}
  const cutoff=Date.now()-Number(WAR.hours)*3600000;
  const edges=WAR.researchGraph.edges.filter(e=>(!WAR.server||e.producer_id===WAR.server)&&new Date(e.last_at).getTime()>=cutoff);
  const layer=svg("g",{class:"war-research-links","aria-label":"Behavioral evidence relationships"});let drawn=0;
  const connect=(a,b,relation,evidence)=>{
    if(drawn>=40)return;const from=locations.get(a),to=locations.get(b);if(!from||!to||a===b)return;
    const midX=(from[0]+to[0])/2,midY=(from[1]+to[1])/2-35;
    const path=svg("path",{d:`M${from[0]} ${from[1]} Q${midX} ${midY} ${to[0]} ${to[1]}`,class:relation==="producer_reported_connection"?"research-connection":"research-similarity",tabindex:"0",role:"button","aria-label":`${relation}: ${a} to ${b}`});
    const title=svg("title");title.textContent=`${a} → ${b} · ${relation} · identity not established`;path.append(title);
    const inspect=()=>{const result=h("div",{class:"war-inspector-head"},h("h2",null,"Research relationship"),h("p",null,`${a} → ${b}`),h("p",null,relation==="producer_reported_connection"?"An enrolled source reported this connection. Verify the source evidence and capture point.":"These observations share a fingerprint. This does not establish a connection or the same actor."),h("pre",{class:"war-context"},JSON.stringify({relation,evidence_ids:evidence,identity:"not_established"},null,2)));clear(WAR.inspector).append(result);};
    path.addEventListener("click",inspect);path.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();inspect();}});layer.append(path);drawn++;
  };
  const fingerprints=new Map();
  for(const edge of edges){
    if(edge.relation==="producer_reported_connection")connect(edge.source_ip,edge.target_ip,edge.relation,edge.evidence);
    else if(edge.source_ip){if(!fingerprints.has(edge.target))fingerprints.set(edge.target,[]);fingerprints.get(edge.target).push(edge);}
  }
  for(const members of fingerprints.values()){for(let i=1;i<Math.min(members.length,8);i++)connect(members[0].source_ip,members[i].source_ip,"shared_fingerprint",[...members[0].evidence,...members[i].evidence].slice(0,12));}
  map.append(layer);
}

async function refreshWarRoom() {
  const request = ++WAR.request;
  try {
    const data = await api("GET", `/api/war-room?hours=${enc(WAR.hours)}&server_id=${enc(WAR.server)}`);
    if (!WAR.open || request !== WAR.request) return;
    WAR.data = data;
 if (!data.settings.enabled && !WAR.consentShown) { WAR.consentShown=true; WAR.config.hidden=false; WAR.settingsButton.setAttribute("aria-expanded","true"); paintWarSettings(); }
    WAR.status.textContent = "Updated " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    paintWarRoom();
    if (!WAR.land) {
      try {
        const r = await fetch("/assets/world-land.json", { credentials: "same-origin" });
        if (!r.ok) throw new Error("map unavailable");
        WAR.land = await r.json();
        if (WAR.open) paintWarRoom();
      } catch { if (WAR.open) WAR.status.textContent = "Map background unavailable; source details remain available"; }
    }
  } catch (e) { if (WAR.open && request === WAR.request && e.status !== 401) WAR.status.textContent = "Could not refresh activity: " + e.message; }
}

function warGroups() {
  const query = WAR.query.trim().toLowerCase(), groups = new Map();
  for (const source of WAR.data.sources) {
    const intel = source.intel || {};
    const matchesSource = [source.ip, intel.provider, intel.asn, intel.type, intel.city, intel.country].join(" ").toLowerCase().includes(query);
    const events = source.events.filter((event) => (!WAR.severity || event.severity === WAR.severity) && (!query || matchesSource || [event.title, event.detail, event.server_name, event.context].join(" ").toLowerCase().includes(query)));
    if (!events.length) continue;
    const located = typeof intel.latitude === "number" && typeof intel.longitude === "number";
    const key = located ? intel.latitude.toFixed(1) + "," + intel.longitude.toFixed(1) : "unmapped:" + source.ip;
    if (!groups.has(key)) groups.set(key, { key, located, latitude: intel.latitude, longitude: intel.longitude, name: located ? [intel.city, intel.country].filter(Boolean).join(", ") || "Located source" : source.public ? "Location unavailable" : "Private or reserved network", sources: [], events: [] });
    const group = groups.get(key);
    group.sources.push({ ...source, events }); group.events.push(...events);
  }
  for (const group of groups.values()) {
    group.events = [...new Map(group.events.map((event) => [event.server_id + ":" + event.finding_id, event])).values()].sort((a, b) => new Date(b.last_at) - new Date(a.last_at));
    group.severity = group.events.reduce((value, event) => warRank(event.severity) > warRank(value) ? event.severity : value, "info");
  }
  return [...groups.values()].sort((a, b) => b.events.length - a.events.length || a.key.localeCompare(b.key));
}
const warRank = (s) => ["info", "low", "medium", "high", "critical"].indexOf(s);
const warProject = (lon, lat) => [(lon + 180) * 1000 / 360, (90 - lat) * 500 / 180];

function paintWarRoom() {
  if (!WAR.open || !WAR.data) return;
  const groups = warGroups(), sources = groups.flatMap((g) => g.sources);
  const events = [...new Map(groups.flatMap((g) => g.events).map((e) => [e.server_id + ":" + e.finding_id, e])).values()];
  const cases = new Set(events.filter((e) => e.incident_id).map((e) => e.server_id + ":" + e.incident_id));
  clear(WAR.stats).append(...[[sources.length, "Source IPs"], [groups.filter((g) => g.located).length, "Locations"], [cases.size, "Linked incidents"], [events.length, "Registered findings"]].map(([count, label]) => h("div", { class: "war-stat" }, h("span", { class: "war-stat-n" }, count.toLocaleString()), h("span", { class: "faint small" }, label))));
  WAR.notice.hidden = !WAR.data.truncated;
  WAR.notice.textContent = WAR.data.truncated ? `Showing the latest ${WAR.data.limit.toLocaleString()} source records. Narrow the time range or choose a server to see more.` : "";
  const selected = groups.find((g) => g.key === WAR.selected);
  if (!selected) WAR.selected = null;
  paintWarMap(groups);
  paintWarInspector(groups, selected);
  const recent = events.sort((a, b) => new Date(b.last_at) - new Date(a.last_at)).slice(0, 5);
  clear(WAR.recent).append(h("div", { class: "war-section-label" }, "LATEST ACTIVITY", h("span", { class: "faint" }, "Click a location to explore its history")),
    ...(recent.length ? recent.map((event) => {
      const group = groups.find((g) => g.events.includes(event));
      return h("button", { class: "war-feed-row", type: "button", on: { click: () => selectWarGroup(group.key) } }, h("span", { class: "dot war-sev " + event.severity }), h("span", { class: "war-feed-title" }, event.title), h("span", { class: "small faint" }, event.server_name), h("time", { class: "mono faint small", title: when(event.last_at) }, ago(event.last_at)));
    }) : [h("div", { class: "war-empty" }, "No source activity in this view. Public source IPs appear here when findings reach the hub.")]));
}

function paintWarMap(groups) {
  const cam = WAR.camera;
  const map = svg("svg", { viewBox: `${cam.x} ${cam.y} ${cam.width} ${cam.height}`, class: "war-world", role: "group", "aria-label": "Source locations. Select a marker to see associated incidents." });
  const grid = svg("g", { class: "war-graticule", "aria-hidden": "true" });
  for (let lon = -150; lon <= 150; lon += 30) { const x = warProject(lon, 0)[0]; grid.append(svg("path", { d: `M${x} 0V500` })); }
  for (let lat = -60; lat <= 60; lat += 30) { const y = warProject(0, lat)[1]; grid.append(svg("path", { d: `M0 ${y}H1000` })); }
  map.append(grid);
  const land = svg("g", { class: "war-land", "aria-hidden": "true" });
  for (const polygon of WAR.land || []) {
    const d = polygon.map((ring) => ring.map(([lon, lat], i) => { const [x, y] = warProject(lon, lat); return (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1); }).join("") + "Z").join("");
    land.append(svg("path", { d, "fill-rule": "evenodd" }));
  }
  map.append(land);
  paintWarResearchLinks(map,groups);
  for (const group of groups.filter((g) => g.located)) {
    const [x, y] = warProject(group.longitude, group.latitude), radius = 4 + Math.min(8, Math.sqrt(group.events.length) * 1.5);
    const marker = svg("g", { class: "war-marker " + group.severity + (WAR.selected === group.key ? " selected" : ""), transform: `translate(${x},${y})`, tabindex: "0", role: "button", "aria-label": `${group.name}: ${group.sources.length} source IPs, ${group.events.length} findings`, "aria-pressed": String(WAR.selected === group.key) });
    const title = svg("title"); title.textContent = `${group.name} · ${group.events.length} findings`;
    marker.append(title, svg("circle", { r: radius + 6, class: "war-marker-hit" }), svg("circle", { r: radius + 3, class: "war-marker-ring" }), svg("circle", { r: radius, class: "war-marker-core" }));
    marker.addEventListener("click", () => selectWarGroup(group.key));
    marker.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectWarGroup(group.key); } });
    map.append(marker);
  }
  // Panning changes only the viewport; source coordinates remain unchanged.
  let drag = null;
  map.addEventListener("pointerdown", (e) => {
    if (e.target.closest(".war-marker,.war-research-links") || e.button !== 0) return;
    drag = { x: e.clientX, y: e.clientY, left: cam.x, top: cam.y };
    map.setPointerCapture(e.pointerId);
  });
  map.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const bounds = map.getBoundingClientRect();
    cam.x = Math.max(0, Math.min(1000 - cam.width, drag.left - (e.clientX - drag.x) * cam.width / bounds.width));
    cam.y = Math.max(0, Math.min(500 - cam.height, drag.top - (e.clientY - drag.y) * cam.height / bounds.height));
    map.setAttribute("viewBox", `${cam.x} ${cam.y} ${cam.width} ${cam.height}`);
  });
  map.addEventListener("pointerup", () => { drag = null; });
  map.addEventListener("pointercancel", () => { drag = null; });
  clear(WAR.map).append(map);
  const zoom = (factor) => {
    const selected = groups.find((g) => g.key === WAR.selected && g.located);
    const center = selected ? warProject(selected.longitude, selected.latitude) : [cam.x + cam.width / 2, cam.y + cam.height / 2];
    cam.width = Math.max(125, Math.min(1000, cam.width * factor)); cam.height = cam.width / 2;
    cam.x = Math.max(0, Math.min(1000 - cam.width, center[0] - cam.width / 2));
    cam.y = Math.max(0, Math.min(500 - cam.height, center[1] - cam.height / 2));
    paintWarMap(groups);
  };
  WAR.map.append(h("div", { class: "war-map-controls" },
    h("button", { type: "button", "aria-label": "Zoom in", title: "Zoom in", on: { click: () => zoom(.5) } }, "+"),
    h("button", { type: "button", "aria-label": "Zoom out", title: "Zoom out", on: { click: () => zoom(2) } }, "−"),
    h("button", { type: "button", "aria-label": "Reset map", title: "Reset map", on: { click: () => { WAR.camera = { x: 0, y: 0, width: 1000, height: 500 }; paintWarMap(groups); } } }, ic("refresh", 12))));
  const located = groups.filter((g) => g.located).length;
  if (!located) WAR.map.append(h("div", { class: "war-map-empty" }, h("strong", null, groups.length ? "Waiting for source locations" : "No activity to plot"), h("span", null, groups.length ? "Pending, private, and unlocated IPs remain available in the source list." : "Registered findings with source IPs will appear on this map.")));
  WAR.map.append(h("div", { class: "war-legend" }, ["critical", "high", "medium", "low"].map((s) => h("span", null, h("i", { class: "dot war-sev " + s }), s))));
}

function selectWarGroup(key) {
  WAR.selected = key; WAR.eventLimit = 50; paintWarRoom();
  WAR.inspector.scrollTop = 0;
  const heading = WAR.inspector.querySelector("h2"); if (heading) heading.focus({ preventScroll: true });
  if (window.matchMedia("(max-width: 760px)").matches) WAR.inspector.scrollIntoView({ block: "start", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

function paintWarInspector(groups, selected) {
  clear(WAR.inspector);
  if (!selected) {
    WAR.inspector.append(h("div", { class: "war-inspector-head" }, h("span", { class: "war-section-label" }, "INTELLIGENCE"), h("h2", null, "Source locations"), h("p", { class: "small muted" }, "Select a point on the map or a source below to inspect its incidents, timeline, and context.")));
    if (!groups.length) WAR.inspector.append(h("div", { class: "war-empty" }, "No matching sources. Try a wider time range or clear the filters."));
    for (const group of groups) WAR.inspector.append(h("button", { class: "war-location", type: "button", on: { click: () => selectWarGroup(group.key) } },
      h("span", { class: "dot war-sev " + group.severity }), h("span", { class: "war-location-body" }, h("strong", null, group.name), h("span", { class: "small faint mono" }, group.sources.length === 1 ? group.sources[0].ip : `${group.sources.length} source IPs`)), h("span", { class: "war-count" }, group.events.length), ic("chevRight", 13)));
    return;
  }
  WAR.inspector.append(h("div", { class: "war-inspector-head" }, h("button", { class: "war-back", type: "button", on: { click: () => { WAR.selected = null; paintWarRoom(); } } }, "← All locations"), h("h2", { tabindex: "-1" }, selected.name), h("div", { class: "small faint" }, `${selected.sources.length} source IPs · ${selected.events.length} findings`)));
  for (const source of selected.sources) {
    const intel = source.intel || {};
    WAR.inspector.append(h("div", { class: "war-ip" }, h("div", { class: "war-ip-top" }, h("code", null, source.ip), h("span", { class: "badge" }, source.public ? intel.type || "unknown" : "private / reserved")),
      h("div", { class: "small" }, intel.provider || (source.status === "pending" ? "Public data lookup pending" : "Provider unavailable")),
      h("div", { class: "small faint mono" }, intel.asn || "ASN unavailable"),
      h("div", { class: "small faint" }, source.looked_at && new Date(source.looked_at).getFullYear() > 2000 ? "Public data checked " + ago(source.looked_at) : source.public ? "Lookup status: " + source.status : "Local address; never sent for public lookup")));
  }
  WAR.inspector.append(h("div", { class: "war-section-label war-history-label" }, "INCIDENTS & CONTEXT", h("span", { class: "faint" }, "Newest activity first")));
  for (const event of selected.events.slice(0, WAR.eventLimit)) {
    const href = event.incident_id ? taskHash(null, event.server_id, event.incident_id) : `#/s/${enc(event.server_id)}/findings`;
    WAR.inspector.append(h("article", { class: "war-event" },
      h("div", { class: "war-event-meta" }, h("span", { class: "badge " + (event.severity === "critical" || event.severity === "high" ? "b-bad" : "") }, event.severity), h("span", { class: "faint small" }, event.incident_status || event.status)),
      h("a", { class: "war-event-title", href, on: { click: closeWarRoom } }, event.incident_title || event.title),
      h("div", { class: "small faint" }, event.server_name, event.incident_id ? " · Incident #" + event.incident_id : " · Finding #" + event.finding_id),
      h("div", { class: "war-event-time small mono" }, h("time", { datetime: event.first_at }, when(event.first_at))),
      event.first_at !== event.last_at ? h("div", { class: "small faint" }, "Last updated " + when(event.last_at)) : null,
      warEventContext(event),
      h("div", { class: "war-evidence small mono faint" }, Object.entries(event.evidence || {}).map(([k, v]) => h("div", null, k, ": ", v))),
      h("div", { class: "small faint" }, event.rule, event.occurrences > 1 ? " · " + event.occurrences + " occurrences" : "")));
  }
  if (selected.events.length > WAR.eventLimit) WAR.inspector.append(h("button", { class: "btn small war-show-more", type: "button", on: { click: () => { WAR.eventLimit += 50; paintWarInspector(groups, selected); } } }, `Show more findings (${WAR.eventLimit} of ${selected.events.length} shown)`));

}

function paintWarSettings() {
  if (!WAR.data) return;
  const current = WAR.data.settings;
  const enabled = h("input", { type: "checkbox", checked: current.enabled });
  enabled.disabled = !!current.pinned_off;
 const key = h("input", { type: "password", autocomplete: "off", spellcheck: "false", placeholder: current.key_configured ? "Leave blank to keep the stored key" : "Optional ipapi.is API key", "aria-label": "IP enrichment API key" });
  const status = h("span", { class: "small faint", role: "status" });
  const save = h("button", { class: "btn small primary", type: "button" }, "Save");
  const clearKey = h("button", { class: "btn small", type: "button", hidden: !current.key_configured }, "Clear key");
  const persist = async (clear) => {
    save.disabled = true; clearKey.disabled = true;
    try {
      if (enabled.checked && !current.enabled && !confirm("Enable third-party enrichment? Public source IPs, including legitimate users and fleet addresses, will be sent to ipapi.is. The provider learns which IPs this hub investigates.")) { save.disabled=false; clearKey.disabled=false; return; }
 const values = { enabled: enabled.checked };
      if (clear) values.api_key = ""; else if (key.value.trim()) values.api_key = key.value.trim();
      WAR.data.settings = await api("PUT", "/api/settings/war-room", values);
      key.value = ""; paintWarSettings();
    } catch (e) { status.textContent = e.message; save.disabled = false; clearKey.disabled = false; }
  };
  save.addEventListener("click", () => persist(false)); clearKey.addEventListener("click", () => persist(true));
  add(clear(WAR.config), [h("label", { class: "war-enable" }, enabled, "Public IP enrichment"), h("span", { class: "small muted" }, current.pinned_off ? "Enrichment is disabled by the hub administrator." : "Off by default. Enabling sends public source IPs to ipapi.is, including legitimate users and fleet addresses. This reveals which IPs the hub investigates. Event details stay local."),
    h("div", { class: "war-key-row" }, key, save, clearKey),
    current.paused_until ? h("div", { class: "small c-orange" }, "Provider lookups paused until " + when(current.paused_until)) : null,
    h("div", { class: "small faint" }, `${current.used_today} / ${current.daily_limit} lookups reserved today · cached for 7 days. Anonymous results include ownership and location; an optional key adds network classification.`), status]);
}

function warEventContext(event){
 WAR.details ||= new Map();
 const id=event.server_id+":"+event.finding_id+":"+event.revision;
 const loaded=WAR.details.get(id);
 const view=h("div",null,h("p",{class:"war-context"},loaded?.detail || event.detail || event.title),
   loaded?.context ? h("p",{class:"war-context muted"},loaded.context) : null);
 if(loaded || !event.has_more)return view;
 const button=h("button",{class:"btn small",type:"button"},"Load full context");view.append(button);
 button.addEventListener("click",async()=>{
  button.disabled=true;
  try{
   const finding=await api("GET",`/api/servers/${enc(event.server_id)}/records/finding/${enc(event.finding_id)}`);
   let context="";
   if(event.incident_id){
    WAR.contextCache ||= new Map();const key=event.server_id+":"+event.incident_id+":"+event.revision.split(":")[1];
    if(!WAR.contextCache.has(key))WAR.contextCache.set(key,api("GET",`/api/servers/${enc(event.server_id)}/records/incident/${enc(event.incident_id)}`).catch(e=>{WAR.contextCache.delete(key);throw e}));
    const incident=await WAR.contextCache.get(key);context=(incident.data || incident).summary || "";
   }
   WAR.details.set(id,{detail:(finding.data || finding).detail || event.detail,context});
   for(const cache of [WAR.details,WAR.contextCache])while(cache?.size>256)cache.delete(cache.keys().next().value);
   view.replaceWith(warEventContext(event));
  }catch(error){button.textContent=error.message;button.disabled=false}
 });return view;
}
