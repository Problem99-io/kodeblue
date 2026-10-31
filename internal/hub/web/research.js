/* Research UI: DOM/text only; evidence never becomes HTML or instructions. */
(() => {
  "use strict";
  const $ = id => root?.querySelector(`#${id}`);
  let root = null, csrf = "", sites = [], generation = 0, onGraph = null, graphResize=null,graphSnapshot=null;
  const node = (tag, text) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = String(text); return e; };
  async function api(path, options = {}) {
    const res = await fetch(path, { ...options, headers: { "Content-Type": "application/json", "X-Kodeblue-CSRF": csrf, ...options.headers } });
    const data = await res.json(); if (!res.ok) throw new Error(data.error || "Research unavailable"); return data;
  }
  const text = (id, value) => { $(id).textContent = value; };
  function table(target, headings, rows) {
    const t = node("table"), head = node("tr"); headings.forEach(h => head.append(node("th", h))); t.append(head);
    rows.forEach(values => { const r = node("tr"); values.forEach(v => r.append(node("td", v))); t.append(r); });
    $(target).replaceChildren(t);
  }
  function graph(data, observations) {
    const svg = $("network"), ns = "http://www.w3.org/2000/svg"; svg.replaceChildren(); $("evidence").replaceChildren();
    const width=svg.clientWidth||800;svg.setAttribute("viewBox",`0 0 ${width} 380`);
    const names = [...new Set(data.edges.flatMap(e => [e.source, e.target]))].slice(0, 12);
    const outgoing=new Set(data.edges.map(e=>e.source)),left=names.filter(n=>outgoing.has(n)),right=names.filter(n=>!outgoing.has(n));
    const positions=new Map();for(const [column,x]of [[left,32],[right,width-32]])column.forEach((name,i)=>positions.set(name,{x,y:30+(i+1)*320/(column.length+1)}));
    const show = edge => {
      const matched = observations.filter(o => edge.evidence.includes(o.sequence));
      const panel = node("pre", JSON.stringify({ relation: edge.relation, source: edge.source, target: edge.target, count: edge.count, evidence_ids: edge.evidence, missing_evidence: edge.evidence.filter(id=>!matched.some(o=>o.sequence===id)), observations: matched }, null, 2));
      panel.className = "research-evidence"; $("evidence").replaceChildren(panel);
    };
    for (const edge of data.edges.slice(0, 60)) {
      const a = positions.get(edge.source), b = positions.get(edge.target); if (!a || !b) continue;
      const line = document.createElementNS(ns, "line");
      for (const [k,v] of Object.entries({ x1:a.x, y1:a.y, x2:b.x, y2:b.y, tabindex:0, role:"button", "aria-label":`${edge.relation}: ${edge.source} to ${edge.target}` })) line.setAttribute(k,v);
      if (edge.relation !== "producer_reported_connection") line.classList.add("similarity");
      line.addEventListener("click", () => show(edge)); line.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); show(edge); } }); svg.append(line);
    }
    for (const name of names) {
      const p = positions.get(name), circle = document.createElementNS(ns,"circle"), label = document.createElementNS(ns,"text"), title = document.createElementNS(ns,"title");
      circle.setAttribute("cx",p.x); circle.setAttribute("cy",p.y); circle.setAttribute("r",9); title.textContent = name; circle.append(title);
      const edge=data.edges.find(e=>e.source===name||e.target===name);
      const short=name.startsWith("fingerprint:")?`${name.split(":")[1].toUpperCase()} · ${name.split(":").at(-1).slice(0,10)}`:(edge?.source===name?edge.source_ip:edge?.target_ip)||name;
      const max=width<400?17:26;
      label.setAttribute("x",p.x > width/2 ? p.x - 8 : p.x + 13); label.setAttribute("y",p.y - 14); label.setAttribute("text-anchor",p.x > width/2 ? "end" : "start"); label.textContent = short.length > max ? short.slice(0,max-1)+"…" : short; svg.append(circle,label);
    }
    $("network-links").replaceChildren(...data.edges.slice(0,8).map(edge=>{const button=node("button",edge.relation==="producer_reported_connection"?`Inspect connection · ${edge.source_ip} → ${edge.target_ip}`:`Inspect fingerprint · ${edge.source_ip||edge.producer_id}`);button.type="button";button.className="btn small";button.addEventListener("click",()=>show(edge));return button;}));
    text("graph-note", names.length ? `Identity not established. ${data.capped || names.length === 12 || data.edges.length>8 ? "Bounded view; more retained evidence may exist." : "Only the returned evidence slice is shown."}` : "No connection or fingerprint evidence in this retained slice.");
  }
  async function load() {
    if (!root?.isConnected) return;
    const site = $("site").value; if (!site) return;
    const mine = ++generation, base = `/api/research/sites/${encodeURIComponent(site)}`;
    text("status","Loading scoped evidence…");
    try {
      const [report, page, map] = await Promise.all([api(`${base}/daily?date=${encodeURIComponent($("day").value)}`),api(`${base}/events?tail=1`),api(`${base}/graph`)]);
      if (mine !== generation) return;
      const metrics = [["Requests",report.requests],["Page views",report.pageviews],["Interactions",report.interactions],["Server-error requests",report.errors]];
      $("metrics").replaceChildren(...metrics.map(([name,value]) => { const e = node("div"); e.className="research-metric"; e.append(node("span",name),node("strong",value.toLocaleString())); return e; }));
      text("period",`${report.date} · ${report.timezone} · ${report.start} → ${report.end}. ${report.baseline}${report.boundary_uncertainty ? ". Boundary totals are approximate." : ""}`);
      table("traffic",["Hour (UTC)","Requests","Page views","Interactions","5xx"],report.hours.map(h=>[new Date(h.at).toISOString().slice(11,16),h.requests,h.pageviews,h.interactions,h.errors]));
      if (!report.findings.length) text("findings","No qualifying patterns found in received observations. This does not establish that all traffic was safe or observed.");
      else table("findings",["Rule","Conclusion","Count","Evidence and limits"],report.findings.map(f=>[f.rule,f.conclusion,f.count,f.explanation]));
      const c = report.coverage;
      text("coverage",`Accepted since site creation: ${c.accepted}. Rejected batches: ${c.rejected}. Detail evicted by capacity: ${c.detail_evicted}. Summary buckets evicted: ${c.summary_evicted}. Detail TTL: ${c.detail_hours}h; summaries: ${c.summary_days}d. ${c.notes.join(" ")}`);
      graphSnapshot={map,observations:page.observations};graph(map,page.observations);
      onGraph?.(map);
      text("status","Loaded. No model or external enrichment was called.");
    } catch(e) { if (mine === generation) text("status",e.message); }
  }
  async function refreshSites() {
    const mounted=root;
    const data = await api("/api/research");
    if (root!==mounted || !root?.isConnected) return;
    if (!data.enabled) { text("status","Research is disabled. Start the hub with --behavioral-research to enable this experimental module. Existing agents are unchanged."); return; }
    sites=data.sites; $("configuration").hidden=false; $("workspace").hidden=false;
    const selected=$("site").value; $("site").replaceChildren(...sites.map(s=>{const o=node("option",s.name);o.value=s.id;return o;}));
    if (sites.some(s=>s.id===selected)) $("site").value=selected;
    if (!sites.length) { text("status","No research sites configured. Add a site below; collection starts only when you connect a source."); $("configuration").open=true; }
    else await load();
  }
  function bind(){
  $("day").value=new Date(Date.now()-86400000).toISOString().slice(0,10);
  $("refresh").addEventListener("click",load); $("site").addEventListener("change",load);
  $("site-form").addEventListener("submit",async e=>{
    e.preventDefault(); const id=$("config-id").value.trim();
    const list=id=>$(id).value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    try { await api(`/api/research/sites/${encodeURIComponent(id)}`,{method:"PUT",body:JSON.stringify({name:$("config-name").value.trim(),timezone:$("config-timezone").value.trim(),origins:list("config-origins"),browser_paths:list("config-paths"),servers:list("config-servers"),browser_enabled:$("config-browser").checked})}); await refreshSites(); }
    catch(err){text("status",err.message);}
  });
  }
  window.KodeBlueResearch = {
    async mount(host,options={}) {
      const token=++generation;
      const response=await fetch("/assets/research-panel.html");
      if (!response.ok) throw new Error("Research panel unavailable");
      const markup=await response.text();
      if (token!==generation || !host.isConnected) return;
      const doc=new DOMParser().parseFromString(markup,"text/html");
      root=document.importNode(doc.querySelector("main.research-page"),true);
      root.querySelector(".research-heading a")?.remove();
      host.replaceChildren(root);onGraph=options.onGraph||null;bind();
      graphSnapshot=null;graphResize?.disconnect();graphResize=new ResizeObserver(()=>{if(root?.isConnected&&graphSnapshot)graph(graphSnapshot.map,graphSnapshot.observations);});graphResize.observe($("network"));
      try {const me=await api("/api/me");if(token!==generation)return;csrf=me.csrf;await refreshSites();}
      catch {if(token===generation && root?.isConnected)text("status","Research unavailable; geography and incident evidence remain available.");}
    },
    close(){generation++;root=null;onGraph=null;graphSnapshot=null;graphResize?.disconnect();graphResize=null;},
  };
})();
