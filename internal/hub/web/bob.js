// Plain-language explanations use a dedicated read-only conversation. Bob never
// continues an investigator session or changes a case's board/approval state.
let bobDialog = null;
function closeBob() { if (bobDialog?.isConnected) bobDialog.close(); bobDialog = null; }
function bobUnavailable(server) {
  if (!server || !server.enrolled || server.revoked) return "This server is not connected.";
  if (!server.status?.accepts_bob || server.status?.accepts_messages === false) return "Bob is unavailable here. Ask an administrator to update the agent or enable messages and a model.";
  return "";
}
function bobButton(srv, inc) {
  const why = bobUnavailable(S.servers.find((s) => s.id === srv));
  return h("button", { class: "btn", type: "button", disabled: !!why, title: why || "Get a plain-language explanation of this report", on: { click: () => askBob(srv, inc) } }, "Ask Bob");
}
function bobConversation(messages) {
  const all = (messages || []).filter((m) => m.command === "bob").slice().sort((a, b) => a.id - b.id);
  const id = all.length ? all[all.length - 1].conversation_id : "";
  return { id, messages: all.filter((m) => m.conversation_id === id) };
}
async function askBob(srv, inc) {
  if (bobDialog?.isConnected) return;
  const why = bobUnavailable(S.servers.find((s) => s.id === srv));
  if (why) { toast(why, true); return; }
  let closed = false, timer = null, conversation = "", pending = false, busy = false, loaded = false, loadVersion = 0;
  const thread = h("div", { class: "bob-thread", "aria-label": "Conversation with Bob", "aria-live": "polite" });
  const note = h("p", { class: "muted", role: "status" }, "Loading your conversation…");
  const input = h("textarea", { class: "ta", rows: 2, maxlength: 8000, "aria-label": "Question for Bob", placeholder: "Ask Bob about this report…" });
  const send = h("button", { class: "btn primary", type: "button", disabled: true }, "Ask Bob");
  const refresh = h("button", { class: "btn", type: "button" }, "Refresh conversation");
  const updateSend = () => { send.disabled = !loaded || busy || pending || !input.value.trim(); input.disabled = busy || !loaded; refresh.disabled = busy; };
  const dialog = modal("Ask Bob", [
    h("p", null, "Bob explains the report; he cannot make changes."),
    h("a", { href: taskHash(parseHash().srv, srv, inc.id), on: { click: () => dialog.close() } }, "Original report #" + inc.id + ": " + inc.title),
    h("p", { class: "muted" }, "Uses the server’s AI budget. Ask a follow-up for updates."),
    thread, note, input
  ], [refresh, send], () => { closed = true; clearTimeout(timer); bobDialog = null; });
  bobDialog = dialog;
  const gone = () => closed || !dialog.isConnected;
  function paint(messages) {
    clear(thread);
    let latestAnswer = null;
    for (const m of messages) {
      thread.append(h("div", { class: "bob-question" }, h("strong", null, m.author), h("p", null, m.body)));
      if (m.reply) {
        latestAnswer = h("div", { class: "bob-answer" }, h("strong", null, "Bob"), m.status === "failed" || m.status === "refused" ? h("p", { class: "warn-t" }, "Bob could not complete this answer.") : null, md(m.reply), h("small", { class: "muted" }, when(m.replied_at) + (m.cost_usd ? " · " + usd(m.cost_usd) : "")));
        thread.append(latestAnswer);
      }
      else if (m.status === "failed" || m.status === "refused") thread.append(h("p", { class: "warn-t" }, "Bob could not answer this question (" + m.status + ")."));
    }
    thread.scrollTop = latestAnswer ? latestAnswer.offsetTop : thread.scrollHeight;
  }
  async function load(first = false) {
    clearTimeout(timer);
    if (gone()) return;
    const version = ++loadVersion;
    try {
      const all = await api("GET", `/api/servers/${enc(srv)}/messages?bob_incident_id=${enc(inc.id)}`);
      if (gone() || version !== loadVersion) return;
      const current = bobConversation(all);
      conversation = current.id; pending = current.messages.some((m) => m.status === "queued" || m.status === "delivered");
      loaded = true; paint(current.messages); updateSend();
      note.textContent = pending ? "Waiting for Bob. Your question may be queued until the server is available." : "Ask a follow-up, or check the original report for the technical details. Recent conversation history is shown.";
      if (first && !current.messages.length) { await submit("Please explain this report."); return; }
      if (pending && !gone()) timer = setTimeout(() => load(), 2000);
    } catch (e) {
      if (gone() || version !== loadVersion) return;
      loaded = false; updateSend(); note.textContent = "Could not load Bob’s conversation. Refresh before sending so your question is not duplicated. " + e.message;
    }
  }
  async function submit(text) {
    text = text.trim();
    if (!text || text.length > 8000 || !loaded || busy || pending || gone()) return;
    if (!input.value.trim()) input.value = text;
    busy = true; updateSend(); note.textContent = "Sending your question…";
    try {
      await api("POST", `/api/servers/${enc(srv)}/bob`, { body: text, incident_id: Number(inc.id), conversation_id: conversation });
      if (gone()) return;
      input.value = ""; await load();
    } catch (e) {
      if (gone()) return;
      loaded = false; note.textContent = "Could not confirm delivery. Your question is kept here. Refresh the conversation before retrying. " + e.message;
    } finally { busy = false; if (!gone()) updateSend(); }
  }
  input.addEventListener("input", updateSend);
  send.addEventListener("click", () => submit(input.value));
  refresh.addEventListener("click", () => load());
  await load(true);
  if (!gone()) input.focus();
}
