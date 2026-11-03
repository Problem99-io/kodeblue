/* KodeBlue's optional first-party analytics SDK. No cookies, persistent IDs,
 * device fingerprinting, arbitrary properties, or background model activity. */
(() => {
  "use strict";
  if (window.kodeblueAnalytics) return;
  let config = null;
  const allowed = new Set(["contact_click", "booking_intent", "navigation", "service_interest", "gallery_interaction",
    "scroll_25", "scroll_50", "scroll_75", "scroll_100", "active_30", "active_60", "active_120", "lcp", "inp", "cls", "fcp", "ttfb"]);
  const permitted = () => {
    try { return config && config.permitted() === true && navigator.doNotTrack !== "1" && window.doNotTrack !== "1" && navigator.globalPrivacyControl !== true; }
    catch { return false; }
  };
  async function track(kind, name, value) {
    if (!permitted() || !["pageview", "interaction", "performance"].includes(kind)) return false;
    if (kind !== "pageview" && !allowed.has(name)) return false;
    if (value !== undefined && (!Number.isFinite(value) || value < 0 || value > 60000)) return false;
    if (typeof crypto.randomUUID !== "function") return false;
    const event = { id: crypto.randomUUID(), at: new Date().toISOString(), kind, path: location.pathname };
    if (kind !== "pageview") event.name = name;
    if (value !== undefined) event.value = value;
    try {
      const response = await fetch(config.endpoint, { method: "POST", credentials: "omit", referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify({ events: [event] }), keepalive: true });
      if (!response.ok) return false;
      const receipt = await response.json();
      return receipt.stored === true;
    } catch { return false; } // One attempt only: a timeout has unknown delivery.
  }
  window.kodeblueAnalytics = Object.freeze({
    start(options) {
      if (!options || !/^[A-Za-z0-9_-]{1,96}$/.test(options.site) || typeof options.permitted !== "function") return false;
      let endpoint;
      try {
        endpoint = new URL(options.endpoint || `/collect/research/${encodeURIComponent(options.site)}`, location.origin);
        if (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && ["localhost", "127.0.0.1"].includes(endpoint.hostname))) return false;
        if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) return false;
      } catch { return false; }
      config = { endpoint: endpoint.href, permitted: options.permitted };
      return true; // Collection is explicit: start does not silently create events.
    }, track,
    stop() { config = null; },
  });
})();
