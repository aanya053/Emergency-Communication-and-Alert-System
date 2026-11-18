"use strict";

/**
 * Safe DOM element builder — never uses innerHTML so user-derived text is always escaped.
 */
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "className") node.className = v;
    else if (k === "textContent") node.textContent = String(v);
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
    else node.setAttribute(k, String(v));
  }
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined) continue;
    if (typeof child === "string" || typeof child === "number") {
      node.appendChild(document.createTextNode(String(child)));
    } else {
      node.appendChild(child);
    }
  }
  return node;
}

function getThemeVar(name, fallback) {
  const val = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return val || fallback;
}

function updateThemeToggleLabels(theme) {
  const label = theme === "light" ? "Dark Mode" : "Light Mode";
  for (const id of ["theme-toggle-login", "theme-toggle-app"]) {
    const btn = document.getElementById(id);
    if (btn) btn.textContent = label;
  }
}

function redrawThemeCanvases() {
  if (state.topology && state.topology.nodes && state.topology.nodes.length) {
    drawTopologyCanvas();
  }
  if (state.metrics) {
    const hist = state.metrics.history || [];
    drawLineChart(
      document.getElementById("rtt-chart"),
      hist.map((s) => s.avg_rtt_ms ?? 0),
      "#38bdf8",
      "Avg RTT (ms)"
    );
    drawLineChart(
      document.getElementById("tput-chart"),
      hist.map((s) => s.throughput_bps ?? 0),
      "#10b981",
      "Throughput (B/s)"
    );
  }
  const loadSel = document.getElementById("ns2-replay-load");
  if (loadSel) {
    drawNs2BarChart(state.ns2Results || {});
    const trace = (state.ns2Results || {})[loadSel.value];
    drawNs2CwndChart(trace);
    drawReplayFrame(trace, state.replay.activePackets || []);
  }
}

function applyTheme(theme) {
  const resolved = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = resolved;
  localStorage.setItem("ecas_theme", resolved);
  updateThemeToggleLabels(resolved);
  redrawThemeCanvases();
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
  applyTheme(current === "light" ? "dark" : "light");
}

const state = {
  token: sessionStorage.getItem("ecas_token") || null,
  username: sessionStorage.getItem("ecas_username") || null,
  role: sessionStorage.getItem("ecas_role") || null,
  activeTab: null,
  ws: null,
  pollTimer: null,
  topology: { nodes: [], links: [] },
  routeComparison: null,
  metrics: null,
  ns2Results: {},
  replay: {
    playing: false,
    timerId: null,
    idx: 0,
    activePackets: [],
  },
};

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }
  if (!(options.body instanceof FormData) && options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const resp = await fetch(path, { ...options, headers });
  if (resp.status === 401 && path !== "/api/login") {
    doLogout();
    throw new Error("Session expired or unauthorized");
  }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || `Request failed (${resp.status})`);
  }
  return data;
}

function priorityBadge(p) {
  const map = {
    1: ["CRITICAL", "pill pill-danger"],
    2: ["HIGH", "pill pill-warn"],
    3: ["NORMAL", "pill pill-info"],
  };
  const [label, cls] = map[p] || [String(p), "pill pill-muted"];
  return el("span", { className: cls, textContent: label });
}

function statusBadge(d) {
  const st = d.status || "QUEUED";
  let text = st;
  let cls = "pill pill-muted";
  if (st === "ACKNOWLEDGED") cls = "pill pill-success";
  else if (st === "DELIVERED" || st === "REROUTED") cls = "pill pill-info";
  else if (st === "WAITING_NETWORK") {
    const est = d.estimated_wait_sec !== null && d.estimated_wait_sec !== undefined ? `~${d.estimated_wait_sec}s` : "...";
    text = `Waiting for network - est. ${est}`;
    cls = "pill pill-warn";
  } else if (st === "FAILED") {
    cls = "pill pill-danger";
  }
  const wrap = el("span", {}, [el("span", { className: cls, textContent: text })]);
  if (d.rerouted) {
    wrap.appendChild(document.createTextNode(" "));
    wrap.appendChild(el("span", { className: "pill pill-info", textContent: "REROUTED" }));
  }
  return wrap;
}

/* ---------- Auth & Tabs ---------- */
function doLogout() {
  sessionStorage.removeItem("ecas_token");
  sessionStorage.removeItem("ecas_username");
  sessionStorage.removeItem("ecas_role");
  state.token = null;
  state.username = null;
  state.role = null;
  if (state.ws) {
    state.ws.close();
    state.ws = null;
  }
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  document.getElementById("app-view").classList.add("hidden");
  document.getElementById("login-view").classList.remove("hidden");
}

function getTabsForRole(role) {
  const tabs = [];
  if (role === "admin") {
    tabs.push({ id: "ecc", label: "ECC Console" });
  } else if (role === "citizen") {
    tabs.push({ id: "citizen", label: "Citizen SOS" });
  } else {
    tabs.push({ id: "inbox", label: "Responder Inbox" });
  }
  tabs.push({ id: "network", label: "Network & Routing" });
  tabs.push({ id: "wireshark", label: "Wireshark" });
  tabs.push({ id: "ns2", label: "NS-2 Simulation" });
  return tabs;
}

function renderTabs() {
  const tabs = getTabsForRole(state.role);
  const bar = document.getElementById("tab-bar");
  bar.replaceChildren();
  if (!state.activeTab || !tabs.some((t) => t.id === state.activeTab)) {
    state.activeTab = tabs[0].id;
  }
  for (const t of tabs) {
    const btn = el("button", {
      type: "button",
      className: `tab-btn ${t.id === state.activeTab ? "active" : ""}`,
      textContent: t.label,
      onClick: () => switchTab(t.id),
    });
    bar.appendChild(btn);
  }
  for (const panel of document.querySelectorAll(".tab-panel")) {
    panel.classList.add("hidden");
  }
  const activePanel = document.getElementById(`tab-${state.activeTab}`);
  if (activePanel) activePanel.classList.remove("hidden");
}

function switchTab(tabId) {
  state.activeTab = tabId;
  renderTabs();
  refreshActiveView();
}

function enterApp() {
  document.getElementById("login-view").classList.add("hidden");
  document.getElementById("app-view").classList.remove("hidden");
  document.getElementById("user-badge").textContent = `${state.username} (${state.role.toUpperCase()})`;
  const inboxRoleLbl = document.getElementById("inbox-role-label");
  if (inboxRoleLbl) inboxRoleLbl.textContent = state.role.toUpperCase();
  renderTabs();
  connectWebSocket();
  refreshActiveView();
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(refreshActiveView, 2000);
}

function connectWebSocket() {
  if (!state.token) return;
  if (state.ws) state.ws.close();
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${proto}//${location.host}/ws/telemetry?token=${encodeURIComponent(state.token)}`;
  const wsStatus = document.getElementById("ws-status");
  const ws = new WebSocket(wsUrl);
  state.ws = ws;

  ws.onopen = () => {
    wsStatus.className = "pill pill-success";
    wsStatus.textContent = "WS: Live";
  };
  ws.onclose = () => {
    wsStatus.className = "pill pill-muted";
    wsStatus.textContent = "WS: Disconnected";
  };
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === "metrics" || msg.type === "alert_created" || msg.type === "delivery_updated" || msg.type === "topology_updated") {
        refreshActiveView();
      }
    } catch (_) {
      // ignore malformed frames
    }
  };
}

async function refreshActiveView() {
  if (!state.token) return;
  try {
    if (state.activeTab === "ecc") {
      await Promise.all([refreshDeliveriesECC(), refreshMetricsSummary()]);
    } else if (state.activeTab === "inbox") {
      await refreshResponderInbox();
    } else if (state.activeTab === "citizen") {
      await refreshCitizenInbox();
    } else if (state.activeTab === "network") {
      await Promise.all([refreshTopologyAndRoutes(), refreshMetricsAndCharts(), refreshLogs()]);
    } else if (state.activeTab === "wireshark") {
      await refreshWireshark();
    } else if (state.activeTab === "ns2") {
      await refreshNs2();
    }
  } catch (err) {
    console.warn("Refresh error:", err.message);
  }
}

/* ---------- ECC Console ---------- */
async function refreshDeliveriesECC() {
  const data = await apiFetch("/api/deliveries");
  const tbody = document.getElementById("ecc-deliveries-body");
  tbody.replaceChildren();
  for (const d of data.deliveries) {
    const routeText = d.route_list && d.route_list.length ? d.route_list.join(" -> ") : "-";
    const rttText = d.rtt_ms !== null && d.rtt_ms !== undefined ? `${Number(d.rtt_ms).toFixed(2)}` : "-";
    const tr = el("tr", {}, [
      el("td", { textContent: d.alert_code }),
      el("td", { textContent: d.title }),
      el("td", {}, [priorityBadge(d.priority)]),
      el("td", { textContent: d.target_role }),
      el("td", { textContent: d.protocol + (d.sensitive ? " (TLS*)" : "") }),
      el("td", {}, [statusBadge(d)]),
      el("td", { textContent: rttText }),
      el("td", { textContent: d.attempts }),
      el("td", { textContent: routeText }),
    ]);
    tbody.appendChild(tr);
  }
}

async function refreshMetricsSummary() {
  const data = await apiFetch("/api/metrics");
  state.metrics = data;
  const qList = document.getElementById("queue-list");
  qList.replaceChildren();
  if (!data.queue.length) {
    qList.appendChild(el("div", { className: "mini-item muted", textContent: "Queue empty" }));
  } else {
    for (const q of data.queue) {
      qList.appendChild(
        el("div", { className: "mini-item" }, [
          el("span", { textContent: `${q.alert_id} -> ${q.target_role} (${q.protocol})` }),
          el("span", { textContent: `Base P${q.base_priority} / Eff P${q.effective_priority} • ${q.age_sec}s` }),
        ])
      );
    }
  }

  const cList = document.getElementById("clients-list");
  cList.replaceChildren();
  if (!data.connected_clients.length) {
    cList.appendChild(el("div", { className: "mini-item muted", textContent: "No socket clients connected" }));
  } else {
    for (const c of data.connected_clients) {
      cList.appendChild(
        el("div", { className: "mini-item" }, [
          el("span", { textContent: `${c.client_id} (${c.role})` }),
          el("span", { className: "pill pill-success", textContent: `${c.protocol} • ${c.addr}` }),
        ])
      );
    }
  }
}

/* ---------- Responder Inbox & Citizen SOS ---------- */
async function refreshResponderInbox() {
  const data = await apiFetch("/api/deliveries");
  const tbody = document.getElementById("inbox-body");
  tbody.replaceChildren();
  for (const d of data.deliveries) {
    const canAck = d.status !== "ACKNOWLEDGED";
    const ackBtn = canAck
      ? el("button", {
          type: "button",
          className: "btn btn-success btn-sm",
          textContent: "ACK",
          onClick: async () => {
            await apiFetch(`/api/deliveries/${encodeURIComponent(d.alert_id)}/ack`, { method: "POST" });
            await refreshResponderInbox();
          },
        })
      : el("span", { className: "muted", textContent: "ACKed" });

    const tr = el("tr", {}, [
      el("td", { textContent: d.alert_code }),
      el("td", {}, [priorityBadge(d.priority)]),
      el("td", {}, [
        el("div", { textContent: d.title }),
        el("div", { className: "muted", textContent: d.message }),
      ]),
      el("td", { textContent: d.location }),
      el("td", { textContent: d.protocol }),
      el("td", {}, [statusBadge(d)]),
      el("td", { textContent: d.rtt_ms !== null && d.rtt_ms !== undefined ? Number(d.rtt_ms).toFixed(2) : "-" }),
      el("td", { textContent: (d.route_list || []).join(" -> ") || "-" }),
      el("td", {}, [ackBtn]),
    ]);
    tbody.appendChild(tr);
  }
}

async function refreshCitizenInbox() {
  const data = await apiFetch("/api/deliveries");
  const tbody = document.getElementById("citizen-inbox-body");
  tbody.replaceChildren();
  for (const d of data.deliveries) {
    if (d.target_role !== "citizen") continue;
    const canAck = d.status !== "ACKNOWLEDGED";
    const ackBtn = canAck
      ? el("button", {
          type: "button",
          className: "btn btn-success btn-sm",
          textContent: "Confirm",
          onClick: async () => {
            await apiFetch(`/api/deliveries/${encodeURIComponent(d.alert_id)}/ack`, { method: "POST" });
            await refreshCitizenInbox();
          },
        })
      : el("span", { className: "muted", textContent: "Confirmed" });

    tbody.appendChild(
      el("tr", {}, [
        el("td", { textContent: d.alert_code }),
        el("td", { textContent: d.title }),
        el("td", { textContent: d.location }),
        el("td", {}, [statusBadge(d)]),
        el("td", {}, [ackBtn]),
      ])
    );
  }
}

/* ---------- Network, Topology, Routing & Charts ---------- */
async function refreshTopologyAndRoutes() {
  const dst = document.getElementById("route-dst-select").value || "POLICE";
  const [topo, routeCmp] = await Promise.all([
    apiFetch("/api/topology"),
    apiFetch(`/api/routes?src=ECC_HQ&dst=${encodeURIComponent(dst)}`),
  ]);
  state.topology = topo;
  state.routeComparison = routeCmp;

  renderRouteComparison(routeCmp);
  renderLinksTable(topo);
  drawTopologyCanvas(topo, routeCmp);
}

function formatHopPath(routeObj) {
  if (!routeObj || !routeObj.reachable) return "UNREACHABLE";
  if (routeObj.hop_ips && routeObj.hop_ips.length) {
    return routeObj.hop_ips
      .map((h) => (h.ip_address ? `${h.node_id} (${h.ip_address}/24)` : h.node_id))
      .join(" -> ");
  }
  return routeObj.path.join(" -> ");
}

function renderRouteComparison(cmp) {
  const box = document.getElementById("route-compare-box");
  box.replaceChildren();
  const dij = cmp.dijkstra;
  const dv = cmp.distance_vector;
  const lastHop = (dij.hop_ips && dij.hop_ips.length && dij.hop_ips[dij.hop_ips.length - 1]) || null;
  box.appendChild(
    el("div", {
      textContent: `Dijkstra: ${dij.reachable ? `${formatHopPath(dij)} (${dij.total_delay_ms} ms)` : "UNREACHABLE"}`,
    })
  );
  box.appendChild(
    el("div", {
      textContent: `Distance Vector (Bellman-Ford, ${dv.convergence_rounds} rounds): ${dv.reachable ? `${formatHopPath(dv)} (${dv.total_delay_ms} ms)` : "UNREACHABLE"}`,
    })
  );
  if (lastHop && lastHop.subnet_mask) {
    box.appendChild(
      el("div", {
        className: "muted mt-12",
        textContent: `Dest Subnet Mask: ${lastHop.subnet_mask} | Gateway: ${lastHop.gateway}`,
      })
    );
  }
  box.appendChild(
    el("div", {
      className: cmp.costs_match ? "pill pill-success mt-12" : "pill pill-danger mt-12",
      textContent: cmp.costs_match ? "Dijkstra == Distance Vector Cost Match" : "Cost Mismatch",
    })
  );
}

function renderLinksTable(topo) {
  const tbody = document.getElementById("links-control-body");
  tbody.replaceChildren();
  const statsById = {};
  for (const s of topo.emulated_stats || []) {
    statsById[s.link_id] = s;
  }
  const isAdmin = state.role === "admin";
  for (const link of topo.links) {
    const st = statsById[link.link_id] || {};
    const toggleBtn = isAdmin
      ? el("button", {
          type: "button",
          className: `btn btn-sm ${link.is_up ? "btn-danger" : "btn-success"}`,
          textContent: link.is_up ? "Fail Link" : "Restore",
          onClick: async () => {
            await apiFetch(`/api/topology/link/${encodeURIComponent(link.link_id)}`, {
              method: "POST",
              body: JSON.stringify({ is_up: !link.is_up }),
            });
            await refreshTopologyAndRoutes();
          },
        })
      : el("span", {
          className: link.is_up ? "pill pill-success" : "pill pill-danger",
          textContent: link.is_up ? "UP" : "DOWN",
        });

    tbody.appendChild(
      el("tr", {}, [
        el("td", { textContent: `${link.link_id} (${link.label || "emulated link"})` }),
        el("td", { textContent: `${link.src} <-> ${link.dst}` }),
        el("td", { textContent: `${link.delay_ms}ms / ${link.bandwidth_kbps}kbps / Q=${link.queue_limit}` }),
        el("td", { textContent: String(st.total_dropped ?? 0) }),
        el("td", {}, [toggleBtn]),
      ])
    );
  }
}

function drawTopologyCanvas(topo, routeCmp) {
  const canvas = document.getElementById("topology-canvas");
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const nodeMap = {};
  for (const n of topo.nodes) {
    nodeMap[n.node_id] = n;
  }

  const dijSet = new Set();
  const dijPath = (routeCmp && routeCmp.dijkstra && routeCmp.dijkstra.path) || [];
  for (let i = 0; i < dijPath.length - 1; i++) {
    dijSet.add(`${dijPath[i]}|${dijPath[i + 1]}`);
    dijSet.add(`${dijPath[i + 1]}|${dijPath[i]}`);
  }

  const dvSet = new Set();
  const dvPath = (routeCmp && routeCmp.distance_vector && routeCmp.distance_vector.path) || [];
  for (let i = 0; i < dvPath.length - 1; i++) {
    dvSet.add(`${dvPath[i]}|${dvPath[i + 1]}`);
    dvSet.add(`${dvPath[i + 1]}|${dvPath[i]}`);
  }

  const sx = w / 880;
  const sy = h / 440;

  for (const link of topo.links) {
    const a = nodeMap[link.src];
    const b = nodeMap[link.dst];
    if (!a || !b) continue;
    const x1 = a.x * sx;
    const y1 = a.y * sy;
    const x2 = b.x * sx;
    const y2 = b.y * sy;
    const onDij = dijSet.has(`${link.src}|${link.dst}`);
    const onDv = dvSet.has(`${link.src}|${link.dst}`);

    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    if (!link.is_up) {
      ctx.strokeStyle = "#ef4444";
      ctx.setLineDash([6, 5]);
      ctx.lineWidth = 2;
    } else if (onDij) {
      ctx.strokeStyle = "#10b981";
      ctx.setLineDash([]);
      ctx.lineWidth = 4;
    } else if (onDv) {
      ctx.strokeStyle = "#38bdf8";
      ctx.setLineDash([4, 3]);
      ctx.lineWidth = 3;
    } else {
      ctx.strokeStyle = getThemeVar("--canvas-grid", "#334155");
      ctx.setLineDash([]);
      ctx.lineWidth = 2;
    }
    ctx.stroke();
    ctx.setLineDash([]);

    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    ctx.fillStyle = link.is_up ? getThemeVar("--muted", "#94a3b8") : "#f87171";
    ctx.font = "10px monospace";
    ctx.fillText(link.is_up ? `${link.delay_ms}ms` : "DOWN", mx - 14, my - 4);
  }

  for (const n of topo.nodes) {
    const x = n.x * sx;
    const y = n.y * sy;
    ctx.beginPath();
    ctx.arc(x, y, 18, 0, Math.PI * 2);
    ctx.fillStyle = !n.is_up ? "#7f1d1d" : n.node_id === "ECC_HQ" ? "#2563eb" : n.node_type === "relay" ? "#0f766e" : "#334155";
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = n.is_up ? "#93c5fd" : "#ef4444";
    ctx.stroke();

    ctx.fillStyle = getThemeVar("--canvas-text", "#f8fafc");
    ctx.font = "bold 10px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(n.node_id, x, y + 30);
    if (n.ip_address) {
      ctx.fillStyle = getThemeVar("--canvas-ip", "#7dd3fc");
      ctx.font = "9px monospace";
      ctx.fillText(`${n.ip_address}/24`, x, y + 41);
    }
  }
  ctx.textAlign = "left";
}

async function refreshMetricsAndCharts() {
  const data = await apiFetch("/api/metrics");
  state.metrics = data;
  const cur = data.current;
  const rtt = cur.rtt || {};
  const kpiWrap = document.getElementById("metrics-kpis");
  kpiWrap.replaceChildren();
  const kpis = [
    ["Avg RTT", rtt.avg_rtt_ms !== null ? `${rtt.avg_rtt_ms} ms` : "No samples"],
    ["P95 RTT", rtt.p95_rtt_ms !== null ? `${rtt.p95_rtt_ms} ms` : "No samples"],
    ["Throughput", `${cur.throughput_bps} B/s`],
    ["ACK Rate", `${(cur.ack_rate * 100).toFixed(1)}%`],
    ["Loss Rate", `${(cur.loss_rate * 100).toFixed(2)}%`],
    ["Emulated Link Drops", String(cur.totals.emulated_link_drops)],
  ];
  for (const [lbl, val] of kpis) {
    kpiWrap.appendChild(
      el("div", { className: "kpi-card" }, [
        el("div", { className: "kpi-label", textContent: lbl }),
        el("div", { className: "kpi-val", textContent: val }),
      ])
    );
  }

  const pBody = document.getElementById("proto-breakdown-body");
  pBody.replaceChildren();
  for (const proto of ["TCP", "UDP", "TLS"]) {
    const p = cur.by_protocol[proto] || {};
    pBody.appendChild(
      el("tr", {}, [
        el("td", { textContent: proto }),
        el("td", { textContent: p.tx_packets ?? 0 }),
        el("td", { textContent: p.acked ?? 0 }),
        el("td", { textContent: `${p.timeouts ?? 0} / ${p.udp_gap_losses ?? 0}` }),
        el("td", { textContent: `${p.emulated_drops ?? 0} (emulated link)` }),
        el("td", { textContent: `${((p.ack_rate ?? 0) * 100).toFixed(1)}%` }),
        el("td", { textContent: p.avg_rtt_ms !== null && p.avg_rtt_ms !== undefined ? `${p.avg_rtt_ms} ms` : "-" }),
      ])
    );
  }

  const hist = data.history || [];
  drawLineChart(
    document.getElementById("rtt-chart"),
    hist.map((s) => s.avg_rtt_ms ?? 0),
    "#38bdf8",
    "Avg RTT (ms)"
  );
  drawLineChart(
    document.getElementById("tput-chart"),
    hist.map((s) => s.throughput_bps ?? 0),
    "#10b981",
    "Throughput (B/s)"
  );
}

function drawLineChart(canvas, values, color, title) {
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  const mutedColor = getThemeVar("--muted", "#94a3b8");
  const gridColor = getThemeVar("--canvas-grid", "#1e293b");
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = mutedColor;
  ctx.font = "11px sans-serif";
  ctx.fillText(title, 12, 18);

  if (!values.length) {
    ctx.fillText("Waiting for 1 Hz samples...", 12, h / 2);
    return;
  }
  const maxVal = Math.max(1, ...values);
  const padL = 42;
  const padB = 22;
  const padT = 28;
  const padR = 14;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padL, padT);
  ctx.lineTo(padL, h - padB);
  ctx.lineTo(w - padR, h - padB);
  ctx.stroke();

  ctx.fillStyle = mutedColor;
  ctx.font = "10px monospace";
  ctx.fillText(maxVal.toFixed(1), 4, padT + 8);
  ctx.fillText("0", 4, h - padB);

  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.beginPath();
  values.forEach((val, idx) => {
    const x = padL + (values.length === 1 ? plotW : (idx / (values.length - 1)) * plotW);
    const y = h - padB - (val / maxVal) * plotH;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

async function refreshLogs() {
  const data = await apiFetch("/api/logs?limit=60");
  const feed = document.getElementById("logs-feed");
  feed.replaceChildren();
  for (const log of data.logs) {
    const t = new Date(log.timestamp * 1000).toLocaleTimeString();
    feed.appendChild(
      el("div", {
        className: "log-line",
        textContent: `[${t}] [${log.level}] ${log.component} ${log.event}: ${log.details}`,
      })
    );
  }
}

/* ---------- Wireshark ---------- */
async function refreshWireshark() {
  const data = await apiFetch("/api/wireshark/captures");
  if (data.capture) renderCaptureResult(data.capture);
}

function renderCaptureResult(cap) {
  const sum = document.getElementById("pcap-summary");
  sum.replaceChildren();
  const items = [
    ["File", `${cap.filename} (${cap.format})`],
    ["Total Packets", cap.total_packets],
    ["EMRG Packets", cap.emrg_packets],
    ["TCP / UDP / TLS", `${cap.tcp_packets} / ${cap.udp_packets} / ${cap.tls_packets}`],
    ["CRC Valid / Invalid", `${cap.crc_valid_count} / ${cap.crc_invalid_count}`],
  ];
  for (const [k, v] of items) {
    sum.appendChild(
      el("div", { className: "kpi-card" }, [
        el("div", { className: "kpi-label", textContent: k }),
        el("div", { className: "kpi-val", textContent: v }),
      ])
    );
  }

  const tbody = document.getElementById("pcap-packets-body");
  tbody.replaceChildren();
  for (const pkt of cap.packets) {
    let emrgText = "-";
    if (pkt.is_emrg && pkt.emrg) {
      const e = pkt.emrg;
      emrgText = `${e.msg_type} P=${e.priority} seq=${e.seq} ${e.alert_code || ""} [${e.crc_valid ? "CRC OK" : "CRC BAD"}]`;
    }
    const row = el(
      "tr",
      {
        className: "clickable-row",
        onClick: () => {
          const hexEl = document.getElementById("pcap-hex-view");
          const hdr = pkt.is_emrg
            ? `EMRG Frame: ${JSON.stringify(pkt.emrg, null, 2)}\n\n`
            : "";
          hexEl.textContent = `${hdr}Hex Dump (${pkt.length} bytes):\n${pkt.hex_dump}`;
        },
      },
      [
        el("td", { textContent: pkt.index }),
        el("td", { textContent: pkt.timestamp.toFixed(4) }),
        el("td", { textContent: `${pkt.src_ip}:${pkt.src_port ?? "-"}` }),
        el("td", { textContent: `${pkt.dst_ip}:${pkt.dst_port ?? "-"}` }),
        el("td", { textContent: pkt.transport }),
        el("td", { textContent: pkt.length }),
        el("td", { textContent: emrgText }),
      ]
    );
    tbody.appendChild(row);
  }
}

/* ---------- NS-2 ---------- */
async function refreshNs2() {
  const data = await apiFetch("/api/ns2/results");
  state.ns2Results = data.loads || {};
  renderNs2Comparison();
}

function renderNs2Comparison() {
  const loads = state.ns2Results;
  const tbody = document.getElementById("ns2-compare-body");
  tbody.replaceChildren();
  const order = ["low", "normal", "heavy"];
  for (const load of order) {
    const res = loads[load];
    if (!res) {
      tbody.appendChild(
        el("tr", {}, [
          el("td", { textContent: load.toUpperCase() }),
          el("td", { colspan: "8", className: "muted", textContent: "Not uploaded yet — run ns2/run_ns2.sh in Ubuntu WSL and upload .tr" }),
        ])
      );
      continue;
    }
    const s = res.summary;
    const tcp = res.tcp;
    const udp = res.udp;
    tbody.appendChild(
      el("tr", {}, [
        el("td", { textContent: load.toUpperCase() }),
        el("td", { textContent: s.sent }),
        el("td", { textContent: s.received }),
        el("td", { textContent: s.dropped }),
        el("td", { textContent: `${s.loss_pct}%` }),
        el("td", { textContent: s.avg_delay_ms !== null ? `${s.avg_delay_ms} ms` : "-" }),
        el("td", { textContent: `${s.throughput_kbps} kbps` }),
        el("td", { textContent: `${tcp.loss_pct}% / ${tcp.throughput_kbps} kbps` }),
        el("td", { textContent: `${udp.loss_pct}% / ${udp.throughput_kbps} kbps` }),
      ])
    );
  }

  drawNs2BarChart(loads);
  const replayLoad = document.getElementById("ns2-replay-load").value;
  const chosen = loads[replayLoad] || loads.heavy || loads.normal || loads.low;
  drawNs2CwndChart(chosen);
  if (!state.replay.playing) {
    drawReplayFrame(chosen, []);
  }
}

function drawNs2BarChart(loads) {
  const canvas = document.getElementById("ns2-bar-chart");
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const mutedColor = getThemeVar("--muted", "#94a3b8");
  const labelColor = getThemeVar("--hex-text", "#cbd5e1");
  const textColor = getThemeVar("--canvas-text", "#f8fafc");
  const keys = ["low", "normal", "heavy"].filter((k) => loads[k]);
  if (!keys.length) {
    ctx.fillStyle = mutedColor;
    ctx.font = "12px sans-serif";
    ctx.fillText("Upload Low / Normal / Heavy .tr files to plot comparison", 20, h / 2);
    return;
  }

  const maxLoss = Math.max(10, ...keys.map((k) => loads[k].summary.loss_pct));
  const maxDelay = Math.max(10, ...keys.map((k) => loads[k].summary.avg_delay_ms || 0));
  const maxTput = Math.max(10, ...keys.map((k) => loads[k].summary.throughput_kbps));

  const groupW = (w - 80) / keys.length;
  keys.forEach((k, idx) => {
    const s = loads[k].summary;
    const gx = 50 + idx * groupW;
    const bars = [
      { val: s.loss_pct / maxLoss, label: `${s.loss_pct}%`, color: "#ef4444" },
      { val: (s.avg_delay_ms || 0) / maxDelay, label: `${s.avg_delay_ms ?? 0}ms`, color: "#f59e0b" },
      { val: s.throughput_kbps / maxTput, label: `${s.throughput_kbps}k`, color: "#10b981" },
    ];
    bars.forEach((b, bi) => {
      const bh = Math.max(4, b.val * (h - 70));
      const bx = gx + bi * 28;
      const by = h - 35 - bh;
      ctx.fillStyle = b.color;
      ctx.fillRect(bx, by, 22, bh);
      ctx.fillStyle = labelColor;
      ctx.font = "9px monospace";
      ctx.fillText(b.label, bx - 2, by - 4);
    });
    ctx.fillStyle = textColor;
    ctx.font = "bold 11px sans-serif";
    ctx.fillText(k.toUpperCase(), gx + 15, h - 14);
  });

  ctx.fillStyle = "#ef4444"; ctx.fillRect(14, 10, 10, 10);
  ctx.fillStyle = labelColor; ctx.font = "10px sans-serif"; ctx.fillText("Loss %", 28, 19);
  ctx.fillStyle = "#f59e0b"; ctx.fillRect(80, 10, 10, 10);
  ctx.fillStyle = labelColor; ctx.fillText("Delay ms", 94, 19);
  ctx.fillStyle = "#10b981"; ctx.fillRect(156, 10, 10, 10);
  ctx.fillStyle = labelColor; ctx.fillText("Throughput kbps", 170, 19);
}

function drawNs2CwndChart(trace) {
  const canvas = document.getElementById("ns2-cwnd-chart");
  const series = (trace && trace.cwnd_series) || [];
  drawLineChart(
    canvas,
    series.map((p) => p.cwnd),
    "#a78bfa",
    trace ? `TCP cwnd (${trace.load.toUpperCase()})` : "TCP cwnd"
  );
}

const NS2_NODE_COORDS = {
  0: { name: "ECC_HQ", x: 110, y: 180 },
  1: { name: "TOWER_NORTH", x: 320, y: 85 },
  2: { name: "TOWER_SOUTH", x: 320, y: 275 },
  3: { name: "SUBSTATION_A", x: 540, y: 180 },
  4: { name: "POLICE", x: 770, y: 55 },
  5: { name: "FIRE", x: 770, y: 135 },
  6: { name: "AMBULANCE", x: 770, y: 225 },
  7: { name: "HOSPITAL", x: 770, y: 305 },
};
const NS2_EDGES = [
  [0, 1], [0, 2], [1, 3], [2, 3], [1, 4], [3, 4], [1, 5], [3, 5], [2, 6], [3, 6], [2, 7], [3, 7],
];

function drawReplayFrame(trace, activeEvents) {
  const canvas = document.getElementById("ns2-replay-canvas");
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  for (const [u, v] of NS2_EDGES) {
    const a = NS2_NODE_COORDS[u];
    const b = NS2_NODE_COORDS[v];
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.strokeStyle = getThemeVar("--canvas-grid", "#334155");
    ctx.lineWidth = 2;
    ctx.stroke();
  }

  for (const ev of activeEvents) {
    const a = NS2_NODE_COORDS[ev.u];
    const b = NS2_NODE_COORDS[ev.v];
    if (!a || !b) continue;
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    ctx.beginPath();
    ctx.arc(mx, my, 7, 0, Math.PI * 2);
    if (ev.ev === "d") ctx.fillStyle = "#ef4444";
    else if (ev.cat === "CONTROL") ctx.fillStyle = "#f59e0b";
    else if (ev.type === "tcp") ctx.fillStyle = "#38bdf8";
    else ctx.fillStyle = "#10b981";
    ctx.fill();
  }

  const nodeLabelColor = getThemeVar("--canvas-text", "#f8fafc");
  const nodeRingColor = getThemeVar("--muted", "#94a3b8");
  for (const [id, n] of Object.entries(NS2_NODE_COORDS)) {
    ctx.beginPath();
    ctx.arc(n.x, n.y, 16, 0, Math.PI * 2);
    ctx.fillStyle = id === "0" ? "#2563eb" : "#1e293b";
    ctx.fill();
    ctx.strokeStyle = nodeRingColor;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = nodeLabelColor;
    ctx.font = "bold 10px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(n.name, n.x, n.y + 28);
  }
  ctx.textAlign = "left";
}

function startReplay() {
  const load = document.getElementById("ns2-replay-load").value;
  const trace = state.ns2Results[load];
  if (!trace || !trace.replay_events || !trace.replay_events.length) return;
  if (state.replay.timerId) clearInterval(state.replay.timerId);
  state.replay.playing = true;
  const events = trace.replay_events;
  const lbl = document.getElementById("ns2-replay-status");

  state.replay.timerId = setInterval(() => {
    if (!state.replay.playing) return;
    if (state.replay.idx >= events.length) {
      state.replay.playing = false;
      clearInterval(state.replay.timerId);
      return;
    }
    const batch = events.slice(state.replay.idx, state.replay.idx + 6);
    state.replay.idx += batch.length;
    const lastEv = batch[batch.length - 1];
    lbl.textContent = `t = ${lastEv.t.toFixed(3)}s | ${lastEv.u_name} -> ${lastEv.v_name} (${lastEv.type} ${lastEv.ev})`;
    drawReplayFrame(trace, batch);
  }, 60);
}

/* ---------- Event Listeners ---------- */
document.getElementById("theme-toggle-login").addEventListener("click", toggleTheme);
document.getElementById("theme-toggle-app").addEventListener("click", toggleTheme);

document.getElementById("show-login-btn").addEventListener("click", () => {
  document.getElementById("login-form").classList.remove("hidden");
  document.getElementById("register-form").classList.add("hidden");
  document.getElementById("show-login-btn").className = "btn btn-primary btn-sm";
  document.getElementById("show-register-btn").className = "btn btn-ghost btn-sm";
});

document.getElementById("show-register-btn").addEventListener("click", () => {
  document.getElementById("login-form").classList.add("hidden");
  document.getElementById("register-form").classList.remove("hidden");
  document.getElementById("show-login-btn").className = "btn btn-ghost btn-sm";
  document.getElementById("show-register-btn").className = "btn btn-primary btn-sm";
});

document.getElementById("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msgBox = document.getElementById("reg-msg");
  msgBox.classList.add("hidden");
  const username = document.getElementById("reg-username").value.trim();
  const password = document.getElementById("reg-password").value;
  try {
    const res = await apiFetch("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password, role: "citizen" }),
    });
    msgBox.className = "info-banner";
    msgBox.textContent = `${res.message}. You can now sign in.`;
    msgBox.classList.remove("hidden");
    document.getElementById("login-username").value = res.username;
    document.getElementById("register-form").reset();
  } catch (err) {
    msgBox.className = "error-banner";
    msgBox.textContent = err.message;
    msgBox.classList.remove("hidden");
  }
});

document.getElementById("admin-reg-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msgBox = document.getElementById("admin-reg-msg");
  msgBox.classList.add("hidden");
  const username = document.getElementById("admin-reg-username").value.trim();
  const password = document.getElementById("admin-reg-password").value;
  const role = document.getElementById("admin-reg-role").value;
  try {
    const res = await apiFetch("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password, role }),
    });
    msgBox.className = "info-banner";
    msgBox.textContent = res.message;
    msgBox.classList.remove("hidden");
    document.getElementById("admin-reg-form").reset();
  } catch (err) {
    msgBox.className = "error-banner";
    msgBox.textContent = err.message;
    msgBox.classList.remove("hidden");
  }
});

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errBox = document.getElementById("login-error");
  errBox.classList.add("hidden");
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  try {
    const res = await apiFetch("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    state.token = res.token;
    state.username = res.username;
    state.role = res.role;
    sessionStorage.setItem("ecas_token", res.token);
    sessionStorage.setItem("ecas_username", res.username);
    sessionStorage.setItem("ecas_role", res.role);
    enterApp();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove("hidden");
  }
});

document.getElementById("logout-btn").addEventListener("click", doLogout);

/* ---------- Alert Templates & Presets ---------- */
const ALERT_PRESETS = {
  fire: {
    title: "Major Commercial Fire at Sector 62",
    type: "fire",
    priority: "1",
    protocol: "TCP",
    location: "Block B, Sector 62 Industrial Area, Noida",
    message: "Level-3 structural fire reported in commercial complex. Multiple occupants reported on upper floors; fire engines, police perimeter, and standby trauma ambulances required.",
    targets: ["fire", "police", "ambulance"],
    sensitive: false,
  },
  accident: {
    title: "Multi-Vehicle Collision on Expressway",
    type: "accident",
    priority: "2",
    protocol: "TCP",
    location: "Noida-Greater Noida Expressway KM 14",
    message: "Four-car collision blocking two lanes with trapped victims. Police route clearing, heavy extrication gear, and emergency ambulance transport needed.",
    targets: ["ambulance", "police", "hospital"],
    sensitive: false,
  },
  medical: {
    title: "Critical Trauma ICU Transfer & Code Blue",
    type: "medical",
    priority: "1",
    protocol: "TLS",
    location: "Fortis Hospital Sector 62, Trauma Bay 3",
    message: "Immediate high-dependency ICU patient transport with real-time biometric telemetry. Encrypted TLS socket channel required for patient data.",
    targets: ["hospital", "police"],
    sensitive: true,
  },
  crime: {
    title: "Active Armed Robbery & Hostage Situation",
    type: "crime",
    priority: "1",
    protocol: "TLS",
    location: "Sector 18 Commercial Market",
    message: "Armed perpetrators contained within facility. Police SWAT tactical response engaged. Hospital emergency unit on high trauma standby.",
    targets: ["police", "hospital"],
    sensitive: true,
  },
  disaster: {
    title: "Urban Flash Flood & Floodplain Evacuation",
    type: "disaster",
    priority: "2",
    protocol: "UDP",
    location: "Hindon River Low-Lying Catchment Zone",
    message: "Dam discharge alert: water rising above warning mark. Fast connectionless UDP broadcast to all citizen sectors. Emergency relief shelters opened at Substation A.",
    targets: ["citizen", "police", "fire", "ambulance"],
    sensitive: false,
  },
  general: {
    title: "Public Safety Advisory: Road Diversion",
    type: "general",
    priority: "3",
    protocol: "UDP",
    location: "Sector 62 Metro Station Crossing",
    message: "Scheduled emergency culvert and road maintenance in effect from 22:00 to 06:00. Commuters advised to follow marked alternate routes.",
    targets: ["citizen", "police"],
    sensitive: false,
  },
  tactical: {
    title: "Tactical Perimeter Lockdown & Transit Escort",
    type: "tactical",
    priority: "1",
    protocol: "TLS",
    location: "Master Plan Road 3 to Sector 62",
    message: "High-security transport corridor activated. Establish rolling police checkpoints and maintain encrypted tactical communications.",
    targets: ["police", "hospital"],
    sensitive: true,
  },
  sos: {
    title: "Emergency Distress SOS Beacon",
    type: "sos",
    priority: "1",
    protocol: "TCP",
    location: "Hostel Block 3 Outer Perimeter",
    message: "Citizen emergency alert triggered. Immediate police patrol intercept and medical check requested.",
    targets: ["police", "ambulance"],
    sensitive: false,
  },
};

const SOS_PRESETS = {
  medical: {
    title: "Severe Medical Distress / Collapse",
    location: "Sector 62 Gate 2 Crossing",
    message: "Individual collapsed unconscious with chest pain and difficulty breathing. Urgent ambulance required immediately.",
    targets: ["ambulance", "police"],
  },
  accident: {
    title: "Two-Wheeler Road Crash with Trapped Rider",
    location: "Sector 62 Underpass Flyover",
    message: "Vehicle collision with severe bleeding and injury. Traffic blocked, urgent medical assistance needed.",
    targets: ["police", "ambulance"],
  },
  crime: {
    title: "Immediate Personal Safety Threat",
    location: "Near Sector 62 Metro Station Exit 2",
    message: "Suspicious individuals attempting forced entry. Immediate police intervention required.",
    targets: ["police"],
  },
};

function applyAlertPreset(presetKey) {
  const p = ALERT_PRESETS[presetKey];
  if (!p) return;
  const titleEl = document.getElementById("alert-title");
  const typeEl = document.getElementById("alert-type");
  const prioEl = document.getElementById("alert-priority");
  const protoEl = document.getElementById("alert-protocol");
  const locEl = document.getElementById("alert-location");
  const msgEl = document.getElementById("alert-message");
  const sensEl = document.getElementById("alert-sensitive");
  if (!titleEl) return;

  titleEl.value = p.title;
  typeEl.value = p.type;
  prioEl.value = p.priority;
  protoEl.value = p.protocol;
  locEl.value = p.location;
  msgEl.value = p.message;
  sensEl.checked = !!p.sensitive;

  const targetSet = new Set(p.targets);
  document.querySelectorAll('input[name="target"]').forEach((cb) => {
    cb.checked = targetSet.has(cb.value);
  });

  document.querySelectorAll("[data-preset]").forEach((btn) => {
    if (btn.dataset.preset === presetKey) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  [titleEl, locEl, msgEl].forEach((el) => {
    el.classList.remove("autofill-flash");
    void el.offsetWidth;
    el.classList.add("autofill-flash");
  });
}

function applySosPreset(presetKey) {
  const p = SOS_PRESETS[presetKey];
  if (!p) return;
  const titleEl = document.getElementById("sos-title");
  const locEl = document.getElementById("sos-location");
  const msgEl = document.getElementById("sos-message");
  if (!titleEl) return;

  titleEl.value = p.title;
  locEl.value = p.location;
  msgEl.value = p.message;

  const targetSet = new Set(p.targets);
  document.querySelectorAll('input[name="sos-target"]').forEach((cb) => {
    cb.checked = targetSet.has(cb.value);
  });

  document.querySelectorAll("[data-sos-preset]").forEach((btn) => {
    if (btn.dataset.sosPreset === presetKey) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  [titleEl, locEl, msgEl].forEach((el) => {
    el.classList.remove("autofill-flash");
    void el.offsetWidth;
    el.classList.add("autofill-flash");
  });
}

document.addEventListener("click", (e) => {
  const alertBtn = e.target.closest("[data-preset]");
  if (alertBtn) {
    e.preventDefault();
    applyAlertPreset(alertBtn.dataset.preset);
    return;
  }
  const sosBtn = e.target.closest("[data-sos-preset]");
  if (sosBtn) {
    e.preventDefault();
    applySosPreset(sosBtn.dataset.sosPreset);
    return;
  }
});

document.getElementById("alert-type").addEventListener("change", (e) => {
  const val = e.target.value;
  if (ALERT_PRESETS[val]) {
    applyAlertPreset(val);
  }
});

document.getElementById("alert-sensitive").addEventListener("change", (e) => {
  const protoSel = document.getElementById("alert-protocol");
  if (e.target.checked) {
    protoSel.value = "TLS";
  }
});

document.getElementById("create-alert-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const banner = document.getElementById("create-alert-msg");
  banner.classList.add("hidden");
  const targets = Array.from(document.querySelectorAll('input[name="target"]:checked')).map((c) => c.value);
  const body = {
    title: document.getElementById("alert-title").value.trim(),
    alert_type: document.getElementById("alert-type").value,
    priority: Number(document.getElementById("alert-priority").value),
    protocol: document.getElementById("alert-protocol").value,
    location: document.getElementById("alert-location").value.trim(),
    message: document.getElementById("alert-message").value.trim(),
    target_roles: targets,
    sensitive: document.getElementById("alert-sensitive").checked,
  };
  try {
    const res = await apiFetch("/api/alerts", { method: "POST", body: JSON.stringify(body) });
    banner.className = "info-banner";
    banner.textContent = `Dispatched ${res.alert.alert_code} (${res.alert.status})`;
    banner.classList.remove("hidden");
    await refreshDeliveriesECC();
  } catch (err) {
    banner.className = "error-banner";
    banner.textContent = err.message;
    banner.classList.remove("hidden");
  }
});

document.getElementById("admin-clear-btn").addEventListener("click", async () => {
  await apiFetch("/api/admin/clear", { method: "POST" });
  await refreshDeliveriesECC();
  await refreshMetricsSummary();
});

document.getElementById("refresh-inbox-btn").addEventListener("click", refreshResponderInbox);

document.getElementById("sos-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const banner = document.getElementById("sos-msg");
  banner.classList.add("hidden");
  const targets = Array.from(document.querySelectorAll('input[name="sos-target"]:checked')).map((c) => c.value);
  try {
    const res = await apiFetch("/api/alerts", {
      method: "POST",
      body: JSON.stringify({
        title: document.getElementById("sos-title").value.trim(),
        location: document.getElementById("sos-location").value.trim(),
        message: document.getElementById("sos-message").value.trim(),
        alert_type: "sos",
        priority: 1,
        protocol: "TCP",
        target_roles: targets,
        sensitive: false,
      }),
    });
    banner.className = "info-banner";
    banner.textContent = `SOS Sent: ${res.alert.alert_code}`;
    banner.classList.remove("hidden");
    await refreshCitizenInbox();
  } catch (err) {
    banner.className = "error-banner";
    banner.textContent = err.message;
    banner.classList.remove("hidden");
  }
});

document.getElementById("route-dst-select").addEventListener("change", refreshTopologyAndRoutes);

document.getElementById("pcap-upload-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById("pcap-file-input");
  if (!fileInput.files.length) return;
  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  const res = await apiFetch("/api/wireshark/upload", { method: "POST", body: fd });
  renderCaptureResult(res);
});

document.getElementById("ns2-upload-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById("ns2-file-input");
  const load = document.getElementById("ns2-load-select").value;
  if (!fileInput.files.length) return;
  const fd = new FormData();
  fd.append("load", load);
  fd.append("file", fileInput.files[0]);
  await apiFetch("/api/ns2/upload", { method: "POST", body: fd });
  document.getElementById("ns2-replay-load").value = load;
  await refreshNs2();
});

document.getElementById("ns2-play-btn").addEventListener("click", startReplay);
document.getElementById("ns2-pause-btn").addEventListener("click", () => {
  state.replay.playing = false;
});
document.getElementById("ns2-reset-btn").addEventListener("click", () => {
  state.replay.playing = false;
  state.replay.idx = 0;
  document.getElementById("ns2-replay-status").textContent = "t = 0.000s";
  const load = document.getElementById("ns2-replay-load").value;
  drawReplayFrame(state.ns2Results[load], []);
});
document.getElementById("ns2-replay-load").addEventListener("change", renderNs2Comparison);

applyTheme(localStorage.getItem("ecas_theme") || "dark");

if (state.token && state.role) {
  enterApp();
}

