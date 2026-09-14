let lastReconResult = null;

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res.json();
}

async function getJSON(url) {
  const res = await fetch(url);
  return res.json();
}

document.getElementById("roleSelect").addEventListener("change", async (e) => {
  await postJSON("/api/role", { role: e.target.value });
});

async function runOsint() {
  const target = document.getElementById("osintTarget").value;
  const out = document.getElementById("osintOutput");
  out.textContent = "Running...";
  const data = await postJSON("/api/osint", { target });
  out.textContent = JSON.stringify(data, null, 2);
}

async function grantConsent() {
  const target = document.getElementById("consentTarget").value;
  const consent_text = document.getElementById("consentText").value;
  const out = document.getElementById("consentOutput");
  out.textContent = "Submitting...";
  const data = await postJSON("/api/consent", { target, consent_text });
  out.textContent = JSON.stringify(data, null, 2);
}

async function runRecon() {
  const target = document.getElementById("reconTarget").value;
  const out = document.getElementById("reconOutput");
  out.textContent = "Running (requires consent from step 2)...";
  const data = await postJSON("/api/recon", { target });
  out.textContent = JSON.stringify(data, null, 2);
  if (data.ok) lastReconResult = data.result;
}

async function runPlugin(name) {
  const target = document.getElementById("pluginTarget").value;
  const out = document.getElementById("pluginOutput");
  out.textContent = "Running...";
  const data = await postJSON(`/api/plugins/${name}/run`, { target });
  out.textContent = JSON.stringify(data, null, 2);
}

async function generateReport() {
  const out = document.getElementById("reportOutput");
  if (!lastReconResult) {
    out.textContent = "Run recon first (needs role 'lead' or higher to generate).";
    return;
  }
  out.textContent = "Generating...";
  const data = await postJSON("/api/report", {
    target: lastReconResult.target,
    findings: lastReconResult,
  });
  out.textContent = JSON.stringify(data, null, 2);
}

async function loadAudit() {
  const out = document.getElementById("auditOutput");
  out.textContent = "Loading...";
  const data = await getJSON("/api/audit");
  out.textContent = JSON.stringify(data, null, 2);
}

// ---------------------------------------------------------------------
// 7. Attack Surface Map
// ---------------------------------------------------------------------
async function renderAttackSurfaceMap() {
  const target = document.getElementById("mapTarget").value;
  const container = document.getElementById("mapContainer");
  container.innerHTML = "Building...";
  const data = await postJSON("/api/attack-surface", { target });
  if (!data.ok) { container.textContent = JSON.stringify(data); return; }

  const { nodes, edges, note } = data.result;
  const W = 600, H = 360, cx = W / 2, cy = H / 2, R = 140;
  const root = nodes.find(n => n.type === "root");
  const others = nodes.filter(n => n.type !== "root");

  const positions = { [root.id]: { x: cx, y: cy } };
  others.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(others.length, 1);
    positions[n.id] = { x: cx + R * Math.cos(angle), y: cy + R * Math.sin(angle) };
  });

  const colorFor = (type) => type === "root" ? "#2dd4bf" : type === "port" ? "#f87171" : "#f6c343";

  let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%">`;
  edges.forEach(e => {
    const a = positions[e.from], b = positions[e.to];
    if (a && b) svg += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#232a3b" stroke-width="1.5"/>`;
  });
  nodes.forEach(n => {
    const p = positions[n.id];
    if (!p) return;
    const r = n.type === "root" ? 22 : 14;
    svg += `<circle cx="${p.x}" cy="${p.y}" r="${r}" fill="${colorFor(n.type)}" opacity="0.9"/>`;
    svg += `<text x="${p.x}" y="${p.y + r + 12}" fill="#d6e0f0" font-size="10" text-anchor="middle">${n.label}</text>`;
  });
  svg += `</svg>`;

  container.innerHTML = svg + (note ? `<p class="hint">${note}</p>` : "");
}

// ---------------------------------------------------------------------
// 8. Zero Trust Score
// ---------------------------------------------------------------------
async function runScore() {
  const out = document.getElementById("scoreOutput");
  const badge = document.getElementById("scoreBadge");
  if (!lastReconResult) { out.textContent = "Run recon first (panel 3)."; return; }
  out.textContent = "Scoring...";
  const data = await postJSON("/api/score", { findings: lastReconResult });
  out.textContent = JSON.stringify(data, null, 2);
  if (data.ok) {
    badge.textContent = data.result.grade;
    badge.className = "score-badge grade-" + data.result.grade;
  }
}

// ---------------------------------------------------------------------
// 9. AI Risk Analyst
// ---------------------------------------------------------------------
async function runAiAnalysis() {
  const out = document.getElementById("aiOutput");
  if (!lastReconResult) { out.textContent = "Run recon first (panel 3)."; return; }
  out.textContent = "Analyzing...";
  const data = await postJSON("/api/ai-analysis", { findings: lastReconResult });
  out.textContent = `[${data.result.source}]\n\n${data.result.summary}`;
}

// ---------------------------------------------------------------------
// 10. Live Defend Feed
// ---------------------------------------------------------------------
let defendSource = null;
function connectDefendFeed() {
  const feed = document.getElementById("defendFeed");
  if (defendSource) defendSource.close();
  feed.innerHTML = "";
  defendSource = new EventSource("/api/defend/stream");
  defendSource.onmessage = (e) => {
    const event = JSON.parse(e.data);
    const line = document.createElement("div");
    line.className = "feed-line sev-" + event.severity.toLowerCase();
    line.textContent = `[${event.timestamp}] ${event.message}`;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
  };
}

async function injectSimulatedEvent() {
  await postJSON("/api/defend/simulate", {});
}

// ---------------------------------------------------------------------
// 11. Session Timeline
// ---------------------------------------------------------------------
async function renderTimeline() {
  const container = document.getElementById("timelineContainer");
  container.textContent = "Loading...";
  const data = await getJSON("/api/audit");
  if (!data.log) { container.textContent = JSON.stringify(data); return; }

  const chronological = [...data.log].reverse();
  container.innerHTML = chronological.map(entry => `
    <div class="timeline-entry">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <div class="timeline-time">${entry.timestamp}</div>
        <div class="timeline-action">${entry.action} &rarr; ${entry.target}</div>
        <div class="timeline-detail">${entry.detail} (user: ${entry.user_id})</div>
      </div>
    </div>
  `).join("");
}

// ---------------------------------------------------------------------
// Ghost OS Assistant — chat panel
// ---------------------------------------------------------------------
let chatHistory = [];

function appendChatBubble(role, text, source) {
  const win = document.getElementById("chatWindow");
  const bubble = document.createElement("div");
  bubble.className = "chat-msg " + role;
  bubble.textContent = text;
  if (source) {
    const src = document.createElement("span");
    src.className = "chat-source";
    src.textContent = source;
    bubble.appendChild(src);
  }
  win.appendChild(bubble);
  win.scrollTop = win.scrollHeight;
}

async function sendChatMessage() {
  const input = document.getElementById("chatInput");
  const message = input.value.trim();
  if (!message) return;
  input.value = "";

  appendChatBubble("user", message);
  chatHistory.push({ role: "user", content: message });

  const data = await postJSON("/api/assistant/chat", { message, history: chatHistory.slice(0, -1) });
  appendChatBubble("assistant", data.reply, data.source);
  if (data.ok) chatHistory.push({ role: "assistant", content: data.reply });
}

document.getElementById("chatInput")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendChatMessage();
});
