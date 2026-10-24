/* SENTINEL IDS dashboard — live client.
   Two channels. One WebSocket carries alerts as events: each message either adds a
   new alert row or updates an existing row's repeat counter (matched by DB id).
   The charts are aggregates, re-read from /api/stats every few seconds, and the
   incident log's filters re-read history from /api/alerts.
   Plain ES6, no framework; the only library is Chart.js (loaded in index.html). */

"use strict";

// Display-only cap on how many rows we keep in the DOM. This is a UI concern,
// not a detection threshold, so it lives here and not in config.yaml.
const MAX_ALERTS = 100;

// How often the charts re-read the aggregates - a display rhythm too.
const STATS_POLL_MS = 5000;

const listEl     = document.getElementById("alert-list");
const countEl    = document.getElementById("alert-count");
const statusEl   = document.getElementById("connection-status");
const rateEl     = document.getElementById("packet-rate");
const talkersEl  = document.getElementById("talker-list");
const blockedEl  = document.getElementById("blocked-list");

const filterType     = document.getElementById("filter-type");
const filterSeverity = document.getElementById("filter-severity");
const filterRange    = document.getElementById("filter-range");

const ACCENT = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim();

const seenIds = new Set();               // every episode the socket delivered, shown or filtered out

function chartOptions(extraScales = {}) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,                 // redrawn every few seconds; motion would only blur it
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, ...extraScales },
    };
}

function barChart(id) {
    return new Chart(document.getElementById(id), {
        type: "bar",
        data: { labels: [], datasets: [{ data: [], backgroundColor: ACCENT }] },
        options: chartOptions(),
    });
}

const typeChart   = barChart("type-chart");
const hourlyChart = barChart("hourly-chart");

const trafficChart = new Chart(document.getElementById("traffic-chart"), {
    type: "line",
    data: {
        labels: [],
        datasets: [{ data: [], borderColor: ACCENT, borderWidth: 1.5, pointRadius: 0,
                     fill: true, backgroundColor: ACCENT + "22" }],
    },
    options: chartOptions({ x: { ticks: { maxTicksLimit: 6, maxRotation: 0 } } }),
});

function setSeries(chart, labels, values) {
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.update();
}

function formatTime(epochSeconds) {
    // the server stores time as epoch seconds (float); JS Date wants milliseconds
    return new Date(epochSeconds * 1000).toLocaleTimeString("en-GB");
}

function formatHour(epochSeconds) {
    return new Date(epochSeconds * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}

function cell(className, text) {
    const span = document.createElement("span");
    span.className = className;
    span.textContent = text;             // textContent, never innerHTML: src_ip is
    return span;                         // attacker-controlled — this neutralises XSS
}

function countText(count) {
    return count > 1 ? `×${count}` : "";   // a first sighting shows no multiplier
}

function flagOf(iso) {
    // the two letters shifted into the regional-indicator block: "US" -> 🇺🇸
    if (!iso || iso.length !== 2) return "";
    const base = 0x1f1e6 - "A".charCodeAt(0);
    return String.fromCodePoint(...[...iso.toUpperCase()].map(c => c.charCodeAt(0) + base));
}

function locationText(geo) {
    if (!geo) return "";
    const place = `${flagOf(geo.iso)} ${geo.country}`.trim();
    return geo.city ? `${place} · ${geo.city}` : place;
}

function pcapText(details) {
    const path = details && details.pcap;
    if (!path) return "";
    return "⬇ " + path.split(/[\\/]/).pop();   // the filename alone, not the path
}

function paintScore(el, msg) {
    el.textContent = msg.score;
    el.dataset.level = msg.score_level;   // the band the server resolved; drives the colour
}

function renderAlert(msg) {
    const existing = listEl.querySelector(`li[data-id="${msg.id}"]`);
    if (existing) {                      // a repeat: refresh everything that moves with it
        existing.querySelector(".alert-count").textContent = countText(msg.count);
        paintScore(existing.querySelector(".alert-score"), msg);   // the score climbs too
        return;
    }

    const li = document.createElement("li");
    li.className = "alert-item";
    li.dataset.id = msg.id;              // lets a later count bump find this row
    li.dataset.severity = msg.severity;  // drives the CSS colour chain

    const score = cell("alert-score", "");
    paintScore(score, msg);

    li.append(
        score,
        cell("alert-time", formatTime(msg.timestamp)),
        cell("alert-type", msg.type),
        cell("alert-ip", msg.src_ip),
        cell("alert-geo", locationText(msg.details && msg.details.geo)),
        cell("alert-sev", msg.severity),
        cell("alert-count", countText(msg.count)),
        cell("alert-pcap", pcapText(msg.details)),
    );

    listEl.prepend(li);                  // newest on top

    // keep the DOM bounded: drop the oldest row once past the cap
    while (listEl.children.length > MAX_ALERTS) {
        listEl.lastElementChild.remove();
    }
}

function matchesFilters(msg) {
    return (!filterType.value || msg.type === filterType.value)
        && (!filterSeverity.value || msg.severity === filterSeverity.value);
}

async function loadIncidents() {
    const params = new URLSearchParams({ seconds: filterRange.value });
    if (filterType.value) params.set("type", filterType.value);
    if (filterSeverity.value) params.set("severity", filterSeverity.value);

    let rows;
    try {
        const response = await fetch(`/api/alerts?${params}`);
        if (!response.ok) return;
        rows = await response.json();    // newest first
    } catch {
        return;
    }
    listEl.replaceChildren();
    rows.reverse().forEach(renderAlert); // oldest first, so the newest ends up on top
}

function listOrEmpty(el, items, emptyText) {
    el.replaceChildren(...(items.length ? items : [cell("empty", emptyText)]));
}

function drawTalkers(rows) {
    const top = rows.length ? rows[0].packets : 1;
    listOrEmpty(talkersEl, rows.map(row => {
        const li  = document.createElement("li");
        const bar = cell("talker-bar", "");
        bar.style.width = `${(100 * row.packets / top).toFixed(1)}%`;   // relative to the busiest
        li.append(cell("talker-ip", row.ip), cell("talker-count", row.packets.toLocaleString()), bar);
        return li;
    }), "no traffic recorded");
}

function drawBlocked(rows) {
    listOrEmpty(blockedEl, rows.map(row => {
        const li = document.createElement("li");
        li.append(cell("blocked-ip", row.ip),
                  cell("blocked-meta", `${row.reason} · since ${formatTime(row.blocked_at)}`));
        return li;
    }), "nothing blocked");
}

function labelWindows(windows) {
    const text = {
        traffic: `· ${windows.traffic_seconds}s`,
        alerts:  `· ${windows.alert_stats_hours}h`,
        talkers: `· ${Math.round(windows.top_sources_seconds / 60)}m`,
    };
    document.querySelectorAll("[data-window]").forEach(el => {
        el.textContent = text[el.dataset.window];
    });
}

async function refreshStats() {
    let stats;
    try {
        const response = await fetch("/api/stats");
        if (!response.ok) return;
        stats = await response.json();
    } catch {
        return;                          // the server is down; the WebSocket badge already says so
    }

    setSeries(trafficChart, stats.traffic.map(p => formatTime(p.t)), stats.traffic.map(p => p.packets));
    setSeries(hourlyChart, stats.alerts_per_hour.map(h => formatHour(h.t)),
              stats.alerts_per_hour.map(h => h.alerts));
    setSeries(typeChart, Object.keys(stats.alert_types), Object.values(stats.alert_types));

    const latest = stats.traffic[stats.traffic.length - 1];
    rateEl.textContent = latest ? latest.packets.toLocaleString() : "–";

    drawTalkers(stats.top_sources);
    drawBlocked(stats.blocked);
    labelWindows(stats.windows);
}

function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.onopen = () => {
        statusEl.textContent = "● LIVE";
        statusEl.className = "online";
    };

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);   // the wire is text JSON -> object
        if (!seenIds.has(msg.id)) {           // count distinct episodes, not repeats
            seenIds.add(msg.id);
            countEl.textContent = seenIds.size;
        }
        if (matchesFilters(msg)) renderAlert(msg);
    };

    ws.onclose = () => {
        statusEl.textContent = "OFFLINE";
        statusEl.className = "offline";
        setTimeout(connect, 2000);            // retry until the server is back
    };

    ws.onerror = () => ws.close();            // funnel errors into onclose -> retry
}

document.getElementById("filters").addEventListener("change", loadIncidents);

connect();
refreshStats();
setInterval(refreshStats, STATS_POLL_MS);
