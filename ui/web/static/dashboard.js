/* SENTINEL IDS dashboard — live client.
   Opens one WebSocket to the server; each message either adds a new alert row or
   updates an existing row's repeat counter (matched by DB id), and bumps the
   count-by-type chart on new alerts only.
   Plain ES6, no framework; the only library is Chart.js (loaded in index.html). */

"use strict";

// Display-only cap on how many rows we keep in the DOM. This is a UI concern,
// not a detection threshold, so it lives here and not in config.yaml.
const MAX_ALERTS = 100;

const listEl   = document.getElementById("alert-list");
const countEl  = document.getElementById("alert-count");
const statusEl = document.getElementById("connection-status");
const chartEl  = document.getElementById("type-chart");

let alertCount = 0;
const counts = {};                       // { "PORT_SCAN": 3, "SYN_FLOOD": 1, ... }

const chart = new Chart(chartEl, {
    type: "bar",
    data: {
        labels: [],
        datasets: [{ label: "Alerts", data: [], backgroundColor: "#00d4aa" }],
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
});

function bumpChart(type) {
    // tally one more of this attack type, then push the tally into the chart
    counts[type] = (counts[type] || 0) + 1;
    chart.data.labels = Object.keys(counts);
    chart.data.datasets[0].data = Object.values(counts);
    chart.update();
}

function formatTime(epochSeconds) {
    // the server stores time as epoch seconds (float); JS Date wants milliseconds
    return new Date(epochSeconds * 1000).toLocaleTimeString("en-GB");
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
    );

    listEl.prepend(li);                  // newest on top

    // keep the DOM bounded: drop the oldest row once past the cap
    while (listEl.children.length > MAX_ALERTS) {
        listEl.lastElementChild.remove();
    }

    countEl.textContent = ++alertCount;  // count distinct episodes, not repeats
    bumpChart(msg.type);
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
        renderAlert(msg);
    };

    ws.onclose = () => {
        statusEl.textContent = "OFFLINE";
        statusEl.className = "offline";
        setTimeout(connect, 2000);            // retry until the server is back
    };

    ws.onerror = () => ws.close();            // funnel errors into onclose -> retry
}

connect();
