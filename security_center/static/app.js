/* ═══════════════════════════════════════════════════════════
   SafeVision Security Center — Client Application
   ═══════════════════════════════════════════════════════════ */

const App = (() => {
    /*  State  */
    let token = null;
    let role = null;
    let user = null;
    let sse = null;
    let guardSse = null;
    let liveAlerts = [];
    let guardAlerts = [];
    let charts = {};
    let refreshTimer = null;
    let _hmacKeyStr = null;
    let streamWs = null;
    let streamCryptoKey = null;

    // Helper to convert hex string to Uint8Array
    function hexToBytes(hex) {
        let bytes = new Uint8Array(Math.ceil(hex.length / 2));
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }

    async function verifySignature(payloadText, hexSig) {
        if (!_hmacKeyStr) return true; // Key not yet available (e.g. before login)
        try {
            const keyBytes = hexToBytes(_hmacKeyStr);
            const sigBytes = hexToBytes(hexSig);
            const key = await crypto.subtle.importKey(
                "raw", keyBytes,
                { name: "HMAC", hash: "SHA-256" },
                false, ["verify"]
            );
            const dataBytes = new TextEncoder().encode(payloadText);
            return await crypto.subtle.verify("HMAC", key, sigBytes, dataBytes);
        } catch (e) {
            console.error("Signature verification error", e);
            return false;
        }
    }

    const API = "";   // same origin

    /*  DOM helpers  */
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    /*  API fetch wrapper  */
    async function api(path, opts = {}) {
        const headers = { "Content-Type": "application/json" };
        if (token) headers["Authorization"] = `Bearer ${token}`;
        const res = await fetch(API + path, { ...opts, headers });
        if (res.status === 401) { logout(); throw new Error("Unauthorized"); }

        const text = await res.text();
        const sig = res.headers.get("X-Signature");
        if (sig && _hmacKeyStr) {
            const isValid = await verifySignature(text, sig);
            if (!isValid) throw new Error("SECURITY ALERT: Response integrity verification failed (tampered data detected).");
        }
        return text ? JSON.parse(text) : {};
    }

    /* 
       AUTH
        */
    function initLogin() {
        $("#login-form").addEventListener("submit", async (e) => {
            e.preventDefault();
            const username = $("#username").value.trim();
            const password = $("#password").value;
            $("#login-error").textContent = "";
            try {
                const data = await api("/api/login", {
                    method: "POST",
                    body: JSON.stringify({ username, password }),
                });
                if (data.error) throw new Error(data.error);
                token = data.token;
                role = data.role;
                user = data.user;
                if (data.hmac_key) {
                    _hmacKeyStr = data.hmac_key;
                    window._svHmac = data.hmac_key; // Export for bridge
                }
                window._svToken = token;
                showDashboard();
            } catch (err) {
                $("#login-error").textContent = err.message || "Login failed";
            }
        });
    }

    function showDashboard() {
        $("#login-overlay").classList.add("hidden");
        $("#dashboard").classList.remove("hidden");
        $("#user-name").textContent = user;
        $("#user-role").textContent = role;
        $("#user-avatar").textContent = user.charAt(0).toUpperCase();
        window._svToken = token;   // expose for Guards module bridge

        loadOverview();
        startSSE();
        startAlarmSSE();
        startClock();
        refreshTimer = setInterval(loadOverview, 15000);
    }

    function logout() {
        token = null;
        if (sse) { sse.close(); sse = null; }
        if (guardSse) { guardSse.close(); guardSse = null; }
        if (alarmSse) { alarmSse.close(); alarmSse = null; }
        if (refreshTimer) clearInterval(refreshTimer);
        $("#login-overlay").classList.remove("hidden");
        $("#dashboard").classList.add("hidden");
        $("#password").value = "";
    }

    /* 
       NAVIGATION
        */
    function initNav() {
        $$(".nav-item").forEach(item => {
            item.addEventListener("click", (e) => {
                e.preventDefault();
                const section = item.dataset.section;
                if (section) App.switchSection(section);
            });
        });
        $("#logout-btn").addEventListener("click", logout);
    }

    function switchSection(sectionId) {
        $$(".content-section").forEach(s => s.classList.remove("active"));
        $$(".nav-item").forEach(n => n.classList.remove("active"));

        const sec = document.getElementById(sectionId);
        if (sec) sec.classList.add("active");

        const nav = document.querySelector(`.nav-item[data-section="${sectionId}"]`);
        if (nav) nav.classList.add("active");

        const titles = {
            "overview-section": "Overview",
            "alerts-section": "Live Alerts",
            "alarms-section": "Alarms",
            "guards-section": "Guards & Zones",
            "reports-section": "Reports",
            "system-section": "System Status",
            "guardiance-section": "Guardiance Monitoring",
            "security-section": "Communication Security",
            "live-stream-section": "Live Video Feed"
        };
        $("#page-title").textContent = titles[sectionId] || "Dashboard";

        // Lazy load
        if (sectionId === "reports-section") loadReports();
        if (sectionId === "system-section") loadSystemStatus();
        if (sectionId === "guardiance-section") loadGuardiance();
        if (sectionId === "security-section") loadSecurity();

        if (sectionId === "live-stream-section") {
            App.initLiveStream?.();
        } else {
            App.disconnectStream?.();
        }
    }

    /* 
       OVERVIEW
        */
    async function loadOverview() {
        try {
            const [summary, status, timeline, srvStatus] = await Promise.all([
                api("/api/reports/summary"),
                api("/api/system/status"),
                api("/api/reports/timeline"),
                api("/api/server/status"),
            ]);

            // Cards
            $("#stat-total").textContent = summary.total_events.toLocaleString();
            $("#stat-alerts").textContent = summary.alert_events.toLocaleString();
            $("#stat-safe").textContent = summary.safe_percentage + "%";
            $("#stat-uptime").textContent = status.uptime_human;

            // Live clients card
            const clientCount = srvStatus.active_clients ?? 0;
            const clientEl = $("#stat-clients");
            if (clientEl) {
                clientEl.textContent = clientCount;
                // Pulse the card green when ≥1 client is live
                const card = $("#card-clients");
                if (card) {
                    card.classList.toggle("card-live", clientCount > 0);
                }
            }

            // Recent alerts
            const alertsData = await api("/api/alerts?limit=8");
            renderAlertsList("overview-alerts-list", alertsData.alerts);

            // Timeline
            renderOverviewChart(timeline.timeline);
        } catch (err) {
            console.error("Overview load error:", err);
        }
    }

    function renderOverviewChart(timeline) {
        const ctx = document.getElementById("overview-chart");
        if (!ctx) return;

        // Sample data: take every Nth entry to keep chart readable
        let data = timeline;
        const maxPoints = 60;
        if (data.length > maxPoints) {
            const step = Math.ceil(data.length / maxPoints);
            data = data.filter((_, i) => i % step === 0);
        }

        if (charts.overview) charts.overview.destroy();
        charts.overview = new Chart(ctx, {
            type: "line",
            data: {
                labels: data.map(d => d.time.split(" ")[1] || d.time),
                datasets: [
                    {
                        label: "Safe",
                        data: data.map(d => d.safe),
                        borderColor: "#10b981",
                        backgroundColor: "rgba(16,185,129,0.1)",
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                    {
                        label: "Alert",
                        data: data.map(d => d.alert),
                        borderColor: "#dc2626",
                        backgroundColor: "rgba(220,38,38,0.1)",
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                ]
            },
            options: chartOpts("Events Over Time"),
        });
    }

    /* 
       LIVE ALERTS (SSE)
        */
    function startSSE() {
        if (sse) sse.close();
        sse = new EventSource(`/api/alerts/realtime?token=${token}`);
        sse.onmessage = (e) => {
            try {
                const alert = JSON.parse(e.data);
                liveAlerts.unshift(alert);
                if (liveAlerts.length > 200) liveAlerts.length = 200;

                // Update badge
                const badge = $("#alert-badge");
                badge.textContent = parseInt(badge.textContent || 0) + 1;

                renderFilteredAlerts();
            } catch (err) { /* skip bad lines */ }
        };
        sse.onerror = () => {
            const dot = $(".dot");
            if (dot) { dot.className = "dot dot-red"; }
        };

        // Filter change
        $("#filter-risk").addEventListener("change", renderFilteredAlerts);
        $("#btn-clear-alerts").addEventListener("click", () => {
            liveAlerts = [];
            const badge = $("#alert-badge");
            if (badge) badge.textContent = "0";
            renderFilteredAlerts();
        });
    }

    function renderFilteredAlerts() {
        const filter = $("#filter-risk").value;
        let filtered = liveAlerts;
        if (filter !== "") {
            filtered = liveAlerts.filter(a => String(a.risk_level) === filter);
        }
        renderAlertsList("live-alerts-list", filtered);
    }


    async function loadReports() {
        try {
            const [summary, timeline] = await Promise.all([
                api("/api/reports/summary"),
                api("/api/reports/timeline"),
            ]);

            // Pie chart
            const pieCtx = document.getElementById("reports-pie-chart");
            if (charts.pie) charts.pie.destroy();
            charts.pie = new Chart(pieCtx, {
                type: "doughnut",
                data: {

                    labels: ["Safe", "Alert"],
                    datasets: [{
                        data: [summary.safe_events, summary.alert_events],
                        backgroundColor: ["#10b981", "#dc2626"],
                        borderWidth: 0,
                        hoverOffset: 8,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: "bottom", labels: { color: "#9ca3af", padding: 16, font: { family: "Inter" } } },
                    },
                    cutout: "65%",
                },
            });

            // Camera chart
            const camCtx = document.getElementById("reports-camera-chart");
            const camLabels = Object.keys(summary.cameras);
            const camValues = Object.values(summary.cameras);
            if (charts.camera) charts.camera.destroy();
            charts.camera = new Chart(camCtx, {
                type: "bar",
                data: {
                    labels: camLabels,
                    datasets: [{
                        label: "Events",
                        data: camValues,
                        backgroundColor: "rgba(59,130,246,0.6)",
                        borderColor: "#3b82f6",
                        borderWidth: 1,
                        borderRadius: 6,
                    }]
                },
                options: chartOpts("Events per Camera"),
            });

            // Timeline
            let tl = timeline.timeline;
            const maxP = 80;
            if (tl.length > maxP) {
                const step = Math.ceil(tl.length / maxP);
                tl = tl.filter((_, i) => i % step === 0);
            }
            const tlCtx = document.getElementById("reports-timeline-chart");
            if (charts.timeline) charts.timeline.destroy();
            charts.timeline = new Chart(tlCtx, {
                type: "bar",
                data: {
                    labels: tl.map(d => d.time.split(" ")[1] || d.time),
                    datasets: [
                        { label: "Safe", data: tl.map(d => d.safe), backgroundColor: "rgba(16,185,129,0.6)", borderRadius: 3, },
                        { label: "Alert", data: tl.map(d => d.alert), backgroundColor: "rgba(220,38,38,0.6)", borderRadius: 3, },
                    ]
                },
                options: { ...chartOpts("Detection Timeline"), scales: { ...chartOpts("").scales, x: { ...chartOpts("").scales.x, stacked: true }, y: { ...chartOpts("").scales.y, stacked: true } } },
            });

            // Summary stats
            const statsHtml = `
                <div class="stats-item"><div class="label">Total Events</div><div class="value">${summary.total_events.toLocaleString()}</div></div>
                <div class="stats-item"><div class="label">Safe Events</div><div class="value" style="color:var(--green)">${summary.safe_events.toLocaleString()}</div></div>
                <div class="stats-item"><div class="label">Alert Events</div><div class="value" style="color:var(--accent)">${summary.alert_events.toLocaleString()}</div></div>
                <div class="stats-item"><div class="label">Safe Rate</div><div class="value">${summary.safe_percentage}%</div></div>
                <div class="stats-item"><div class="label">Avg Probability</div><div class="value">${summary.average_probability}</div></div>
                <div class="stats-item"><div class="label">Cameras</div><div class="value">${camLabels.length}</div></div>
            `;
            $("#summary-stats").innerHTML = statsHtml;
        } catch (err) {
            console.error("Reports error:", err);
        }
    }

    /* 
       SYSTEM STATUS
        */
    async function loadSystemStatus() {
        try {
            const data = await api("/api/system/status");
            const rows = [
                ["Status", `<span class="sec-tag">${data.status.toUpperCase()}</span>`],
                ["Uptime", data.uptime_human],
                ["Model Version", data.model_version],
                ["Location", data.location],
                ["TLS Enabled", data.tls_enabled ? "✅ Yes" : "❌ No"],
                ["Certificate", data.cert_file],
            ];
            $("#system-details").innerHTML = rows.map(([l, v]) =>
                `<div class="detail-row"><span class="detail-label">${l}</span><span class="detail-value">${v}</span></div>`
            ).join("");

            const dbRows = Object.entries(data.database_files).map(([name, size]) =>
                `<div class="detail-row"><span class="detail-label">${name}</span><span class="detail-value">${formatBytes(size)}</span></div>`
            ).join("");
            $("#db-details").innerHTML = dbRows || '<div class="empty-state">No database files found</div>';
        } catch (err) {
            console.error("System status error:", err);
        }
    }

    /* 
       GUARDIANCE
        */
    async function loadGuardiance() {
        try {
            const stats = await api("/api/guard/stats");
            $("#guard-total-events").textContent = stats.total_events.toLocaleString();
            $("#guard-auth-fails").textContent = stats.auth_failures.toLocaleString();
            $("#guard-blocked-frames").textContent = stats.blocked_frames.toLocaleString();
            $("#guard-anomalies").textContent = stats.anomalies.toLocaleString();

            const auditData = await api("/api/guard/audit?limit=20");
            guardAlerts = auditData.audit || [];
            renderGuardAlerts();

            startGuardSSE();
        } catch (err) {
            console.error("Guardiance error:", err);
        }
    }

    function startGuardSSE() {
        if (guardSse) guardSse.close();
        guardSse = new EventSource(`/api/guard/realtime?token=${token}`);
        guardSse.onmessage = (e) => {
            try {
                const event = JSON.parse(e.data);
                guardAlerts.unshift(event);
                if (guardAlerts.length > 100) guardAlerts.length = 100;
                renderGuardAlerts();
            } catch (err) { }
        };
    }

    function renderGuardAlerts() {
        const container = $("#guard-audit-list");
        if (!guardAlerts.length) {
            container.innerHTML = "No audit events logged yet.";
            return;
        }
        container.innerHTML = guardAlerts.map(a => {
            const time = (a.timestamp || "").split("Z")[0].replace("T", " ");
            const color = a.success ? "#10b981" : "#ef4444";
            return `<div style="margin-bottom:8px; border-bottom:1px solid #374151; padding-bottom:8px;">
                <span style="color:#6b7280">[${time}]</span> 
                <span style="color:${color}; font-weight:bold;">[${a.event}]</span> 
                <span style="color:#9ca3af">${a.actor}:</span> 
                <span style="color:#f3f4f6">${a.detail}</span>
            </div>`;
        }).join("");
    }

    /* 
       SECURITY
        */
    async function loadSecurity() {
        try {
            const data = await api("/api/system/security");

            // Transport
            const t = data.transport_encryption;
            $("#sec-transport").innerHTML = detailRows([
                ["Protocol", t.protocol],
                ["Certificate", t.certificate],
                ["Key", t.key],
                ["Status", `<span class="sec-tag">${t.status.toUpperCase()}</span>`],
            ]);

            // Signatures
            const s = data.digital_signatures;
            $("#sec-signatures").innerHTML = detailRows([
                ["Algorithm", s.algorithm],
                ["Header", s.header],
            ]) + `<p style="margin-top:8px;color:var(--text-muted);font-size:0.8rem">${s.description}</p>`;

            // Integrity
            const di = data.data_integrity;
            $("#sec-integrity").innerHTML = detailRows([
                ["Algorithm", di.algorithm],
            ]) + `<p style="margin-top:8px;color:var(--text-muted);font-size:0.8rem">Applied to: ${di.applied_to.join(", ")}</p>`;

            // RBAC
            const ac = data.access_control;
            let rbacHtml = `<p style="margin-bottom:10px;font-weight:600;color:var(--text)">${ac.type}</p>`;
            for (const r of ac.roles) {
                rbacHtml += `<div style="margin-bottom:6px"><span style="font-weight:600;color:var(--accent)">${r.name}</span>: ${r.permissions.join(", ")}</div>`;
            }
            $("#sec-rbac").innerHTML = rbacHtml;

            // Encryption
            const enc = data.encryption_layer;
            $("#sec-encryption").innerHTML = detailRows([
                ["Stream Cipher", enc.stream_cipher],
                ["Key Exchange", enc.key_exchange],
                ["Model Protection", enc.model_protection],
            ]);
        } catch (err) {
            console.error("Security error:", err);
        }
    }

    /* 
       HELPERS
        */
    function renderAlertsList(containerId, alerts) {
        const container = document.getElementById(containerId);
        if (!alerts || alerts.length === 0) {
            container.innerHTML = '<div class="empty-state">No alerts to display</div>';
            return;
        }
        container.innerHTML = alerts.map(a => {
            const isSafe = a.risk_level === 0;
            const riskClass = isSafe ? "safe" : "alert";
            const riskLabel = isSafe ? "Safe" : "Alert";
            const time = (a.timestamp || "").split(" ")[1] || a.timestamp;
            const prob = a.probability !== undefined ? (a.probability * 100).toFixed(1) + "%" : "";
            return `
                <div class="alert-item risk-${riskClass}">
                    <span class="alert-risk ${riskClass}">${riskLabel}</span>
                    <div class="alert-meta">
                        <span class="alert-camera">${a.camera_id || "—"}</span>
                        <span class="alert-location">${a.location || ""}</span>
                        <span class="alert-prob">${prob}</span>
                    </div>
                    <span class="alert-time">${time || ""}</span>
                </div>`;
        }).join("");
    }

    function detailRows(rows) {
        return rows.map(([l, v]) =>
            `<div class="sec-detail-row"><span class="sec-detail-label">${l}</span><span class="sec-detail-value">${v}</span></div>`
        ).join("");
    }

    function formatBytes(b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
        return (b / 1024 / 1024).toFixed(2) + " MB";
    }

    function chartOpts(title) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true, labels: { color: "#9ca3af", padding: 12, font: { family: "Inter", size: 11 } } },
                title: title ? { display: false } : undefined,
            },
            scales: {
                x: { ticks: { color: "#6b7280", font: { family: "Inter", size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 12 }, grid: { color: "rgba(255,255,255,0.04)" } },
                y: { ticks: { color: "#6b7280", font: { family: "Inter", size: 10 } }, grid: { color: "rgba(255,255,255,0.04)" }, beginAtZero: true },
            },
        };
    }

    function startClock() {
        const el = $("#topbar-time");
        const tick = () => {
            const now = new Date();
            el.textContent = now.toLocaleTimeString("en-GB") + "  " + now.toLocaleDateString("en-GB");
        };
        tick();
        setInterval(tick, 1000);
    }

    /* 
       ALARMS
        */
    let alarmSse = null;
    let _alarmData = [];

    // Toast container (created once)
    let _toastContainer = null;
    function getToastContainer() {
        if (!_toastContainer) {
            _toastContainer = document.createElement("div");
            _toastContainer.className = "alarm-toast-container";
            document.body.appendChild(_toastContainer);
        }
        return _toastContainer;
    }

    function showToast(alarm) {
        const isSecurity = (alarm.label || "").startsWith("SECURITY:");
        const isCritical = alarm.severity === "CRITICAL";
        const toast = document.createElement("div");
        toast.className = "alarm-toast" + (isSecurity ? " security" : isCritical ? "" : " warning");
        const icon = isSecurity ? "🔒" : isCritical ? "🚨" : "⚠️";
        const labelDisplay = isSecurity
            ? (alarm.label || "").replace("SECURITY:", "")
            : alarm.label;
        toast.innerHTML = `
            <span class="toast-icon">${icon}</span>
            <div class="toast-body">
                <div class="toast-title">${alarm.severity} — ${labelDisplay}</div>
                <div class="toast-msg">
                    📷 ${alarm.camera_id || "—"} &nbsp;|&nbsp; 📍 ${alarm.location || "—"}<br>
                    Prob: ${((alarm.probability || 0) * 100).toFixed(1)}%
                    ${alarm.sms_sent ? '<span class="sms-indicator">📱 SMS Sent</span>' : ""}
                </div>
            </div>
            <button class="toast-close" title="Close">✕</button>`;
        toast.querySelector(".toast-close").onclick = () => toast.remove();
        getToastContainer().prepend(toast);
        setTimeout(() => { if (toast.parentNode) toast.remove(); }, 8000);
    }

    function playAlarmSound(isCritical) {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const beeps = isCritical ? 3 : 1;
            for (let i = 0; i < beeps; i++) {
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.type = "square";
                osc.frequency.value = isCritical ? 880 : 660;
                gain.gain.setValueAtTime(0.15, ctx.currentTime + i * 0.35);
                gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i * 0.35 + 0.3);
                osc.start(ctx.currentTime + i * 0.35);
                osc.stop(ctx.currentTime + i * 0.35 + 0.3);
            }
        } catch (_) { /* AudioContext may be blocked until user interaction */ }
    }

    async function loadAlarms() {
        try {
            const stateFilter = $("#alarm-filter-state")?.value || "";
            const [statsData, alarmsData] = await Promise.all([
                api("/api/alarms/stats"),
                api(`/api/alarms?limit=100${stateFilter ? "&state=" + stateFilter : ""}`),
            ]);
            // Update stat cards
            $("#alarm-stat-active").textContent = statsData.ACTIVE ?? 0;
            $("#alarm-stat-ack").textContent = statsData.ACKNOWLEDGED ?? 0;
            $("#alarm-stat-dismissed").textContent = statsData.DISMISSED ?? 0;
            $("#alarm-stat-total").textContent = statsData.total ?? 0;

            // Update nav badge
            const activeCnt = statsData.ACTIVE ?? 0;
            const badge = $("#alarm-badge");
            badge.textContent = activeCnt;
            badge.classList.toggle("has-alarms", activeCnt > 0);

            _alarmData = alarmsData.alarms || [];
            renderAlarmTable(_alarmData);

            // Start SSE if not running
            if (!alarmSse) startAlarmSSE();

            // Load rules
            loadAlarmRules();
        } catch (err) {
            console.error("Alarm load error:", err);
        }
    }

    function renderAlarmTable(alarms) {
        const tbody = $("#alarm-table-body");
        if (!alarms.length) {
            tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No alarms to display</td></tr>`;
            return;
        }
        tbody.innerHTML = alarms.map(a => {
            const isSecurity = (a.label || "").startsWith("SECURITY:");
            const sevClass = isSecurity
                ? "severity-security"
                : a.severity === "CRITICAL" ? "severity-critical" : "severity-warning";
            const stateClass = {
                ACTIVE: "state-active", ACKNOWLEDGED: "state-acknowledged", DISMISSED: "state-dismissed"
            }[a.state] || "";
            const rowClass = {
                ACTIVE: "alarm-row-active", ACKNOWLEDGED: "alarm-row-acknowledged", DISMISSED: "alarm-row-dismissed"
            }[a.state] || "";
            const prob = ((a.probability || 0) * 100).toFixed(1) + "%";
            const time = (a.fired_at || "").replace("T", " ").split(".")[0];
            const smsTag = a.sms_sent ? `<span class="sms-indicator">📱 SMS</span>` : "";
            const labelDisplay = isSecurity
                ? `🔒 ${(a.label || "").replace("SECURITY:", "")}`
                : (a.label || "—");
            const ackBtn = a.state === "ACTIVE"
                ? `<button class="btn-ack" onclick="App.acknowledgeAlarm('${a.alarm_id}')">Acknowledge</button>` : "";
            const disBtn = (a.state === "ACTIVE" || a.state === "ACKNOWLEDGED")
                ? `<button class="btn-dismiss" onclick="App.dismissAlarm('${a.alarm_id}')">Dismiss</button>` : "";
            return `<tr class="${rowClass}">
                <td><span class="severity-badge ${sevClass}">${a.severity}</span></td>
                <td>${a.camera_id || "—"}</td>
                <td>${a.location || "—"}</td>
                <td>${labelDisplay}</td>
                <td>${prob} ${smsTag}</td>
                <td style="font-variant-numeric:tabular-nums;white-space:nowrap;color:var(--text-muted)">${time}</td>
                <td><span class="state-badge ${stateClass}">${a.state}</span></td>
                <td>${ackBtn}${disBtn}</td>
            </tr>`;
        }).join("");
    }

    function startAlarmSSE() {
        if (alarmSse) alarmSse.close();
        alarmSse = new EventSource(`/api/alarms/realtime?token=${token}`);
        alarmSse.onmessage = (e) => {
            try {
                const alarm = JSON.parse(e.data);
                // Prepend to local list and re-render
                _alarmData.unshift(alarm);
                if (_alarmData.length > 100) _alarmData.length = 100;
                renderAlarmTable(_alarmData);

                // Update badge
                const badge = $("#alarm-badge");
                const cnt = parseInt(badge.textContent || "0") + 1;
                badge.textContent = cnt;
                badge.classList.add("has-alarms");

                // Toast + sound
                showToast(alarm);
                playAlarmSound(alarm.severity === "CRITICAL");
            } catch (_) { }
        };
    }

    async function acknowledgeAlarm(alarmId) {
        try {
            await api(`/api/alarms/${alarmId}/acknowledge`, { method: "POST" });
            loadAlarms();
        } catch (err) { console.error("Ack error:", err); }
    }

    async function dismissAlarm(alarmId) {
        try {
            await api(`/api/alarms/${alarmId}/dismiss`, { method: "POST" });
            loadAlarms();
        } catch (err) { console.error("Dismiss error:", err); }
    }

    /*  Alarm Rules  */
    async function loadAlarmRules() {
        try {
            const data = await api("/api/alarm-rules");
            const rules = data.rules || [];
            const tbody = $("#alarm-rules-body");
            const isAdmin = role === "admin";

            // Show add button only for admin
            const addBtn = $("#btn-add-rule");
            if (addBtn) addBtn.style.display = isAdmin ? "inline-block" : "none";
            const actionsHeader = $("#rules-actions-header");
            if (actionsHeader) actionsHeader.textContent = isAdmin ? "Actions" : "";

            tbody.innerHTML = rules.map(r => {
                const enabledTag = r.enabled
                    ? `<span class="state-badge state-active">Active</span>`
                    : `<span class="state-badge state-dismissed">Disabled</span>`;
                const smsTag = r.notify_sms
                    ? `<span class="sms-indicator">📱 Yes</span>`
                    : `<span style="color:var(--text-muted)">No</span>`;
                const sevClass = r.severity === "CRITICAL" ? "severity-critical" : "severity-warning";
                const delBtn = isAdmin
                    ? `<button class="btn-delete-rule" onclick="App.deleteRule('${r.id}')">Delete</button>` : "";
                return `<tr>
                    <td style="font-weight:600">${r.name}</td>
                    <td>${(r.label_triggers || []).join(", ")}</td>
                    <td>${((r.min_probability || 0) * 100).toFixed(0)}%</td>
                    <td>${r.cooldown_seconds}s</td>
                    <td><span class="severity-badge ${sevClass}">${r.severity}</span></td>
                    <td>${smsTag}</td>
                    <td>${enabledTag}</td>
                    <td>${delBtn}</td>
                </tr>`;
            }).join("") || `<tr><td colspan="8" class="empty-state">No rules defined</td></tr>`;
        } catch (err) { console.error("Rules load error:", err); }
    }

    function initAlarmRuleForm() {
        $("#btn-add-rule")?.addEventListener("click", () => {
            $("#add-rule-form").style.display = "block";
            $("#btn-add-rule").style.display = "none";
        });
        $("#btn-cancel-rule")?.addEventListener("click", () => {
            $("#add-rule-form").style.display = "none";
            $("#btn-add-rule").style.display = role === "admin" ? "inline-block" : "none";
            $("#rule-form-error").textContent = "";
        });
        $("#btn-submit-rule")?.addEventListener("click", async () => {
            const triggers = [];
            if ($("#trig-violence")?.checked) triggers.push("VIOLENCE");
            if ($("#trig-previolence")?.checked) triggers.push("PRE-VIOLENCE");
            const body = {
                name: $("#rule-name")?.value.trim(),
                severity: $("#rule-severity")?.value,
                min_probability: parseFloat($("#rule-min-prob")?.value) || 0.55,
                cooldown_seconds: parseInt($("#rule-cooldown")?.value) || 60,
                label_triggers: triggers,
                notify_sms: $("#rule-sms")?.checked || false,
                notify_email: $("#rule-email")?.checked || false,
                enabled: true,
            };
            if (!body.name) { $("#rule-form-error").textContent = "Name is required"; return; }
            if (!triggers.length) { $("#rule-form-error").textContent = "Select at least one trigger"; return; }
            try {
                await api("/api/alarm-rules", { method: "POST", body: JSON.stringify(body) });
                $("#add-rule-form").style.display = "none";
                $("#btn-add-rule").style.display = "inline-block";
                $("#rule-form-error").textContent = "";
                loadAlarmRules();
            } catch (err) {
                $("#rule-form-error").textContent = err.message || "Failed to save rule";
            }
        });
        $("#btn-refresh-alarms")?.addEventListener("click", loadAlarms);
        $("#alarm-filter-state")?.addEventListener("change", loadAlarms);
    }

    async function deleteRule(ruleId) {
        if (!confirm("Delete this alarm rule?")) return;
        try {
            await api(`/api/alarm-rules/${ruleId}`, { method: "DELETE" });
            loadAlarmRules();
        } catch (err) { console.error("Delete rule error:", err); }
    }

    /* 
       INIT
        */
    function init() {
        initLogin();
        initNav();
    }

    // Patch switchSection to lazy-load Alarms + Guards sections
    const _origSwitchSection = switchSection;
    switchSection = function (sectionId) {
        _origSwitchSection(sectionId);
        if (sectionId === "alarms-section") loadAlarms();
        if (sectionId === "guards-section") App.loadGuards?.();
    };

    // Patch showDashboard to init alarm form after DOM is ready
    const _origShowDashboard = showDashboard;

    document.addEventListener("DOMContentLoaded", () => {
        init();
        initAlarmRuleForm();
        // NOTE: App.initGuardForms() is called after the Guards module loads (below)
    });

    // Public API for inline onclick
    return { switchSection, acknowledgeAlarm, dismissAlarm, deleteRule };
})();

/* ══════════════════════════════════════════════════════
   GUARDS & ZONES MODULE
   ══════════════════════════════════════════════════════ */
Object.assign(App, (() => {

    // Cached data for assignment panel
    let _guardsCache = [];
    let _zonesCache = [];

    const $ = sel => document.querySelector(sel);
    const token = () => window._svToken;   // set below

    // Re-use App's api() by referencing it through the closure trick:
    // Since App is the IIFE above, we call its api via a thin wrapper
    async function gApi(path, opts = {}) {
        // Reach into App closure by calling a helper exposed on window
        return window._svApi(path, opts);
    }

    async function loadGuards() {
        try {
            const [gr, zr] = await Promise.all([
                gApi("/api/guards"),
                gApi("/api/zones"),
            ]);
            _guardsCache = gr.guards || [];
            _zonesCache = zr.zones || [];
            renderGuardsTable(_guardsCache, _zonesCache);
            renderZonesTable(_zonesCache);
        } catch (err) {
            console.error("Guards load error:", err);
            // Ensure tables show error or empty state instead of being blank
            renderGuardsTable([], []);
            renderZonesTable([]);
        }
    }

    function _makeEl(tag, props = {}, children = []) {
        const el = document.createElement(tag);
        for (const [k, v] of Object.entries(props)) {
            if (k === "style") Object.assign(el.style, v);
            else if (k === "class") el.className = v;
            else if (k === "text") el.textContent = v;
            else el[k] = v;
        }
        children.forEach(c => el.appendChild(typeof c === "string"
            ? document.createTextNode(c) : c));
        return el;
    }

    function _makeChips(items, placeholder) {
        const wrap = document.createElement("div");
        wrap.className = "zone-chips";
        if (!items || !items.length) {
            const s = document.createElement("span");
            s.style.color = "var(--text-muted)";
            s.textContent = placeholder;
            wrap.appendChild(s);
        } else {
            items.forEach(text => {
                const chip = document.createElement("span");
                chip.className = "zone-chip";
                chip.textContent = text;
                wrap.appendChild(chip);
            });
        }
        return wrap;
    }

    function renderGuardsTable(guards, zones) {
        const tbody = $("#guards-table-body");
        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
        if (!guards.length) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 6; td.className = "empty-state"; td.textContent = "No guards registered";
            tr.appendChild(td); tbody.appendChild(tr);
            return;
        }
        guards.forEach(g => {
            const tr = document.createElement("tr");

            // Name
            const tdName = document.createElement("td");
            tdName.style.fontWeight = "600"; tdName.textContent = g.name;
            tr.appendChild(tdName);

            // Phone
            const tdPhone = document.createElement("td");
            tdPhone.style.fontVariantNumeric = "tabular-nums"; tdPhone.textContent = g.phone;
            tr.appendChild(tdPhone);

            // Badge
            const tdBadge = document.createElement("td");
            tdBadge.style.color = "var(--text-muted)"; tdBadge.textContent = g.badge_id || "—";
            tr.appendChild(tdBadge);

            // Zones
            const tdZones = document.createElement("td");
            const zoneNames = (g.zones || []).map(zid => {
                const z = zones.find(zz => zz.zone_id === zid);
                return z ? z.name : null;
            }).filter(Boolean);
            tdZones.appendChild(_makeChips(zoneNames, "None"));
            tr.appendChild(tdZones);

            // Status
            const tdStatus = document.createElement("td");
            const badge = document.createElement("span");
            badge.className = "state-badge " + (g.active ? "state-active" : "state-dismissed");
            badge.textContent = g.active ? "Active" : "Inactive";
            tdStatus.appendChild(badge); tr.appendChild(tdStatus);

            // Actions
            const tdAct = document.createElement("td");
            const btnAssign = document.createElement("button");
            btnAssign.className = "btn-ack"; btnAssign.style.fontSize = "0.7rem";
            btnAssign.textContent = "Assign Zones";
            btnAssign.addEventListener("click", () => openAssignment(g.guard_id));
            const btnDel = document.createElement("button");
            btnDel.className = "btn-dismiss"; btnDel.textContent = "Remove";
            btnDel.addEventListener("click", () => deleteGuard(g.guard_id));
            tdAct.appendChild(btnAssign); tdAct.appendChild(btnDel);
            tr.appendChild(tdAct);

            tbody.appendChild(tr);
        });
    }

    function renderZonesTable(zones) {
        const tbody = $("#zones-table-body");
        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
        if (!zones.length) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 5; td.className = "empty-state"; td.textContent = "No zones defined";
            tr.appendChild(td); tbody.appendChild(tr);
            return;
        }
        zones.forEach(z => {
            const tr = document.createElement("tr");

            const tdName = document.createElement("td");
            tdName.style.fontWeight = "600"; tdName.textContent = z.name;
            tr.appendChild(tdName);

            const tdDesc = document.createElement("td");
            tdDesc.style.color = "var(--text-muted)"; tdDesc.textContent = z.description || "—";
            tr.appendChild(tdDesc);

            const tdCams = document.createElement("td");
            tdCams.appendChild(_makeChips(z.cameras || [], "None"));
            tr.appendChild(tdCams);

            const tdGuards = document.createElement("td");
            const gbadge = document.createElement("span");
            gbadge.className = "state-badge state-active";
            const gc = z.guard_count ?? 0;
            gbadge.textContent = `${gc} guard${gc !== 1 ? "s" : ""}`;
            tdGuards.appendChild(gbadge); tr.appendChild(tdGuards);

            const tdAct = document.createElement("td");
            const btnDel = document.createElement("button");
            btnDel.className = "btn-dismiss"; btnDel.textContent = "Delete";
            btnDel.addEventListener("click", () => deleteZone(z.zone_id));
            tdAct.appendChild(btnDel); tr.appendChild(tdAct);

            tbody.appendChild(tr);
        });
    }

    function openAssignment(guardId) {
        const guard = _guardsCache.find(g => g.guard_id === guardId);
        if (!guard) return;
        const panel = $("#assignment-panel");
        const title = $("#assignment-title");
        const body = $("#assignment-body");
        title.textContent = `Zone Assignment — ${guard.name}`;
        while (body.firstChild) body.removeChild(body.firstChild);

        if (!_zonesCache.length) {
            const p = document.createElement("p");
            p.className = "empty-state"; p.textContent = "No zones yet — create a zone first.";
            body.appendChild(p);
        } else {
            _zonesCache.forEach(z => {
                const assigned = (guard.zones || []).includes(z.zone_id);
                const card = document.createElement("div");
                card.className = "assignment-card" + (assigned ? " assigned" : "");
                card.id = `acard-${z.zone_id}`;

                const info = document.createElement("div");
                info.className = "assignment-info";

                const zoneName = document.createElement("span");
                zoneName.className = "assignment-zone-name"; zoneName.textContent = z.name;
                info.appendChild(zoneName);

                const zoneDesc = document.createElement("span");
                zoneDesc.className = "assignment-zone-desc"; zoneDesc.textContent = z.description || "";
                info.appendChild(zoneDesc);

                const chips = _makeChips(z.cameras || [], "");
                chips.style.marginTop = "4px";
                info.appendChild(chips);
                card.appendChild(info);

                const lbl = document.createElement("label");
                lbl.className = "toggle-switch";
                const chk = document.createElement("input");
                chk.type = "checkbox"; chk.checked = assigned;
                chk.addEventListener("change", () => _toggleZone(guardId, z.zone_id, chk.checked));
                const slider = document.createElement("span");
                slider.className = "toggle-slider";
                lbl.appendChild(chk); lbl.appendChild(slider);
                card.appendChild(lbl);

                body.appendChild(card);
            });
        }

        panel.style.display = "block";
        panel.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    async function _toggleZone(guardId, zoneId, checked) {
        try {
            const endpoint = checked ? "assign-zone" : "remove-zone";
            await gApi(`/api/guards/${guardId}/${endpoint}`, {
                method: "POST",
                body: JSON.stringify({ zone_id: zoneId }),
            });
            // Update cache immediately
            const g = _guardsCache.find(g => g.guard_id === guardId);
            if (g) {
                if (checked) g.zones = [...(g.zones || []), zoneId];
                else g.zones = (g.zones || []).filter(z => z !== zoneId);
            }
            // Reflect assigned class
            const card = document.getElementById(`acard-${zoneId}`);
            if (card) card.classList.toggle("assigned", checked);
            // Refresh main table
            renderGuardsTable(_guardsCache, _zonesCache);
        } catch (err) { console.error("Zone toggle error:", err); }
    }

    async function deleteGuard(guardId) {
        if (!confirm("Remove this guard permanently?")) return;
        try {
            await gApi(`/api/guards/${guardId}`, { method: "DELETE" });
            loadGuards();
        } catch (err) { console.error(err); }
    }

    async function deleteZone(zoneId) {
        if (!confirm("Delete this zone? Guards will be unassigned from it.")) return;
        try {
            await gApi(`/api/zones/${zoneId}`, { method: "DELETE" });
            loadGuards();
        } catch (err) { console.error(err); }
    }

    function initGuardForms() {
        // Guard form
        $("#btn-show-add-guard")?.addEventListener("click", () => {
            $("#add-guard-form").style.display = "block";
        });
        $("#btn-cancel-guard")?.addEventListener("click", () => {
            $("#add-guard-form").style.display = "none";
            $("#guard-form-error").textContent = "";
        });
        $("#btn-submit-guard")?.addEventListener("click", async () => {
            const name = $("#guard-name")?.value.trim();
            const phone = $("#guard-phone")?.value.trim();
            if (!name || !phone) { $("#guard-form-error").textContent = "Name and phone are required"; return; }
            try {
                await gApi("/api/guards", {
                    method: "POST", body: JSON.stringify({
                        name, phone,
                        email: $("#guard-email")?.value.trim(),
                        badge_id: $("#guard-badge")?.value.trim(),
                        notes: $("#guard-notes")?.value.trim(),
                    })
                });
                $("#add-guard-form").style.display = "none";
                $("#guard-form-error").textContent = "";
                ["guard-name", "guard-phone", "guard-email", "guard-badge", "guard-notes"]
                    .forEach(id => { const el = $(`#${id}`); if (el) el.value = ""; });
                loadGuards();
            } catch (err) { $("#guard-form-error").textContent = err.message || "Error"; }
        });

        // Zone form
        $("#btn-show-add-zone")?.addEventListener("click", () => {
            $("#add-zone-form").style.display = "block";
        });
        $("#btn-cancel-zone")?.addEventListener("click", () => {
            $("#add-zone-form").style.display = "none";
            $("#zone-form-error").textContent = "";
        });
        $("#btn-submit-zone")?.addEventListener("click", async () => {
            const name = $("#zone-name")?.value.trim();
            if (!name) { $("#zone-form-error").textContent = "Zone name is required"; return; }
            const cameras = ($("#zone-cameras")?.value || "").split(",").map(s => s.trim()).filter(Boolean);
            try {
                await gApi("/api/zones", {
                    method: "POST", body: JSON.stringify({
                        name, cameras,
                        description: $("#zone-desc")?.value.trim(),
                    })
                });
                $("#add-zone-form").style.display = "none";
                $("#zone-form-error").textContent = "";
                ["zone-name", "zone-desc", "zone-cameras"]
                    .forEach(id => { const el = $(`#${id}`); if (el) el.value = ""; });
                loadGuards();
            } catch (err) { $("#zone-form-error").textContent = err.message || "Error"; }
        });

        // Close assignment panel
        $("#btn-close-assignment")?.addEventListener("click", () => {
            $("#assignment-panel").style.display = "none";
        });
    }

    return { loadGuards, deleteGuard, deleteZone, openAssignment, _toggleZone, initGuardForms };

})());

// Expose api and token bridge for Guards module
(function patchAppBridge() {
    // The Guards module uses window._svApi — we wire it after the IIFE closes
    // by attaching to window after App is defined.
    const _origInit = document.addEventListener;
    window._svApi = async function (path, opts) {
        // Reach App's internal api() via a re-implemented fetch wrapper
        const tok = window._svToken;
        const hmacKeyStr = window._svHmac;
        const headers = { "Content-Type": "application/json" };
        if (tok) headers["Authorization"] = `Bearer ${tok}`;
        const res = await fetch(path, { ...opts, headers });
        if (res.status === 401) throw new Error("Unauthorized");

        const text = await res.text();
        const sig = res.headers.get("X-Signature");
        if (sig && hmacKeyStr) {
            try {
                const hexToBytes = hex => {
                    let bytes = new Uint8Array(Math.ceil(hex.length / 2));
                    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                    return bytes;
                };
                const key = await crypto.subtle.importKey(
                    "raw", hexToBytes(hmacKeyStr),
                    { name: "HMAC", hash: "SHA-256" },
                    false, ["verify"]
                );
                const isValid = await crypto.subtle.verify(
                    "HMAC", key, hexToBytes(sig), new TextEncoder().encode(text)
                );
                if (!isValid) throw new Error("SECURITY ALERT: Response integrity verification failed (tampered data detected).");
            } catch (e) {
                console.error("Bridge signature error", e);
                if (e.message.includes("SECURITY ALERT")) throw e;
            }
        }
        return text ? JSON.parse(text) : {};
    };
})();

//  Initialize Guard forms now that the Guards module exists 
function _tryInitGuards() {
    if (App.initGuardForms) App.initGuardForms();
}
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", _tryInitGuards);
} else {
    _tryInitGuards();
}

/* ══════════════════════════════════════════════════════
   REPORTS MODULE
   ══════════════════════════════════════════════════════ */
Object.assign(App, (() => {

    const $ = sel => document.querySelector(sel);
    let _lastReportParams = {};   // remembered for export links

    // Stream state (owned by this block)
    let streamWs = null;
    let streamCryptoKey = null;

    //  Date helpers 
    function fmtDate(d) {
        return d.toISOString().slice(0, 10);
    }
    function initReportDates() {
        const today = new Date();
        const d30 = new Date(today); d30.setDate(today.getDate() - 30);
        const toEl = $("#rpt-to");
        const fromEl = $("#rpt-from");
        if (toEl && !toEl.value) toEl.value = fmtDate(today);
        if (fromEl && !fromEl.value) fromEl.value = fmtDate(d30);
    }

    function getParams() {
        return {
            from: $("#rpt-from")?.value || "",
            to: $("#rpt-to")?.value || "",
            camera_id: $("#rpt-camera")?.value.trim() || "",
            severity: $("#rpt-severity")?.value || "",
            encryption_key: $("#rpt-encryption-key")?.value || "",
        };
    }

    function buildQS(params) {
        const p = new URLSearchParams();
        if (params.from) p.set("from", params.from);
        if (params.to) p.set("to", params.to);
        if (params.camera_id) p.set("camera_id", params.camera_id);
        if (params.severity) p.set("severity", params.severity);
        if (params.encryption_key) p.set("encryption_key", params.encryption_key);
        return p.toString() ? "?" + p.toString() : "";
    }

    //  Generate report ─
    async function runReport() {
        const btn = $("#btn-run-report");
        if (btn) { btn.disabled = true; btn.textContent = "⏳ Loading…"; }
        try {
            const params = getParams();
            _lastReportParams = params;
            const data = await window._svApi(`/api/reports/violence${buildQS(params)}`);
            renderReport(data);
        } catch (err) {
            console.error("Report error:", err);
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = "🔍 Generate Report"; }
        }
    }

    //  Render 
    function renderReport(data) {
        const s = data.summary || {};
        const rt = data.response_times || {};
        const m = data.meta || {};

        // Show all panels
        ["rpt-stat-cards", "rpt-charts-row", "rpt-bottom-row", "rpt-incidents-panel"]
            .forEach(id => { const el = $("#" + id); if (el) el.style.display = ""; });

        // Stat cards
        setText("rpt-total", s.total ?? "—");
        setText("rpt-critical", s.critical ?? "—");
        setText("rpt-warning", s.warning ?? "—");
        setText("rpt-cameras", s.cameras_affected ?? "—");
        setText("rpt-sms", s.sms_sent ?? "—");
        setText("rpt-email", s.emails_sent ?? "—");
        const ackSec = rt.avg_seconds;
        setText("rpt-ack-time", ackSec != null ? formatDuration(ackSec) : "—");

        // Meta text
        const metaEl = $("#rpt-meta-text");
        if (metaEl) metaEl.innerHTML =
            `<b>Period:</b> ${m.from?.slice(0, 10)} → ${m.to?.slice(0, 10)}<br>
             <b>Generated:</b> ${m.generated?.slice(0, 19)} UTC<br>
             <b>Incidents/day:</b> ${s.incidents_per_day ?? "—"}<br>
             <b>Peak hour:</b> ${s.peak_hour != null ? s.peak_hour.toString().padStart(2, "0") + ":00" : "—"}<br>
             <b>Peak camera:</b> ${s.peak_camera ?? "—"}`;

        // Incident count label
        const icLbl = $("#rpt-incident-count");
        if (icLbl) icLbl.textContent = `${(data.incidents || []).length} records`;

        // Charts
        drawDailyChart(data.by_day || []);
        drawHourlyChart(data.by_hour || []);

        // Camera table
        renderCameraTable(data.by_camera || []);

        // Incident log
        renderIncidentLog(data.incidents || []);
    }

    function setText(id, val) {
        const el = $("#" + id); if (el) el.textContent = val;
    }

    function formatDuration(sec) {
        if (sec < 60) return `${sec}s`;
        if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
        return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
    }

    //  Charts (Canvas) ─
    function drawDailyChart(byDay) {
        const canvas = $("#rpt-chart-daily");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const W = canvas.offsetWidth || 600;
        canvas.width = W;
        canvas.height = 180;

        const data = byDay.slice(-30);   // last 30 days
        const max = Math.max(1, ...data.map(d => d.total));
        const pad = { t: 20, r: 10, b: 40, l: 36 };
        const cW = W - pad.l - pad.r;
        const cH = canvas.height - pad.t - pad.b;
        const barW = Math.max(2, cW / data.length - 2);

        ctx.clearRect(0, 0, W, canvas.height);

        // Grid lines
        ctx.strokeStyle = "rgba(255,255,255,0.06)";
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = pad.t + (cH * i / 4);
            ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
        }

        data.forEach((d, i) => {
            const x = pad.l + i * (cW / data.length);
            // Warning bar (bottom)
            const wH = (d.warning / max) * cH;
            ctx.fillStyle = "rgba(245,158,11,0.65)";
            ctx.fillRect(x, pad.t + cH - wH, barW, wH);
            // Critical bar (stacked on top)
            const crH = (d.critical / max) * cH;
            ctx.fillStyle = "rgba(220,38,38,0.80)";
            ctx.fillRect(x, pad.t + cH - wH - crH, barW, crH);

            // X labels every 5 days
            if (i % 5 === 0) {
                ctx.fillStyle = "rgba(156,163,175,0.9)";
                ctx.font = "9px sans-serif";
                ctx.textAlign = "center";
                ctx.fillText(d.date?.slice(5) || "", x + barW / 2, canvas.height - 8);
            }
        });

        // Y axis labels
        ctx.fillStyle = "rgba(156,163,175,0.9)";
        ctx.font = "9px sans-serif";
        ctx.textAlign = "right";
        for (let i = 0; i <= 4; i++) {
            const val = Math.round(max * (4 - i) / 4);
            const y = pad.t + (cH * i / 4);
            ctx.fillText(val, pad.l - 4, y + 4);
        }

        // Legend
        ctx.font = "10px sans-serif"; ctx.textAlign = "left";
        ctx.fillStyle = "rgba(220,38,38,0.9)"; ctx.fillRect(pad.l, 4, 10, 8);
        ctx.fillStyle = "#9ca3af"; ctx.fillText("Critical", pad.l + 13, 12);
        ctx.fillStyle = "rgba(245,158,11,0.9)"; ctx.fillRect(pad.l + 65, 4, 10, 8);
        ctx.fillStyle = "#9ca3af"; ctx.fillText("Warning", pad.l + 78, 12);
    }

    function drawHourlyChart(byHour) {
        const canvas = $("#rpt-chart-hourly");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const W = canvas.offsetWidth || 600;
        canvas.width = W;
        canvas.height = 180;

        const max = Math.max(1, ...byHour.map(h => h.count));
        const pad = { t: 20, r: 10, b: 40, l: 36 };
        const cW = W - pad.l - pad.r;
        const cH = canvas.height - pad.t - pad.b;
        const barW = Math.max(2, cW / 24 - 2);

        ctx.clearRect(0, 0, W, canvas.height);

        // Grid
        ctx.strokeStyle = "rgba(255,255,255,0.06)";
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = pad.t + (cH * i / 4);
            ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
        }

        byHour.forEach((h, i) => {
            const x = pad.l + i * (cW / 24);
            const barH = (h.count / max) * cH;
            // Colour based on count intensity
            const ratio = h.count / max;
            const alpha = 0.3 + ratio * 0.7;
            const r = Math.round(220 * ratio + 59 * (1 - ratio));
            const g = Math.round(38 * ratio + 130 * (1 - ratio));
            const b = Math.round(38 * ratio + 246 * (1 - ratio));
            ctx.fillStyle = `rgba(${r},${g},${b},${alpha})`;
            ctx.fillRect(x, pad.t + cH - barH, barW, barH);

            if (i % 4 === 0) {
                ctx.fillStyle = "rgba(156,163,175,0.9)";
                ctx.font = "9px sans-serif";
                ctx.textAlign = "center";
                ctx.fillText(`${i}:00`, x + barW / 2, canvas.height - 8);
            }
        });

        ctx.fillStyle = "rgba(156,163,175,0.9)"; ctx.font = "9px sans-serif"; ctx.textAlign = "right";
        for (let i = 0; i <= 4; i++) {
            const val = Math.round(max * (4 - i) / 4);
            ctx.fillText(val, pad.l - 4, pad.t + (cH * i / 4) + 4);
        }
    }

    //  Camera table 
    function renderCameraTable(cameras) {
        const tbody = $("#rpt-camera-table");
        if (!tbody) return;
        if (!cameras.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No incidents</td></tr>`;
            return;
        }
        tbody.innerHTML = cameras.map(c => {
            const pct = ((c.avg_probability || 0) * 100).toFixed(1) + "%";
            return `<tr>
                <td style="font-weight:600">${c.camera_id}</td>
                <td style="color:var(--text-muted)">${c.location || "—"}</td>
                <td><b>${c.total}</b></td>
                <td><span class="severity-badge severity-critical">${c.critical}</span></td>
                <td><span class="severity-badge severity-warning">${c.warning}</span></td>
                <td>${pct}</td>
            </tr>`;
        }).join("");
    }

    //  Incident log 
    function renderIncidentLog(incidents) {
        const tbody = $("#rpt-incidents-body");
        if (!tbody) return;
        if (!incidents.length) {
            tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No incidents</td></tr>`;
            return;
        }
        tbody.innerHTML = incidents.map(inc => {
            const sevCls = inc.severity === "CRITICAL" ? "severity-critical" : "severity-warning";
            const stCls = { ACTIVE: "state-active", ACKNOWLEDGED: "state-acknowledged", DISMISSED: "state-dismissed" }[inc.state] || "";
            const guards = Array.isArray(inc.notified_guards) && inc.notified_guards.length
                ? inc.notified_guards.join(", ")
                : `<span style="color:var(--text-muted)">—</span>`;
            return `<tr>
                <td style="font-variant-numeric:tabular-nums;white-space:nowrap">${(inc.fired_at || "").replace("T", " ").slice(0, 16)}</td>
                <td>${inc.camera_id || "—"}</td>
                <td style="color:var(--text-muted)">${inc.location || "—"}</td>
                <td>${inc.label || "—"}</td>
                <td><span class="severity-badge ${sevCls}">${inc.severity}</span></td>
                <td>${((inc.probability || 0) * 100).toFixed(1)}%</td>
                <td><span class="state-badge ${stCls}">${inc.state}</span></td>
                <td style="font-size:0.78rem">${guards}</td>
            </tr>`;
        }).join("");
    }

    //  Export helpers 
    function exportUrl(format) {
        const params = getParams();
        const qs = buildQS(params);
        return `/api/reports/violence/${format}${qs}`;
    }

    function downloadFile(url) {
        // Attach token as query param for file downloads (no header support)
        const sep = url.includes("?") ? "&" : "?";
        const tok = window._svToken || "";
        const a = document.createElement("a");
        a.href = url + sep + "token=" + encodeURIComponent(tok);
        a.target = "_blank";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    //  Init 
    function initReports() {
        initReportDates();

        $("#btn-run-report")?.addEventListener("click", runReport);

        // Quick presets
        document.querySelectorAll(".preset-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                const days = parseInt(btn.dataset.days);
                const today = new Date();
                const from = new Date(today); from.setDate(today.getDate() - days);
                const toEl = $("#rpt-to"); if (toEl) toEl.value = fmtDate(today);
                const fromEl = $("#rpt-from"); if (fromEl) fromEl.value = fmtDate(from);
                runReport();
            });
        });

        // Exports
        $("#btn-export-csv")?.addEventListener("click", () => downloadFile(exportUrl("csv")));
        $("#btn-export-pdf")?.addEventListener("click", () => downloadFile(exportUrl("pdf")));
        $("#btn-print-report")?.addEventListener("click", () => window.print());
    }

    /* 
       LIVE STREAM (ENCRYPTED)
    */
    function initLiveStream() {
        const connectBtn = $("#btn-connect-stream");
        const disconnectBtn = $("#btn-disconnect-stream");
        if (!connectBtn) return;

        connectBtn.onclick = () => {
            const camId = $("#stream-camera-id").value.trim();
            if (camId) connectStream(camId);
        };
        disconnectBtn.onclick = disconnectStream;
    }

    async function connectStream(cameraId) {
        if (streamWs) disconnectStream();

        const statusEl = $("#stream-status");
        const imgEl = $("#live-stream-img");
        const connectBtn = $("#btn-connect-stream");
        const disconnectBtn = $("#btn-disconnect-stream");

        statusEl.textContent = "Connecting and fetching key...";
        statusEl.style.display = "block";
        imgEl.style.display = "none";

        try {
            // 1. Fetch the decryption key
            const keyData = await window._svApi("/api/stream/key");
            if (!keyData || !keyData.key) {
                throw new Error(keyData ? keyData.error : "Missing key data");
            }
            const rawKey = Uint8Array.from(atob(keyData.key), c => c.charCodeAt(0));

            streamCryptoKey = await crypto.subtle.importKey(
                "raw", rawKey,
                { name: "AES-GCM" },
                false, ["decrypt"]
            );

            // 2. Open WebSocket
            const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
            const wsUrl = `${proto}//${window.location.host}/api/stream/${cameraId}?token=${window._svToken}`;

            streamWs = new WebSocket(wsUrl);
            streamWs.binaryType = "arraybuffer";

            streamWs.onopen = () => {
                statusEl.textContent = "Connected. Decrypting stream...";
                connectBtn.style.display = "none";
                disconnectBtn.style.display = "inline-block";
            };

            streamWs.onmessage = async (msg) => {
                try {
                    if (typeof msg.data === "string") {
                        console.error("Stream error from server:", msg.data);
                        try {
                            const errObj = JSON.parse(msg.data);
                            if (errObj.error === "Unauthorized") {
                                statusEl.textContent = "Session expired — please log out and log in again.";
                                statusEl.style.display = "block";
                                statusEl.style.color = "#f87171";
                                return;
                            }
                        } catch (e) { }
                        statusEl.textContent = "Server error: " + msg.data;
                        statusEl.style.display = "block";
                        return;
                    }
                    const data = new Uint8Array(msg.data);
                    if (data.length < 13) return; // Nonce(12) + Tag(16) + Payload

                    // Extract 12-byte nonce
                    const nonce = data.slice(0, 12);
                    const ciphertext = data.slice(12);

                    // Decrypt using Web Crypto API
                    const decrypted = await crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: nonce },
                        streamCryptoKey,
                        ciphertext
                    );

                    // Render to image
                    const blob = new Blob([decrypted], { type: "image/jpeg" });
                    const url = URL.createObjectURL(blob);

                    const oldUrl = imgEl.src;
                    imgEl.src = url;
                    imgEl.style.display = "block";
                    statusEl.style.display = "none";

                    if (oldUrl.startsWith("blob:")) URL.revokeObjectURL(oldUrl);
                } catch (err) {
                    console.error("Stream decryption error:", err);
                    statusEl.textContent = "Decryption error. Check console.";
                    statusEl.style.display = "block";
                }
            };

            streamWs.onclose = () => {
                const prevText = statusEl.textContent;
                cleanupStreamUI();
                // Preserve error messages — don't overwrite with generic 'Disconnected'
                if (prevText && prevText !== "Disconnected" && prevText !== "Connected. Decrypting stream...") {
                    statusEl.textContent = prevText;
                    statusEl.style.display = "block";
                }
            };

            streamWs.onerror = (err) => {
                console.error("Stream WebSocket error:", err);
                statusEl.textContent = "Connection error.";
                cleanupStreamUI();
            };

        } catch (err) {
            console.error("Failed to start stream:", err);
            statusEl.textContent = "Auth/Key error: " + err.message;
        }
    }

    function disconnectStream() {
        if (streamWs) {
            streamWs.close();
            streamWs = null;
        }
        cleanupStreamUI();
    }

    function cleanupStreamUI() {
        const statusEl = $("#stream-status");
        const imgEl = $("#live-stream-img");
        const connectBtn = $("#btn-connect-stream");
        const disconnectBtn = $("#btn-disconnect-stream");

        if (statusEl && !streamWs) { statusEl.textContent = "Disconnected"; statusEl.style.color = ""; }
        if (imgEl) {
            const oldUrl = imgEl.src;
            imgEl.style.display = "none";
            imgEl.src = "";
            if (oldUrl.startsWith("blob:")) URL.revokeObjectURL(oldUrl);
        }
        if (connectBtn) connectBtn.style.display = "inline-block";
        if (disconnectBtn) disconnectBtn.style.display = "none";
    }

    return { initReports, runReport, initLiveStream, disconnectStream };

})());

// Patch switchSection to lazy-load Reports section
(function patchReportSwitch() {
    const _orig = App.switchSection.bind(App);
    App.switchSection = function (sectionId) {
        _orig(sectionId);
        if (sectionId === "reports-section") App.initReports?.();
        if (sectionId === "recordings-section") App.loadRecordings?.();
    };
    // Also hook into DOMContentLoaded
    function _tryInitReports() {
        if (App.initReports) App.initReports();
        if (App.initRecordings) App.initRecordings();
    }
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", _tryInitReports);
    } else {
        _tryInitReports();
    }
})();

/* ══════════════════════════════════════════════════════
   RECORDINGS MODULE
   ══════════════════════════════════════════════════════ */
Object.assign(App, (() => {
    const $ = sel => document.querySelector(sel);

    async function loadRecordings() {
        try {
            const data = await window._svApi("/api/recordings");
            renderRecordingsTable(data.recordings || []);
        } catch (err) {
            console.error("Recordings load error:", err);
            renderRecordingsTable([]);
        }
    }

    function renderRecordingsTable(recordings) {
        const tbody = $("#recordings-table-body");
        if (!tbody) return;
        
        if (!recordings.length) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No recordings found.</td></tr>`;
            return;
        }

        tbody.innerHTML = recordings.map(r => {
            const sizeMB = (r.size / (1024 * 1024)).toFixed(2) + " MB";
            const dateStr = r.date.replace("T", " ").slice(0, 19);
            return `<tr>
                <td style="font-weight:600; color:var(--accent);">${r.filename}</td>
                <td>${dateStr}</td>
                <td>${sizeMB}</td>
                <td>
                    <button class="btn-sm btn-primary" onclick="App.playRecording('${r.filename}')">Play</button>
                </td>
            </tr>`;
        }).join("");
    }

    async function playRecording(filename) {
        const key = $("#recordings-master-key")?.value.trim();
        if (!key) {
            alert("Please enter the Master Decryption Key first to unlock recordings.");
            return;
        }

        const btn = $("#btn-unlock-recordings");
        if (btn) {
            btn.textContent = "Decrypting...";
            btn.disabled = true;
        }

        try {
            const token = window._svToken;
            const res = await fetch(`/api/recordings/${filename}/decrypt`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`
                },
                body: JSON.stringify({ key })
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || "Decryption failed");
            }

            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            
            const playerContainer = $("#recordings-player-container");
            const video = $("#recordings-video-player");
            const title = $("#recordings-player-title");
            
            title.textContent = "Playback: " + filename;
            video.src = url;
            playerContainer.style.display = "block";
            
            video.play().catch(e => console.warn("Auto-play prevented", e));
        } catch (err) {
            console.error("Playback error:", err);
            alert("Error: " + err.message);
        } finally {
            if (btn) {
                btn.textContent = "Unlock";
                btn.disabled = false;
            }
        }
    }

    function initRecordings() {

        $("#btn-unlock-recordings")?.addEventListener("click", async () => {
            const key = $("#recordings-master-key")?.value.trim();
            if (!key) {
                alert("Please enter a key.");
                return;
            }

            const btn = $("#btn-unlock-recordings");
            const originalText = btn.textContent;
            btn.textContent = "Verifying...";
            btn.disabled = true;

            try {
                const token = window._svToken;
                const res = await fetch(`/api/verify-master-key`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${token}`
                    },
                    body: JSON.stringify({ key })
                });

                if (!res.ok) {
                    throw new Error("Incorrect master key");
                }

                btn.textContent = "Key Verified!";
                btn.style.backgroundColor = "#10b981"; // success green
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.backgroundColor = "";
                }, 3000);
            } catch (err) {
                alert(err.message);
                btn.textContent = originalText;
            } finally {
                btn.disabled = false;
            }
        });

        $("#btn-close-player")?.addEventListener("click", () => {
            const container = $("#recordings-player-container");
            const video = $("#recordings-video-player");
            if (container) container.style.display = "none";
            if (video) {
                video.pause();
                URL.revokeObjectURL(video.src);
                video.src = "";
            }
        });
    }

    return { loadRecordings, playRecording, initRecordings };
})());
