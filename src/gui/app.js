document.addEventListener('DOMContentLoaded', () => {
    
    // ══════════════════════════════════════════════════════════════════════════
    // COLLAPSIBLE SIDEBAR & NAVIGATION SYSTEM
    // ══════════════════════════════════════════════════════════════════════════

    const body = document.body;
    const collapseBtn = document.getElementById('collapse-btn');
    const viewTitle = document.getElementById('view-title');
    const navItems = document.querySelectorAll('.rail-item[data-view], .app-item[data-view]');
    const views = document.querySelectorAll('.dt-view');

    // Sidebar Collapse Toggle
    if (collapseBtn) {
        collapseBtn.addEventListener('click', () => {
            body.classList.toggle('collapsible-sidebar-active');
        });
    }

    // View Switching Logic
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetViewId = item.getAttribute('data-view');
            
            // Remove active class from all nav items
            navItems.forEach(nav => nav.classList.remove('active'));
            
            // Add active class to corresponding nav items (both rail and app grid)
            document.querySelectorAll(`[data-view="${targetViewId}"]`).forEach(n => n.classList.add('active'));

            // Switch Views
            views.forEach(v => {
                v.style.display = 'none';
                v.classList.remove('active');
            });
            const targetView = document.getElementById(`view-${targetViewId}`);
            if (targetView) {
                targetView.style.display = 'flex';
                // Trigger reflow for animations
                void targetView.offsetWidth;
                targetView.classList.add('active');
            }

            // Update Header Title depending on view
            if (targetViewId === 'hub') viewTitle.textContent = 'Browse all';
            else if (targetViewId === 'dashboard') viewTitle.textContent = 'Dashboards / Main Analytics';
            else if (targetViewId === 'logs') viewTitle.textContent = 'Log Discovery (DQL)';
            
            // Re-render charts if dashboard is active to ensure proper canvas sizing
            if (targetViewId === 'dashboard') {
                if (window._dtWaveChart) window._dtWaveChart.resize();
            }
        });
    });

    // Sub-Navigation Home Button inside Hub Hero
    const heroHomeBtn = document.querySelector('.hero-home-btn');
    if (heroHomeBtn) {
        heroHomeBtn.addEventListener('click', () => {
            document.querySelector('.rail-item[data-view="hub"]').click();
        });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // DYNATRACE NEON CHART ENGINE (Trends in Motion)
    // ══════════════════════════════════════════════════════════════════════════
    
    const neonColors = [
        '#ff00ff', // Magenta
        '#00ffff', // Cyan
        '#7fbb00', // Lime
        '#7b7bff', // Purple-Blue
        '#ffcc00', // Yellow
        '#ff5050'  // Red
    ];

    function generateWaveData(offset, frequency, amplitude) {
        const data = [];
        for (let i = 0; i < 50; i++) {
            data.push(Math.sin(i * frequency + offset) * amplitude);
        }
        return data;
    }

    const ctxWave = document.getElementById('waveChart');
    if (ctxWave) {
        window._dtWaveChart = new Chart(ctxWave.getContext('2d'), {
            type: 'line',
            data: {
                labels: Array.from({length: 50}, (_, i) => `Feb ${Math.floor(i/10)+3}`),
                datasets: neonColors.map((color, idx) => ({
                    label: `Trend ${idx}`,
                    data: generateWaveData(idx * 0.5, 0.2, 1 - idx * 0.1),
                    borderColor: color,
                    borderWidth: 2,
                    pointRadius: 0,
                    fill: false,
                    tension: 0.4
                }))
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { color: 'rgba(255,255,255,0.3)', font: { size: 9 } } },
                    y: { min: -1.5, max: 1.5, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { display: false } }
                }
            }
        });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // WIDGET GENERATORS (Heatmap)
    // ══════════════════════════════════════════════════════════════════════════

    // Heatmap (Green intensity grid)
    const heatmap = document.getElementById('heatmap');
    if (heatmap) {
        for (let i = 0; i < 200; i++) {
            const cell = document.createElement('div');
            cell.className = 'hm-cell';
            const opacity = Math.random();
            cell.style.background = `rgba(127, 187, 0, ${opacity})`;
            heatmap.appendChild(cell);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // REAL DATA INTEGRATION (Log Discovery Table)
    // ══════════════════════════════════════════════════════════════════════════
    
    async function fetchLogs() {
        try {
            const res = await fetch('/api/logs');
            const data = await res.json();
            
            // Populate Discovery Table
            const tbody = document.getElementById('logs-tbody');
            if (tbody && data.length > 0) {
                tbody.innerHTML = '';
                data.slice(0, 50).forEach(log => {
                    const statusColor = log.status === 'CRITICAL' ? '#ff5050' : 
                                      (log.status === 'WARN' ? '#ffcc00' : '#7b7bff');
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="color:var(--text-muted);">${log.timestamp}</td>
                        <td><span style="font-weight:700; color:${statusColor};">${log.status}</span></td>
                        <td style="font-family:'Fira Code'; opacity:0.8;">${(log.message || log.raw).substring(0, 80)}...</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            // Update Critical KPIs on Dashboard
            const criticals = data.filter(l => l.status === 'CRITICAL').length;
            const uptimeEl = document.querySelector('.uptime-val');
            if (uptimeEl) {
                uptimeEl.textContent = (99.9 - (criticals * 0.1)).toFixed(1);
            }
        } catch (e) {
            console.error("Grail Engine Polling Error:", e);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // DISTRIBUTED TRACING ENGINE (SCREENSHOT 5 REPLICATION)
    // ══════════════════════════════════════════════════════════════════════════

    const ctxTrace = document.getElementById('traceChart');
    if (ctxTrace) {
        // Mock data logic for the dense timeseries chart
        const labels = Array.from({length: 60}, (_, i) => `09:${20 + Math.floor(i/2)} PM`);
        const barData = Array.from({length: 60}, () => Math.random() * 8000 + 4000);
        const lineData = Array.from({length: 60}, (_, i) => (i % 7 === 0) ? Math.random() * 8000 + 1000 : Math.random() * 2000);

        new Chart(ctxTrace.getContext('2d'), {
            data: {
                labels: labels,
                datasets: [
                    {
                        type: 'line',
                        label: 'Average',
                        data: lineData,
                        borderColor: '#7b7bff',
                        borderWidth: 2,
                        pointRadius: 0,
                        tension: 0.2
                    },
                    {
                        type: 'bar',
                        label: 'Failed requests',
                        data: barData,
                        backgroundColor: 'rgba(50, 80, 100, 0.4)',
                        barPercentage: 1.0,
                        categoryPercentage: 1.0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10 }, maxTicksLimit: 5 } },
                    y: { 
                        position: 'left', 
                        grid: { color: 'rgba(255,255,255,0.05)' }, 
                        ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10 }, callback: v => v >= 1000 ? (v/1000) + 'k' : v }
                    }
                }
            }
        });
    }

    // Populate Trace Table with exact data from Screenshot 5
    const traceTbody = document.getElementById('trace-tbody');
    if (traceTbody) {
        const traceData = [
            { time: "Apr 6, 21:42:50.945", ep: "ingress", srv: "frontend-proxy", dur: "13.88 ms", code: "200" },
            { time: "Apr 6, 21:42:50.944", ep: "ingress", srv: "frontend-proxy", dur: "17.08 ms", code: "200" },
            { time: "Apr 6, 21:42:50.765", ep: "oteldemo.ProductCatalog...", srv: "my-otel-demo-productca...", dur: "104.60 µs", code: "" },
            { time: "Apr 6, 21:42:50.728", ep: "imageprovider", srv: "my-otel-demo-imageprov...", dur: "0.00 ns", code: "200" },
            { time: "Apr 6, 21:42:50.617", ep: "oteldemo.ProductCatalog...", srv: "my-otel-demo-productca...", dur: "57.06 µs", code: "" },
            { time: "Apr 6, 21:42:50.606", ep: "HTTP GET", srv: "my-otel-demo-loadgener...", dur: "169.00 ms", code: "200" },
            { time: "Apr 6, 21:42:50.495", ep: "HTTP GET", srv: "my-otel-demo-loadgener...", dur: "159.00 ms", code: "200" },
            { time: "Apr 6, 21:42:50.440", ep: "ingress", srv: "my-otel-demo-frontendpr...", dur: "134.47 ms", code: "200" },
            { time: "Apr 6, 21:42:50.392", ep: "oteldemo.ProductCatalog...", srv: "my-otel-demo-productca...", dur: "1.89 ms", code: "" },
            { time: "Apr 6, 21:42:50.391", ep: "oteldemo.ProductCatalog...", srv: "my-otel-demo-productca...", dur: "115.49 µs", code: "" },
            { time: "Apr 6, 21:42:50.372", ep: "oteldemo.ProductCatalog...", srv: "my-otel-demo-productca...", dur: "125.64 µs", code: "" },
            { time: "Apr 6, 21:42:49.851", ep: "ingress", srv: "my-otel-demo-frontendpr...", dur: "9.56 ms", code: "200" },
            { time: "Apr 6, 21:42:49.777", ep: "GET", srv: "frontend", dur: "414.24 ms", code: "200" }
        ];

        let html = '';
        traceData.forEach(r => {
            let codeHtml = r.code ? `<span class="http-code">${r.code}</span>` : '';
            html += `
                <tr>
                    <td><svg viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.3)" stroke-width="2" width="10" style="margin-right:6px;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg> ${r.time}</td>
                    <td>${r.ep}</td>
                    <td>${r.srv}</td>
                    <td class="dur">${r.dur}</td>
                    <td><span class="success-tag">Success</span></td>
                    <td>${codeHtml}</td>
                </tr>
            `;
        });
        traceTbody.innerHTML = html;
    // ══════════════════════════════════════════════════════════════════════════
    // LOGS ANALYSIS DASHBOARD (SCREENSHOT 6 REPLICATION)
    // ══════════════════════════════════════════════════════════════════════════
    
    // Bar Chart Data (Red Errors)
    const errBarLabels = Array.from({length: 100}, (_, i) => i);
    const errBarData = Array.from({length: 100}, () => Math.random() * 50 + 80);
    // Add some random spikes
    errBarData[20] = 250; errBarData[50] = 200; errBarData[80] = 240;

    const commonBarOptions = {
        responsive: true, maintainAspectRatio: false,
        plugins: { 
            legend: { 
                display: true, position: 'right', 
                labels: { color: '#ccc', font: { size: 10 }, usePointStyle: true, boxWidth: 6 } 
            }
        },
        scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#888', font: { size: 10 }, callback: (v, i) => i === 0 ? '08 PM' : i === 50 ? '09 PM' : i === 99 ? '10 PM' : '' } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#888', font: { size: 10 } } }
        }
    };

    if(document.getElementById('lc-bar-1')) {
        new Chart(document.getElementById('lc-bar-1').getContext('2d'), {
            type: 'bar',
            data: { labels: errBarLabels, datasets: [{ label: 'ERROR', data: errBarData, backgroundColor: '#c73a4b', barPercentage: 1.0, categoryPercentage: 1.0 }] },
            options: commonBarOptions
        });
    }

    if(document.getElementById('lc-bar-2')) {
        new Chart(document.getElementById('lc-bar-2').getContext('2d'), {
            type: 'bar',
            data: { labels: errBarLabels, datasets: [{ label: 'ERROR', data: errBarData, backgroundColor: '#c73a4b', barPercentage: 1.0, categoryPercentage: 1.0 }] },
            options: commonBarOptions
        });
    }

    // Pie Charts
    const commonPieOptions = {
        responsive: true, maintainAspectRatio: false,
        plugins: { 
            legend: { 
                display: true, position: 'right',
                labels: { color: '#ccc', font: { size: 10 }, usePointStyle: true, boxWidth: 6 }
            }
        }
    };

    if(document.getElementById('lc-pie-1')) {
        new Chart(document.getElementById('lc-pie-1').getContext('2d'), {
            type: 'pie',
            data: { labels: ['ERROR', 'INFO', 'WARN'], datasets: [{ data: [1, 99, 0], backgroundColor: ['#ff4d4d', '#2c5ae9', '#ffcc00'], borderWidth: 0 }] },
            options: commonPieOptions
        });
    }

    if(document.getElementById('lc-pie-2')) {
        new Chart(document.getElementById('lc-pie-2').getContext('2d'), {
            type: 'pie',
            data: { labels: [''], datasets: [{ data: [1, 99], backgroundColor: ['#ff4d4d', '#2c5ae9'], borderWidth: 0 }] },
            options: { ...commonPieOptions, plugins: { legend: { display: false } } }
        });
    }

    // KPI Sparkline
    if(document.getElementById('lc-spark')) {
        new Chart(document.getElementById('lc-spark').getContext('2d'), {
            type: 'line',
            data: { labels: errBarLabels, datasets: [{ data: errBarData, borderColor: '#ff4d4d', borderWidth: 1.5, pointRadius: 0, tension: 0.1, fill: false }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { display: false }, y: { display: false } } }
        });
    }

    // Populate exact table from Screenshot 6
    const ltTbody = document.getElementById('lt-tbody');
    if (ltTbody) {
        const exactRows = [
            { ts: "4/6/2026, 7:47:46 PM", content: "<1>Apr 06 14:17:46 NYC-Cisco-ASR9000-Edge-Router %ILPOWER-5-SENSE_PO...", src: "null", dt: "CUSTOM_D" },
            { ts: "4/6/2026, 7:47:47 PM", content: "E0406 14:17:47.603392 1 leaderelection.go:452] error initially creat...", src: "Container Output", dt: "PROCESS_(" },
            { ts: "4/6/2026, 7:47:48 PM", content: "E0406 14:17:48.136685 1 leaderelection.go:452] error initially creat...", src: "Container Output", dt: "PROCESS_(" },
            { ts: "4/6/2026, 7:47:48 PM", content: "<33>Apr 06 14:17:48 NYC-NetApp-R9-Storage %APF_HA-6-CLIENT_TEMP_DB_F...", src: "null", dt: "CUSTOM_D" },
            { ts: "4/6/2026, 7:47:50 PM", content: "E0406 14:17:50.393957 1 leaderelection.go:452] error initially creat...", src: "Container Output", dt: "PROCESS_(" },
            { ts: "4/6/2026, 7:47:50 PM", content: "<33>Apr 06 14:17:50 NYC-Cisco-2950-Switch %SFF8472-3-THRESHOLD_VIOLA...", src: "null", dt: "CUSTOM_D" },
            { ts: "4/6/2026, 7:47:52 PM", content: "E0406 14:17:52.044178 1 leaderelection.go:452] error initially creat...", src: "Container Output", dt: "PROCESS_(" },
            { ts: "4/6/2026, 7:47:52 PM", content: "<1>Apr 06 14:17:52 prod-f5-bigip %EMWEB-6-PARSE_ERROR: [PA]webauth_r...", src: "null", dt: "CUSTOM_D" },
            { ts: "4/6/2026, 7:47:54 PM", content: "E0406 14:17:54.041866 1 leaderelection.go:452] error initially creat...", src: "Container Output", dt: "PROCESS_(" },
            { ts: "4/6/2026, 7:47:54 PM", content: "ERROR:exporter.DtBizExporter:Got exception Can't overwrite existing ...", src: "Container Output", dt: "PROCESS_(" },
            { ts: "4/6/2026, 7:47:54 PM", content: "<35>Apr 06 14:17:54 NYC-HP-Printer failed for vostros on /dev/pts/8", src: "null", dt: "CUSTOM_D" },
            { ts: "4/6/2026, 7:47:55 PM", content: "2026-04-06T14:17:55.260Z error exporterhelper/queued_retry.go:115 Dr...", src: "Container Output", dt: "PROCESS_(" },
            { ts: "4/6/2026, 7:47:55 PM", content: "2026-04-06T14:17:55.357Z error scraperhelper/scrapercontroller.go:20...", src: "Container Output", dt: "PROCESS_(" }
        ];

        let html = '';
        exactRows.forEach(r => {
            // Apply magenta styling to parts of the string matching the screenshot
            let stylizedContent = r.content.replace(/(E0406 14:17:[0-9.]+ 1 |\<[0-9]+\>Apr 06 14:17:[0-9]+ |2026-04-06T14:17:[0-9.Z]+ )(error |)(leaderelection\.go:452|exporterhelper.*?go:115|scraperhelper.*?go:20|)?/, (match, p1, p2, p3) => {
                return `<span class="lt-content-err">${p1}</span>${p2}<span class="lt-content-err">${p3 || ''}</span>`;
            });

            html += `
                <tr>
                    <td class="status-err">ERROR</td>
                    <td class="ts">${r.ts}</td>
                    <td>${stylizedContent}</td>
                    <td>${r.src}</td>
                    <td>${r.dt}</td>
                </tr>
            `;
        });
        ltTbody.innerHTML = html;
    }

    // Initialize View based on URL hash or default to Dashboard View (Screenshot 6)
    const dashboardNav = Array.from(navItems).find(n => n.getAttribute('data-view') === 'dashboard');
    if (dashboardNav) dashboardNav.click();

    // Re-trigger layout for new charts
    setTimeout(() => { window.dispatchEvent(new Event('resize')); }, 100);
    fetchLogs();
    setInterval(fetchLogs, 15000);
});
