document.addEventListener("DOMContentLoaded", () => {
    // 1. Live Clock Setup
    function updateClock() {
        const now = new Date();
        const dateStr = now.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
        const clockEl = document.getElementById('live-clock');
        if (clockEl) {
            clockEl.textContent = `${dateStr} ${timeStr}`;
        }
    }
    setInterval(updateClock, 1000);
    updateClock();

    // 2. Sidebar Navigation & Flash Highlight
    const navLinks = document.querySelectorAll('aside nav a');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            if (!targetId || targetId === '#') return;

            e.preventDefault();
            const targetSection = document.querySelector(targetId);

            if (targetSection) {
                navLinks.forEach(nav => {
                    nav.classList.remove('bg-blue-600/20', 'text-blue-400', 'border', 'border-blue-500/30');
                    nav.classList.add('text-slate-400');
                });
                this.classList.add('bg-blue-600/20', 'text-blue-400', 'border', 'border-blue-500/30');
                this.classList.remove('text-slate-400');

                targetSection.scrollIntoView({ behavior: 'smooth', block: 'center' });

                targetSection.classList.add('ring-2', 'ring-blue-500', 'bg-slate-800/80', 'transition-all', 'duration-300');
                setTimeout(() => {
                    targetSection.classList.remove('ring-2', 'ring-blue-500', 'bg-slate-800/80');
                }, 2000);
            }
        });
    });

    // 3. Stock-Market-Style Fluctuating Chart Renderer (IDS Detection & IPS Detection)
    let securityChart = null;
    let latestEventsCache = [];
    let prevIdsTotal = null;
    let prevIpsTotal = null;
    let idsMomentum = 4;
    let ipsMomentum = 3;

    function renderChart(currentIdsTotal, currentIpsTotal) {
        const canvas = document.getElementById('securityActivityChart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        // Calculate new events arrived since the last 2-second poll
        const newIds = prevIdsTotal === null ? 2 : Math.max(0, currentIdsTotal - prevIdsTotal);
        const newIps = prevIpsTotal === null ? 2 : Math.max(0, currentIpsTotal - prevIpsTotal);
        prevIdsTotal = currentIdsTotal;
        prevIpsTotal = currentIpsTotal;

        // Combine live interval arrivals with mean-reverting wave momentum so both lines rise, dip, and cross naturally
        const idsSwing = Math.floor(Math.random() * 5) - 2; // -2 to +2
        const ipsSwing = Math.floor(Math.random() * 5) - 2; // -2 to +2

        idsMomentum = Math.max(1, Math.min(12, Math.round(idsMomentum * 0.65 + newIds * 1.4 + idsSwing)));
        ipsMomentum = Math.max(1, Math.min(12, Math.round(ipsMomentum * 0.65 + newIps * 1.4 + ipsSwing)));

        const currentTimeLabel = new Date().toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        if (!securityChart) {
            securityChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [currentTimeLabel],
                    datasets: [
                        {
                            label: 'IDS Detection',
                            data: [idsMomentum],
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.12)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2,
                            pointRadius: 3
                        },
                        {
                            label: 'IPS Detection',
                            data: [ipsMomentum],
                            borderColor: '#a855f7',
                            backgroundColor: 'rgba(168, 85, 247, 0.12)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2,
                            pointRadius: 3
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { labels: { color: '#94a3b8', font: { size: 11 } } }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(51, 65, 85, 0.3)' },
                            ticks: { color: '#64748b', font: { size: 10 } }
                        },
                        y: {
                            beginAtZero: true,
                            suggestedMax: 14,
                            grid: { color: 'rgba(51, 65, 85, 0.3)' },
                            ticks: { color: '#64748b', font: { size: 10 }, precision: 0 }
                        }
                    }
                }
            });
        } else {
            securityChart.data.labels.push(currentTimeLabel);
            securityChart.data.datasets[0].data.push(idsMomentum);
            securityChart.data.datasets[1].data.push(ipsMomentum);

            if (securityChart.data.labels.length > 35) {
                securityChart.data.labels.shift();
                securityChart.data.datasets[0].data.shift();
                securityChart.data.datasets[1].data.shift();
            }

            securityChart.update();
        }
    }

    // 4. Events & Blocked Tables Renderer
    function renderEventsTable(events) {
        const tbody = document.getElementById('events-table-body');
        if (!tbody) return;

        const searchInput = document.getElementById('event-search');
        const typeSelect = document.getElementById('event-filter') || document.getElementById('event-type-filter');

        const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : '';
        const selectedType = (typeSelect && typeSelect.value) ? typeSelect.value.trim().toUpperCase() : 'ALL';

        const safeEvents = Array.isArray(events) ? events : [];

        const filtered = safeEvents.filter(evt => {
            const evtType = (evt.type || '').trim().toUpperCase();
            const matchesType = (selectedType === 'ALL') || (evtType === selectedType);
            const matchesSearch = !searchTerm ||
                (evt.ip && evt.ip.toLowerCase().includes(searchTerm)) ||
                (evt.details && evt.details.toLowerCase().includes(searchTerm)) ||
                (evt.severity && evt.severity.toLowerCase().includes(searchTerm));
            return matchesType && matchesSearch;
        });

        // Keep subtitle synced with exact table row count
        const eventsSubtitle = document.querySelector('#security-events-section p');
        if (eventsSubtitle) {
            eventsSubtitle.textContent = `Showing ${filtered.length} of ${safeEvents.length} recorded security events`;
        }

        if (filtered.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="py-8 text-center text-slate-500 text-xs">Waiting for live network events...</td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = filtered.map(evt => {
            let severityColor = 'bg-amber-950/80 text-amber-400 border-amber-800';
            if (evt.severity === 'High' || evt.severity === 'CRITICAL') {
                severityColor = 'bg-rose-950/80 text-rose-400 border-rose-800';
            }

            const evtType = (evt.type || 'IDS').trim().toUpperCase();
            let typeColor = 'bg-indigo-950 text-indigo-400 border-indigo-800';
            if (evtType === 'IPS') {
                typeColor = 'bg-purple-950 text-purple-400 border-purple-800';
            } else if (evtType === 'FIREWALL') {
                typeColor = 'bg-rose-950 text-rose-400 border-rose-800';
            }

            return `
                <tr class="hover:bg-slate-800/40 transition border-b border-slate-800/40">
                    <td class="py-2.5 px-3 text-slate-400 font-mono text-xs">${evt.time || '--'}</td>
                    <td class="py-2.5 px-3 font-semibold text-blue-400 font-mono text-xs">${evt.ip || '--'}</td>
                    <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded ${typeColor} border text-[10px] font-bold">${evtType}</span></td>
                    <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded ${severityColor} border text-[10px] font-bold">${evt.severity || 'Low'}</span></td>
                    <td class="py-2.5 px-3 text-slate-300 font-sans text-xs">${evt.details || ''}</td>
                </tr>
            `;
        }).join('');
    }

    function renderBlockedTable(blockedList) {
        const tbody = document.getElementById('blocked-ips-table-body');
        if (!tbody) return;

        const safeBlocked = Array.isArray(blockedList) ? blockedList : [];

        if (safeBlocked.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="2" class="py-4 text-center text-slate-500 text-xs">No blocked IPs</td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = safeBlocked.map(item => `
            <tr class="hover:bg-slate-800/30 transition border-b border-slate-800/40">
                <td class="py-2 pr-3 text-rose-400 font-bold font-mono text-xs whitespace-nowrap">${item.ip}</td>
                <td class="py-2 text-slate-400 text-[11px] font-sans">${item.reason}</td>
            </tr>
        `).join('');
    }

    // 5. API Polling Loop
    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics');
            if (!res.ok) return;
            const data = await res.json();

            latestEventsCache = Array.isArray(data.events) ? data.events : [];

            // Derive KPI counts directly from latestEventsCache so top cards match the table 1-to-1
            const fwCount = latestEventsCache.filter(e => (e.type || '').toUpperCase() === 'FIREWALL').length;
            const idsCount = latestEventsCache.filter(e => (e.type || '').toUpperCase() === 'IDS').length;
            const ipsCount = latestEventsCache.filter(e => (e.type || '').toUpperCase() === 'IPS').length;
            const highCount = latestEventsCache.filter(e => e.severity === 'High').length;

            if (document.getElementById('stat-total-events')) document.getElementById('stat-total-events').textContent = latestEventsCache.length;
            if (document.getElementById('stat-firewall-events')) document.getElementById('stat-firewall-events').textContent = fwCount;
            if (document.getElementById('stat-ids-events')) document.getElementById('stat-ids-events').textContent = idsCount;
            if (document.getElementById('stat-ips-events')) document.getElementById('stat-ips-events').textContent = ipsCount;
            if (document.getElementById('stat-blocked-ips')) document.getElementById('stat-blocked-ips').textContent = data.blocked_count || 0;
            if (document.getElementById('stat-active-threats')) document.getElementById('stat-active-threats').textContent = highCount;

            const lastUpdated = document.getElementById('last-updated-text');
            if (lastUpdated) {
                lastUpdated.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
            }

            // Plot fluctuating IDS Detection & IPS Detection activity rate
            renderChart(idsCount, ipsCount);
            renderEventsTable(latestEventsCache);
            renderBlockedTable(data.blocked_ips || []);

        } catch (err) {
            console.error("Error fetching metrics:", err);
        }
    }

    const searchInput = document.getElementById('event-search');
    const typeSelect = document.getElementById('event-filter') || document.getElementById('event-type-filter');
    if (searchInput) searchInput.addEventListener('input', () => renderEventsTable(latestEventsCache));
    if (typeSelect) typeSelect.addEventListener('change', () => renderEventsTable(latestEventsCache));

    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', fetchMetrics);

    fetchMetrics();
    setInterval(fetchMetrics, 2000);
});