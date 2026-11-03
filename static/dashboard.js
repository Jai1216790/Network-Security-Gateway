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

    // 3. Stable Horizontal Scrolling Chart Renderer
    let securityChart = null;
    let latestEventsCache = [];

    function renderChart(events) {
        const canvas = document.getElementById('securityActivityChart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const safeEvents = Array.isArray(events) ? events : [];

        // Count events from the active cache slice to keep lines balanced
        let totalIds = safeEvents.filter(e => e.type === 'IDS').length;
        let totalIps = safeEvents.filter(e => e.type === 'IPS' || e.type === 'FIREWALL').length;

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
                            data: [totalIds],
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.15)',
                            fill: true,
                            tension: 0.3,
                            borderWidth: 2,
                            pointRadius: 3
                        },
                        {
                            label: 'IPS Detection',
                            data: [totalIps],
                            borderColor: '#a855f7',
                            backgroundColor: 'rgba(168, 85, 247, 0.15)',
                            fill: true,
                            tension: 0.3,
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
                            grid: { color: 'rgba(51, 65, 85, 0.3)' },
                            ticks: { color: '#64748b', font: { size: 10 }, stepSize: 1 }
                        }
                    }
                }
            });
        } else {
            securityChart.data.labels.push(currentTimeLabel);
            securityChart.data.datasets[0].data.push(totalIds);
            securityChart.data.datasets[1].data.push(totalIps);

            // Keep rolling history limit to enable horizontal scrolling inspection
            if (securityChart.data.labels.length > 30) {
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
        const selectedType = typeSelect ? typeSelect.value : 'ALL';

        const safeEvents = Array.isArray(events) ? events : [];

        const filtered = safeEvents.filter(evt => {
            const matchesType = (selectedType === 'ALL') || (evt.type === selectedType);
            const matchesSearch = !searchTerm ||
                (evt.ip && evt.ip.toLowerCase().includes(searchTerm)) ||
                (evt.details && evt.details.toLowerCase().includes(searchTerm)) ||
                (evt.severity && evt.severity.toLowerCase().includes(searchTerm));
            return matchesType && matchesSearch;
        });

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

            let typeColor = 'bg-indigo-950 text-indigo-400 border-indigo-800';
            if (evt.type === 'IPS') {
                typeColor = 'bg-purple-950 text-purple-400 border-purple-800';
            } else if (evt.type === 'FIREWALL') {
                typeColor = 'bg-rose-950 text-rose-400 border-rose-800';
            }

            return `
                <tr class="hover:bg-slate-800/40 transition border-b border-slate-800/40">
                    <td class="py-2.5 px-3 text-slate-400 font-mono text-xs">${evt.time}</td>
                    <td class="py-2.5 px-3 font-semibold text-blue-400 font-mono text-xs">${evt.ip}</td>
                    <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded ${typeColor} border text-[10px] font-bold">${evt.type}</span></td>
                    <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded ${severityColor} border text-[10px] font-bold">${evt.severity}</span></td>
                    <td class="py-2.5 px-3 text-slate-300 font-sans text-xs">${evt.details}</td>
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
                    <td colspan="3" class="py-4 text-center text-slate-500 text-xs">No blocked IPs</td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = safeBlocked.map(item => `
            <tr class="hover:bg-slate-800/30 transition border-b border-slate-800/40">
                <td class="py-2 text-rose-400 font-bold font-mono text-xs">${item.ip}</td>
                <td class="py-2 text-slate-400 text-[11px] font-sans">${item.reason}</td>
                <td class="py-2 text-right">
                    <button data-ip="${item.ip}" class="unblock-btn px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-rose-400 border border-slate-700 text-[10px] font-sans transition">
                        Remove
                    </button>
                </td>
            </tr>
        `).join('');

        document.querySelectorAll('.unblock-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const ip = e.target.getAttribute('data-ip');
                await unblockIP(ip);
            });
        });
    }

    async function unblockIP(ip) {
        try {
            const res = await fetch('/api/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            if (res.ok) fetchMetrics();
        } catch (err) {
            console.error("Unblock failed:", err);
        }
    }

    // 5. API Polling Loop
    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics');
            if (!res.ok) return;
            const data = await res.json();

            if (document.getElementById('stat-total-events')) document.getElementById('stat-total-events').textContent = data.total_events || 0;
            if (document.getElementById('stat-ids-events')) document.getElementById('stat-ids-events').textContent = data.ids_events || 0;
            if (document.getElementById('stat-ips-events')) document.getElementById('stat-ips-events').textContent = data.ips_events || 0;
            if (document.getElementById('stat-blocked-ips')) document.getElementById('stat-blocked-ips').textContent = data.blocked_count || 0;
            if (document.getElementById('stat-active-threats')) document.getElementById('stat-active-threats').textContent = data.active_threats || 0;

            const lastUpdated = document.getElementById('last-updated-text');
            if (lastUpdated) {
                lastUpdated.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
            }

            latestEventsCache = data.events || [];
            renderChart(latestEventsCache);
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

    fetchMetrics();
    setInterval(fetchMetrics, 2000);
});