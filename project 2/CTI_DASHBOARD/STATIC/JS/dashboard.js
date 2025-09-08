document.addEventListener('DOMContentLoaded', function() {
    console.log("Igloo Inc. Inspired Dashboard Initialized.");

    const socket = io();
    let map = null;

    // --- Helper to apply new Chart.js styles ---
    function setChartDefaults() {
        Chart.defaults.font.family = "'IBMPlexMono-Regular', monospace";
        Chart.defaults.color = '#6D7278'; // text-secondary
        Chart.defaults.plugins.legend.display = false;
        Chart.defaults.interaction.mode = 'index';
        Chart.defaults.interaction.intersect = false;
    }

    // --- DASHBOARD PAGE ---
    async function initDashboard() {
        setChartDefaults();

        // 1. Threats Over Time Chart (Bar Chart)
        const threatsOverTimeCtx = document.getElementById('threats-over-time-chart');
        if (threatsOverTimeCtx) {
            const response = await fetch('/api/threat_trends');
            const trendsData = await response.json();
            new Chart(threatsOverTimeCtx, {
                type: 'bar',
                data: {
                    labels: trendsData.labels,
                    datasets: [{
                        data: trendsData.data,
                        backgroundColor: '#2C2F33', // Dark text color for bars
                        borderRadius: 4
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, grid: { color: '#EAECEF' } }, x: { grid: { display: false } } } }
            });
        }

        // 2. Threats by Severity Chart (Doughnut Chart)
        const threatSeverityCtx = document.getElementById('threat-severity-chart');
        if (threatSeverityCtx) {
            const response = await fetch('/api/dashboard/threats_by_severity');
            const severityData = await response.json();
            new Chart(threatSeverityCtx, {
                type: 'doughnut',
                data: {
                    labels: severityData.labels,
                    datasets: [{
                        data: severityData.data,
                        backgroundColor: ['#FF4D4D', '#FFC700', '#007AFF'], // Red, Yellow, Blue
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, cutout: '60%', plugins: { legend: { display: true, position: 'bottom' } } }
            });
        }

        // 3. Initialize the World Map (with light theme)
        const mapDiv = document.getElementById('threat-map');
        if (mapDiv && !mapDiv._leaflet_id) {
            map = L.map('threat-map').setView([20, 0], 2);
            // Use CartoDB's 'Positron' light-themed map tiles
            L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; CARTO', maxZoom: 19
            }).addTo(map);
        }
    }

    // --- Live Data Handling ---
    const liveFeedDiv = document.getElementById('live-detections-feed');
    socket.on('new_threat_data', msg => {
        // Feed the live table on the main dashboard
        if (liveFeedDiv) {
            const item = document.createElement('div');
            item.className = 'live-feed-item';
            let severity = msg.data.severity || 'low';
            item.innerHTML = `
                <p style="font-family: var(--font-medium);">${msg.data.indicator}</p>
                <p style="font-size: 0.9rem; color: var(--text-secondary);">
                    Source: ${msg.source} | Severity: ${severity} | Country: ${msg.data.country || 'N/A'}
                </p>
            `;
            liveFeedDiv.prepend(item);
            if (liveFeedDiv.children.length > 10) {
                liveFeedDiv.lastChild.remove();
            }
        }
        
        // Plot on map
        if (map && msg.data.latitude && msg.data.longitude) {
            const dotIcon = L.divIcon({ className: 'map-marker-dot', iconSize: [10, 10] });
            const marker = L.marker([msg.data.latitude, msg.data.longitude], { icon: dotIcon }).addTo(map);
            setTimeout(() => map.removeLayer(marker), 3000);
        }
    });

    // --- PAGE ROUTER (No changes needed from previous step) ---
    if (document.querySelector('.dashboard-grid')) initDashboard();
    // ... other page initializers if needed
});