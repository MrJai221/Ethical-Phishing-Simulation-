document.addEventListener('DOMContentLoaded', function () {
    // --- WebSocket Connection ---
    const socket = io();

    // --- DOM Element References ---
    const lookupBtn = document.getElementById('lookup-btn');
    const indicatorInput = document.getElementById('indicator-input');
    const statusBar = document.getElementById('status-bar');
    const liveFeedBody = document.getElementById('live-feed-body');
    
    // KPI Cards
    const kpiNewIndicators = document.getElementById('kpi-new-indicators');
    const kpiHighSeverity = document.getElementById('kpi-high-severity');
    
    // Modal Elements
    const modalContainer = document.getElementById('modal-container');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    const modalIndicator = document.getElementById('modal-indicator');
    const modalBody = document.getElementById('modal-body');

    // --- State Management ---
    let threatCounts = { high: 0, medium: 0, low: 0 };
    let indicatorsToday = 0;

    // --- Map Initialization (Leaflet.js) ---
    const map = L.map('threat-map', { preferCanvas: true }).setView([20, 0], 2.5);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; CARTO',
    }).addTo(map);

    // --- Chart Initialization (Chart.js) ---
    const ctx = document.getElementById('severity-chart').getContext('2d');
    const severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                label: 'Threats by Severity',
                data: [0, 0, 0],
                backgroundColor: ['#e74c3c', '#f39c12', '#3498db'],
                borderColor: '#272935',
                borderWidth: 4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { color: '#e1e1e1' } } }
        }
    });

    // --- Event Listeners ---
    lookupBtn.addEventListener('click', performLookup);
    indicatorInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performLookup();
    });
    modalCloseBtn.addEventListener('click', () => modalContainer.classList.remove('show'));
    modalContainer.addEventListener('click', (e) => {
        if (e.target === modalContainer) modalContainer.classList.remove('show');
    });

    function performLookup() {
        const indicator = indicatorInput.value.trim();
        if (indicator) {
            socket.emit('lookup_indicator', { indicator: indicator });
            indicatorInput.value = '';
        }
    }

    // --- WebSocket Event Handlers ---
    socket.on('connect', () => statusBar.textContent = 'Connected');
    socket.on('status_update', (data) => statusBar.textContent = data.message);
    socket.on('new_threat_data', (threat) => handleNewThreat(threat.source, threat.data));
    socket.on('new_geo_threat', (threat) => addGeoPoint(threat));

    // --- Main Logic Functions ---
    function handleNewThreat(source, data) {
        // 1. Create and prepend the new row to the table
        const newRow = createThreatTableRow(source, data);
        liveFeedBody.prepend(newRow);
        
        // Add highlight animation
        newRow.classList.add('new-threat');
        setTimeout(() => newRow.classList.remove('new-threat'), 2000);

        // Limit table rows to prevent performance issues
        while (liveFeedBody.rows.length > 50) {
            liveFeedBody.deleteRow(-1);
        }

        // 2. Update KPIs and Chart
        updateDashboardStats(data);
    }
    
    function createThreatTableRow(source, data) {
        const row = document.createElement('tr');
        row.dataset.indicatorData = JSON.stringify(data); // Store data for modal
        row.addEventListener('click', () => showThreatModal(data));

        row.innerHTML = `
            <td><span class="severity-dot severity-${data.severity}"></span></td>
            <td>${data.indicator}</td>
            <td>${source}</td>
            <td>${data.isp || data.owner || 'N/A'}</td>
            <td>${data.country ? getFlagEmoji(data.country) + ' ' + data.country : 'N/A'}</td>
        `;
        return row;
    }

    function updateDashboardStats(data) {
        // Update KPI for new indicators
        indicatorsToday++;
        kpiNewIndicators.textContent = indicatorsToday;

        // Update severity counts and chart
        if (data.severity === 'high') threatCounts.high++;
        else if (data.severity === 'medium') threatCounts.medium++;
        else threatCounts.low++;
        
        kpiHighSeverity.textContent = threatCounts.high;
        
        severityChart.data.datasets[0].data = [
            threatCounts.high, 
            threatCounts.medium, 
            threatCounts.low
        ];
        severityChart.update();
    }
    
    function addGeoPoint(threat) {
        if (threat.latitude && threat.longitude) {
            const color = threat.severity === 'high' ? '#e74c3c' : (threat.severity === 'medium' ? '#f39c12' : '#3498db');
            L.circle([threat.latitude, threat.longitude], {
                color: color,
                fillColor: color,
                fillOpacity: 0.6,
                radius: 30000 
            }).addTo(map).bindPopup(`<b>${threat.indicator}</b><br>Score: ${threat.abuse_score}`);
        }
    }

    function showThreatModal(data) {
        modalIndicator.textContent = data.indicator;
        modalBody.innerHTML = `
            <p><strong>Severity:</strong> <span class="severity-${data.severity}" style="font-weight:bold;">${data.severity.toUpperCase()}</span></p>
            <p><strong>Country:</strong> ${data.country ? getFlagEmoji(data.country) + ' ' + data.country : 'N/A'}</p>
            <p><strong>Abuse Score:</strong> ${data.abuse_score || 'N/A'}</p>
            <p><strong>Malicious Votes (VT):</strong> ${data.malicious_score || 'N/A'}</p>
            <p><strong>ISP / Owner:</strong> ${data.isp || data.owner || 'N/A'}</p>
            <p><strong>Domain:</strong> ${data.domain || 'N/A'}</p>
        `;
        modalContainer.classList.add('show');
    }

    function getFlagEmoji(countryCode) {
        if (!countryCode || countryCode.length !== 2) return '';
        const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt());
        return String.fromCodePoint(...codePoints);
    }
     const analysisSnippets = [
        "ANALYSIS: Correlating multiple high-confidence reports from AbuseIPDB with recent VirusTotal detections. A potential coordinated brute-force campaign targeting SSH on port 22 is emerging from ISP 'DigitalOcean'.",
        "TRENDING: Observed a 35% increase in phishing indicators originating from country code 'VN' (Vietnam) over the past 6 hours. Associated domains frequently use keywords like 'invoice' and 'payment'.",
        "ALERT: New indicator '198.54.117.199' matches signature for 'Cobalt Strike' C2 server. This IP should be considered high-risk and blocked at the perimeter immediately. Escalating for investigation.",
        "INSIGHT: Geolocation data shows a cluster of malicious activity in Central Europe. Cross-referencing with ISP data suggests a single actor may be using a botnet for credential stuffing attacks.",
        "MONITORING: A low-severity but high-volume scan is detected from the ASN 'AS-CHOOPA'. While currently benign, this behavior is often a precursor to a larger attack. Continuing to monitor."
    ];
    let analysisIndex = 0;

    // ... (all existing event listeners and function definitions) ...

    // NEW: Function to update the analysis widget
    function updateAnalysisWidget() {
        if (!analysisContent) return; // Only run on dashboard page
        analysisContent.style.opacity = 0; // Fade out
        setTimeout(() => {
            analysisIndex = (analysisIndex + 1) % analysisSnippets.length;
            analysisContent.textContent = analysisSnippets[analysisIndex];
            analysisContent.style.opacity = 1; // Fade in
        }, 500); // Wait for fade out to complete
    }

    // NEW: Start the analysis cycle only if the widget exists
    if (analysisContent) {
        setInterval(updateAnalysisWidget, 10000); // Update every 10 seconds
        updateAnalysisWidget(); // Initial call
    }
});

