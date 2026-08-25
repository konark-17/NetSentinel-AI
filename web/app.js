// App state tracker
const state = {
    totalPackets: 0,
    activeFlows: new Map(),
    threatCount: 0,
    totalFlowsSeen: 0,
    chartData: {
        labels: [],
        packetRates: []
    }
};

// Initialize Chart.js
let liveChart;
const ctx = document.getElementById('liveChart').getContext('2d');
const chartGradient = ctx.createLinearGradient(0, 0, 0, 300);
chartGradient.addColorStop(0, 'rgba(6, 182, 212, 0.4)');
chartGradient.addColorStop(1, 'rgba(6, 182, 212, 0.0)');

function initChart() {
    liveChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: state.chartData.labels,
            datasets: [{
                label: 'Throughput (Packets/Sec)',
                data: state.chartData.packetRates,
                borderColor: '#06b6d4',
                borderWidth: 2,
                backgroundColor: chartGradient,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#64748b' }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#64748b' }
                }
            }
        }
    });

    // Populate initial empty labels
    const now = new Date();
    for (let i = 9; i >= 0; i--) {
        const timeStr = new Date(now - i * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        state.chartData.labels.push(timeStr);
        state.chartData.packetRates.push(0);
    }
    liveChart.update();
}

// Connect to WebSocket Server
function connectWebSocket() {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
    const socket = new WebSocket(wsUrl);

    const statusDot = document.querySelector('.status-dot');
    const statusText = document.getElementById('conn-status');

    socket.onopen = () => {
        console.log("WebSocket connection established");
        statusDot.style.backgroundColor = '#10b981';
        statusDot.style.boxShadow = '0 0 10px #10b981';
        statusText.innerText = "WS MONITORING ACTIVE";
        statusText.style.color = '#10b981';
    };

    socket.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            if (message.type === 'flow') {
                handleFlowMessage(message.data);
            } else if (message.type === 'alert') {
                handleAlertMessage(message.data);
            }
        } catch (err) {
            console.error("Error processing websocket message:", err);
        }
    };

    socket.onclose = () => {
        console.log("WebSocket connection lost. Retrying in 3 seconds...");
        statusDot.style.backgroundColor = '#ef4444';
        statusDot.style.boxShadow = '0 0 10px #ef4444';
        statusText.innerText = "MONITOR DISCONNECTED (RECONNECTING)";
        statusText.style.color = '#ef4444';
        setTimeout(connectWebSocket, 3000);
    };

    socket.onerror = (err) => {
        console.error("WebSocket error:", err);
    };
}

// Handle flow messages from backend
function handleFlowMessage(flow) {
    // Flow key generator
    const flowKey = `${flow.src_ip}:${flow.src_port}->${flow.dst_ip}:${flow.dst_port}[${flow.protocol}]`;
    
    const wasThreat = state.activeFlows.has(flowKey) ? state.activeFlows.get(flowKey).classified > 0 : false;
    
    state.activeFlows.set(flowKey, flow);

    // Track total flows seen for anomalous ratio
    if (!wasThreat && flow.classified > 0) {
        state.threatCount++;
        state.totalFlowsSeen++;
    } else if (!state.activeFlows.has(flowKey)) {
        state.totalFlowsSeen++;
    }

    // Refresh telemetry view
    renderFlowTable();
    updateMetrics();
}

// Handle real-time alert messages
const activeAlerts = new Set();
function handleAlertMessage(alert) {
    const alertKey = `${alert.src_ip}-${alert.classified}-${alert.start_time}`;
    if (activeAlerts.has(alertKey)) return;
    
    activeAlerts.add(alertKey);
    const alertFeed = document.getElementById('alert-feed');
    
    // Remove "System Healthy" item if it exists
    const benignAlert = alertFeed.querySelector('.alert-item.benign');
    if (benignAlert) {
        alertFeed.removeChild(benignAlert);
    }

    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-item ${alert.status}`;
    
    let icon = "fa-radiation";
    let colorClass = "var(--color-ddos)";
    if (alert.status === "DDOS") {
        icon = "fa-shield-virus";
        colorClass = "var(--color-ddos)";
    } else if (alert.status === "PORTSCAN") {
        icon = "fa-radar";
        colorClass = "var(--color-portscan)";
    } else if (alert.status === "BRUTEFORCE") {
        icon = "fa-key";
        colorClass = "var(--color-bruteforce)";
    }

    const time = new Date(alert.last_seen).toLocaleTimeString();
    
    alertDiv.innerHTML = `
        <div class="alert-meta" style="color: ${colorClass}">
            <span class="alert-title"><i class="fa-solid ${icon}"></i> INTRUSION DETECTED: ${alert.status}</span>
            <span>${time}</span>
        </div>
        <div class="alert-desc">Suspicious traffic pattern matching ML classification rules.</div>
        <div class="alert-details">
            Flow: ${alert.src_ip}:${alert.src_port} &rarr; ${alert.dst_ip}:${alert.dst_port}<br>
            Packets: ${alert.packet_count} | Size: ${(alert.byte_count / 1024).toFixed(2)} KB | SYN flags: ${alert.flag_syn}
        </div>
    `;

    alertFeed.insertBefore(alertDiv, alertFeed.firstChild);

    // Keep alert list capped at 10 items
    if (alertFeed.children.length > 10) {
        alertFeed.removeChild(alertFeed.lastChild);
    }
}

// Refresh table data
function renderFlowTable() {
    const tbody = document.getElementById('flow-table-body');
    tbody.innerHTML = '';

    if (state.activeFlows.size === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">
                    No active sessions detected on network.
                </td>
            </tr>
        `;
        return;
    }

    // Sort flows: show threats first, then sort by latest packets
    const sortedFlows = Array.from(state.activeFlows.values()).sort((a, b) => {
        if (b.classified !== a.classified) {
            return b.classified - a.classified;
        }
        return b.packet_count - a.packet_count;
    });

    // Render top 15 flows
    sortedFlows.slice(0, 15).forEach(flow => {
        const tr = document.createElement('tr');
        
        let badgeClass = "benign";
        let statusText = "Benign";
        
        if (flow.classified === 1) {
            badgeClass = "ddos";
            statusText = "DDoS Threat";
        } else if (flow.classified === 2) {
            badgeClass = "portscan";
            statusText = "Port Scan";
        } else if (flow.classified === 3) {
            badgeClass = "bruteforce";
            statusText = "Brute Force";
        }

        const duration = (new Date(flow.last_seen) - new Date(flow.start_time)) / 1000;
        const pktRate = (flow.packet_count / (duration || 0.1)).toFixed(1);

        tr.innerHTML = `
            <td class="mono">${flow.src_ip}:${flow.src_port}</td>
            <td class="mono">${flow.dst_ip}:${flow.dst_port}</td>
            <td class="mono">${flow.protocol === 1 ? 'TCP' : flow.protocol === 2 ? 'UDP' : 'ICMP'}</td>
            <td class="mono">${pktRate}/s</td>
            <td class="mono">${(flow.byte_count / 1024).toFixed(1)} KB</td>
            <td class="mono">${flow.flag_syn}/${flow.flag_ack}/${flow.flag_fin}</td>
            <td class="mono">${duration.toFixed(2)}s</td>
            <td><span class="badge ${badgeClass}">${statusText}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Refresh metrics scoreboard
function updateMetrics() {
    let packetSum = 0;
    state.activeFlows.forEach(flow => {
        packetSum += flow.packet_count;
    });

    document.getElementById('metric-packets').innerText = packetSum.toLocaleString();
    document.getElementById('metric-flows').innerText = state.activeFlows.size;
    document.getElementById('metric-threats').innerText = state.threatCount;
    
    const ratio = state.totalFlowsSeen > 0 
        ? ((state.threatCount / state.totalFlowsSeen) * 100).toFixed(1) 
        : "0.0";
    document.getElementById('metric-ratio').innerText = `${ratio}%`;
}

// Refresh throughput chart every second
setInterval(() => {
    let currentPacketsPerSecond = 0;
    const now = new Date();
    
    // Clean flows that haven't received updates in 10 seconds
    const timeoutThreshold = 10000; 
    state.activeFlows.forEach((flow, key) => {
        const timeSinceUpdate = now - new Date(flow.last_seen);
        if (timeSinceUpdate > timeoutThreshold) {
            state.activeFlows.delete(key);
        } else {
            const duration = (new Date(flow.last_seen) - new Date(flow.start_time)) / 1000;
            currentPacketsPerSecond += flow.packet_count / (duration || 0.1);
        }
    });

    // Shift data
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    state.chartData.labels.shift();
    state.chartData.labels.push(timeStr);
    
    state.chartData.packetRates.shift();
    state.chartData.packetRates.push(Math.round(currentPacketsPerSecond));

    if (liveChart) {
        liveChart.update();
    }
    
    renderFlowTable();
    updateMetrics();
}, 1000);

// Startup sequence
window.addEventListener('DOMContentLoaded', () => {
    initChart();
    connectWebSocket();
});
