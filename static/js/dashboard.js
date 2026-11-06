/*
 * dashboard.js
 * -------------
 * Renders the 4 Chart.js charts on the Dashboard page using the
 * `dashboardStats` object injected by dashboard.html.
 */

const CHART_COLORS = {
    green: "#00e5a0",
    red: "#ff5a63",
    blue: "#3fb1ff",
    yellow: "#ffcc4d",
    grid: "rgba(255,255,255,0.06)",
    text: "#8b98a5",
};

Chart.defaults.color = CHART_COLORS.text;
Chart.defaults.font.family = "Segoe UI, Roboto, sans-serif";

function baseGridOptions() {
    return {
        scales: {
            x: { grid: { color: CHART_COLORS.grid }, ticks: { color: CHART_COLORS.text } },
            y: { grid: { color: CHART_COLORS.grid }, ticks: { color: CHART_COLORS.text }, beginAtZero: true },
        },
        plugins: { legend: { labels: { color: CHART_COLORS.text } } },
        maintainAspectRatio: false,
    };
}

// 1. Normal vs Anomaly (doughnut)
new Chart(document.getElementById("chartNormalAnomaly"), {
    type: "doughnut",
    data: {
        labels: ["Normal", "Anomaly"],
        datasets: [{
            data: [dashboardStats.total_normal, dashboardStats.total_anomalies],
            backgroundColor: [CHART_COLORS.blue, CHART_COLORS.red],
            borderWidth: 0,
        }],
    },
    options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } },
});

// 2. Protocol distribution (bar)
const protocolLabels = Object.keys(dashboardStats.protocol_distribution);
const protocolValues = Object.values(dashboardStats.protocol_distribution);
new Chart(document.getElementById("chartProtocol"), {
    type: "bar",
    data: {
        labels: protocolLabels,
        datasets: [{
            label: "Records",
            data: protocolValues,
            backgroundColor: CHART_COLORS.green,
            borderRadius: 6,
        }],
    },
    options: { ...baseGridOptions(), plugins: { legend: { display: false } } },
});

// 3. Traffic activity over recent uploads (line)
const activity = dashboardStats.traffic_activity || [];
new Chart(document.getElementById("chartActivity"), {
    type: "line",
    data: {
        labels: activity.map(a => a.upload_batch_id),
        datasets: [
            {
                label: "Total",
                data: activity.map(a => a.total),
                borderColor: CHART_COLORS.blue,
                backgroundColor: "rgba(63,177,255,0.15)",
                tension: 0.35,
                fill: true,
            },
            {
                label: "Anomalies",
                data: activity.map(a => a.anomalies),
                borderColor: CHART_COLORS.red,
                backgroundColor: "rgba(255,90,99,0.15)",
                tension: 0.35,
                fill: true,
            },
        ],
    },
    options: baseGridOptions(),
});

// 4. Risk distribution (pie)
const riskDist = dashboardStats.risk_distribution || { Low: 0, Medium: 0, High: 0 };
new Chart(document.getElementById("chartRisk"), {
    type: "pie",
    data: {
        labels: ["Low", "Medium", "High"],
        datasets: [{
            data: [riskDist.Low, riskDist.Medium, riskDist.High],
            backgroundColor: [CHART_COLORS.green, CHART_COLORS.yellow, CHART_COLORS.red],
            borderWidth: 0,
        }],
    },
    options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } },
});
