// Dashboard JS Logic

let financialChart = null;
let distributionChart = null;

document.addEventListener('DOMContentLoaded', function() {
    loadDashboardData();
    
    // Wire up Recalculate button
    document.getElementById('btn-recalculate').addEventListener('click', triggerRecalculate);
});

async function loadDashboardData() {
    try {
        // 1. Fetch Dashboard Metrics
        const dashResponse = await fetch('/api/dashboard');
        const metrics = await dashResponse.json();
        
        // Populate KPI Cards
        document.getElementById('kpi-risk-score').innerText = Math.round(metrics.overall_risk_score) + '/100';
        document.getElementById('kpi-expected-loss').innerText = formatRupees(metrics.total_expected_loss);
        document.getElementById('kpi-crit-vulns').innerText = metrics.critical_vulnerabilities;
        document.getElementById('kpi-control-coverage').innerText = formatPercent(metrics.control_coverage_pct);
        
        // Dynamic Risk level badge
        const levelBadge = document.getElementById('kpi-risk-level');
        levelBadge.innerText = getRiskLevelText(metrics.overall_risk_score);
        levelBadge.className = 'badge mt-1 ' + getRiskLevelBadgeClass(metrics.overall_risk_score);
        
        // Populate ML Metrics
        if (metrics.ml_metrics) {
            document.getElementById('ml-accuracy').innerText = formatPercent(metrics.ml_metrics.accuracy * 100);
            document.getElementById('ml-precision').innerText = formatPercent(metrics.ml_metrics.precision * 100);
            document.getElementById('ml-recall').innerText = formatPercent(metrics.ml_metrics.recall * 100);
            document.getElementById('ml-f1').innerText = formatPercent(metrics.ml_metrics.f1_score * 100);
            document.getElementById('ml-auc').innerText = formatPercent(metrics.ml_metrics.roc_auc * 100);
        } else {
            // Model not trained fallback message
            document.getElementById('ml-metrics-panel').innerHTML = `
                <div class="col-12 text-muted py-2">
                    <i class="fa-solid fa-triangle-exclamation text-warning me-2"></i>
                    ML Model is not yet trained. Using standard heuristics. Go to <strong>System Controls</strong> to train the model.
                </div>`;
        }
        
        // 2. Fetch Assets & Risks Details
        const risksResponse = await fetch('/api/risks');
        const risks = await risksResponse.json();
        
        // Populate Charts
        renderFinancialExposureChart(risks.slice(0, 10)); // Top 10 assets
        renderRiskDistributionChart(metrics.risk_distribution);
        
        // Populate Heatmap
        populateHeatmap(risks);
        
        // 3. Fetch Alerts Feed
        const alertsResponse = await fetch('/api/alerts');
        const alerts = await alertsResponse.json();
        renderAlertsFeed(alerts.slice(0, 5)); // Show top 5 recent alerts
        
    } catch (err) {
        console.error("Error loading dashboard data", err);
        showToast("Error loading dashboard metrics.", "danger");
    }
}

function getRiskLevelText(score) {
    if (score <= 25) return 'Low';
    if (score <= 50) return 'Medium';
    if (score <= 75) return 'High';
    return 'Critical';
}

function getRiskLevelBadgeClass(score) {
    if (score <= 25) return 'bg-success text-white';
    if (score <= 50) return 'bg-info text-dark';
    if (score <= 75) return 'bg-warning text-dark';
    return 'bg-danger text-white';
}

function renderFinancialExposureChart(assets) {
    const ctx = document.getElementById('chart-financial-exposure').getContext('2d');
    
    if (financialChart) {
        financialChart.destroy();
    }
    
    const labels = assets.map(a => a.asset_name);
    const data = assets.map(a => a.expected_loss);
    
    financialChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Expected Loss (INR ₹)',
                data: data,
                backgroundColor: 'rgba(13, 202, 240, 0.4)',
                borderColor: '#0dcaf0',
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    grid: { color: '#16233d' },
                    ticks: {
                        color: '#8c9cb6',
                        callback: function(val) {
                            return '₹' + (val / 100000).toFixed(0) + 'L';
                        }
                    }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#8c9cb6', maxRotation: 45, minRotation: 45 }
                }
            }
        }
    });
}

function renderRiskDistributionChart(dist) {
    const ctx = document.getElementById('chart-risk-distribution').getContext('2d');
    
    if (distributionChart) {
        distributionChart.destroy();
    }
    
    distributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: [dist.Low, dist.Medium, dist.High, dist.Critical],
                backgroundColor: [
                    'rgba(25, 135, 84, 0.7)',
                    'rgba(13, 202, 240, 0.7)',
                    'rgba(255, 193, 7, 0.7)',
                    'rgba(220, 53, 69, 0.7)'
                ],
                borderColor: '#0a1122',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#cfd7e6' }
                }
            }
        }
    });
}

async function populateHeatmap(assets) {
    // Clear all heatmap cells first
    document.querySelectorAll('.heatmap-cell').forEach(cell => {
        cell.innerHTML = '';
    });
    
    for (const a of assets) {
        // Fetch detailed risk score to get raw likelihood & impact (1-5 scale)
        try {
            const detailResponse = await fetch(`/api/risks/${a.asset_id}`);
            const detail = await detailResponse.json();
            
            // Round coordinates to nearest integer in [1, 5]
            const y = Math.min(5, Math.max(1, Math.round(detail.factors.threat_frequency / 20))); // likelihood
            const x = Math.min(5, Math.max(1, Math.round(detail.factors.asset_criticality / 20))); // impact
            
            const cellId = `cell-${y}-${x}`;
            const cell = document.getElementById(cellId);
            
            if (cell) {
                const tag = document.createElement('div');
                tag.className = 'heatmap-asset-tag';
                tag.innerText = a.asset_name;
                tag.title = `${a.asset_name} (Risk Score: ${a.risk_score.toFixed(1)}/100)`;
                
                // Click on asset inside heatmap redirects to risk detail page
                tag.addEventListener('click', (e) => {
                    e.stopPropagation();
                    window.location.href = `/risks?asset_id=${a.asset_id}`;
                });
                
                cell.appendChild(tag);
            }
        } catch (err) {
            console.error("Failed to position asset in heatmap", a, err);
        }
    }
}

function renderAlertsFeed(alerts) {
    const feed = document.getElementById('dashboard-alerts-feed');
    feed.innerHTML = '';
    
    if (alerts.length === 0) {
        feed.innerHTML = '<div class="text-muted text-center py-4">No active alerts.</div>';
        return;
    }
    
    alerts.forEach(al => {
        let borderClass = 'border-info';
        let textClass = 'text-info';
        
        if (al.severity === 'CRITICAL') { borderClass = 'border-danger'; textClass = 'text-danger'; }
        else if (al.severity === 'HIGH') { borderClass = 'border-warning'; textClass = 'text-warning'; }
        else if (al.severity === 'WARNING') { borderClass = 'border-warning'; textClass = 'text-warning'; }
        
        const card = document.createElement('div');
        card.className = `p-2 mb-2 bg-dark rounded border-start border-3 ${borderClass} text-sm`;
        card.innerHTML = `
            <div class="d-flex justify-content-between fw-bold text-light">
                <span class="${textClass}"><i class="fa-solid fa-triangle-exclamation me-2"></i>${al.title}</span>
                <small class="text-muted" style="font-size: 10px;">${formatAlertDate(al.created_at)}</small>
            </div>
            <div class="text-muted mt-1 text-xs" style="line-height: 1.2;">${al.message}</div>
        `;
        feed.appendChild(card);
    });
}

function formatAlertDate(isoStr) {
    if (!isoStr) return '';
    const date = new Date(isoStr);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

async function triggerRecalculate() {
    const btn = document.getElementById('btn-recalculate');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>Recalculating...';
    
    try {
        const response = await fetch('/api/recalculate-risk', { method: 'POST' });
        const result = await response.json();
        
        if (response.ok) {
            showToast(result.message, 'success');
            loadDashboardData();
        } else {
            showToast(result.error || "Recalculation failed.", 'danger');
        }
    } catch (err) {
        console.error("Recalculation failed", err);
        showToast("Network error triggering recalculation.", 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-rotate me-2"></i>Recalculate Risk';
    }
}
