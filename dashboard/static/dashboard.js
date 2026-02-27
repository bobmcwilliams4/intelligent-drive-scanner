/**
 * Intelligent Drive Scanner v2.0 — Dashboard JavaScript
 *
 * D3.js visualizations, API integration, WebSocket scan progress,
 * and interactive file exploration.
 */

// ── State ───────────────────────────────────────────────────────────────────

const state = {
    activeScanId: null,
    activeTab: 'overview',
    filesPage: 0,
    filesLimit: 50,
    filesSearch: '',
    filesDomain: '',
    filesExtension: '',
    ws: null,
    scanning: false,
};

// ── API Client ──────────────────────────────────────────────────────────────

async function api(path, options = {}) {
    try {
        const resp = await fetch(path, {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options,
        });
        if (!resp.ok) throw new Error(`API ${resp.status}: ${await resp.text()}`);
        return await resp.json();
    } catch (err) {
        console.error('API error:', path, err);
        return null;
    }
}

// ── Formatting ──────────────────────────────────────────────────────────────

function humanSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function humanDuration(seconds) {
    if (seconds < 60) return seconds.toFixed(1) + 's';
    if (seconds < 3600) return (seconds / 60).toFixed(1) + 'm';
    return (seconds / 3600).toFixed(1) + 'h';
}

function scoreBadge(score, inverse = false) {
    let cls = 'neutral';
    if (inverse) {
        if (score >= 70) cls = 'low';
        else if (score >= 40) cls = 'medium';
        else cls = 'high';
    } else {
        if (score >= 70) cls = 'high';
        else if (score >= 40) cls = 'medium';
        else cls = 'low';
    }
    return `<span class="score-badge ${cls}">${score.toFixed(1)}</span>`;
}

function severityTag(sev) {
    return `<span class="severity ${sev}">${sev}</span>`;
}

// ── Tab Navigation ──────────────────────────────────────────────────────────

function switchTab(tabId) {
    state.activeTab = tabId;
    document.querySelectorAll('.tab-nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

    const btn = document.querySelector(`.tab-nav button[data-tab="${tabId}"]`);
    const panel = document.getElementById(`tab-${tabId}`);
    if (btn) btn.classList.add('active');
    if (panel) panel.classList.add('active');

    // Lazy-load tab data
    switch (tabId) {
        case 'overview': loadOverview(); break;
        case 'files': loadFiles(); break;
        case 'domains': loadDomains(); break;
        case 'duplicates': loadDuplicates(); break;
        case 'recommendations': loadRecommendations(); break;
        case 'risk': loadRisk(); break;
        case 'timeline': loadTimeline(); break;
    }
}

// ── Overview Tab ────────────────────────────────────────────────────────────

async function loadOverview() {
    const status = await api('/api/scan/status');
    if (!status || status.status === 'no_scans') {
        document.getElementById('overview-stats').innerHTML = `
            <div class="stat-card highlight">
                <div class="label">No Scans Yet</div>
                <div class="value" style="font-size:16px">Start a scan to see intelligence</div>
            </div>`;
        return;
    }

    state.activeScanId = status.id;
    const results = await api(`/api/scan/${status.id}/results`);
    if (!results) return;

    const s = results;
    document.getElementById('overview-stats').innerHTML = `
        <div class="stat-card highlight">
            <div class="label">Total Files</div>
            <div class="value">${(s.total_files || 0).toLocaleString()}</div>
        </div>
        <div class="stat-card">
            <div class="label">Total Size</div>
            <div class="value">${humanSize(s.total_size_bytes || 0)}</div>
        </div>
        <div class="stat-card success">
            <div class="label">Classified</div>
            <div class="value">${(s.files_classified || 0).toLocaleString()}</div>
        </div>
        <div class="stat-card">
            <div class="label">Duration</div>
            <div class="value">${humanDuration(s.duration_seconds || 0)}</div>
        </div>
        <div class="stat-card warning">
            <div class="label">Duplicates</div>
            <div class="value">${s.duplicate_clusters || 0}</div>
            <div class="subtext">${humanSize(s.wasted_bytes || 0)} wasted</div>
        </div>
        <div class="stat-card">
            <div class="label">Recommendations</div>
            <div class="value">${s.recommendation_count || 0}</div>
        </div>
        <div class="stat-card danger">
            <div class="label">High Risk</div>
            <div class="value">${s.high_risk_count || 0}</div>
        </div>
        <div class="stat-card warning">
            <div class="label">Sensitive</div>
            <div class="value">${s.sensitive_count || 0}</div>
        </div>
    `;

    // Load domain distribution for sunburst
    loadDomainSunburst();
    loadScoreDistribution();
}

async function loadDomainSunburst() {
    const data = await api('/api/domains');
    if (!data || !data.domains || !data.domains.length) return;

    const container = document.getElementById('domain-sunburst');
    if (!container) return;
    container.innerHTML = '';

    const width = container.clientWidth || 400;
    const height = 350;
    const radius = Math.min(width, height) / 2 - 20;

    // Build hierarchy
    const root = { name: 'All', children: [] };
    for (const d of data.domains) {
        root.children.push({
            name: d.domain || 'UNKNOWN',
            value: d.file_count || 0,
            avgScore: d.avg_score || 0,
            size: d.total_size_bytes || 0,
        });
    }

    const hierarchy = d3.hierarchy(root).sum(d => d.value || 0).sort((a, b) => b.value - a.value);
    const partition = d3.partition().size([2 * Math.PI, radius]);
    partition(hierarchy);

    const color = d3.scaleOrdinal(d3.schemeTableau10);
    const arc = d3.arc()
        .startAngle(d => d.x0)
        .endAngle(d => d.x1)
        .innerRadius(d => d.y0)
        .outerRadius(d => d.y1 - 1);

    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .append('g')
        .attr('transform', `translate(${width / 2},${height / 2})`);

    svg.selectAll('path')
        .data(hierarchy.descendants().filter(d => d.depth > 0))
        .join('path')
        .attr('d', arc)
        .attr('fill', d => color(d.data.name))
        .attr('stroke', '#0a0a0f')
        .attr('stroke-width', 1)
        .style('opacity', 0.85)
        .style('cursor', 'pointer')
        .on('mouseover', function (event, d) {
            d3.select(this).style('opacity', 1);
            const tooltip = `${d.data.name}: ${d.value.toLocaleString()} files`;
            showTooltip(event, tooltip);
        })
        .on('mouseout', function () {
            d3.select(this).style('opacity', 0.85);
            hideTooltip();
        });

    // Center label
    svg.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '-0.2em')
        .attr('fill', '#e0e0e0')
        .attr('font-size', '24px')
        .attr('font-weight', '700')
        .text(data.total_domains);

    svg.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '1.2em')
        .attr('fill', '#a0a0a0')
        .attr('font-size', '11px')
        .text('DOMAINS');
}

async function loadScoreDistribution() {
    const data = await api('/api/scores/distribution?dimension=overall_score');
    if (!data || !data.buckets || !data.buckets.length) return;

    const container = document.getElementById('score-heatmap');
    if (!container) return;
    container.innerHTML = '';

    const width = container.clientWidth || 400;
    const height = 250;
    const margin = { top: 20, right: 20, bottom: 40, left: 50 };

    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    const x = d3.scaleBand()
        .domain(data.buckets.map(b => b.label || b.range || ''))
        .range([0, innerW])
        .padding(0.1);

    const y = d3.scaleLinear()
        .domain([0, d3.max(data.buckets, b => b.count || 0)])
        .range([innerH, 0]);

    // Bars
    g.selectAll('rect')
        .data(data.buckets)
        .join('rect')
        .attr('x', d => x(d.label || d.range || '') || 0)
        .attr('y', d => y(d.count || 0))
        .attr('width', x.bandwidth())
        .attr('height', d => innerH - y(d.count || 0))
        .attr('fill', '#00d4ff')
        .attr('rx', 2)
        .style('opacity', 0.8);

    // Axes
    g.append('g')
        .attr('transform', `translate(0,${innerH})`)
        .call(d3.axisBottom(x).tickSize(0))
        .selectAll('text')
        .attr('fill', '#a0a0a0')
        .attr('font-size', '10px');

    g.append('g')
        .call(d3.axisLeft(y).ticks(5).tickSize(-innerW))
        .selectAll('text')
        .attr('fill', '#a0a0a0')
        .attr('font-size', '10px');

    g.selectAll('.tick line').attr('stroke', '#2a2a3e');
    g.selectAll('.domain').attr('stroke', '#2a2a3e');
}

// ── Files Tab ───────────────────────────────────────────────────────────────

async function loadFiles() {
    const params = new URLSearchParams();
    if (state.filesSearch) params.set('search', state.filesSearch);
    if (state.filesDomain) params.set('domain', state.filesDomain);
    if (state.filesExtension) params.set('extension', state.filesExtension);
    params.set('limit', state.filesLimit);
    params.set('offset', state.filesPage * state.filesLimit);

    const data = await api(`/api/files?${params}`);
    if (!data) return;

    const tbody = document.getElementById('files-tbody');
    if (!tbody) return;

    tbody.innerHTML = data.files.map(item => {
        const f = item.file;
        const s = item.score;
        return `<tr onclick="showFileDetail(${f.id})">
            <td title="${f.path}">${f.filename}</td>
            <td title="${f.path}">${f.parent_dir ? f.parent_dir.split('\\').slice(-2).join('\\') : ''}</td>
            <td>${humanSize(f.size_bytes)}</td>
            <td>${s ? s.primary_domain || '-' : '-'}</td>
            <td>${s ? scoreBadge(s.quality_score) : '-'}</td>
            <td>${s ? scoreBadge(s.importance_score) : '-'}</td>
            <td>${s ? scoreBadge(s.risk_score, true) : '-'}</td>
            <td>${s ? scoreBadge(s.overall_score) : '-'}</td>
        </tr>`;
    }).join('');

    // Pagination info
    const info = document.getElementById('files-pagination-info');
    if (info) {
        const start = state.filesPage * state.filesLimit + 1;
        const end = start + data.count - 1;
        info.textContent = `Showing ${start}-${end}`;
    }
}

async function showFileDetail(fileId) {
    const data = await api(`/api/files/${fileId}`);
    if (!data) return;

    const f = data.file;
    const s = data.score;
    const modal = document.getElementById('file-detail-modal');
    const content = document.getElementById('file-detail-content');

    let html = `<h3>${f.filename}</h3><p style="color:var(--text-secondary);font-size:12px">${f.path}</p>`;

    if (s) {
        html += `<div class="stats-grid" style="margin-top:16px">
            <div class="stat-card"><div class="label">Overall</div><div class="value">${s.overall_score.toFixed(1)}</div></div>
            <div class="stat-card"><div class="label">Quality</div><div class="value">${s.quality_score.toFixed(1)}</div></div>
            <div class="stat-card"><div class="label">Importance</div><div class="value">${s.importance_score.toFixed(1)}</div></div>
            <div class="stat-card"><div class="label">Sensitivity</div><div class="value">${s.sensitivity_score.toFixed(1)}</div></div>
            <div class="stat-card"><div class="label">Staleness</div><div class="value">${s.staleness_score.toFixed(1)}</div></div>
            <div class="stat-card"><div class="label">Risk</div><div class="value">${s.risk_score.toFixed(1)}</div></div>
        </div>`;
    }

    if (data.classifications && data.classifications.length) {
        html += `<h4 style="margin-top:16px">Classifications (${data.classifications.length})</h4>
        <table style="margin-top:8px"><thead><tr><th>Engine</th><th>Domain</th><th>Topic</th><th>Score</th><th>Confidence</th></tr></thead><tbody>`;
        for (const c of data.classifications) {
            html += `<tr><td>${c.engine_id}</td><td>${c.domain}</td><td>${c.topic}</td>
                <td>${scoreBadge(c.score)}</td><td>${c.confidence}</td></tr>`;
        }
        html += '</tbody></table>';
    }

    if (data.relationships && data.relationships.length) {
        html += `<h4 style="margin-top:16px">Relationships (${data.relationships.length})</h4>
        <table style="margin-top:8px"><thead><tr><th>Type</th><th>Target</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>`;
        for (const r of data.relationships) {
            html += `<tr><td>${r.relationship_type}</td><td>#${r.target_file_id}</td>
                <td>${(r.confidence * 100).toFixed(0)}%</td><td>${r.evidence || ''}</td></tr>`;
        }
        html += '</tbody></table>';
    }

    content.innerHTML = html;
    modal.classList.add('active');
}

// ── Domains Tab ─────────────────────────────────────────────────────────────

async function loadDomains() {
    const data = await api('/api/domains');
    if (!data || !data.domains) return;

    const container = document.getElementById('domains-grid');
    if (!container) return;

    container.innerHTML = data.domains
        .sort((a, b) => (b.file_count || 0) - (a.file_count || 0))
        .map(d => `
            <div class="domain-card">
                <div class="domain-name">${d.domain}</div>
                <div class="domain-label">${d.domain_label || ''}</div>
                <div class="domain-stat"><span>Files</span><span>${(d.file_count || 0).toLocaleString()}</span></div>
                <div class="domain-stat"><span>Size</span><span>${humanSize(d.total_size_bytes || 0)}</span></div>
                <div class="domain-stat"><span>Avg Score</span><span>${(d.avg_score || 0).toFixed(1)}</span></div>
            </div>
        `).join('');
}

// ── Duplicates Tab ──────────────────────────────────────────────────────────

async function loadDuplicates() {
    const data = await api('/api/duplicates');
    if (!data) return;

    const summary = document.getElementById('dup-summary');
    if (summary) {
        summary.innerHTML = `
            <div class="stat-card"><div class="label">Clusters</div><div class="value">${data.total_clusters || 0}</div></div>
            <div class="stat-card warning"><div class="label">Wasted Space</div><div class="value">${humanSize(data.total_wasted_bytes || 0)}</div></div>
        `;
    }

    const list = document.getElementById('dup-list');
    if (!list || !data.clusters) return;

    list.innerHTML = data.clusters.slice(0, 50).map(c => {
        const members = c.members || [];
        const memberHtml = members.map(m =>
            `<div class="cluster-files ${m.is_keeper ? 'keeper' : 'duplicate'}">
                ${m.is_keeper ? '★ ' : '✕ '}${m.file_path} (${humanSize(m.size_bytes)})
            </div>`
        ).join('');

        return `<div class="cluster-card">
            <div class="cluster-header">
                <strong>${c.file_count} files</strong>
                <span style="color:var(--accent-red)">${humanSize(c.total_wasted_bytes)} wasted</span>
            </div>
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">Hash: ${c.cluster_hash ? c.cluster_hash.substring(0, 16) + '...' : '-'}</div>
            ${memberHtml}
        </div>`;
    }).join('');
}

// ── Recommendations Tab ─────────────────────────────────────────────────────

async function loadRecommendations() {
    const data = await api('/api/recommendations');
    if (!data || !data.recommendations) return;

    const container = document.getElementById('rec-grid');
    if (!container) return;

    container.innerHTML = data.recommendations.map(r => `
        <div class="rec-card ${r.severity}">
            <div class="rec-header">
                <h4>${r.title}</h4>
                ${severityTag(r.severity)}
            </div>
            <div class="rec-body">${r.description}</div>
            <div class="rec-meta">
                <span>Category: ${r.category}</span>
                <span>Files: ${r.affected_count}</span>
                <span>Impact: ${r.estimated_impact || '-'}</span>
            </div>
            <div class="rec-actions">
                ${r.auto_executable ? `<button class="btn btn-success btn-sm" onclick="executeRec(${r.id})">Execute</button>` : ''}
                <button class="btn btn-sm" onclick="dismissRec(${r.id})">Dismiss</button>
            </div>
        </div>
    `).join('');
}

async function executeRec(id) {
    const resp = await api(`/api/recommendations/${id}/execute`, { method: 'POST' });
    if (resp) loadRecommendations();
}

function dismissRec(id) {
    const card = event.target.closest('.rec-card');
    if (card) card.style.display = 'none';
}

// ── Risk Tab ────────────────────────────────────────────────────────────────

async function loadRisk() {
    const data = await api('/api/scores/risk?min_risk=30');
    if (!data || !data.files) return;

    const tbody = document.getElementById('risk-tbody');
    if (!tbody) return;

    tbody.innerHTML = data.files.map(s => `
        <tr>
            <td>#${s.file_id}</td>
            <td>${scoreBadge(s.risk_score, true)}</td>
            <td>${scoreBadge(s.sensitivity_score)}</td>
            <td>${s.primary_domain || '-'}</td>
            <td>${scoreBadge(s.overall_score)}</td>
        </tr>
    `).join('');
}

// ── Timeline Tab ────────────────────────────────────────────────────────────

async function loadTimeline() {
    const data = await api('/api/timeline');
    if (!data || !data.scans) return;

    const container = document.getElementById('timeline-list');
    if (!container) return;

    container.innerHTML = data.scans.map(s => `
        <div class="cluster-card">
            <div class="cluster-header">
                <strong>Scan #${s.id}</strong>
                <span style="color:var(--text-secondary)">${s.started_at ? s.started_at.substring(0, 19) : '-'}</span>
            </div>
            <div style="display:flex;gap:24px;font-size:13px;color:var(--text-secondary)">
                <span>Status: <strong style="color:${s.status === 'completed' ? 'var(--accent-green)' : 'var(--accent-red)'}">${s.status}</strong></span>
                <span>Files: ${(s.total_files || 0).toLocaleString()}</span>
                <span>Classified: ${s.files_classified || 0}</span>
                <span>Duration: ${humanDuration(s.duration_seconds || 0)}</span>
                <span>Profile: ${s.profile || '-'}</span>
            </div>
        </div>
    `).join('');
}

// ── WebSocket ───────────────────────────────────────────────────────────────

function connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    state.ws = new WebSocket(`${proto}//${location.host}/api/ws/scan`);

    state.ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateScanProgress(data);
    };

    state.ws.onclose = () => {
        setTimeout(connectWebSocket, 3000);
    };

    state.ws.onerror = () => {
        console.warn('WebSocket error, will reconnect');
    };

    // Keep alive
    setInterval(() => {
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send('ping');
        }
    }, 30000);
}

function updateScanProgress(data) {
    const modal = document.getElementById('scan-progress-modal');
    if (!modal) return;

    if (data.phase === 'completed' || data.phase === 'failed') {
        modal.classList.remove('active');
        state.scanning = false;
        loadOverview();
        return;
    }

    modal.classList.add('active');
    state.scanning = true;

    const total = data.total_files || 1;
    const processed = data.processed_files || 0;
    const pct = Math.min(100, (processed / total) * 100);

    const fill = document.getElementById('progress-fill');
    if (fill) fill.style.width = pct + '%';

    const els = {
        'progress-phase': data.phase || '-',
        'progress-files': `${processed.toLocaleString()} / ${total.toLocaleString()}`,
        'progress-classified': (data.classified_files || 0).toLocaleString(),
        'progress-current': data.current_file || '-',
        'progress-elapsed': humanDuration(data.elapsed_seconds || 0),
        'progress-eta': data.eta_seconds ? humanDuration(data.eta_seconds) : '-',
        'progress-api': (data.api_calls || 0).toLocaleString(),
        'progress-throughput': (data.throughput_files_per_min || 0).toFixed(0) + '/min',
    };

    for (const [id, text] of Object.entries(els)) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    }
}

// ── Scan Control ────────────────────────────────────────────────────────────

async function startScan() {
    const pathInput = prompt('Enter paths to scan (comma-separated):', 'O:\\');
    if (!pathInput) return;

    const paths = pathInput.split(',').map(p => p.trim()).filter(Boolean);
    const resp = await api('/api/scan/start', {
        method: 'POST',
        body: JSON.stringify({ paths, profile: 'INTELLIGENCE' }),
    });

    if (resp) {
        state.scanning = true;
        const modal = document.getElementById('scan-progress-modal');
        if (modal) modal.classList.add('active');
    }
}

// ── Tooltip ─────────────────────────────────────────────────────────────────

let tooltipEl = null;

function showTooltip(event, text) {
    if (!tooltipEl) {
        tooltipEl = document.createElement('div');
        tooltipEl.style.cssText = `
            position:fixed;z-index:300;background:#1a1a2e;color:#e0e0e0;
            padding:6px 10px;border-radius:4px;font-size:12px;
            pointer-events:none;border:1px solid #2a2a3e;
        `;
        document.body.appendChild(tooltipEl);
    }
    tooltipEl.textContent = text;
    tooltipEl.style.display = 'block';
    tooltipEl.style.left = (event.clientX + 12) + 'px';
    tooltipEl.style.top = (event.clientY - 24) + 'px';
}

function hideTooltip() {
    if (tooltipEl) tooltipEl.style.display = 'none';
}

// ── Export ───────────────────────────────────────────────────────────────────

async function exportReport() {
    const data = await api('/api/export/report');
    if (!data) return;

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `intelligence-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// ── Modal Close ─────────────────────────────────────────────────────────────

function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.remove('active');
}

// ── Init ────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Tab clicks
    document.querySelectorAll('.tab-nav button[data-tab]').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // Search
    const searchInput = document.getElementById('files-search');
    if (searchInput) {
        let debounce;
        searchInput.addEventListener('input', () => {
            clearTimeout(debounce);
            debounce = setTimeout(() => {
                state.filesSearch = searchInput.value;
                state.filesPage = 0;
                loadFiles();
            }, 300);
        });
    }

    // Domain filter
    const domainFilter = document.getElementById('files-domain-filter');
    if (domainFilter) {
        domainFilter.addEventListener('change', () => {
            state.filesDomain = domainFilter.value;
            state.filesPage = 0;
            loadFiles();
        });
    }

    // Pagination
    const prevBtn = document.getElementById('files-prev');
    const nextBtn = document.getElementById('files-next');
    if (prevBtn) prevBtn.addEventListener('click', () => { if (state.filesPage > 0) { state.filesPage--; loadFiles(); } });
    if (nextBtn) nextBtn.addEventListener('click', () => { state.filesPage++; loadFiles(); });

    // Modal close on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.classList.remove('active');
        });
    });

    // Connect WebSocket
    connectWebSocket();

    // Load initial data
    switchTab('overview');
});
