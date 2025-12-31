// reports_report.js
// Logic for /reports/report/<scan_id> page

(function () {
    'use strict';

    const container = document.querySelector('.scanner-container[data-scan-id]');
    if (!container) return;

    const scanId = container.getAttribute('data-scan-id');
    const apiGetReport = `/api/reports/${encodeURIComponent(scanId)}`;

    const backBtn = document.getElementById('reportBackBtn');
    const downloadJsonBtn = document.getElementById('reportDownloadJsonBtn');

    const targetEl = document.getElementById('reportTarget');
    const scanTypeEl = document.getElementById('reportScanType');
    const dateEl = document.getElementById('reportDate');
    const durationEl = document.getElementById('reportDuration');
    const totalVulnsEl = document.getElementById('reportTotalVulns');
    const modulesContainer = document.getElementById('reportModules');

    const riskMeterFill = document.getElementById('reportRiskMeterFill');
    const riskScoreEl = document.getElementById('reportRiskScore');
    const riskLevelEl = document.getElementById('reportRiskLevel');

    const critCountEl = document.getElementById('reportCriticalCount');
    const highCountEl = document.getElementById('reportHighCount');
    const medCountEl = document.getElementById('reportMediumCount');
    const lowCountEl = document.getElementById('reportLowCount');
    const infoCountEl = document.getElementById('reportInfoCount');

    const vulnsList = document.getElementById('reportVulnsList');
    const noVulns = document.getElementById('reportNoVulns');

    const portsList = document.getElementById('reportPortsList');
    const noPorts = document.getElementById('reportNoPorts');

    const techList = document.getElementById('reportTechList');
    const noTech = document.getElementById('reportNoTech');

    const securityHeadersList = document.getElementById('reportSecurityHeadersList');
    const allHeadersList = document.getElementById('reportAllHeadersList');
    const noHeaders = document.getElementById('reportNoHeaders');

    const vulnFilterGroup = document.getElementById('reportVulnFilter');
    const vulnSearchInput = document.getElementById('reportVulnSearch');

    const vulnModal = document.getElementById('reportVulnModal');
    const vulnModalTitle = document.getElementById('reportVulnModalTitle');
    const vulnModalBody = document.getElementById('reportVulnModalBody');
    const copyVulnBtn = document.getElementById('reportCopyVulnBtn');

    let reportData = null;

    function setRisk(score, severitySummary) {
        if (riskScoreEl) riskScoreEl.textContent = String(score || 0);
        if (riskMeterFill) riskMeterFill.style.width = `${score || 0}%`;

        let level = 'Low';
        let badgeClass = 'badge bg-success';

        if (score >= 75) {
            level = 'Critical';
            badgeClass = 'badge bg-danger';
        } else if (score >= 50) {
            level = 'High';
            badgeClass = 'badge bg-warning';
        } else if (score >= 25) {
            level = 'Medium';
            badgeClass = 'badge bg-info';
        }

        if (riskLevelEl) {
            riskLevelEl.textContent = level;
            riskLevelEl.className = badgeClass;
        }

        const sev = severitySummary || {};
        if (critCountEl) critCountEl.textContent = sev.critical || 0;
        if (highCountEl) highCountEl.textContent = sev.high || 0;
        if (medCountEl) medCountEl.textContent = sev.medium || 0;
        if (lowCountEl) lowCountEl.textContent = sev.low || 0;
        if (infoCountEl) infoCountEl.textContent = sev.info || 0;
    }

    function renderSummary(data) {
        const target = data.target || (data.target_info && data.target_info.target) || '-';
        const type = data.scan_type || (data.summary && data.summary.scan_type) || 'unknown';
        const date = data.timestamp || data.date || '-';
        const duration = (data.duration != null
            ? `${data.duration.toFixed ? data.duration.toFixed(1) : data.duration}s`
            : (data.summary && data.summary.duration ? `${data.summary.duration}s` : '-'));

        const severity = data.severity_summary || (data.summary && data.summary.severity_breakdown) || {};
        const riskScore = data.risk_score || (data.summary && data.summary.risk_score) || 0;

        const totalVulns = data.total_vulnerabilities ||
            (data.vulnerabilities && data.vulnerabilities.length) ||
            (data.all_vulnerabilities && data.all_vulnerabilities.length) ||
            (Array.isArray(data.findings) ? data.findings.length : 0);

        if (targetEl) targetEl.textContent = target;
        if (scanTypeEl) scanTypeEl.textContent = type;
        if (dateEl) dateEl.textContent = date;
        if (durationEl) durationEl.textContent = duration;
        if (totalVulnsEl) totalVulnsEl.textContent = totalVulns;

        const modules = [];
        if (data.port_scan) modules.push('Port Scan');
        if (data.dns_lookup) modules.push('DNS');
        if (data.whois_lookup) modules.push('WHOIS');
        if (data.subdomain_enum) modules.push('Subdomains');
        if (data.tech_detection) modules.push('Tech Detect');
        if (data.ssl_analysis) modules.push('SSL/TLS');
        if (data.header_analysis) modules.push('Headers');
        if (data.directory_scan) modules.push('Dir Scan');
        if (data.crawl) modules.push('Crawl');
        if (data.xss_scan) modules.push('XSS');
        if (data.sqli_scan) modules.push('SQLi');

        if (modulesContainer) {
            modulesContainer.innerHTML = '';
            if (modules.length) {
                modules.forEach(m => {
                    const span = document.createElement('span');
                    span.className = 'badge bg-secondary p-2';
                    span.textContent = m;
                    modulesContainer.appendChild(span);
                });
            } else {
                modulesContainer.innerHTML = '<span class="text-muted small">No module details recorded.</span>';
            }
        }

        setRisk(riskScore, severity);
    }

    function collectVulns(data) {
        if (Array.isArray(data.vulnerabilities)) return data.vulnerabilities;
        if (Array.isArray(data.all_vulnerabilities)) return data.all_vulnerabilities;
        if (Array.isArray(data.findings)) return data.findings;
        return [];
    }

    function renderVulns(vulns) {
        if (!vulnsList) return;
        if (!vulns || vulns.length === 0) {
            vulnsList.innerHTML = '';
            if (noVulns) noVulns.style.display = 'block';
            return;
        }
        if (noVulns) noVulns.style.display = 'none';

        vulnsList.innerHTML = vulns.map((v, idx) => {
            const sev = (v.severity || 'info').toLowerCase();
            const sevBadge = {
                critical: 'danger',
                high: 'warning',
                medium: 'info',
                low: 'success',
                info: 'secondary'
            }[sev] || 'secondary';

            return `
<div class="vuln-card ${sev}" data-index="${idx}" data-severity="${sev}">
  <div class="vuln-header">
    <div>
      <h6 class="vuln-title">${v.name || v.type || 'Vulnerability'}</h6>
      <div class="vuln-detail">${v.url ? `<code>${v.url}</code>` : ''}</div>
    </div>
    <span class="badge bg-${sevBadge}">${(v.severity || '').toUpperCase()}</span>
  </div>
  <div class="vuln-meta mt-1">
    ${v.parameter ? `<span class="badge bg-secondary">Param: ${v.parameter}</span>` : ''}
    ${v.method ? `<span class="badge bg-secondary">${v.method}</span>` : ''}
  </div>
  <div class="mt-2">
    <button type="button" class="btn btn-sm btn-outline-primary report-vuln-details" data-index="${idx}">
      <i class="bi bi-info-circle me-1"></i>Details
    </button>
  </div>
</div>`;
        }).join('');

        attachVulnHandlers();
    }

    function attachVulnHandlers() {
        if (!vulnsList) return;
        vulnsList.querySelectorAll('.report-vuln-details').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = parseInt(btn.getAttribute('data-index'), 10);
                showVulnModal(idx);
            });
        });
    }

    function filterVulns(filter, term) {
        if (!vulnsList || !reportData) return;
        const vulns = collectVulns(reportData);
        const search = (term || '').toLowerCase();
        const cards = vulnsList.querySelectorAll('.vuln-card');

        cards.forEach((card, idx) => {
            const sev = card.getAttribute('data-severity');
            let visible = (filter === 'all' || filter === sev);
            if (visible && search) {
                const v = vulns[idx];
                const txt = [
                    v.name,
                    v.type,
                    v.url,
                    v.parameter,
                    v.description
                ].map(x => (x || '').toString().toLowerCase()).join(' ');
                visible = txt.includes(search);
            }
            card.style.display = visible ? '' : 'none';
        });
    }

    function showVulnModal(index) {
        if (!reportData) return;
        const vulns = collectVulns(reportData);
        const vuln = vulns[index];
        if (!vuln) return;

        if (vulnModalTitle) {
            vulnModalTitle.textContent = vuln.name || vuln.type || 'Vulnerability Details';
        }

        if (vulnModalBody) {
            vulnModalBody.innerHTML = `
<table class="table table-sm">
  <tr><th style="width: 25%;">Severity</th><td>${(vuln.severity || '').toUpperCase()}</td></tr>
  <tr><th>Type</th><td>${vuln.type || '-'}</td></tr>
  <tr><th>URL</th><td>${vuln.url ? `<code>${vuln.url}</code>` : '-'}</td></tr>
  ${vuln.parameter ? `<tr><th>Parameter</th><td><code>${vuln.parameter}</code></td></tr>` : ''}
  ${vuln.method ? `<tr><th>Method</th><td>${vuln.method}</td></tr>` : ''}
  ${vuln.payload ? `<tr><th>Payload</th><td><code class="text-break">${vuln.payload}</code></td></tr>` : ''}
</table>
${vuln.description ? `<h6>Description</h6><p>${vuln.description}</p>` : ''}
${vuln.remediation ? `<h6>Remediation</h6><p>${vuln.remediation}</p>` : ''}`;
        }

        if (typeof bootstrap !== 'undefined' && vulnModal) {
            const modal = bootstrap.Modal.getOrCreateInstance(vulnModal);
            modal.show();
        }
    }

    function renderPorts(data) {
        if (!portsList) return;
        const portScan = data.port_scan;
        if (!portScan || !portScan.open_ports || portScan.open_ports.length === 0) {
            portsList.innerHTML = '<tr><td colspan="5" class="text-muted text-center">No port scan data.</td></tr>';
            if (noPorts) noPorts.style.display = 'block';
            return;
        }
        if (noPorts) noPorts.style.display = 'none';
        portsList.innerHTML = portScan.open_ports.map(p => {
            const risk = (p.risk_level || 'low').toLowerCase();
            const riskBadge = risk === 'high' ? 'danger' : risk === 'medium' ? 'warning' : 'success';
            return `
<tr>
  <td><strong>${p.port}</strong></td>
  <td><span class="badge bg-success">${p.state || 'open'}</span></td>
  <td>${p.service || '-'}</td>
  <td>${p.version || '-'}</td>
  <td><span class="badge bg-${riskBadge}">${(p.risk_level || 'LOW').toUpperCase()}</span></td>
</tr>`;
        }).join('');
    }

    function renderTech(data) {
        if (!techList) return;
        const tech = data.tech_detection && data.tech_detection.technologies
            ? data.tech_detection.technologies
            : [];
        if (!tech.length) {
            techList.innerHTML = '';
            if (noTech) noTech.style.display = 'block';
            return;
        }
        if (noTech) noTech.style.display = 'none';
        techList.innerHTML = `
<div class="d-flex flex-wrap gap-2">
${tech.map(t => {
    const label = t.version ? `${t.name} ${t.version}` : t.name;
    return `<span class="badge bg-primary p-2">${label}</span>`;
}).join('')}
</div>`;
    }

    function renderHeaders(data) {
        if (!securityHeadersList || !allHeadersList) return;

        const headerData = data.header_analysis || {};
        const secHeaders = headerData.security_headers || [];
        const allHeaders = headerData.headers || {};

        if (!Object.keys(allHeaders).length && !secHeaders.length) {
            if (noHeaders) noHeaders.style.display = 'block';
            return;
        }
        if (noHeaders) noHeaders.style.display = 'none';

        // Security headers
        securityHeadersList.innerHTML = '';
        secHeaders.forEach(h => {
            const wrapper = document.createElement('div');
            wrapper.className = 'header-item mb-2';
            const valid = h.valid;
            let stateClass = 'warning';
            if (valid && h.present) stateClass = 'good';
            if (!h.present) stateClass = 'bad';
            wrapper.classList.add(stateClass);

            wrapper.innerHTML = `
<div class="d-flex justify-content-between align-items-start">
  <div>
    <h6 class="mb-1">${h.name}</h6>
    ${h.value ? `<code class="small">${h.value}</code>` : '<span class="small text-muted">No value</span>'}
  </div>
  <span class="badge bg-${valid ? 'success' : 'warning'}">${h.score || 0}/${h.max_score || 10}</span>
</div>
${h.recommendation ? `<p class="text-muted small mt-2 mb-0">${h.recommendation}</p>` : ''}`;
            securityHeadersList.appendChild(wrapper);
        });

        // All headers
        allHeadersList.innerHTML = '';
        Object.entries(allHeaders).forEach(([name, value]) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
<td><strong>${name}</strong></td>
<td><code class="small">${value}</code></td>`;
            allHeadersList.appendChild(tr);
        });
    }

    async function loadReport() {
        try {
            const data = await VulnScanner.apiRequest(apiGetReport, 'GET');
            reportData = data;

            renderSummary(data);
            const vulns = collectVulns(data);
            renderVulns(vulns);
            renderPorts(data);
            renderTech(data);
            renderHeaders(data);

        } catch (err) {
            VulnScanner.showAlert('Failed to load report: ' + err.message, 'danger');
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        loadReport();

        if (backBtn) {
            backBtn.addEventListener('click', () => {
                window.location.href = '/scanner/history';
            });
        }

        if (downloadJsonBtn) {
            downloadJsonBtn.addEventListener('click', async () => {
                try {
                    const data = await VulnScanner.apiRequest(apiGetReport, 'GET');
                    VulnScanner.downloadJSON(data, `scan_report_${scanId}.json`);
                } catch (err) {
                    VulnScanner.showAlert('Failed to download report: ' + err.message, 'danger');
                }
            });
        }

        if (vulnFilterGroup) {
            vulnFilterGroup.querySelectorAll('button[data-filter]').forEach(btn => {
                btn.addEventListener('click', () => {
                    vulnFilterGroup.querySelectorAll('button[data-filter]')
                        .forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    const filter = btn.getAttribute('data-filter');
                    const term = vulnSearchInput ? vulnSearchInput.value : '';
                    filterVulns(filter, term);
                });
            });
        }

        if (vulnSearchInput) {
            vulnSearchInput.addEventListener('input', () => {
                const activeBtn = vulnFilterGroup
                    ? vulnFilterGroup.querySelector('button.active[data-filter]')
                    : null;
                const filter = activeBtn ? activeBtn.getAttribute('data-filter') : 'all';
                filterVulns(filter, vulnSearchInput.value);
            });
        }

        if (copyVulnBtn && vulnModalBody) {
            copyVulnBtn.addEventListener('click', () => {
                const text = vulnModalBody.innerText;
                navigator.clipboard.writeText(text).then(() => {
                    VulnScanner.showAlert('Vulnerability details copied to clipboard', 'success');
                });
            });
        }
    });
})();