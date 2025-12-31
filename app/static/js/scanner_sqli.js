// scanner_sqli.js
// Logic for /scanner/sqli-scan page

(function () {
    'use strict';

    const apiSqliScan = '/scanner/api/sqli-scan';

    let scanActive = false;
    let scanResults = null;
    let timerInterval = null;
    let startTime = null;

    const form = document.getElementById('sqliScanForm');
    if (!form) return;

    const targetInput = document.getElementById('sqliTarget');
    const methodSelect = document.getElementById('sqliMethod');
    const errorBasedChk = document.getElementById('sqliErrorBased');
    const booleanBasedChk = document.getElementById('sqliBooleanBased');
    const timeBasedChk = document.getElementById('sqliTimeBased');
    const unionBasedChk = document.getElementById('sqliUnionBased');
    const testFormsChk = document.getElementById('sqliTestForms');
    const respectRobotsChk = document.getElementById('sqliRespectRobots');

    const startBtn = document.getElementById('sqliStartBtn');
    const stopBtn = document.getElementById('sqliStopBtn');

    const timerContainer = document.getElementById('sqliScanTimer');
    const timerDisplay = document.getElementById('sqliScanTimerDisplay');

    const logCard = document.getElementById('sqliLogCard');
    const logContainer = document.getElementById('sqliLog');
    const clearLogBtn = document.getElementById('sqliClearLogBtn');

    const progressCard = document.getElementById('sqliProgressCard');
    const progressBar = document.getElementById('sqliProgressBar');
    const progressText = document.getElementById('sqliProgressText');
    const currentStatus = document.getElementById('sqliCurrentStatus');

    const noResults = document.getElementById('sqliNoResults');
    const resultsContainer = document.getElementById('sqliResultsContainer');
    const resultActions = document.getElementById('sqliResultActions');

    const riskMeterFill = document.getElementById('sqliRiskMeterFill');
    const riskScoreEl = document.getElementById('sqliRiskScore');
    const riskLevelEl = document.getElementById('sqliRiskLevel');

    const critCountEl = document.getElementById('sqliCriticalCount');
    const highCountEl = document.getElementById('sqliHighCount');
    const medCountEl = document.getElementById('sqliMediumCount');
    const lowCountEl = document.getElementById('sqliLowCount');
    const infoCountEl = document.getElementById('sqliInfoCount');
    const vulnsBadge = document.getElementById('sqliVulnsBadge');

    const vulnsList = document.getElementById('sqliVulnsList');
    const paramsList = document.getElementById('sqliParamsList');

    const vulnFilterGroup = document.getElementById('sqliVulnFilter');

    const downloadJsonBtn = document.getElementById('sqliDownloadJson');
    const downloadReportBtn = document.getElementById('sqliDownloadReport');

    const vulnModal = document.getElementById('sqliVulnModal');
    const vulnModalTitle = document.getElementById('sqliVulnModalTitle');
    const vulnModalBody = document.getElementById('sqliVulnModalBody');
    const copyVulnDetailsBtn = document.getElementById('sqliCopyVulnDetails');

    function addLog(level, message) {
        if (!logContainer) return;
        const time = new Date().toLocaleTimeString();
        const div = document.createElement('div');
        div.className = 'log-entry';
        div.innerHTML = `<span class="log-time">[${time}]</span> <span class="log-${level}">${message}</span>`;
        logContainer.appendChild(div);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    function updateTimer() {
        if (!startTime || !timerDisplay) return;
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        timerDisplay.textContent = `${h}:${m}:${s}`;
    }

    function setButtons(running) {
        if (startBtn) startBtn.disabled = running;
        if (stopBtn) stopBtn.disabled = !running;
    }

    function resetUI() {
        scanActive = false;
        scanResults = null;

        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }

        if (timerContainer) timerContainer.style.display = 'none';
        if (logCard) logCard.style.display = 'none';
        if (progressCard) progressCard.style.display = 'none';

        if (progressBar) progressBar.style.width = '0%';
        if (progressText) progressText.textContent = '0%';
        if (currentStatus) currentStatus.textContent = 'Waiting to start...';

        if (noResults) noResults.style.display = 'block';
        if (resultsContainer) resultsContainer.style.display = 'none';
        if (resultActions) resultActions.style.display = 'none';

        if (riskMeterFill) riskMeterFill.style.width = '0%';
        if (riskScoreEl) riskScoreEl.textContent = '0';
        if (riskLevelEl) {
            riskLevelEl.textContent = 'Unknown';
            riskLevelEl.className = 'badge';
        }

        [critCountEl, highCountEl, medCountEl, lowCountEl, infoCountEl, vulnsBadge].forEach(el => {
            if (el) el.textContent = '0';
        });

        if (vulnsList) vulnsList.innerHTML = '';
        if (paramsList) paramsList.innerHTML = '';
    }

    function updateProgress(percent, statusText) {
        if (progressBar) progressBar.style.width = `${percent}%`;
        if (progressText) progressText.textContent = `${percent}%`;
        if (currentStatus && statusText) currentStatus.textContent = statusText;
    }

    function setRisk(score, severitySummary) {
        if (riskScoreEl) riskScoreEl.textContent = String(score);
        if (riskMeterFill) riskMeterFill.style.width = `${score}%`;

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

        if (severitySummary) {
            if (critCountEl) critCountEl.textContent = severitySummary.critical || 0;
            if (highCountEl) highCountEl.textContent = severitySummary.high || 0;
            if (medCountEl) medCountEl.textContent = severitySummary.medium || 0;
            if (lowCountEl) lowCountEl.textContent = severitySummary.low || 0;
            if (infoCountEl) infoCountEl.textContent = severitySummary.info || 0;

            const total =
                (severitySummary.critical || 0) +
                (severitySummary.high || 0) +
                (severitySummary.medium || 0) +
                (severitySummary.low || 0) +
                (severitySummary.info || 0);
            if (vulnsBadge) vulnsBadge.textContent = total;
        }
    }

    function renderVulns(vulns) {
        if (!vulnsList) return;
        if (!vulns || vulns.length === 0) {
            vulnsList.innerHTML = '';
            const empty = document.createElement('div');
            empty.className = 'text-muted text-center py-4';
            empty.innerHTML = '<i class="bi bi-check-circle display-6 d-block mb-2"></i>No SQL injection vulnerabilities found.';
            vulnsList.appendChild(empty);
            return;
        }

        vulnsList.innerHTML = vulns.map((v, idx) => {
            const sev = (v.severity || 'critical').toLowerCase();
            const sevBadge = sev === 'critical' ? 'danger' : 'warning';
            return `
<div class="vuln-card ${sev}" data-index="${idx}" data-severity="${sev}">
  <div class="vuln-header">
    <div>
      <h6 class="vuln-title">${v.name || v.type || 'SQL Injection'}</h6>
      <div class="vuln-detail">${v.url ? `<code>${v.url}</code>` : ''}</div>
    </div>
    <span class="badge bg-${sevBadge}">${(v.severity || '').toUpperCase()}</span>
  </div>
  <div class="vuln-meta mt-1">
    ${v.parameter ? `<span class="badge bg-secondary">Param: ${v.parameter}</span>` : ''}
    ${v.technique ? `<span class="badge bg-secondary">${v.technique}</span>` : ''}
    ${v.database ? `<span class="badge bg-secondary">${v.database}</span>` : ''}
  </div>
  <div class="mt-2">
    <button type="button" class="btn btn-sm btn-outline-primary sqli-vuln-details" data-index="${idx}">
      <i class="bi bi-info-circle me-1"></i>Details
    </button>
  </div>
</div>`;
        }).join('');
    }

    function renderParams(data) {
        if (!paramsList) return;
        // The back-end can be extended to include details about tested params.
        // For now, we display a placeholder.
        paramsList.innerHTML = '<tr><td colspan="4" class="text-muted text-center">Detailed parameter testing info not available.</td></tr>';
    }

    function attachVulnHandlers() {
        if (!vulnsList) return;
        vulnsList.querySelectorAll('.sqli-vuln-details').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = parseInt(btn.getAttribute('data-index'), 10);
                showVulnModal(idx);
            });
        });
    }

    function showVulnModal(index) {
        if (!scanResults || !scanResults.vulnerabilities) return;
        const vuln = scanResults.vulnerabilities[index];
        if (!vuln) return;

        if (vulnModalTitle) {
            vulnModalTitle.textContent = vuln.name || vuln.type || 'SQL Injection';
        }

        if (vulnModalBody) {
            vulnModalBody.innerHTML = `
<table class="table table-sm">
  <tr><th style="width: 25%;">Severity</th><td>${(vuln.severity || 'critical').toUpperCase()}</td></tr>
  <tr><th>Technique</th><td>${vuln.technique || '-'}</td></tr>
  <tr><th>Database</th><td>${vuln.database || '-'}</td></tr>
  <tr><th>URL</th><td>${vuln.url ? `<code>${vuln.url}</code>` : '-'}</td></tr>
  ${vuln.parameter ? `<tr><th>Parameter</th><td><code>${vuln.parameter}</code></td></tr>` : ''}
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

    function filterVulns(filter) {
        if (!vulnsList) return;
        const cards = vulnsList.querySelectorAll('.vuln-card');
        cards.forEach(card => {
            const sev = card.getAttribute('data-severity');
            card.style.display = (filter === 'all' || filter === sev) ? '' : 'none';
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        resetUI();

        if (clearLogBtn && logContainer) {
            clearLogBtn.addEventListener('click', () => {
                logContainer.innerHTML = '';
            });
        }

        if (vulnFilterGroup) {
            vulnFilterGroup.querySelectorAll('button[data-filter]').forEach(btn => {
                btn.addEventListener('click', () => {
                    vulnFilterGroup.querySelectorAll('button[data-filter]')
                        .forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    filterVulns(btn.getAttribute('data-filter'));
                });
            });
        }

        if (downloadJsonBtn) {
            downloadJsonBtn.addEventListener('click', () => {
                if (!scanResults) return;
                VulnScanner.downloadJSON(scanResults, 'sqli_scan_report.json');
            });
        }

        if (downloadReportBtn) {
            downloadReportBtn.addEventListener('click', () => {
                VulnScanner.showAlert('Standalone SQLi report export not implemented yet.', 'info');
            });
        }

        if (copyVulnDetailsBtn && vulnModalBody) {
            copyVulnDetailsBtn.addEventListener('click', () => {
                const text = vulnModalBody.innerText;
                navigator.clipboard.writeText(text).then(() => {
                    VulnScanner.showAlert('Vulnerability details copied to clipboard', 'success');
                });
            });
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!targetInput) return;

            const url = targetInput.value.trim();
            if (!url) {
                VulnScanner.showAlert('Please enter a target URL', 'warning');
                return;
            }

            resetUI();
            scanActive = true;
            setButtons(true);

            if (timerContainer) timerContainer.style.display = 'block';
            if (progressCard) progressCard.style.display = 'block';
            if (logCard) logCard.style.display = 'block';
            if (noResults) noResults.style.display = 'none';

            VulnScanner.showLoading(true, 'Running SQL injection scan...');
            addLog('info', `Starting SQL injection scan on ${url}`);

            startTime = Date.now();
            timerInterval = setInterval(updateTimer, 1000);
            updateProgress(10, 'Initializing...');

            const selectedMethod = methodSelect ? methodSelect.value : 'GET';

            // Techniques and options are not currently exposed directly in the backend API.
            // They can be later passed via "params" if you extend the server.
            const payload = {
                url: url,
                method: selectedMethod,
                params: {}
            };

            try {
                const data = await VulnScanner.apiRequest(apiSqliScan, 'POST', payload);

                scanActive = false;
                VulnScanner.showLoading(false);
                setButtons(false);
                updateProgress(100, 'Completed');

                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }

                if (!data || data.error) {
                    VulnScanner.showAlert('SQLi scan failed: ' + (data.error || 'Unknown error'), 'danger');
                    addLog('error', data.error || 'Scan failed');
                    return;
                }

                scanResults = data;
                if (resultsContainer) resultsContainer.style.display = 'block';
                if (resultActions) resultActions.style.display = 'flex';

                setRisk(data.risk_score || 0, data.severity_summary || {});
                renderVulns(data.vulnerabilities || []);
                renderParams(data);
                attachVulnHandlers();

            } catch (err) {
                scanActive = false;
                VulnScanner.showLoading(false);
                setButtons(false);
                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }
                VulnScanner.showAlert('SQLi scan failed: ' + err.message, 'danger');
                addLog('error', err.message);
            }
        });

        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                if (!scanActive) return;
                VulnScanner.showAlert('Stop requested. Current request will finish.', 'info');
                scanActive = false;
                setButtons(false);
            });
        }
    });
})();