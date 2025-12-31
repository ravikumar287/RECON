// scanner_xss.js
// Logic for /scanner/xss-scan page

(function () {
    'use strict';

    const apiXssScan = '/scanner/api/xss-scan';

    let scanActive = false;
    let scanResults = null;
    let timerInterval = null;
    let startTime = null;

    const form = document.getElementById('xssScanForm');
    if (!form) return;

    const targetInput = document.getElementById('xssTarget');
    const crawlChk = document.getElementById('xssCrawl');
    const crawlDepthRange = document.getElementById('xssCrawlDepth');
    const crawlDepthValue = document.getElementById('xssCrawlDepthValue');
    const payloadProfile = document.getElementById('xssPayloadProfile');
    const customPayloadsContainer = document.getElementById('xssCustomPayloadsContainer');
    const customPayloadsInput = document.getElementById('xssCustomPayloads');
    const testFormsChk = document.getElementById('xssTestForms');
    const testGetChk = document.getElementById('xssTestGetParams');

    const startBtn = document.getElementById('xssStartBtn');
    const stopBtn = document.getElementById('xssStopBtn');

    const timerContainer = document.getElementById('xssScanTimer');
    const timerDisplay = document.getElementById('xssScanTimerDisplay');

    const logCard = document.getElementById('xssLogCard');
    const logContainer = document.getElementById('xssLog');
    const clearLogBtn = document.getElementById('xssClearLogBtn');

    const progressCard = document.getElementById('xssProgressCard');
    const progressBar = document.getElementById('xssProgressBar');
    const progressText = document.getElementById('xssProgressText');
    const currentStatus = document.getElementById('xssCurrentStatus');

    const noResults = document.getElementById('xssNoResults');
    const resultsContainer = document.getElementById('xssResultsContainer');
    const resultActions = document.getElementById('xssResultActions');

    const riskMeterFill = document.getElementById('xssRiskMeterFill');
    const riskScoreEl = document.getElementById('xssRiskScore');
    const riskLevelEl = document.getElementById('xssRiskLevel');

    const critCountEl = document.getElementById('xssCriticalCount');
    const highCountEl = document.getElementById('xssHighCount');
    const medCountEl = document.getElementById('xssMediumCount');
    const lowCountEl = document.getElementById('xssLowCount');
    const infoCountEl = document.getElementById('xssInfoCount');
    const vulnsBadge = document.getElementById('xssVulnsBadge');

    const vulnsList = document.getElementById('xssVulnsList');
    const payloadsList = document.getElementById('xssPayloadsList');

    const vulnFilterGroup = document.getElementById('xssVulnFilter');

    const downloadJsonBtn = document.getElementById('xssDownloadJson');
    const downloadReportBtn = document.getElementById('xssDownloadReport');

    const vulnModal = document.getElementById('xssVulnModal');
    const vulnModalTitle = document.getElementById('xssVulnModalTitle');
    const vulnModalBody = document.getElementById('xssVulnModalBody');
    const copyVulnDetailsBtn = document.getElementById('xssCopyVulnDetails');

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
        if (progressCard) progressCard.style.display = 'none';
        if (logCard) logCard.style.display = 'none';

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
        if (payloadsList) payloadsList.innerHTML = '';
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
            empty.innerHTML = '<i class="bi bi-check-circle display-6 d-block mb-2"></i>No XSS vulnerabilities found.';
            vulnsList.appendChild(empty);
            return;
        }

        vulnsList.innerHTML = vulns.map((v, idx) => {
            const sev = (v.severity || 'medium').toLowerCase();
            const sevBadge = {
                critical: 'danger',
                high: 'warning',
                medium: 'info',
                low: 'success',
                info: 'secondary'
            }[sev] || 'info';

            return `
<div class="vuln-card ${sev}" data-index="${idx}" data-severity="${sev}">
  <div class="vuln-header">
    <div>
      <h6 class="vuln-title">${v.name || v.type || 'XSS Vulnerability'}</h6>
      <div class="vuln-detail">${v.url ? `<code>${v.url}</code>` : ''}</div>
    </div>
    <span class="badge bg-${sevBadge}">${(v.severity || '').toUpperCase()}</span>
  </div>
  <div class="vuln-meta mt-1">
    ${v.parameter ? `<span class="badge bg-secondary">Param: ${v.parameter}</span>` : ''}
    ${v.context ? `<span class="badge bg-secondary">${v.context}</span>` : ''}
  </div>
  <div class="mt-2">
    <button type="button" class="btn btn-sm btn-outline-primary xss-vuln-details" data-index="${idx}">
      <i class="bi bi-info-circle me-1"></i>Details
    </button>
  </div>
</div>`;
        }).join('');
    }

    function renderPayloads(data) {
        if (!payloadsList) return;
        // The backend XSSScanner does not currently return per-payload info list explicitly.
        // If you extend it to include such info (e.g. data.payloads), you can render it here.
        payloadsList.innerHTML = '<tr><td colspan="3" class="text-muted text-center">Payload details not available.</td></tr>';
    }

    function attachVulnHandlers() {
        if (!vulnsList) return;
        vulnsList.querySelectorAll('.xss-vuln-details').forEach(btn => {
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
            vulnModalTitle.textContent = vuln.name || vuln.type || 'XSS Vulnerability';
        }

        if (vulnModalBody) {
            vulnModalBody.innerHTML = `
<table class="table table-sm">
  <tr><th style="width: 25%;">Severity</th><td>${(vuln.severity || 'medium').toUpperCase()}</td></tr>
  <tr><th>Type</th><td>${vuln.type || '-'}</td></tr>
  <tr><th>URL</th><td>${vuln.url ? `<code>${vuln.url}</code>` : '-'}</td></tr>
  ${vuln.parameter ? `<tr><th>Parameter</th><td><code>${vuln.parameter}</code></td></tr>` : ''}
  ${vuln.context ? `<tr><th>Context</th><td>${vuln.context}</td></tr>` : ''}
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

        if (crawlChk && crawlDepthRange && crawlDepthValue) {
            crawlChk.addEventListener('change', () => {
                const enabled = crawlChk.checked;
                crawlDepthRange.disabled = !enabled;
            });
            crawlDepthRange.addEventListener('input', () => {
                crawlDepthValue.textContent = crawlDepthRange.value;
            });
        }

        if (payloadProfile && customPayloadsContainer) {
            payloadProfile.addEventListener('change', () => {
                customPayloadsContainer.style.display =
                    payloadProfile.value === 'custom' ? 'block' : 'none';
            });
        }

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
                VulnScanner.downloadJSON(scanResults, 'xss_scan_report.json');
            });
        }

        if (downloadReportBtn) {
            downloadReportBtn.addEventListener('click', () => {
                VulnScanner.showAlert('Standalone XSS report export not implemented yet.', 'info');
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

            VulnScanner.showLoading(true, 'Running XSS scan...');
            addLog('info', `Starting XSS scan on ${url}`);

            startTime = Date.now();
            timerInterval = setInterval(updateTimer, 1000);
            updateProgress(10, 'Initializing...');

            const payload = {
                url: url,
                crawl: crawlChk ? crawlChk.checked : false,
                depth: crawlDepthRange && !crawlDepthRange.disabled ? parseInt(crawlDepthRange.value, 10) : 2
            };

            try {
                const data = await VulnScanner.apiRequest(apiXssScan, 'POST', payload);

                scanActive = false;
                VulnScanner.showLoading(false);
                setButtons(false);
                updateProgress(100, 'Completed');

                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }

                if (!data || data.error) {
                    VulnScanner.showAlert('XSS scan failed: ' + (data.error || 'Unknown error'), 'danger');
                    addLog('error', data.error || 'Scan failed');
                    return;
                }

                scanResults = data;
                if (resultsContainer) resultsContainer.style.display = 'block';
                if (resultActions) resultActions.style.display = 'flex';

                setRisk(data.risk_score || 0, data.severity_summary || {});
                renderVulns(data.vulnerabilities || []);
                renderPayloads(data);
                attachVulnHandlers();

            } catch (err) {
                scanActive = false;
                VulnScanner.showLoading(false);
                setButtons(false);
                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }
                VulnScanner.showAlert('XSS scan failed: ' + err.message, 'danger');
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