// scanner_full.js
// Logic for /scanner/full-scan page

(function () {
    'use strict';

    const apiFullScan = '/scanner/api/full-scan';

    let scanActive = false;
    let scanId = null;
    let scanResults = null;
    let timerInterval = null;
    let startTime = null;

    const socket = (window.VulnScanner && VulnScanner.socket) || null; // optional

    // Elements
    const form = document.getElementById('fullScanForm');
    if (!form) return; // page not loaded

    const targetInput = document.getElementById('fullScanTarget');
    const profileSelect = document.getElementById('fullScanProfile');
    const customModulesContainer = document.getElementById('fullScanCustomModules');
    const crawlDepthRange = document.getElementById('fullScanCrawlDepth');
    const crawlDepthValue = document.getElementById('fullScanCrawlDepthValue');
    const followRedirectsChk = document.getElementById('fullScanFollowRedirects');
    const respectRobotsChk = document.getElementById('fullScanRespectRobots');

    const startBtn = document.getElementById('fullScanStartBtn');
    const stopBtn = document.getElementById('fullScanStopBtn');

    const timerContainer = document.getElementById('fullScanTimer');
    const timerDisplay = document.getElementById('fullScanTimerDisplay');

    const stagesCard = document.getElementById('fullScanStagesCard');
    const stagesContainer = document.getElementById('fullScanStages');
    const progressBar = document.getElementById('fullScanProgressBar');
    const currentStageText = document.getElementById('fullScanCurrentStageText');
    const progressText = document.getElementById('fullScanProgressText');

    const logCard = document.getElementById('fullScanLogCard');
    const logContainer = document.getElementById('fullScanLog');
    const clearLogBtn = document.getElementById('fullScanClearLogBtn');

    const noResults = document.getElementById('fullScanNoResults');
    const resultsContainer = document.getElementById('fullScanResultsContainer');
    const resultActions = document.getElementById('fullScanResultActions');

    const riskMeterFill = document.getElementById('fullScanRiskMeterFill');
    const riskScoreEl = document.getElementById('fullScanRiskScore');
    const riskLevelEl = document.getElementById('fullScanRiskLevel');

    const critCountEl = document.getElementById('fullScanCriticalCount');
    const highCountEl = document.getElementById('fullScanHighCount');
    const medCountEl = document.getElementById('fullScanMediumCount');
    const lowCountEl = document.getElementById('fullScanLowCount');
    const infoCountEl = document.getElementById('fullScanInfoCount');
    const vulnsBadge = document.getElementById('fullScanVulnsBadge');

    const vulnsList = document.getElementById('fullScanVulnsList');
    const portsList = document.getElementById('fullScanPortsList');
    const techList = document.getElementById('fullScanTechList');
    const crawlList = document.getElementById('fullScanCrawlList');

    const vulnFilterGroup = document.getElementById('fullScanVulnFilter');

    const downloadJsonBtn = document.getElementById('fullScanDownloadJson');
    const downloadPdfBtn = document.getElementById('fullScanDownloadPdf');
    const viewReportBtn = document.getElementById('fullScanViewReport');

    const vulnModal = document.getElementById('fullScanVulnModal');
    const vulnModalTitle = document.getElementById('fullScanVulnModalTitle');
    const vulnModalBody = document.getElementById('fullScanVulnModalBody');
    const copyVulnDetailsBtn = document.getElementById('fullScanCopyVulnDetails');

    // Helpers
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

    function resetUI() {
        scanActive = false;
        scanId = null;
        scanResults = null;

        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }

        if (timerContainer) timerContainer.style.display = 'none';
        if (stagesCard) stagesCard.style.display = 'none';
        if (logCard) logCard.style.display = 'none';

        if (progressBar) progressBar.style.width = '0%';
        if (progressText) progressText.textContent = '0%';
        if (currentStageText) currentStageText.textContent = 'Waiting to start...';

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
        if (portsList) portsList.innerHTML = '';
        if (techList) techList.innerHTML = '';
        if (crawlList) crawlList.innerHTML = '';
    }

    function setScanButtonsState(running) {
        if (startBtn) startBtn.disabled = running;
        if (stopBtn) stopBtn.disabled = !running;
    }

    function updateProgress(percent, message) {
        if (progressBar) progressBar.style.width = `${percent}%`;
        if (progressText) progressText.textContent = `${percent}%`;
        if (currentStageText && message) currentStageText.textContent = message;
    }

    function setRisk(riskScore, severitySummary) {
        if (riskScoreEl) riskScoreEl.textContent = String(riskScore);
        if (riskMeterFill) riskMeterFill.style.width = `${riskScore}%`;

        let level = 'Low';
        let badgeClass = 'badge bg-success';

        if (riskScore >= 75) {
            level = 'Critical';
            badgeClass = 'badge bg-danger';
        } else if (riskScore >= 50) {
            level = 'High';
            badgeClass = 'badge bg-warning';
        } else if (riskScore >= 25) {
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

    function renderVulnerabilities(vulns) {
        if (!vulnsList) return;
        if (!vulns || vulns.length === 0) {
            vulnsList.innerHTML = '';
            const empty = document.createElement('div');
            empty.className = 'text-muted text-center py-4';
            empty.innerHTML = '<i class="bi bi-check-circle display-6 d-block mb-2"></i>No vulnerabilities found.';
            vulnsList.appendChild(empty);
            return;
        }

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
    ${v.confidence ? `<span class="badge bg-secondary">Confidence: ${v.confidence}</span>` : ''}
  </div>
  <div class="mt-2">
    <button type="button" class="btn btn-sm btn-outline-primary fullscan-vuln-details" data-index="${idx}">
      <i class="bi bi-info-circle me-1"></i>Details
    </button>
  </div>
</div>`;
        }).join('');
    }

    function renderPorts(openPorts) {
        if (!portsList) return;
        if (!openPorts || openPorts.length === 0) {
            portsList.innerHTML = '<tr><td colspan="5" class="text-muted text-center">No open ports found.</td></tr>';
            return;
        }
        portsList.innerHTML = openPorts.map(p => {
            const risk = (p.risk_level || 'low').toLowerCase();
            const riskBadge = risk === 'high' ? 'danger' : risk === 'medium' ? 'warning' : 'success';
            return `
<tr>
  <td><strong>${p.port}</strong></td>
  <td><span class="badge bg-success">${p.state || 'open'}</span></td>
  <td>${p.service || '-'}</td>
  <td>${p.version || '-'}</td>
  <td><span class="badge bg-${riskBadge}">${(p.risk_level || 'low').toUpperCase()}</span></td>
</tr>`;
        }).join('');
    }

    function renderTechnologies(techs) {
        if (!techList) return;
        if (!techs || techs.length === 0) {
            techList.innerHTML = '<div class="text-muted">No technologies detected.</div>';
            return;
        }
        techList.innerHTML = `
<div class="d-flex flex-wrap gap-2">
${techs.map(t => {
    const label = t.version ? `${t.name} ${t.version}` : t.name;
    return `<span class="badge bg-primary p-2">${label}</span>`;
}).join('')}
</div>`;
    }

    function renderCrawledUrls(urls, forms) {
        if (!crawlList) return;
        if (!urls || urls.length === 0) {
            crawlList.innerHTML = '<tr><td colspan="3" class="text-muted text-center">No crawled URLs recorded.</td></tr>';
            return;
        }
        crawlList.innerHTML = urls.slice(0, 200).map(url => {
            const formCount = forms ? forms.filter(f => f.url === url).length : 0;
            return `
<tr>
  <td><a href="${url}" class="text-truncate d-inline-block" style="max-width: 400px;" target="_blank">${url}</a></td>
  <td><span class="badge bg-success">200</span></td>
  <td>${formCount > 0 ? `<span class="badge bg-info">${formCount} forms</span>` : '-'}</td>
</tr>`;
        }).join('');
    }

    function getSelectedModules() {
        if (!customModulesContainer) return [];
        const inputs = customModulesContainer.querySelectorAll('input[name="modules"]:checked');
        return Array.from(inputs).map(i => i.value);
    }

    function attachVulnClickHandlers() {
        if (!vulnsList) return;
        vulnsList.querySelectorAll('.fullscan-vuln-details').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = parseInt(btn.getAttribute('data-index'), 10);
                showVulnModal(idx);
            });
        });
    }

    function showVulnModal(index) {
        if (!scanResults || !scanResults.all_vulnerabilities) return;
        const vuln = scanResults.all_vulnerabilities[index];
        if (!vuln) return;

        if (vulnModalTitle) {
            vulnModalTitle.textContent = vuln.name || vuln.type || 'Vulnerability Details';
        }

        if (vulnModalBody) {
            const sev = (vuln.severity || 'info').toUpperCase();
            vulnModalBody.innerHTML = `
<table class="table table-sm">
  <tr><th style="width: 25%;">Severity</th><td>${sev}</td></tr>
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

    function filterVulns(filter) {
        if (!vulnsList) return;
        const cards = vulnsList.querySelectorAll('.vuln-card');
        cards.forEach(card => {
            const sev = card.getAttribute('data-severity');
            if (filter === 'all' || filter === sev) {
                card.style.display = '';
            } else {
                card.style.display = 'none';
            }
        });
    }

    // Event handlers
    document.addEventListener('DOMContentLoaded', () => {
        resetUI();

        if (profileSelect && customModulesContainer) {
            profileSelect.addEventListener('change', () => {
                customModulesContainer.style.display =
                    profileSelect.value === 'custom' ? 'block' : 'none';
            });
        }

        if (crawlDepthRange && crawlDepthValue) {
            crawlDepthRange.addEventListener('input', () => {
                crawlDepthValue.textContent = crawlDepthRange.value;
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
                VulnScanner.downloadJSON(scanResults, `full_scan_${scanId || 'report'}.json`);
            });
        }

        if (downloadPdfBtn) {
            downloadPdfBtn.addEventListener('click', async () => {
                if (!scanId) {
                    VulnScanner.showAlert('No scan ID available for PDF export', 'warning');
                    return;
                }
                try {
                    const res = await fetch(`/api/export/pdf/${scanId}`);
                    if (!res.ok) {
                        VulnScanner.showAlert('PDF export not available yet', 'info');
                        return;
                    }
                    const blob = await res.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `scan_report_${scanId}.pdf`;
                    a.click();
                    URL.revokeObjectURL(url);
                } catch (e) {
                    VulnScanner.showAlert('PDF export failed: ' + e.message, 'danger');
                }
            });
        }

        if (viewReportBtn) {
            viewReportBtn.addEventListener('click', () => {
                if (!scanId) {
                    VulnScanner.showAlert('No scan ID available', 'warning');
                    return;
                }
                window.location.href = `/scanner/results/${encodeURIComponent(scanId)}`;
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

            const target = targetInput.value.trim();
            if (!target) {
                VulnScanner.showAlert('Please enter a target URL', 'warning');
                return;
            }

            resetUI();

            const options = {
                profile: profileSelect ? profileSelect.value : 'full',
                crawl_depth: crawlDepthRange ? parseInt(crawlDepthRange.value, 10) : 2,
                follow_redirects: followRedirectsChk ? followRedirectsChk.checked : true,
                respect_robots: respectRobotsChk ? respectRobotsChk.checked : true
            };

            if (options.profile === 'custom') {
                options.modules = getSelectedModules();
            }

            scanActive = true;
            setScanButtonsState(true);
            if (timerContainer) timerContainer.style.display = 'block';
            if (stagesCard) stagesCard.style.display = 'block';
            if (logCard) logCard.style.display = 'block';
            if (noResults) noResults.style.display = 'none';
            if (resultsContainer) resultsContainer.style.display = 'none';
            if (resultActions) resultActions.style.display = 'none';

            VulnScanner.showLoading(true, 'Running full vulnerability scan...');
            addLog('info', `Starting full scan on ${target}`);

            startTime = Date.now();
            timerInterval = setInterval(updateTimer, 1000);
            updateProgress(5, 'Initializing scan...');

            try {
                const data = await VulnScanner.apiRequest(apiFullScan, 'POST', {
                    target: target,
                    options: options
                });

                scanActive = false;
                VulnScanner.showLoading(false);
                setScanButtonsState(false);
                updateProgress(100, 'Scan complete');

                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }

                if (!data || data.error) {
                    VulnScanner.showAlert('Scan failed: ' + (data.error || 'Unknown error'), 'danger');
                    addLog('error', data.error || 'Scan failed');
                    return;
                }

                scanId = data.scan_id || null;
                scanResults = data;

                addLog('success', 'Scan completed successfully');
                if (resultsContainer) resultsContainer.style.display = 'block';
                if (resultActions) resultActions.style.display = 'flex';

                setRisk(data.risk_score || 0, data.severity_summary || {});
                renderVulnerabilities(data.all_vulnerabilities || []);
                renderPorts(data.port_scan && data.port_scan.open_ports ? data.port_scan.open_ports : []);
                renderTechnologies(data.tech_detection && data.tech_detection.technologies ? data.tech_detection.technologies : []);
                renderCrawledUrls(
                    data.crawl && data.crawl.urls ? data.crawl.urls : [],
                    data.crawl && data.crawl.forms ? data.crawl.forms : []
                );

                attachVulnClickHandlers();

            } catch (err) {
                scanActive = false;
                VulnScanner.showLoading(false);
                setScanButtonsState(false);
                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }
                VulnScanner.showAlert('Scan failed: ' + err.message, 'danger');
                addLog('error', err.message);
            }
        });

        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                // HTTP-based scan cannot be truly "stopped" mid-request here.
                // We just update UI and rely on server timeout if needed.
                if (!scanActive) return;
                VulnScanner.showAlert('Stop requested. The current request will complete, but further actions are halted.', 'info');
                scanActive = false;
                setScanButtonsState(false);
            });
        }
    });
})();