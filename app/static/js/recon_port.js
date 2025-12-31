// recon_port.js
// Logic for /recon/port-scan page

(function () {
    'use strict';

    const apiUrl = '/recon/api/port-scan';

    const form = document.getElementById('portScanForm');
    if (!form) return;

    const targetInput = document.getElementById('target');
    const portRangeSelect = document.getElementById('portRange');
    const customPortsContainer = document.getElementById('customPortsContainer');
    const customPortsInput = document.getElementById('customPorts');
    const scanTypeSelect = document.getElementById('scanType');
    const timeoutInput = document.getElementById('timeout');

    const startBtn = document.getElementById('startScan');
    const stopBtn = document.getElementById('stopScan');

    const scanProgress = document.getElementById('scanProgress');
    const progressText = document.getElementById('progressText');
    const progressBar = document.getElementById('progressBar');
    const currentPortText = document.getElementById('currentPort');

    const resultsSummary = document.getElementById('resultsSummary');
    const openPortsCount = document.getElementById('openPortsCount');
    const closedPortsCount = document.getElementById('closedPortsCount');
    const filteredPortsCount = document.getElementById('filteredPortsCount');
    const scanDuration = document.getElementById('scanDuration');

    const resultsContainer = document.getElementById('resultsContainer');
    const noResults = document.getElementById('noResults');
    const resultsTable = document.getElementById('resultsTable');
    const scanResultsBody = document.getElementById('scanResults');

    const exportJsonBtn = document.getElementById('exportJson');
    const exportCsvBtn = document.getElementById('exportCsv');

    let lastResult = null;
    let scanActive = false;

    function setButtons(running) {
        if (startBtn) startBtn.disabled = running;
        if (stopBtn) stopBtn.disabled = !running;
    }

    function resetUI() {
        lastResult = null;
        scanActive = false;

        if (scanProgress) scanProgress.style.display = 'none';
        if (resultsSummary) resultsSummary.style.display = 'none';

        if (progressBar) progressBar.style.width = '0%';
        if (progressText) progressText.textContent = '0%';
        if (currentPortText) currentPortText.textContent = 'Idle';

        if (openPortsCount) openPortsCount.textContent = '0';
        if (closedPortsCount) closedPortsCount.textContent = '0';
        if (filteredPortsCount) filteredPortsCount.textContent = '0';
        if (scanDuration) scanDuration.textContent = '0s';

        if (resultsContainer) resultsContainer.style.display = 'block';
        if (noResults) noResults.style.display = 'block';
        if (resultsTable) resultsTable.style.display = 'none';
        if (scanResultsBody) scanResultsBody.innerHTML = '';

        if (exportJsonBtn) exportJsonBtn.disabled = true;
        if (exportCsvBtn) exportCsvBtn.disabled = true;
    }

    function updateProgress(percent, message) {
        if (scanProgress) scanProgress.style.display = 'block';
        if (progressBar) progressBar.style.width = `${percent}%`;
        if (progressText) progressText.textContent = `${percent}%`;
        if (currentPortText && message) currentPortText.textContent = message;
    }

    function parsePortSpec() {
        const val = portRangeSelect ? portRangeSelect.value : 'common';
        if (val === 'custom' && customPortsInput && customPortsInput.value.trim()) {
            return customPortsInput.value.trim();
        }
        if (val === 'quick') return '1-1024';
        if (val === '1-1000') return '1-1000';
        if (val === '1-10000') return '1-10000';
        if (val === '1-65535') return '1-65535';
        // "common" or default
        return '21,22,23,25,53,80,110,143,443,445,3389,8080,8443';
    }

    function renderResults(data) {
        if (!resultsSummary || !scanResultsBody) return;

        const openPorts = data.open_ports || [];
        const filtered = data.filtered_ports || 0;
        const scanned = data.ports_scanned || 0;
        const openCount = openPorts.length;
        const closedCount = scanned > 0 ? Math.max(scanned - openCount - filtered, 0) : 0;

        if (noResults) noResults.style.display = 'none';
        if (resultsTable) resultsTable.style.display = 'block';
        if (resultsSummary) resultsSummary.style.display = 'block';

        if (openPortsCount) openPortsCount.textContent = String(openCount);
        if (filteredPortsCount) filteredPortsCount.textContent = String(filtered);
        if (closedPortsCount) closedPortsCount.textContent = String(closedCount);
        if (scanDuration) scanDuration.textContent = `${(data.duration || 0).toFixed ? data.duration.toFixed(1) : data.duration}s`;

        scanResultsBody.innerHTML = openPorts.map(p => {
            const risk = (p.risk_level || 'low').toLowerCase();
            const riskBadge = risk === 'high' ? 'danger' : risk === 'medium' ? 'warning' : 'success';
            return `
<tr>
  <td>${p.port}</td>
  <td><span class="badge bg-success">Open</span></td>
  <td>${p.service || 'Unknown'}</td>
  <td>${p.version || '-'}</td>
  <td><span class="badge bg-${riskBadge}">${(p.risk_level || 'LOW').toUpperCase()}</span></td>
</tr>`;
        }).join('');

        if (exportJsonBtn) exportJsonBtn.disabled = false;
        if (exportCsvBtn) exportCsvBtn.disabled = false;
    }

    function exportCsv() {
        if (!lastResult || !lastResult.open_ports) {
            VulnScanner.showAlert('No results to export', 'warning');
            return;
        }
        const rows = [['port', 'state', 'service', 'version', 'risk_level']];
        lastResult.open_ports.forEach(p => {
            rows.push([
                p.port,
                p.state || 'open',
                p.service || '',
                p.version || '',
                p.risk_level || ''
            ]);
        });
        const csv = rows.map(r => r.join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'port_scan_results.csv';
        a.click();
        URL.revokeObjectURL(url);
    }

    document.addEventListener('DOMContentLoaded', () => {
        resetUI();
        setButtons(false);

        if (portRangeSelect && customPortsContainer) {
            portRangeSelect.addEventListener('change', () => {
                customPortsContainer.style.display =
                    portRangeSelect.value === 'custom' ? 'block' : 'none';
            });
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const target = targetInput ? targetInput.value.trim() : '';
            if (!target) {
                VulnScanner.showAlert('Please enter a target (domain or IP)', 'warning');
                return;
            }

            resetUI();
            setButtons(true);
            scanActive = true;

            VulnScanner.showLoading(true, 'Running port scan...');
            updateProgress(10, 'Sending request...');

            const payload = {
                target: target,
                ports: parsePortSpec(),
                scan_type: scanTypeSelect ? scanTypeSelect.value : 'tcp'
            };

            try {
                const data = await VulnScanner.apiRequest(apiUrl, 'POST', payload);
                scanActive = false;
                setButtons(false);
                VulnScanner.showLoading(false);
                updateProgress(100, 'Completed');

                if (!data || data.error) {
                    VulnScanner.showAlert('Port scan failed: ' + (data.error || 'Unknown error'), 'danger');
                    return;
                }

                lastResult = data;
                renderResults(data);
            } catch (err) {
                scanActive = false;
                setButtons(false);
                VulnScanner.showLoading(false);
                VulnScanner.showAlert('Port scan failed: ' + err.message, 'danger');
            }
        });

        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                if (!scanActive) return;
                VulnScanner.showAlert('Stop requested. Current scan will finish this request.', 'info');
                scanActive = false;
                setButtons(false);
            });
        }

        if (exportJsonBtn) {
            exportJsonBtn.addEventListener('click', () => {
                if (!lastResult) {
                    VulnScanner.showAlert('No results to export', 'warning');
                    return;
                }
                VulnScanner.downloadJSON(lastResult, 'port_scan_results.json');
            });
        }

        if (exportCsvBtn) {
            exportCsvBtn.addEventListener('click', exportCsv);
        }
    });
})();