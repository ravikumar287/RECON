// scanner_dir.js
// Logic for /scanner/dir-scan page

(function () {
    'use strict';

    const apiDirScan = '/scanner/api/dir-scan';

    let scanActive = false;
    let scanResults = null;
    let timerInterval = null;
    let startTime = null;

    const form = document.getElementById('dirScanForm');
    if (!form) return;

    const targetInput = document.getElementById('dirTarget');
    const wordlistSelect = document.getElementById('dirWordlist');
    const customWordlistContainer = document.getElementById('dirCustomWordlistContainer');
    const customWordlistInput = document.getElementById('dirCustomWordlist');
    const extensionsInput = document.getElementById('dirExtensions');
    const recursiveChk = document.getElementById('dirRecursive');
    const sensitiveChk = document.getElementById('dirSensitive');

    const startBtn = document.getElementById('dirStartBtn');
    const stopBtn = document.getElementById('dirStopBtn');

    const timerContainer = document.getElementById('dirScanTimer');
    const timerDisplay = document.getElementById('dirScanTimerDisplay');

    const logCard = document.getElementById('dirLogCard');
    const logContainer = document.getElementById('dirLog');
    const clearLogBtn = document.getElementById('dirClearLogBtn');

    const progressCard = document.getElementById('dirProgressCard');
    const progressBar = document.getElementById('dirProgressBar');
    const progressText = document.getElementById('dirProgressText');
    const currentStatus = document.getElementById('dirCurrentStatus');

    const noResults = document.getElementById('dirNoResults');
    const resultsContainer = document.getElementById('dirResultsContainer');
    const resultActions = document.getElementById('dirResultActions');

    const critCountEl = document.getElementById('dirCriticalCount');
    const highCountEl = document.getElementById('dirHighCount');
    const medCountEl = document.getElementById('dirMediumCount');
    const lowCountEl = document.getElementById('dirLowCount');

    const totalReqEl = document.getElementById('dirTotalRequests');
    const totalFoundEl = document.getElementById('dirTotalFound');
    const totalErrEl = document.getElementById('dirTotalErrors');

    const pathsList = document.getElementById('dirPathsList');
    const filterGroup = document.getElementById('dirFilter');

    const downloadListBtn = document.getElementById('dirDownloadList');

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

        [critCountEl, highCountEl, medCountEl, lowCountEl].forEach(el => {
            if (el) el.textContent = '0';
        });

        [totalReqEl, totalFoundEl, totalErrEl].forEach(el => {
            if (el) el.textContent = '0';
        });

        if (pathsList) pathsList.innerHTML = '';
    }

    function updateProgress(percent, statusText) {
        if (progressBar) progressBar.style.width = `${percent}%`;
        if (progressText) progressText.textContent = `${percent}%`;
        if (currentStatus && statusText) currentStatus.textContent = statusText;
    }

    function renderPaths(foundPaths) {
        if (!pathsList) return;
        if (!foundPaths || foundPaths.length === 0) {
            pathsList.innerHTML = '<tr><td colspan="5" class="text-muted text-center">No paths discovered.</td></tr>';
            return;
        }

        pathsList.innerHTML = foundPaths.map(p => {
            const sev = (p.severity || 'low').toLowerCase();
            const sevBadge = {
                critical: 'danger',
                high: 'warning',
                medium: 'info',
                low: 'success'
            }[sev] || 'secondary';

            return `
<tr class="dir-row" data-severity="${sev}">
  <td><a href="${p.url}" target="_blank">${p.path}</a></td>
  <td><span class="badge bg-${p.status_code >= 400 ? 'danger' : 'success'}">${p.status_code}</span></td>
  <td>${p.content_length || 0}</td>
  <td><span class="badge bg-${sevBadge}">${sev.toUpperCase()}</span></td>
  <td>${p.type || 'directory'}</td>
</tr>`;
        }).join('');
    }

    function applySeveritySummary(severitySummary) {
        if (!severitySummary) return;
        if (critCountEl) critCountEl.textContent = severitySummary.critical || 0;
        if (highCountEl) highCountEl.textContent = severitySummary.high || 0;
        if (medCountEl) medCountEl.textContent = severitySummary.medium || 0;
        if (lowCountEl) lowCountEl.textContent = severitySummary.low || 0;
    }

    function applyStatistics(stats) {
        if (!stats) return;
        if (totalReqEl) totalReqEl.textContent = stats.total_requests || 0;
        if (totalFoundEl) totalFoundEl.textContent = stats.found || 0;
        if (totalErrEl) totalErrEl.textContent = stats.errors || 0;
    }

    function filterPaths(filter) {
        if (!pathsList) return;
        const rows = pathsList.querySelectorAll('.dir-row');
        rows.forEach(row => {
            const sev = row.getAttribute('data-severity');
            row.style.display = (filter === 'all' || filter === sev) ? '' : 'none';
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        resetUI();

        if (wordlistSelect && customWordlistContainer) {
            wordlistSelect.addEventListener('change', () => {
                customWordlistContainer.style.display =
                    wordlistSelect.value === 'custom' ? 'block' : 'none';
            });
        }

        if (clearLogBtn && logContainer) {
            clearLogBtn.addEventListener('click', () => {
                logContainer.innerHTML = '';
            });
        }

        if (filterGroup) {
            filterGroup.querySelectorAll('button[data-filter]').forEach(btn => {
                btn.addEventListener('click', () => {
                    filterGroup.querySelectorAll('button[data-filter]')
                        .forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    filterPaths(btn.getAttribute('data-filter'));
                });
            });
        }

        if (downloadListBtn) {
            downloadListBtn.addEventListener('click', () => {
                if (!scanResults || !scanResults.found_paths) {
                    VulnScanner.showAlert('No results to export', 'warning');
                    return;
                }
                const lines = scanResults.found_paths.map(p => p.url || p.path);
                const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'dirs_found.txt';
                a.click();
                URL.revokeObjectURL(url);
            });
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!targetInput) return;

            const url = targetInput.value.trim();
            if (!url) {
                VulnScanner.showAlert('Please enter a base URL', 'warning');
                return;
            }

            resetUI();
            scanActive = true;
            setButtons(true);

            if (timerContainer) timerContainer.style.display = 'block';
            if (logCard) logCard.style.display = 'block';
            if (progressCard) progressCard.style.display = 'block';
            if (noResults) noResults.style.display = 'none';

            VulnScanner.showLoading(true, 'Running directory bruteforce scan...');
            addLog('info', `Starting directory scan on ${url}`);

            startTime = Date.now();
            timerInterval = setInterval(updateTimer, 1000);
            updateProgress(10, 'Initializing...');

            const wordlist = wordlistSelect ? wordlistSelect.value : 'default';
            const exts = extensionsInput && extensionsInput.value.trim()
                ? extensionsInput.value.split(',').map(s => s.trim()).filter(Boolean)
                : [];

            const payload = {
                url: url,
                wordlist: wordlist,
                extensions: exts
                // recursive and sensitive options could be added if you extend the backend
            };

            try {
                const data = await VulnScanner.apiRequest(apiDirScan, 'POST', payload);

                scanActive = false;
                VulnScanner.showLoading(false);
                setButtons(false);
                updateProgress(100, 'Completed');

                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }

                if (!data || data.error) {
                    VulnScanner.showAlert('Directory scan failed: ' + (data.error || 'Unknown error'), 'danger');
                    addLog('error', data.error || 'Scan failed');
                    return;
                }

                scanResults = data;
                if (resultsContainer) resultsContainer.style.display = 'block';
                if (resultActions) resultActions.style.display = 'flex';

                renderPaths(data.found_paths || []);
                applySeveritySummary(data.severity_summary || {});
                applyStatistics(data.statistics || {});

            } catch (err) {
                scanActive = false;
                VulnScanner.showLoading(false);
                setButtons(false);
                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }
                VulnScanner.showAlert('Directory scan failed: ' + err.message, 'danger');
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