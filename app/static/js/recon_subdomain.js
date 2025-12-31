// recon_subdomain.js
// Logic for /recon/subdomain page (HTTP-based, non-realtime)

(function () {
    'use strict';

    const apiUrl = '/recon/api/subdomain';

    const form = document.getElementById('subdomainForm');
    if (!form) return;

    const domainInput = document.getElementById('domain');
    const wordlistSelect = document.getElementById('wordlist');
    const customWordlistContainer = document.getElementById('customWordlistContainer');
    const customWordlistInput = document.getElementById('customWordlist');
    const useCrtChk = document.getElementById('useCRT');
    const useRecursiveChk = document.getElementById('useRecursive');

    const startBtn = document.getElementById('startScan');
    const stopBtn = document.getElementById('stopScan');

    const scanProgress = document.getElementById('scanProgress');
    const progressText = document.getElementById('progressText');
    const progressBar = document.getElementById('progressBar');
    const currentStatus = document.getElementById('currentStatus');

    const statsCard = document.getElementById('statsCard');
    const statFound = document.getElementById('statFound');
    const statAlive = document.getElementById('statAlive');
    const statHttp = document.getElementById('statHttp');
    const statDuration = document.getElementById('statDuration');

    const wildcardWarning = document.getElementById('wildcardWarning');

    const noResults = document.getElementById('noResults');
    const resultsContainer = document.getElementById('resultsContainer');
    const subdomainResults = document.getElementById('subdomainResults');

    const filterAllBtn = document.getElementById('filterAll');
    const filterAliveBtn = document.getElementById('filterAlive');
    const exportBtn = document.getElementById('exportResults');

    let scanActive = false;
    let lastResult = null;

    function setButtons(running) {
        if (startBtn) startBtn.disabled = running;
        if (stopBtn) stopBtn.disabled = !running;
    }

    function resetUI() {
        scanActive = false;
        lastResult = null;

        if (scanProgress) scanProgress.style.display = 'none';
        if (statsCard) statsCard.style.display = 'none';
        if (wildcardWarning) wildcardWarning.style.display = 'none';

        if (progressBar) progressBar.style.width = '0%';
        if (progressText) progressText.textContent = '0%';
        if (currentStatus) currentStatus.textContent = 'Idle';

        if (statFound) statFound.textContent = '0';
        if (statAlive) statAlive.textContent = '0';
        if (statHttp) statHttp.textContent = '0';
        if (statDuration) statDuration.textContent = '0s';

        if (noResults) noResults.style.display = 'block';
        if (resultsContainer) resultsContainer.style.display = 'none';
        if (subdomainResults) subdomainResults.innerHTML = '';

        if (filterAllBtn) filterAllBtn.disabled = true;
        if (filterAliveBtn) filterAliveBtn.disabled = true;
        if (exportBtn) exportBtn.disabled = true;
    }

    function updateProgress(percent, message) {
        if (scanProgress) scanProgress.style.display = 'block';
        if (progressBar) progressBar.style.width = `${percent}%`;
        if (progressText) progressText.textContent = `${percent}%`;
        if (currentStatus && message) currentStatus.textContent = message;
    }

    function renderResults(data) {
        if (!subdomainResults) return;
        const subs = data.subdomains || [];

        if (noResults) noResults.style.display = 'none';
        if (resultsContainer) resultsContainer.style.display = 'block';
        if (statsCard) statsCard.style.display = 'block';

        subdomainResults.innerHTML = subs.map(s => {
            const alive = s.alive;
            const httpStatus = s.http_status || '-';
            return `
<tr data-alive="${alive ? '1' : '0'}">
  <td><a href="https://${s.full_domain}" target="_blank">${s.full_domain}</a></td>
  <td>${(s.ips || []).join(', ') || '-'}</td>
  <td>${alive ? '<span class="badge bg-success">Alive</span>' : '<span class="badge bg-secondary">Unknown</span>'}</td>
  <td>${httpStatus !== '-' ? `<span class="badge bg-info">${httpStatus}</span>` : '-'}</td>
  <td>
    <div class="btn-group btn-group-sm">
      <a href="https://${s.full_domain}" target="_blank" class="btn btn-outline-primary" title="Open">
        <i class="bi bi-box-arrow-up-right"></i>
      </a>
    </div>
  </td>
</tr>`;
        }).join('');

        const total = subs.length;
        const aliveCount = subs.filter(s => s.alive).length;
        const httpCount = subs.filter(s => s.http_status).length;

        if (statFound) statFound.textContent = String(total);
        if (statAlive) statAlive.textContent = String(aliveCount);
        if (statHttp) statHttp.textContent = String(httpCount);
        if (statDuration) statDuration.textContent = `${(data.duration || 0).toFixed ? data.duration.toFixed(1) : data.duration}s`;

        if (data.has_wildcard && wildcardWarning) {
            wildcardWarning.style.display = 'block';
        }

        if (filterAllBtn) {
            filterAllBtn.disabled = false;
            filterAllBtn.classList.add('active');
        }
        if (filterAliveBtn) {
            filterAliveBtn.disabled = false;
            filterAliveBtn.classList.remove('active');
        }
        if (exportBtn) {
            exportBtn.disabled = total === 0;
        }
    }

    function filterAliveOnly(aliveOnly) {
        if (!subdomainResults) return;
        subdomainResults.querySelectorAll('tr').forEach(tr => {
            const alive = tr.getAttribute('data-alive') === '1';
            tr.style.display = (!aliveOnly || alive) ? '' : 'none';
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        resetUI();
        setButtons(false);

        if (wordlistSelect && customWordlistContainer) {
            wordlistSelect.addEventListener('change', () => {
                customWordlistContainer.style.display =
                    wordlistSelect.value === 'custom' ? 'block' : 'none';
            });
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            const domain = domainInput ? domainInput.value.trim() : '';
            if (!domain) {
                VulnScanner.showAlert('Please enter a domain', 'warning');
                return;
            }

            resetUI();
            setButtons(true);
            scanActive = true;

            updateProgress(10, 'Enumerating subdomains...');
            VulnScanner.showLoading(true, 'Running subdomain enumeration...');

            const wordlist = wordlistSelect ? wordlistSelect.value : 'default';
            const payload = {
                domain: domain,
                wordlist: wordlist
                // Extra flags (use_crt, recursive) could be passed if handled by backend
            };

            try {
                const data = await VulnScanner.apiRequest(apiUrl, 'POST', payload);
                scanActive = false;
                setButtons(false);
                VulnScanner.showLoading(false);
                updateProgress(100, 'Completed');

                if (!data || data.error) {
                    VulnScanner.showAlert('Subdomain enumeration failed: ' + (data.error || 'Unknown error'), 'danger');
                    return;
                }

                lastResult = data;
                renderResults(data);

            } catch (err) {
                scanActive = false;
                setButtons(false);
                VulnScanner.showLoading(false);
                VulnScanner.showAlert('Subdomain enumeration failed: ' + err.message, 'danger');
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

        if (filterAllBtn) {
            filterAllBtn.addEventListener('click', () => {
                filterAllBtn.classList.add('active');
                if (filterAliveBtn) filterAliveBtn.classList.remove('active');
                filterAliveOnly(false);
            });
        }

        if (filterAliveBtn) {
            filterAliveBtn.addEventListener('click', () => {
                filterAliveBtn.classList.add('active');
                if (filterAllBtn) filterAllBtn.classList.remove('active');
                filterAliveOnly(true);
            });
        }

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                if (!lastResult || !lastResult.subdomains) {
                    VulnScanner.showAlert('No subdomains to export', 'warning');
                    return;
                }
                const lines = lastResult.subdomains.map(s => s.full_domain);
                const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `subdomains_${(domainInput && domainInput.value) || 'target'}.txt`;
                a.click();
                URL.revokeObjectURL(url);
            });
        }
    });
})();