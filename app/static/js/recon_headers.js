// recon_headers.js
// Logic for /recon/headers page (HTTP headers analysis under Recon)

(function () {
    'use strict';

    const apiUrl = '/recon/api/headers';

    const form = document.getElementById('headersForm');
    if (!form) return;

    const urlInput = document.getElementById('url');

    const noResults = document.getElementById('noResults');             // placeholder text block
    const resultsContainer = document.getElementById('resultsContainer'); // main results wrapper

    const statusCodeEl = document.getElementById('respStatusCode');
    const serverEl = document.getElementById('respServer');
    const contentTypeEl = document.getElementById('respContentType');
    const responseTimeEl = document.getElementById('respTime');

    const securityList = document.getElementById('headersSecurityList');
    const allHeadersList = document.getElementById('headersAllList');

    const exportBtn = document.getElementById('headersExportJson');

    let lastResult = null;

    function resetUI() {
        lastResult = null;

        if (noResults) noResults.style.display = 'block';
        if (resultsContainer) resultsContainer.style.display = 'none';

        if (statusCodeEl) statusCodeEl.textContent = '-';
        if (serverEl) serverEl.textContent = '-';
        if (contentTypeEl) contentTypeEl.textContent = '-';
        if (responseTimeEl) responseTimeEl.textContent = '-';

        if (securityList) securityList.innerHTML = '';
        if (allHeadersList) allHeadersList.innerHTML = '';

        if (exportBtn) exportBtn.disabled = true;
    }

    function renderSecurityHeaders(secHeaders, missingHeaders) {
        if (!securityList) return;
        securityList.innerHTML = '';

        if (secHeaders && secHeaders.length > 0) {
            secHeaders.forEach(h => {
                const item = document.createElement('div');
                item.className = 'header-item mb-2';
                const valid = h.valid;
                let stateClass = 'warning';
                if (valid && h.present) stateClass = 'good';
                if (!h.present) stateClass = 'bad';
                item.classList.add(stateClass);

                item.innerHTML = `
<div class="d-flex justify-content-between align-items-start">
  <div>
    <h6 class="mb-1">${h.name}</h6>
    ${h.value ? `<code class="small">${h.value}</code>` : '<small class="text-muted">No value</small>'}
  </div>
  <span class="badge bg-${valid ? 'success' : 'warning'}">${h.score || 0}/${h.max_score || 10}</span>
</div>
${h.recommendation ? `<p class="text-muted small mt-2 mb-0">${h.recommendation}</p>` : ''}`;
                securityList.appendChild(item);
            });
        }

        if (missingHeaders && missingHeaders.length > 0) {
            missingHeaders.forEach(name => {
                const item = document.createElement('div');
                item.className = 'header-item bad mb-2';
                item.innerHTML = `
<h6 class="mb-1">${name}</h6>
<p class="text-muted small mb-0">This recommended security header is missing.</p>`;
                securityList.appendChild(item);
            });
        }

        if (!secHeaders && (!missingHeaders || missingHeaders.length === 0)) {
            securityList.innerHTML = '<p class="text-muted">No security header information available.</p>';
        }
    }

    function renderAllHeaders(headers) {
        if (!allHeadersList) return;
        allHeadersList.innerHTML = '';

        if (!headers || Object.keys(headers).length === 0) {
            allHeadersList.innerHTML = '<tr><td colspan="2" class="text-muted text-center">No headers returned.</td></tr>';
            return;
        }

        allHeadersList.innerHTML = Object.entries(headers).map(([name, value]) => `
<tr>
  <td><strong>${name}</strong></td>
  <td><code class="small">${value}</code></td>
</tr>`).join('');
    }

    document.addEventListener('DOMContentLoaded', () => {
        resetUI();

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = urlInput ? urlInput.value.trim() : '';
            if (!url) {
                VulnScanner.showAlert('Please enter a target URL', 'warning');
                return;
            }

            resetUI();
            VulnScanner.showLoading(true, 'Analyzing HTTP headers...');

            try {
                const data = await VulnScanner.apiRequest(apiUrl, 'POST', { url: url });
                VulnScanner.showLoading(false);

                if (!data || data.error) {
                    VulnScanner.showAlert('Header analysis failed: ' + (data.error || 'Unknown error'), 'danger');
                    return;
                }

                lastResult = data;

                if (noResults) noResults.style.display = 'none';
                if (resultsContainer) resultsContainer.style.display = 'block';
                if (exportBtn) exportBtn.disabled = false;

                if (statusCodeEl) statusCodeEl.textContent = data.status_code || '-';
                if (serverEl) serverEl.textContent = data.server_header || '-';
                if (contentTypeEl) {
                    const ct = data.headers && data.headers['Content-Type'] ? data.headers['Content-Type'] : '-';
                    contentTypeEl.textContent = ct;
                }
                if (responseTimeEl) responseTimeEl.textContent = data.response_time ? data.response_time + 's' : '-';

                renderSecurityHeaders(data.security_headers || [], data.missing_headers || []);
                renderAllHeaders(data.headers || {});

            } catch (err) {
                VulnScanner.showLoading(false);
                VulnScanner.showAlert('Header analysis failed: ' + err.message, 'danger');
            }
        });

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                if (!lastResult) {
                    VulnScanner.showAlert('No results to export', 'warning');
                    return;
                }
                VulnScanner.downloadJSON(lastResult, 'recon_headers.json');
            });
        }
    });
})();