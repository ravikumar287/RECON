// scanner_security_headers.js
// Logic for /scanner/security-headers page

(function () {
    'use strict';

    const apiUrl = '/scanner/api/security-headers';

    const form = document.getElementById('secHeadersForm');
    if (!form) return;

    const urlInput = document.getElementById('secHeadersUrl');
    const methodSelect = document.getElementById('secHeadersMethod');
    const followRedirectsChk = document.getElementById('secHeadersFollowRedirects');

    const timerContainer = document.getElementById('secHeadersTimer');
    const timerDisplay = document.getElementById('secHeadersTimerDisplay');

    const scoreCard = document.getElementById('secHeadersScoreCard');
    const scoreValue = document.getElementById('secHeadersScoreValue');
    const scoreCircle = document.getElementById('secHeadersScoreCircle');
    const gradeLabel = document.getElementById('secHeadersGradeLabel');
    const scoreDescription = document.getElementById('secHeadersScoreDescription');

    const presentCount = document.getElementById('secHeadersPresentCount');
    const missingCount = document.getElementById('secHeadersMissingCount');
    const warningsCount = document.getElementById('secHeadersWarningsCount');

    const checklist = document.getElementById('secHeadersChecklist');

    const statusCodeEl = document.getElementById('secHeadersStatusCode');
    const serverEl = document.getElementById('secHeadersServer');
    const contentTypeEl = document.getElementById('secHeadersContentType');
    const responseTimeEl = document.getElementById('secHeadersResponseTime');

    const noResults = document.getElementById('secHeadersNoResults');
    const resultsContainer = document.getElementById('secHeadersResultsContainer');
    const resultActions = document.getElementById('secHeadersResultActions');
    const downloadJsonBtn = document.getElementById('secHeadersDownloadJson');

    const securityList = document.getElementById('secHeadersSecurityList');
    const allHeadersList = document.getElementById('secHeadersAllList');

    let timerInterval = null;
    let startTime = null;
    let lastResult = null;

    function updateTimer() {
        if (!startTime || !timerDisplay) return;
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        timerDisplay.textContent = `${h}:${m}:${s}`;
    }

    function resetUI() {
        lastResult = null;

        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }

        if (timerContainer) timerContainer.style.display = 'none';
        if (scoreCard) scoreCard.style.display = 'none';
        if (resultsContainer) resultsContainer.style.display = 'none';
        if (resultActions) resultActions.style.display = 'none';

        if (noResults) noResults.style.display = 'block';

        if (scoreValue) scoreValue.textContent = '0';
        if (gradeLabel) {
            gradeLabel.textContent = '-';
            gradeLabel.className = 'badge';
        }
        if (scoreCircle) scoreCircle.style.borderColor = '';

        if (presentCount) presentCount.textContent = '0';
        if (missingCount) missingCount.textContent = '0';
        if (warningsCount) warningsCount.textContent = '0';

        if (statusCodeEl) statusCodeEl.textContent = '-';
        if (serverEl) serverEl.textContent = '-';
        if (contentTypeEl) contentTypeEl.textContent = '-';
        if (responseTimeEl) responseTimeEl.textContent = '-';

        if (securityList) securityList.innerHTML = '';
        if (allHeadersList) allHeadersList.innerHTML = '';

        // Reset checklist icons
        if (checklist) {
            checklist.querySelectorAll('.bi').forEach(icon => {
                icon.className = 'bi bi-circle text-muted me-2';
            });
        }
    }

    function setScore(score, grade, counts) {
        if (scoreValue) scoreValue.textContent = String(score);

        if (gradeLabel) {
            gradeLabel.textContent = grade || '-';
            let cls = 'badge bg-secondary';
            if (!grade) {
                cls = 'badge bg-secondary';
            } else if (grade.startsWith('A')) {
                cls = 'badge bg-success';
            } else if (grade.startsWith('B')) {
                cls = 'badge bg-info';
            } else if (grade.startsWith('C')) {
                cls = 'badge bg-warning';
            } else {
                cls = 'badge bg-danger';
            }
            gradeLabel.className = cls;
        }

        if (scoreCircle) {
            let color = 'var(--border-color)';
            if (score >= 80) {
                color = 'var(--success-color)';
            } else if (score >= 60) {
                color = 'var(--info-color)';
            } else if (score >= 40) {
                color = 'var(--warning-color)';
            } else {
                color = 'var(--danger-color)';
            }
            scoreCircle.style.borderColor = color;
        }

        if (counts) {
            if (presentCount) presentCount.textContent = counts.present || 0;
            if (missingCount) missingCount.textContent = counts.missing || 0;
            if (warningsCount) warningsCount.textContent = counts.warnings || 0;
        }
    }

    function updateChecklist(headers) {
        if (!checklist || !headers) return;

        const headerMap = {};
        Object.keys(headers).forEach(k => {
            headerMap[k.toLowerCase()] = true;
        });

        checklist.querySelectorAll('div.d-flex').forEach(row => {
            const span = row.querySelector('span');
            const icon = row.querySelector('i');
            if (!span || !icon) return;
            const name = span.textContent.trim();
            const present = !!headerMap[name.toLowerCase()];
            if (present) {
                icon.className = 'bi bi-check-circle text-success me-2';
            } else {
                icon.className = 'bi bi-x-circle text-danger me-2';
            }
        });
    }

    function renderSecurityHeaders(securityHeaders, missingHeaders) {
        if (!securityList) return;
        securityList.innerHTML = '';

        if (securityHeaders && securityHeaders.length > 0) {
            securityHeaders.forEach(h => {
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
    <h6 class="mb-1">
      <i class="bi bi-${valid ? 'check-circle text-success' : 'exclamation-triangle text-warning'} me-2"></i>
      ${h.name}
    </h6>
    ${h.value ? `<code class="small">${h.value}</code>` : '<span class="small text-muted">No value</span>'}
  </div>
  <span class="badge bg-${valid ? 'success' : 'warning'}">${h.score || 0}/${h.max_score || 10}</span>
</div>
${h.recommendation ? `<p class="text-muted small mt-2 mb-0">${h.recommendation}</p>` : ''}`;
                securityList.appendChild(wrapper);
            });
        }

        if (missingHeaders && missingHeaders.length > 0) {
            missingHeaders.forEach(name => {
                const wrapper = document.createElement('div');
                wrapper.className = 'header-item bad mb-2';
                wrapper.innerHTML = `
<h6 class="mb-1">
  <i class="bi bi-x-circle text-danger me-2"></i>${name}
</h6>
<p class="text-muted small mb-0">This recommended security header is missing.</p>`;
                securityList.appendChild(wrapper);
            });
        }

        if (!securityHeaders && (!missingHeaders || missingHeaders.length === 0)) {
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

            if (timerContainer) timerContainer.style.display = 'block';
            if (scoreCard) scoreCard.style.display = 'none';
            if (resultsContainer) resultsContainer.style.display = 'none';

            VulnScanner.showLoading(true, 'Analyzing security headers...');
            startTime = Date.now();
            timerInterval = setInterval(updateTimer, 1000);

            try {
                const payload = {
                    url: url,
                    method: methodSelect ? methodSelect.value : 'GET',
                    follow_redirects: followRedirectsChk ? followRedirectsChk.checked : true
                };

                const data = await VulnScanner.apiRequest(apiUrl, 'POST', payload);
                VulnScanner.showLoading(false);

                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }

                if (!data || data.error) {
                    VulnScanner.showAlert('Header analysis failed: ' + (data.error || 'Unknown error'), 'danger');
                    return;
                }

                lastResult = data;

                if (noResults) noResults.style.display = 'none';
                if (scoreCard) scoreCard.style.display = 'block';
                if (resultsContainer) resultsContainer.style.display = 'block';
                if (resultActions) resultActions.style.display = 'flex';

                const score = data.score || 0;
                const grade = data.grade || 'F';
                const counts = {
                    present: data.security_headers ? data.security_headers.filter(h => h.present).length : 0,
                    missing: data.missing_headers ? data.missing_headers.length : 0,
                    warnings: (data.information_disclosure ? data.information_disclosure.length : 0)
                };
                setScore(score, grade, counts);

                if (statusCodeEl) statusCodeEl.textContent = data.status_code || '-';
                if (serverEl) serverEl.textContent = data.server_header || '-';
                if (contentTypeEl) contentTypeEl.textContent = data.headers && data.headers['Content-Type'] ? data.headers['Content-Type'] : '-';
                if (responseTimeEl) responseTimeEl.textContent = data.response_time ? data.response_time + 's' : '-';

                updateChecklist(data.headers || {});
                renderSecurityHeaders(data.security_headers || [], data.missing_headers || []);
                renderAllHeaders(data.headers || {});

            } catch (err) {
                VulnScanner.showLoading(false);
                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }
                VulnScanner.showAlert('Header analysis failed: ' + err.message, 'danger');
            }
        });

        if (downloadJsonBtn) {
            downloadJsonBtn.addEventListener('click', () => {
                if (!lastResult) {
                    VulnScanner.showAlert('No results to export', 'warning');
                    return;
                }
                VulnScanner.downloadJSON(lastResult, 'security_headers_report.json');
            });
        }
    });
})();