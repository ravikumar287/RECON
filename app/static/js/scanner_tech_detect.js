// scanner_tech_detect.js
// Logic for /scanner/tech-detect page (scanner-side entry)

(function () {
    'use strict';

    const apiUrl = '/recon/api/tech-detect';  // reuse recon API

    const form = document.getElementById('techDetectForm');
    if (!form) return;

    const urlInput = document.getElementById('techDetectUrl');
    const headersChk = document.getElementById('techDetectHeaders');
    const htmlChk = document.getElementById('techDetectHtml');
    const jsChk = document.getElementById('techDetectJs');
    const followRedirectsChk = document.getElementById('techDetectFollowRedirects');

    const timerContainer = document.getElementById('techDetectTimer');
    const timerDisplay = document.getElementById('techDetectTimerDisplay');

    const noResults = document.getElementById('techDetectNoResults');
    const resultsContainer = document.getElementById('techDetectResultsContainer');
    const resultActions = document.getElementById('techDetectResultActions');
    const downloadJsonBtn = document.getElementById('techDetectDownloadJson');

    const totalTechEl = document.getElementById('techDetectTotalTech');
    const totalCategoriesEl = document.getElementById('techDetectTotalCategories');
    const withVersionEl = document.getElementById('techDetectWithVersion');

    const quickSummary = document.getElementById('techDetectQuickSummary');
    const byCategoryContainer = document.getElementById('techDetectByCategory');
    const rawHeadersContent = document.getElementById('techDetectRawHeadersContent');

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
        if (resultsContainer) resultsContainer.style.display = 'none';
        if (resultActions) resultActions.style.display = 'none';

        if (noResults) noResults.style.display = 'block';

        if (totalTechEl) totalTechEl.textContent = '0';
        if (totalCategoriesEl) totalCategoriesEl.textContent = '0';
        if (withVersionEl) withVersionEl.textContent = '0';

        if (quickSummary) quickSummary.innerHTML = '';
        if (byCategoryContainer) byCategoryContainer.innerHTML = '';
        if (rawHeadersContent) rawHeadersContent.textContent = '';
    }

    function renderSummary(data) {
        const techs = data.technologies || [];
        const categories = data.categories || {};

        if (totalTechEl) totalTechEl.textContent = techs.length;
        if (totalCategoriesEl) totalCategoriesEl.textContent = Object.keys(categories).length;
        if (withVersionEl) withVersionEl.textContent = techs.filter(t => t.version).length;

        if (quickSummary) {
            quickSummary.innerHTML = '';
            const badges = [];

            if (data.cms) {
                badges.push({ label: `CMS: ${data.cms}`, class: 'bg-warning' });
            }
            if (data.web_server) {
                badges.push({ label: `Server: ${data.web_server}`, class: 'bg-primary' });
            }
            if (data.programming_language) {
                badges.push({ label: `Lang: ${data.programming_language}`, class: 'bg-success' });
            }
            if (data.javascript_frameworks && data.javascript_frameworks.length > 0) {
                data.javascript_frameworks.forEach(fw => {
                    badges.push({ label: `JS: ${fw}`, class: 'bg-info' });
                });
            }

            if (badges.length === 0) {
                quickSummary.innerHTML = '<span class="text-muted small">No high-level summary available.</span>';
            } else {
                badges.forEach(b => {
                    const span = document.createElement('span');
                    span.className = `badge ${b.class} p-2`;
                    span.textContent = b.label;
                    quickSummary.appendChild(span);
                });
            }
        }
    }

    function renderByCategory(categories, techs) {
        if (!byCategoryContainer) return;
        byCategoryContainer.innerHTML = '';

        if (!categories || Object.keys(categories).length === 0) {
            byCategoryContainer.innerHTML = '<p class="text-muted">No technologies detected.</p>';
            return;
        }

        const techMap = {};
        techs.forEach(t => {
            techMap[`${t.name}`] = t;
        });

        Object.entries(categories).forEach(([category, names]) => {
            const section = document.createElement('div');
            section.className = 'tech-category mb-3';

            const header = document.createElement('div');
            header.className = 'tech-category-header d-flex align-items-center gap-2 mb-2';
            header.innerHTML = `
<i class="bi bi-boxes"></i>
<h6 class="mb-0">${category}</h6>
<span class="badge bg-secondary">${names.length}</span>`;
            section.appendChild(header);

            const list = document.createElement('div');
            list.className = 'tech-items';

            names.forEach(name => {
                const t = techMap[name] || { name: name };
                const item = document.createElement('div');
                item.className = 'tech-item mb-2 d-flex justify-content-between align-items-center';

                const left = document.createElement('div');
                left.className = 'tech-info d-flex align-items-center gap-2';
                left.innerHTML = `
<div class="tech-icon">
  <i class="bi bi-box"></i>
</div>
<div>
  <div class="tech-name">${t.name}</div>
  ${t.version ? `<div class="tech-version">v${t.version}</div>` : ''}
</div>`;

                const right = document.createElement('div');
                right.className = 'tech-meta d-flex align-items-center gap-2';
                if (t.outdated) {
                    const outdated = document.createElement('span');
                    outdated.className = 'badge bg-warning';
                    outdated.textContent = 'Outdated';
                    right.appendChild(outdated);
                }
                const bar = document.createElement('div');
                bar.className = 'confidence-bar';
                const fill = document.createElement('div');
                fill.className = 'confidence-bar-fill';
                fill.style.width = `${t.confidence || 100}%`;
                bar.appendChild(fill);
                right.appendChild(bar);

                item.appendChild(left);
                item.appendChild(right);
                list.appendChild(item);
            });

            section.appendChild(list);
            byCategoryContainer.appendChild(section);
        });
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

            VulnScanner.showLoading(true, 'Detecting technologies...');
            startTime = Date.now();
            timerInterval = setInterval(updateTimer, 1000);

            try {
                const payload = {
                    url: url
                    // You can extend this later to pass headers/html/js flags if backend supports it
                };

                const data = await VulnScanner.apiRequest(apiUrl, 'POST', payload);
                VulnScanner.showLoading(false);

                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }

                if (!data || data.error) {
                    VulnScanner.showAlert('Technology detection failed: ' + (data.error || 'Unknown error'), 'danger');
                    return;
                }

                lastResult = data;
                if (noResults) noResults.style.display = 'none';
                if (resultsContainer) resultsContainer.style.display = 'block';
                if (resultActions) resultActions.style.display = 'flex';

                renderSummary(data);
                renderByCategory(data.categories || {}, data.technologies || []);

                if (rawHeadersContent && data.headers) {
                    rawHeadersContent.textContent = JSON.stringify(data.headers, null, 2);
                }
            } catch (err) {
                VulnScanner.showLoading(false);
                if (timerInterval) {
                    clearInterval(timerInterval);
                    timerInterval = null;
                }
                VulnScanner.showAlert('Technology detection failed: ' + err.message, 'danger');
            }
        });

        if (downloadJsonBtn) {
            downloadJsonBtn.addEventListener('click', () => {
                if (!lastResult) {
                    VulnScanner.showAlert('No results to export', 'warning');
                    return;
                }
                VulnScanner.downloadJSON(lastResult, 'tech_detect_report.json');
            });
        }
    });
})();