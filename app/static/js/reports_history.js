// reports_history.js
// Logic for /reports/history page

(function () {
    'use strict';

    const apiListReports = '/api/reports';
    const apiDeleteReport = (id) => `/api/reports/${encodeURIComponent(id)}`;
    const apiDownloadReport = (id) => `/api/reports/${encodeURIComponent(id)}/download`;

    const refreshBtn = document.getElementById('historyRefreshBtn');
    const filterTypeSelect = document.getElementById('historyFilterType');
    const searchInput = document.getElementById('historySearch');

    const emptyState = document.getElementById('historyEmptyState');
    const tableContainer = document.getElementById('historyTableContainer');
    const tableBody = document.getElementById('historyTableBody');
    const countText = document.getElementById('historyCountText');

    if (!tableBody) return;

    let reports = [];

    function renderTable() {
        const filterType = filterTypeSelect ? filterTypeSelect.value : 'all';
        const search = searchInput ? searchInput.value.trim().toLowerCase() : '';

        const filtered = reports.filter(r => {
            if (filterType !== 'all' && r.scan_type !== filterType) {
                return false;
            }
            if (search) {
                const t = (r.target || '').toLowerCase();
                return t.includes(search);
            }
            return true;
        });

        if (filtered.length === 0) {
            tableBody.innerHTML = '';
            if (emptyState) emptyState.style.display = 'block';
            if (tableContainer) tableContainer.style.display = 'none';
        } else {
            if (emptyState) emptyState.style.display = 'none';
            if (tableContainer) tableContainer.style.display = 'block';

            tableBody.innerHTML = filtered.map(r => {
                const findings = Array.isArray(r.findings) ? r.findings.length : (r.findings || 0);
                const date = r.date || r.timestamp || '-';
                const typeLabel = r.scan_type || 'unknown';
                return `
<tr data-id="${r.id}">
  <td><i class="bi bi-globe me-1 text-primary"></i>${r.target || '-'}</td>
  <td><span class="badge bg-secondary">${typeLabel}</span></td>
  <td>${date}</td>
  <td>${findings}</td>
  <td>
    <div class="btn-group btn-group-sm">
      <button type="button" class="btn btn-outline-primary history-view">
        <i class="bi bi-eye"></i>
      </button>
      <button type="button" class="btn btn-outline-success history-download">
        <i class="bi bi-download"></i>
      </button>
      <button type="button" class="btn btn-outline-danger history-delete">
        <i class="bi bi-trash"></i>
      </button>
    </div>
  </td>
</tr>`;
            }).join('');
        }

        if (countText) {
            countText.textContent = `${filtered.length} record${filtered.length === 1 ? '' : 's'}`;
        }

        attachRowHandlers();
    }

    function attachRowHandlers() {
        tableBody.querySelectorAll('.history-view').forEach(btn => {
            btn.addEventListener('click', () => {
                const tr = btn.closest('tr');
                if (!tr) return;
                const id = tr.getAttribute('data-id');
                if (!id) return;
                window.location.href = `/scanner/results/${encodeURIComponent(id)}`;
            });
        });

        tableBody.querySelectorAll('.history-download').forEach(btn => {
            btn.addEventListener('click', () => {
                const tr = btn.closest('tr');
                if (!tr) return;
                const id = tr.getAttribute('data-id');
                if (!id) return;
                window.location.href = apiDownloadReport(id);
            });
        });

        tableBody.querySelectorAll('.history-delete').forEach(btn => {
            btn.addEventListener('click', async () => {
                const tr = btn.closest('tr');
                if (!tr) return;
                const id = tr.getAttribute('data-id');
                if (!id) return;

                if (!confirm('Are you sure you want to delete this report?')) {
                    return;
                }
                try {
                    await VulnScanner.apiRequest(apiDeleteReport(id), 'DELETE');
                    reports = reports.filter(r => r.id !== id);
                    VulnScanner.showAlert('Report deleted successfully', 'success');
                    renderTable();
                } catch (err) {
                    VulnScanner.showAlert('Failed to delete report: ' + err.message, 'danger');
                }
            });
        });
    }

    async function loadReports() {
        try {
            const data = await VulnScanner.apiRequest(apiListReports, 'GET');
            reports = data.reports || [];
            renderTable();
        } catch (err) {
            VulnScanner.showAlert('Failed to load reports: ' + err.message, 'danger');
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        loadReports();

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                loadReports();
            });
        }

        if (filterTypeSelect) {
            filterTypeSelect.addEventListener('change', () => {
                renderTable();
            });
        }

        if (searchInput) {
            searchInput.addEventListener('input', () => {
                renderTable();
            });
        }
    });
})();