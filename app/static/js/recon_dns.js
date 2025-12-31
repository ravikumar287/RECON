// recon_dns.js
// Logic for /recon/dns-lookup page

(function () {
    'use strict';

    const apiUrl = '/recon/api/dns-lookup';

    const form = document.getElementById('dnsLookupForm');
    if (!form) return;

    const domainInput = document.getElementById('domain');

    const noResults = document.getElementById('noResults');
    const resultsContainer = document.getElementById('dnsResults');

    const totalRecordsEl = document.getElementById('totalRecords');
    const recordTypesFoundEl = document.getElementById('recordTypesFound');
    const nameserverCountEl = document.getElementById('nameserverCount');
    const mailServerCountEl = document.getElementById('mailServerCount');

    const aItem = document.getElementById('aRecordsItem');
    const aBody = document.getElementById('aRecordsBody');
    const aCount = document.getElementById('aRecordsCount');

    const mxItem = document.getElementById('mxRecordsItem');
    const mxBody = document.getElementById('mxRecordsBody');
    const mxCount = document.getElementById('mxRecordsCount');

    const nsItem = document.getElementById('nsRecordsItem');
    const nsBody = document.getElementById('nsRecordsBody');
    const nsCount = document.getElementById('nsRecordsCount');

    const txtItem = document.getElementById('txtRecordsItem');
    const txtBody = document.getElementById('txtRecordsBody');
    const txtCount = document.getElementById('txtRecordsCount');

    const soaItem = document.getElementById('soaRecordsItem');
    const soaBody = document.getElementById('soaRecordsBody');

    const securityChecks = document.getElementById('securityChecks');
    const spfCheck = document.getElementById('spfCheck');
    const dmarcCheck = document.getElementById('dmarcCheck');
    const dnssecCheck = document.getElementById('dnssecCheck');

    const exportBtn = document.getElementById('exportDns');

    let lastResult = null;

    function getSelectedRecordTypes() {
        const checks = form.querySelectorAll('input[name="records"]:checked');
        return Array.from(checks).map(c => c.value);
    }

    function setCheckState(el, state) {
        if (!el) return;
        const icon = el.querySelector('i');
        if (!icon) return;
        if (state === 'pass') {
            icon.className = 'bi bi-check-circle text-success';
        } else if (state === 'fail') {
            icon.className = 'bi bi-x-circle text-danger';
        } else {
            icon.className = 'bi bi-circle text-muted';
        }
    }

    function resetResults() {
        lastResult = null;

        if (noResults) noResults.style.display = 'block';
        if (resultsContainer) resultsContainer.style.display = 'none';
        if (exportBtn) exportBtn.disabled = true;

        if (totalRecordsEl) totalRecordsEl.textContent = '0';
        if (recordTypesFoundEl) recordTypesFoundEl.textContent = '0';
        if (nameserverCountEl) nameserverCountEl.textContent = '0';
        if (mailServerCountEl) mailServerCountEl.textContent = '0';

        [aItem, mxItem, nsItem, txtItem, soaItem].forEach(el => {
            if (el) el.style.display = 'none';
        });
        if (aBody) aBody.innerHTML = '';
        if (mxBody) mxBody.innerHTML = '';
        if (nsBody) nsBody.innerHTML = '';
        if (txtBody) txtBody.innerHTML = '';
        if (soaBody) soaBody.innerHTML = '';

        if (aCount) aCount.textContent = '0';
        if (mxCount) mxCount.textContent = '0';
        if (nsCount) nsCount.textContent = '0';
        if (txtCount) txtCount.textContent = '0';

        if (securityChecks) securityChecks.style.display = 'none';
        setCheckState(spfCheck, 'unknown');
        setCheckState(dmarcCheck, 'unknown');
        setCheckState(dnssecCheck, 'unknown');
    }

    function renderRecordType(type, result) {
        if (!result || !result.success || !result.records) return;

        if (type === 'A' && aItem && aBody && aCount) {
            aItem.style.display = 'block';
            aCount.textContent = result.records.length;
            aBody.innerHTML = result.records.map(r => `
<tr>
  <td>${r.ip || '-'}</td>
  <td>${result.ttl || '-'}</td>
</tr>`).join('');
        }

        if (type === 'MX' && mxItem && mxBody && mxCount) {
            mxItem.style.display = 'block';
            mxCount.textContent = result.records.length;
            mxBody.innerHTML = result.records.map(r => `
<tr>
  <td>${r.priority}</td>
  <td>${r.mail_server}</td>
</tr>`).join('');
        }

        if (type === 'NS' && nsItem && nsBody && nsCount) {
            nsItem.style.display = 'block';
            nsCount.textContent = result.records.length;
            nsBody.innerHTML = result.records.map(r => `
<tr>
  <td>${r.nameserver}</td>
</tr>`).join('');
        }

        if (type === 'TXT' && txtItem && txtBody && txtCount) {
            txtItem.style.display = 'block';
            txtCount.textContent = result.records.length;
            txtBody.innerHTML = result.records.map(r => `
<div class="alert alert-secondary small mb-2">
  ${r.text}
</div>`).join('');
        }

        if (type === 'SOA' && soaItem && soaBody) {
            soaItem.style.display = 'block';
            const r = result.records[0] || {};
            soaBody.innerHTML = `
<ul class="small mb-0">
  <li><strong>Primary NS:</strong> ${r.primary_ns || '-'}</li>
  <li><strong>Admin Email:</strong> ${r.admin_email || '-'}</li>
  <li><strong>Serial:</strong> ${r.serial || '-'}</li>
  <li><strong>Refresh:</strong> ${r.refresh || '-'}</li>
  <li><strong>Retry:</strong> ${r.retry || '-'}</li>
  <li><strong>Expire:</strong> ${r.expire || '-'}</li>
  <li><strong>Minimum TTL:</strong> ${r.minimum_ttl || '-'}</li>
</ul>`;
        }
    }

    function renderSecurity(data) {
        if (!securityChecks) return;

        securityChecks.style.display = 'block';

        // Basic: look into TXT records for SPF and DMARC hints
        let hasSpf = false;
        let hasDmarc = false;
        let hasDnssec = false;

        if (data.results && data.results.TXT && data.results.TXT.records) {
            data.results.TXT.records.forEach(r => {
                const text = (r.text || '').toLowerCase();
                if (text.startsWith('v=spf1')) hasSpf = true;
                if (text.startsWith('v=dmarc1')) hasDmarc = true;
            });
        }

        // DNSSEC: we stored in DNSLookupResult.check_dnssec in the service layer;
        // if not present here, just mark unknown.
        if (data.dnssec && data.dnssec.enabled) {
            hasDnssec = true;
        }

        setCheckState(spfCheck, hasSpf ? 'pass' : 'fail');
        setCheckState(dmarcCheck, hasDmarc ? 'pass' : 'fail');
        setCheckState(dnssecCheck, hasDnssec ? 'pass' : 'fail');
    }

    function renderResults(data) {
        if (!resultsContainer) return;

        if (noResults) noResults.style.display = 'none';
        resultsContainer.style.display = 'block';
        if (exportBtn) exportBtn.disabled = false;

        if (totalRecordsEl) totalRecordsEl.textContent = data.total_records || 0;
        if (recordTypesFoundEl) {
            const types = data.record_types_found || Object.keys(data.results || {});
            recordTypesFoundEl.textContent = types.length;
        }

        // Nameservers & MX from convenience methods (if you add them in the API),
        // or derive from results
        const nsResult = data.results && data.results.NS;
        const mxResult = data.results && data.results.MX;
        if (nameserverCountEl) nameserverCountEl.textContent = nsResult && nsResult.records ? nsResult.records.length : 0;
        if (mailServerCountEl) mailServerCountEl.textContent = mxResult && mxResult.records ? mxResult.records.length : 0;

        if (data.results) {
            Object.entries(data.results).forEach(([type, res]) => {
                renderRecordType(type, res);
            });
        }

        renderSecurity(data);
    }

    document.addEventListener('DOMContentLoaded', () => {
        resetResults();

        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            const domain = domainInput ? domainInput.value.trim() : '';
            if (!domain) {
                VulnScanner.showAlert('Please enter a domain', 'warning');
                return;
            }

            resetResults();
            VulnScanner.showLoading(true, 'Performing DNS lookup...');

            try {
                const recordTypes = getSelectedRecordTypes();
                const payload = {
                    domain: domain,
                    record_types: recordTypes.length ? recordTypes : ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
                };

                const data = await VulnScanner.apiRequest(apiUrl, 'POST', payload);
                VulnScanner.showLoading(false);

                if (!data || data.error) {
                    VulnScanner.showAlert('DNS lookup failed: ' + (data.error || 'Unknown error'), 'danger');
                    return;
                }

                lastResult = data;
                renderResults(data);
            } catch (err) {
                VulnScanner.showLoading(false);
                VulnScanner.showAlert('DNS lookup failed: ' + err.message, 'danger');
            }
        });

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                if (!lastResult) {
                    VulnScanner.showAlert('No results to export', 'warning');
                    return;
                }
                VulnScanner.downloadJSON(lastResult, 'dns_lookup.json');
            });
        }
    });
})();