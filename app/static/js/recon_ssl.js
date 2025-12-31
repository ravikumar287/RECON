// recon_ssl.js
// Logic for /recon/ssl-check page

(function () {
    'use strict';

    const apiUrl = '/recon/api/ssl-check';

    const form = document.getElementById('sslForm');
    if (!form) return;

    const hostInput = document.getElementById('host');
    const portInput = document.getElementById('port');
    const checkChainChk = document.getElementById('checkChain');
    const checkCiphersChk = document.getElementById('checkCiphers');
    const checkVulnsChk = document.getElementById('checkVulns');

    const noResults = document.getElementById('noResults');
    const resultsContainer = document.getElementById('resultsContainer');
    const gradeCard = document.getElementById('gradeCard');

    const gradeCircle = document.getElementById('gradeCircle');
    const gradeValueEl = document.getElementById('gradeValue');
    const certStatusEl = document.getElementById('certStatus');
    const protocolStatusEl = document.getElementById('protocolStatus');
    const keyStatusEl = document.getElementById('keyStatus');
    const cipherStatusEl = document.getElementById('cipherStatus');

    const certInfo = document.getElementById('certInfo');
    const protocolInfo = document.getElementById('protocolInfo');
    const cipherInfo = document.getElementById('cipherInfo');
    const vulnInfo = document.getElementById('vulnInfo');

    const exportBtn = document.getElementById('exportSsl');

    let lastResult = null;

    function resetUI() {
        lastResult = null;

        if (noResults) noResults.style.display = 'block';
        if (resultsContainer) resultsContainer.style.display = 'none';
        if (gradeCard) gradeCard.style.display = 'none';

        if (gradeCircle) {
            gradeCircle.className = 'grade-circle';
        }
        if (gradeValueEl) gradeValueEl.textContent = '-';

        [certStatusEl, protocolStatusEl, keyStatusEl, cipherStatusEl].forEach(el => {
            if (el) el.textContent = '-';
        });

        if (certInfo) certInfo.innerHTML = '';
        if (protocolInfo) protocolInfo.innerHTML = '';
        if (cipherInfo) cipherInfo.innerHTML = '';
        if (vulnInfo) vulnInfo.innerHTML = '';

        if (exportBtn) exportBtn.disabled = true;
    }

    function setGrade(grade) {
        if (!gradeCircle || !gradeValueEl) return;
        gradeValueEl.textContent = grade || '-';

        const clsBase = 'grade-circle';
        let cls = clsBase;
        if (!grade) {
            cls = clsBase;
        } else if (grade[0] === 'A') {
            cls = `${clsBase} grade-a`;
        } else if (grade[0] === 'B') {
            cls = `${clsBase} grade-b`;
        } else if (grade[0] === 'C') {
            cls = `${clsBase} grade-c`;
        } else {
            cls = `${clsBase} grade-d`;
        }
        gradeCircle.className = cls;
    }

    function renderCert(cert) {
        if (!certInfo) return;

        if (!cert) {
            certInfo.innerHTML = '<p class="text-muted mb-0">No certificate information available.</p>';
            return;
        }

        const cn = cert.common_name || '-';
        const issuer = cert.issuer_name || '-';
        const validFrom = cert.valid_from || '-';
        const validUntil = cert.valid_until || '-';
        const daysRemaining = cert.days_until_expiry != null ? cert.days_until_expiry : '-';
        const keyType = cert.public_key_type || '-';
        const keyBits = cert.public_key_bits != null ? cert.public_key_bits : '-';
        const sigAlg = cert.signature_algorithm || '-';
        const san = Array.isArray(cert.san) ? cert.san : [];

        let validityAlert = '';
        if (cert.is_expired) {
            validityAlert = '<div class="alert alert-danger mb-3"><i class="bi bi-x-circle me-2"></i>Certificate has expired.</div>';
        } else if (daysRemaining !== '-' && daysRemaining < 30) {
            validityAlert = `<div class="alert alert-warning mb-3"><i class="bi bi-exclamation-triangle me-2"></i>Certificate expires in ${daysRemaining} days.</div>`;
        } else if (daysRemaining !== '-') {
            validityAlert = '<div class="alert alert-success mb-3"><i class="bi bi-check-circle me-2"></i>Certificate is valid.</div>';
        }

        certInfo.innerHTML = `
${validityAlert}
<div class="cert-detail mb-3">
  <h6><i class="bi bi-file-earmark me-2"></i>Subject</h6>
  <div class="cert-detail-row"><span>Common Name</span><strong>${cn}</strong></div>
</div>
<div class="cert-detail mb-3">
  <h6><i class="bi bi-building me-2"></i>Issuer</h6>
  <div class="cert-detail-row"><span>Issuer</span><strong>${issuer}</strong></div>
</div>
<div class="cert-detail mb-3">
  <h6><i class="bi bi-calendar me-2"></i>Validity</h6>
  <div class="cert-detail-row"><span>Valid From</span><strong>${validFrom}</strong></div>
  <div class="cert-detail-row"><span>Valid Until</span><strong>${validUntil}</strong></div>
  <div class="cert-detail-row"><span>Days Remaining</span><strong>${daysRemaining}</strong></div>
</div>
<div class="cert-detail mb-3">
  <h6><i class="bi bi-key me-2"></i>Key</h6>
  <div class="cert-detail-row"><span>Type</span><strong>${keyType}</strong></div>
  <div class="cert-detail-row"><span>Size</span><strong>${keyBits} bits</strong></div>
  <div class="cert-detail-row"><span>Signature Algorithm</span><strong>${sigAlg}</strong></div>
</div>
${san.length ? `
<div class="cert-detail">
  <h6><i class="bi bi-collection me-2"></i>Subject Alternative Names</h6>
  <div class="d-flex flex-wrap gap-1">
    ${san.map(s => `<span class="badge bg-secondary">${s}</span>`).join('')}
  </div>
</div>` : ''}`;
    }

    function renderProtocols(protocols) {
        if (!protocolInfo) return;

        if (!protocols || Object.keys(protocols).length === 0) {
            protocolInfo.innerHTML = '<p class="text-muted mb-0">No protocol information available.</p>';
            return;
        }

        const order = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0', 'SSL 2.0'];
        protocolInfo.innerHTML = `
<div class="table-responsive">
  <table class="table mb-0">
    <thead>
      <tr><th>Protocol</th><th>Supported</th></tr>
    </thead>
    <tbody>
      ${order.map(name => {
          const key = Object.keys(protocols).find(k => k.toLowerCase() === name.toLowerCase().replace(' ', '')) ||
                      Object.keys(protocols).find(k => k.toLowerCase() === name.toLowerCase());
          const supported = key ? protocols[key] : false;
          return `
<tr>
  <td>${name}</td>
  <td>${supported ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-secondary">No</span>'}</td>
</tr>`;
      }).join('')}
    </tbody>
  </table>
</div>`;
    }

    function renderCiphers(ciphers, weakCiphers) {
        if (!cipherInfo) return;

        if (!ciphers || !ciphers.length) {
            cipherInfo.innerHTML = '<p class="text-muted mb-0">No cipher information available.</p>';
            return;
        }

        const weakSet = new Set(weakCiphers || []);
        const strong = ciphers.filter(c => !weakSet.has(c.name || c));
        const weak = ciphers.filter(c => weakSet.has(c.name || c));

        cipherInfo.innerHTML = `
<div class="mb-3">
  <span class="badge bg-success me-2">${strong.length} Strong</span>
  <span class="badge bg-danger">${weak.length} Weak</span>
</div>
${ciphers.map(c => {
    const name = c.name || c;
    const isWeak = weakSet.has(name);
    const cls = isWeak ? 'weak' : 'strong';
    const badge = isWeak ? 'danger' : 'success';
    return `
<div class="cipher-item ${cls} mb-1">
  <span>${name}</span>
  <span class="badge bg-${badge}">${isWeak ? 'Weak' : 'Strong'}</span>
</div>`;
}).join('')}`;
    }

    function renderVulns(vulns) {
        if (!vulnInfo) return;

        if (!vulns || !vulns.length) {
            vulnInfo.innerHTML = `
<div class="alert alert-success mb-0">
  <i class="bi bi-check-circle me-2"></i>No known SSL/TLS vulnerabilities detected.
</div>`;
            return;
        }

        vulnInfo.innerHTML = vulns.map(v => `
<div class="alert alert-danger mb-2">
  <i class="bi bi-bug me-2"></i>${v}
</div>`).join('');
    }

    document.addEventListener('DOMContentLoaded', () => {
        resetUI();

        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            const host = hostInput ? hostInput.value.trim() : '';
            const port = portInput ? parseInt(portInput.value || '443', 10) : 443;
            if (!host) {
                VulnScanner.showAlert('Please enter a hostname', 'warning');
                return;
            }

            resetUI();
            VulnScanner.showLoading(true, 'Analyzing SSL/TLS...');

            try {
                const payload = {
                    host: host,
                    port: port
                    // check_chain, check_ciphers, check_vulns can be added if backend supports them
                };

                const data = await VulnScanner.apiRequest(apiUrl, 'POST', payload);
                VulnScanner.showLoading(false);

                if (!data || data.error) {
                    VulnScanner.showAlert('SSL analysis failed: ' + (data.error || 'Unknown error'), 'danger');
                    return;
                }

                lastResult = data;

                if (noResults) noResults.style.display = 'none';
                if (resultsContainer) resultsContainer.style.display = 'block';
                if (gradeCard) gradeCard.style.display = 'block';
                if (exportBtn) exportBtn.disabled = false;

                const grade = data.grade || 'F';
                setGrade(grade);

                if (certStatusEl) certStatusEl.textContent = data.certificate && data.certificate.is_valid ? '✓' : '✗';
                if (protocolStatusEl) protocolStatusEl.textContent = data.preferred_protocol || '-';
                if (keyStatusEl) {
                    const bits = data.certificate && data.certificate.public_key_bits;
                    keyStatusEl.textContent = bits ? `${bits} bit` : '-';
                }
                if (cipherStatusEl) {
                    const weakCount = data.weak_ciphers ? data.weak_ciphers.length : 0;
                    cipherStatusEl.textContent = weakCount === 0 ? '✓' : `${weakCount} weak`;
                }

                renderCert(data.certificate || null);
                renderProtocols(data.protocols || {});
                renderCiphers(data.cipher_suites || [], data.weak_ciphers || []);
                renderVulns(data.vulnerabilities || []);

            } catch (err) {
                VulnScanner.showLoading(false);
                VulnScanner.showAlert('SSL analysis failed: ' + err.message, 'danger');
            }
        });

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                if (!lastResult) {
                    VulnScanner.showAlert('No results to export', 'warning');
                    return;
                }
                VulnScanner.downloadJSON(lastResult, 'ssl_analysis.json');
            });
        }
    });
})();