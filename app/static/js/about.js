// about.js
// Logic for /about page (optional dynamic info)

(function () {
    'use strict';

    const versionEl = document.getElementById('aboutVersion');
    const supportEmailEl = document.getElementById('aboutSupportEmail');
    const githubEl = document.getElementById('aboutGithub');

    // You can hard-code or fetch these from a /api/health or /api/info endpoint
    const APP_VERSION = '1.0.0';
    const SUPPORT_EMAIL = 'support@example.com';
    const GITHUB_TEXT = 'GitHub repository (configure link in template or here)';

    document.addEventListener('DOMContentLoaded', () => {
        if (versionEl) versionEl.textContent = APP_VERSION;
        if (supportEmailEl) supportEmailEl.textContent = SUPPORT_EMAIL;
        if (githubEl) githubEl.textContent = GITHUB_TEXT;
    });
})();