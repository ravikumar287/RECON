// settings.js
// Logic for /settings page (client-side preferences only)

(function () {
    'use strict';

    const generalForm = document.getElementById('settingsGeneralForm');
    const themeSelect = document.getElementById('settingsTheme');
    const defaultProfileSelect = document.getElementById('settingsDefaultProfile');
    const maxThreadsInput = document.getElementById('settingsMaxThreads');

    const securityForm = document.getElementById('settingsSecurityForm');
    const showDisclaimerChk = document.getElementById('settingsShowDisclaimer');
    const rateLimitInput = document.getElementById('settingsRateLimit');

    const LS_KEY = 'vulnscanner_settings';

    function loadSettings() {
        try {
            const raw = localStorage.getItem(LS_KEY);
            if (!raw) return {};
            return JSON.parse(raw) || {};
        } catch {
            return {};
        }
    }

    function saveSettings(settings) {
        try {
            localStorage.setItem(LS_KEY, JSON.stringify(settings));
        } catch (e) {
            console.error('Failed to save settings to localStorage:', e);
        }
    }

    function applySettingsToUI(settings) {
        if (themeSelect && settings.theme) themeSelect.value = settings.theme;
        if (defaultProfileSelect && settings.default_profile) defaultProfileSelect.value = settings.default_profile;
        if (maxThreadsInput && settings.max_threads != null) maxThreadsInput.value = settings.max_threads;

        if (showDisclaimerChk && settings.show_disclaimer != null) {
            showDisclaimerChk.checked = !!settings.show_disclaimer;
        }
        if (rateLimitInput && settings.rate_limit != null) {
            rateLimitInput.value = settings.rate_limit;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        const settings = loadSettings();
        applySettingsToUI(settings);

        if (generalForm) {
            generalForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const current = loadSettings();
                current.theme = themeSelect ? themeSelect.value : current.theme;
                current.default_profile = defaultProfileSelect ? defaultProfileSelect.value : current.default_profile;
                current.max_threads = maxThreadsInput ? parseInt(maxThreadsInput.value || '50', 10) : current.max_threads;
                saveSettings(current);
                VulnScanner.showAlert('General settings saved locally.', 'success');
            });
        }

        if (securityForm) {
            securityForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const current = loadSettings();
                current.show_disclaimer = showDisclaimerChk ? showDisclaimerChk.checked : current.show_disclaimer;
                current.rate_limit = rateLimitInput ? parseInt(rateLimitInput.value || '10', 10) : current.rate_limit;
                saveSettings(current);
                VulnScanner.showAlert('Security settings saved locally.', 'success');
            });
        }
    });
})();