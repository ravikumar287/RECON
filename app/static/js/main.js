/**
 * VulnScanner - Main JavaScript File
 */

// ============ Global Variables ============
const socket = io();
let currentScanId = null;

// ============ DOM Ready ============
document.addEventListener('DOMContentLoaded', function() {
    initializeSidebar();
    initializeThemeToggle();
    initializeSearch();
    initializeQuickScan();
    initializeSocketEvents();
});

// ============ Sidebar Functions ============
function initializeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const mobileToggle = document.getElementById('mobileToggle');
    
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
        });
    }
    
    if (mobileToggle) {
        mobileToggle.addEventListener('click', function() {
            sidebar.classList.toggle('mobile-open');
        });
    }
    
    // Restore sidebar state
    if (localStorage.getItem('sidebarCollapsed') === 'true') {
        sidebar.classList.add('collapsed');
    }
    
    // Close mobile sidebar on click outside
    document.addEventListener('click', function(e) {
        if (window.innerWidth < 992) {
            if (!sidebar.contains(e.target) && !mobileToggle.contains(e.target)) {
                sidebar.classList.remove('mobile-open');
            }
        }
    });
}

// ============ Theme Toggle ============
function initializeThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    const html = document.documentElement;
    
    // Check saved theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    html.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
    
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
        });
    }
}

function updateThemeIcon(theme) {
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        const icon = themeToggle.querySelector('i');
        icon.className = theme === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun';
    }
}

// ============ Search Functionality ============
function initializeSearch() {
    const searchInput = document.getElementById('globalSearch');
    
    if (searchInput) {
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const query = this.value.trim();
                if (query) {
                    // Redirect to search results or filter current page
                    console.log('Searching for:', query);
                }
            }
        });
    }
}

// ============ Quick Scan ============
function initializeQuickScan() {
    const startQuickScan = document.getElementById('startQuickScan');
    
    if (startQuickScan) {
        startQuickScan.addEventListener('click', function() {
            const target = document.getElementById('quickTarget').value;
            const scanType = document.getElementById('quickScanType').value;
            
            if (!target) {
                showAlert('Please enter a target URL or IP address', 'warning');
                return;
            }
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('quickScanModal'));
            modal.hide();
            
            // Start scan
            startScan(target, scanType);
        });
    }
}

// ============ Socket.IO Events ============
function initializeSocketEvents() {
    socket.on('connect', function() {
        console.log('Connected to server');
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
    });
    
    socket.on('scan_progress', function(data) {
        updateScanProgress(data);
    });
    
    socket.on('scan_complete', function(data) {
        handleScanComplete(data);
    });
    
    socket.on('port_scan_progress', function(data) {
        handlePortScanProgress(data);
    });
    
    socket.on('port_scan_complete', function(data) {
        handlePortScanComplete(data);
    });
}

// ============ Scan Functions ============
function startScan(target, type) {
    showLoading(true);
    
    socket.emit('start_full_scan', {
        target: target,
        options: {
            scan_type: type
        }
    });
}

function updateScanProgress(data) {
    const progressBar = document.getElementById('loadingProgress');
    const loadingText = document.querySelector('.loading-text');
    
    if (progressBar) {
        progressBar.style.width = data.progress + '%';
    }
    
    if (loadingText) {
        loadingText.textContent = `${data.stage}: ${data.message}`;
    }
}

function handleScanComplete(data) {
    showLoading(false);
    
    if (data.error) {
        showAlert('Scan failed: ' + data.error, 'danger');
    } else {
        showAlert('Scan completed successfully!', 'success');
        // Redirect to results page
        window.location.href = '/scanner/results/' + data.scan_id;
    }
}

function handlePortScanProgress(data) {
    const resultsContainer = document.getElementById('scanResults');
    if (resultsContainer && data.status === 'open') {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${data.port}</td>
            <td><span class="badge bg-success">Open</span></td>
            <td>${data.service || 'Unknown'}</td>
        `;
        resultsContainer.appendChild(row);
    }
}

function handlePortScanComplete(data) {
    showLoading(false);
    showAlert(`Port scan completed. Found ${data.open_ports.length} open ports.`, 'success');
}

// ============ Loading Functions ============
function showLoading(show, message = 'Scanning in progress...') {
    const overlay = document.getElementById('loadingOverlay');
    const loadingText = document.querySelector('.loading-text');
    
    if (overlay) {
        overlay.classList.toggle('active', show);
    }
    
    if (loadingText) {
        loadingText.textContent = message;
    }
    
    if (!show) {
        const progressBar = document.getElementById('loadingProgress');
        if (progressBar) {
            progressBar.style.width = '0%';
        }
    }
}

// ============ Alert Functions ============
function showAlert(message, type = 'info') {
    const container = document.querySelector('.page-content');
    if (!container) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    container.insertBefore(alert, container.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        alert.classList.remove('show');
        setTimeout(() => alert.remove(), 150);
    }, 5000);
}

// ============ API Functions ============
async function apiRequest(url, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(url, options);
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'Request failed');
        }
        
        return result;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// ============ Utility Functions ============
function validateTarget(target) {
    const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    
    return urlPattern.test(target) || ipPattern.test(target);
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showAlert('Copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

function downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// ============ Export Functions ============
window.VulnScanner = {
    showLoading,
    showAlert,
    apiRequest,
    validateTarget,
    formatDate,
    copyToClipboard,
    downloadJSON,
    socket
};