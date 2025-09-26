// Dashboard JavaScript for Encrypted Traffic Analysis

class TrafficAnalysisDashboard {
    constructor() {
        this.captureRunning = false;
        this.updateInterval = null;
        this.packetFeed = null;
        this.recentDetections = null;
        this.mode = this.getModeFromUrl();
        
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.init());
        } else {
            this.init();
        }
    }

    getModeFromUrl() {
        try {
            const params = new URLSearchParams(window.location.search);
            const mode = params.get('mode');
            return (mode === 'live' || mode === 'simulation') ? mode : 'simulation';
        } catch (e) {
            return 'simulation';
        }
    }

    init() {
        console.log('Initializing dashboard...');
        this.packetFeed = document.getElementById('packet-feed');
        this.recentDetections = document.getElementById('recent-detections');
        
        if (!this.packetFeed || !this.recentDetections) {
            console.error('Required DOM elements not found');
            return;
        }
        
        this.initializeEventListeners();
        this.loadInitialData();
        this.startPeriodicUpdates();
        console.log('Dashboard initialized successfully');

        // Update start button to reflect desired mode default
        const startBtn = document.getElementById('start-capture');
        if (startBtn) {
            if (this.mode === 'live') {
                startBtn.innerHTML = '<i class="fas fa-play"></i> Start Live Capture';
            } else {
                startBtn.innerHTML = '<i class="fas fa-play"></i> Run Replay';
            }
        }

        // Mode-specific UI: show/hide controls and center detections
        this.applyModeLayout();

        // Reflect mode in System Information
        const sysMode = document.getElementById('system-mode');
        if (sysMode) {
            sysMode.textContent = (this.mode === 'live') ? 'Live' : 'Simulation';
        }
    }

    initializeEventListeners() {
        console.log('Setting up event listeners...');
        
        // Capture controls
        const startBtn = document.getElementById('start-capture');
        const stopBtn = document.getElementById('stop-capture');
        const replayBtn = document.getElementById('replay-capture');
        const clearBtn = document.getElementById('clear-logs');
        
        if (startBtn) startBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('Start capture clicked');
            if (this.mode === 'live') {
                this.startCapture();
            } else {
                this.startReplay();
            }
        });
        
        if (stopBtn) stopBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('Stop capture clicked');
            this.stopCapture();
        });
        
        if (replayBtn) replayBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('Replay clicked');
            this.startReplay();
        });
        
        if (clearBtn) clearBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('Clear logs clicked');
            this.clearLogs();
        });

        // IP management
        const unblockBtn = document.getElementById('unblock-btn');
        const refreshBtn = document.getElementById('refresh-blocks');
        
        if (unblockBtn) unblockBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('Unblock clicked');
            this.unblockIP();
        });
        
        if (refreshBtn) refreshBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('Refresh blocks clicked');
            this.loadBlockedIPs();
        });

        // Export
        const exportBtn = document.getElementById('export-btn');
        if (exportBtn) exportBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('Export clicked');
            this.exportData();
        });
        
        console.log('Event listeners set up');
    }

    async loadInitialData() {
        console.log('Loading initial data...');
        try {
            await Promise.all([
                this.loadStatus(),
                this.loadStats(),
                this.loadLogs(),
                this.loadBlockedIPs()
            ]);
            console.log('Initial data loaded');
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.showToast('Error loading initial data: ' + error.message, 'danger');
        }
    }

    startPeriodicUpdates() {
        console.log('Starting periodic updates...');
        this.updateInterval = setInterval(() => {
            this.loadStatus();
            this.loadStats();
            // Always refresh logs while running live; in simulation, refresh for a short period after triggering
            if (this.captureRunning || this.mode === 'simulation') {
                this.loadLogs();
            }
        }, 2000);
    }

    async startCapture() {
        console.log('Starting capture...');
        try {
            const response = await fetch('/api/capture/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();
            console.log('Capture start response:', result);
            
            if (result.success) {
                this.captureRunning = true;
                this.updateCaptureUI(true);
                this.showToast('Live capture started successfully', 'success');
                this.addPacketToFeed('System', 'Capture started', 'safe');
            } else {
                this.showToast('Failed to start capture: ' + result.error, 'danger');
            }
        } catch (error) {
            console.error('Error starting capture:', error);
            this.showToast('Error starting capture: ' + error.message, 'danger');
        }
    }

    async stopCapture() {
        console.log('Stopping capture...');
        try {
            const response = await fetch('/api/capture/stop', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();
            console.log('Capture stop response:', result);
            
            if (result.success) {
                this.captureRunning = false;
                this.updateCaptureUI(false);
                this.showToast('Capture stopped successfully', 'info');
                this.addPacketToFeed('System', 'Capture stopped', 'safe');
            } else {
                this.showToast('Failed to stop capture: ' + result.error, 'danger');
            }
        } catch (error) {
            console.error('Error stopping capture:', error);
            this.showToast('Error stopping capture: ' + error.message, 'danger');
        }
    }

    async startReplay() {
        console.log('Starting replay...');
        try {
            this.showToast('Starting replay simulation...', 'info');
            const response = await fetch('/api/capture/replay', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();
            console.log('Replay response:', result);
            
            if (result.success) {
                this.showToast('Replay simulation completed', 'success');
                this.loadLogs();
                this.loadStats();
            } else {
                this.showToast('Replay failed: ' + result.error, 'danger');
            }
        } catch (error) {
            console.error('Error running replay:', error);
            this.showToast('Error running replay: ' + error.message, 'danger');
        }
    }

    async clearLogs() {
        if (!confirm('Are you sure you want to clear all logs? This cannot be undone.')) {
            return;
        }

        console.log('Clearing logs...');
        try {
            const response = await fetch('/api/clear-logs', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();
            console.log('Clear logs response:', result);
            
            if (result.success) {
                this.showToast('Logs cleared successfully', 'success');
                this.loadLogs();
                this.loadStats();
            } else {
                this.showToast('Failed to clear logs: ' + result.error, 'danger');
            }
        } catch (error) {
            console.error('Error clearing logs:', error);
            this.showToast('Error clearing logs: ' + error.message, 'danger');
        }
    }

    async loadStatus() {
        try {
            const response = await fetch('/api/status');
            const status = await response.json();
            
            if (status.capture) {
                this.captureRunning = status.capture.running;
                this.updateCaptureUI(this.captureRunning);
                
                if (this.captureRunning) {
                    const packetCountEl = document.getElementById('packet-count');
                    const flaggedCountEl = document.getElementById('flagged-count');
                    const runtimeEl = document.getElementById('runtime');
                    
                    if (packetCountEl) packetCountEl.textContent = status.capture.packets || 0;
                    if (flaggedCountEl) flaggedCountEl.textContent = status.capture.flagged || 0;
                    
                    if (status.capture.start_time && runtimeEl) {
                        const startTime = new Date(status.capture.start_time);
                        const runtime = Math.floor((Date.now() - startTime.getTime()) / 1000);
                        runtimeEl.textContent = this.formatRuntime(runtime);
                    }
                }
            }

            if (status.system) {
                const totalDetectionsEl = document.getElementById('total-detections');
                const totalBlockedEl = document.getElementById('total-blocked');
                const lastUpdatedEl = document.getElementById('last-updated');
                
                if (totalDetectionsEl) totalDetectionsEl.textContent = status.system.total_detections || 0;
                if (totalBlockedEl) totalBlockedEl.textContent = status.system.total_blocked || 0;
                if (lastUpdatedEl) lastUpdatedEl.textContent = this.formatTimestamp(status.system.last_updated);
            }

            // Update status badge
            const statusBadge = document.getElementById('status-badge');
            if (statusBadge) {
                if (this.captureRunning) {
                    statusBadge.textContent = 'Capture Running';
                    statusBadge.className = 'badge bg-success';
                } else {
                    statusBadge.textContent = 'System Ready';
                    statusBadge.className = 'badge bg-secondary';
                }
            }
        } catch (error) {
            console.error('Error loading status:', error);
        }
    }

    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            
            if (stats.mitigation) {
                const highConfidenceEl = document.getElementById('high-confidence');
                if (highConfidenceEl) {
                    highConfidenceEl.textContent = stats.mitigation.high_confidence || 0;
                }
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    async loadLogs() {
        try {
            const response = await fetch('/api/logs');
            const logs = await response.json();
            
            this.displayRecentDetections(logs.slice(0, 10));
        } catch (error) {
            console.error('Error loading logs:', error);
        }
    }

    async loadBlockedIPs() {
        try {
            const response = await fetch('/api/blocks');
            const blocks = await response.json();
            
            this.displayBlockedIPs(blocks);
        } catch (error) {
            console.error('Error loading blocked IPs:', error);
        }
    }

    async unblockIP() {
        const ipInput = document.getElementById('unblock-ip');
        const ip = ipInput ? ipInput.value.trim() : '';
        
        if (!ip) {
            this.showToast('Please enter an IP address', 'warning');
            return;
        }

        console.log('Unblocking IP:', ip);
        try {
            const response = await fetch('/api/unblock', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip: ip })
            });

            const result = await response.json();
            console.log('Unblock response:', result);
            
            if (result.success) {
                this.showToast(`IP ${ip} unblocked successfully`, 'success');
                if (ipInput) ipInput.value = '';
                this.loadBlockedIPs();
            } else {
                this.showToast('Failed to unblock IP: ' + result.message, 'danger');
            }
        } catch (error) {
            console.error('Error unblocking IP:', error);
            this.showToast('Error unblocking IP: ' + error.message, 'danger');
        }
    }

    async exportData() {
        const typeSelect = document.getElementById('export-type');
        const formatSelect = document.getElementById('export-format');
        const hoursInput = document.getElementById('export-hours');
        
        const type = typeSelect ? typeSelect.value : 'logs';
        const format = formatSelect ? formatSelect.value : 'json';
        const hours = hoursInput ? hoursInput.value : '';

        console.log('Exporting data:', { type, format, hours });
        try {
            const response = await fetch('/api/export', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    type: type,
                    format: format,
                    hours: hours ? parseInt(hours) : null
                })
            });

            const result = await response.json();
            console.log('Export response:', result);
            
            if (result.success) {
                this.showToast('Data exported successfully', 'success');
            } else {
                this.showToast('Export failed: ' + result.message, 'danger');
            }
        } catch (error) {
            console.error('Error exporting data:', error);
            this.showToast('Error exporting data: ' + error.message, 'danger');
        }
    }

    updateCaptureUI(running) {
        const startBtn = document.getElementById('start-capture');
        const stopBtn = document.getElementById('stop-capture');
        
        if (startBtn && stopBtn) {
            if (running) {
                startBtn.disabled = true;
                stopBtn.disabled = (this.mode !== 'live');
                startBtn.innerHTML = '<i class="fas fa-play"></i> Capture Running...';
                stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop Capture';
            } else {
                startBtn.disabled = false;
                stopBtn.disabled = true;
                if (this.mode === 'live') {
                    startBtn.innerHTML = '<i class="fas fa-play"></i> Start Live Capture';
                } else {
                    startBtn.innerHTML = '<i class="fas fa-play"></i> Run Replay';
                }
                stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop Capture';
            }
        }
    }

    applyModeLayout() {
        const startBtn = document.getElementById('start-capture');
        const stopBtn = document.getElementById('stop-capture');
        const replayBtn = document.getElementById('replay-capture');
        const clearBtn = document.getElementById('clear-logs');
        const liveFeedCol = document.getElementById('live-feed-col');
        const recentCol = document.getElementById('recent-detections-col');

        if (this.mode === 'live') {
            // Show only Start Live, Stop, Clear Logs
            if (startBtn) startBtn.style.display = '';
            if (stopBtn) stopBtn.style.display = '';
            if (clearBtn) clearBtn.style.display = '';
            if (replayBtn) replayBtn.style.display = 'none';

            // Keep live feed visible, keep layout as 8/4
            if (liveFeedCol) liveFeedCol.style.display = '';
            if (recentCol) {
                recentCol.classList.remove('col-md-12');
                recentCol.classList.remove('offset-md-0');
                recentCol.classList.remove('col-lg-6');
                recentCol.classList.remove('offset-lg-3');
                recentCol.classList.add('col-md-4');
            }
        } else {
            // Simulation: Show only Run Simulation and Clear Logs
            if (startBtn) startBtn.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'none';
            if (clearBtn) clearBtn.style.display = '';
            if (replayBtn) replayBtn.style.display = '';

            // Hide live feed, center recent detections
            if (liveFeedCol) liveFeedCol.style.display = 'none';
            if (recentCol) {
                recentCol.classList.remove('col-md-4');
                recentCol.classList.add('col-md-12');
                recentCol.classList.add('col-lg-6');
                recentCol.classList.add('offset-lg-3');
            }
        }
    }

    displayRecentDetections(detections) {
        if (!this.recentDetections) return;
        
        if (detections.length === 0) {
            this.recentDetections.innerHTML = `
                <div class="text-muted text-center py-4">
                    <i class="fas fa-search fa-2x mb-3"></i>
                    <p>No detections yet</p>
                </div>
            `;
            return;
        }

        this.recentDetections.innerHTML = detections.map(detection => `
            <div class="detection-item ${detection.confidence || 'low-confidence'}">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <strong>${detection.src_ip}</strong>
                        <span class="text-muted">→ ${detection.dst_ip || 'Unknown'}</span>
                    </div>
                    <span class="badge bg-${this.getConfidenceColor(detection.confidence)}">
                        ${detection.confidence || 'low'}
                    </span>
                </div>
                <div class="mt-2">
                    <strong>${detection.indicator}</strong>: ${detection.reason}
                </div>
                <div class="text-muted small mt-1">
                    ${this.formatTimestamp(detection.timestamp)}
                </div>
            </div>
        `).join('');
    }

    displayBlockedIPs(blocks) {
        const tbody = document.getElementById('blocked-ips-tbody');
        if (!tbody) return;
        
        if (blocks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No blocked IPs</td></tr>';
            return;
        }

        tbody.innerHTML = blocks.map(block => `
            <tr>
                <td><code>${block.ip}</code></td>
                <td>${block.reason}</td>
                <td><span class="badge bg-${this.getConfidenceColor(block.confidence)}">${block.confidence}</span></td>
                <td>${this.formatTimestamp(block.blocked_until)}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="dashboard.unblockSpecificIP('${block.ip}')">
                        <i class="fas fa-unlock"></i> Unblock
                    </button>
                </td>
            </tr>
        `).join('');
    }

    async unblockSpecificIP(ip) {
        console.log('Unblocking specific IP:', ip);
        try {
            const response = await fetch('/api/unblock', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip: ip })
            });

            const result = await response.json();
            console.log('Unblock specific IP response:', result);
            
            if (result.success) {
                this.showToast(`IP ${ip} unblocked successfully`, 'success');
                this.loadBlockedIPs();
            } else {
                this.showToast('Failed to unblock IP: ' + result.message, 'danger');
            }
        } catch (error) {
            console.error('Error unblocking specific IP:', error);
            this.showToast('Error unblocking IP: ' + error.message, 'danger');
        }
    }

    addPacketToFeed(src, message, type) {
        if (!this.packetFeed) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const packetElement = document.createElement('div');
        packetElement.className = `packet-item ${type}`;
        packetElement.innerHTML = `
            <div class="d-flex justify-content-between">
                <span><strong>${src}</strong>: ${message}</span>
                <span class="text-muted">${timestamp}</span>
            </div>
        `;
        
        this.packetFeed.insertBefore(packetElement, this.packetFeed.firstChild);
        
        // Keep only last 50 items
        while (this.packetFeed.children.length > 50) {
            this.packetFeed.removeChild(this.packetFeed.lastChild);
        }
    }

    getConfidenceColor(confidence) {
        switch (confidence) {
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'secondary';
        }
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return 'Never';
        const date = new Date(timestamp);
        return date.toLocaleString();
    }

    formatRuntime(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        
        if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    }

    showToast(message, type = 'info') {
        const toast = document.getElementById('toast');
        const toastBody = document.getElementById('toast-body');
        
        if (!toast || !toastBody) {
            console.log('Toast notification:', message);
            return;
        }
        
        toastBody.textContent = message;
        
        // Update toast styling based on type
        const toastHeader = toast.querySelector('.toast-header');
        const icon = toastHeader.querySelector('i');
        
        if (icon) {
            icon.className = `fas me-2 text-${type === 'danger' ? 'danger' : type === 'success' ? 'success' : type === 'warning' ? 'warning' : 'info'}`;
            
            if (type === 'danger') {
                icon.className = 'fas fa-exclamation-triangle me-2 text-danger';
            } else if (type === 'success') {
                icon.className = 'fas fa-check-circle me-2 text-success';
            } else if (type === 'warning') {
                icon.className = 'fas fa-exclamation-circle me-2 text-warning';
            } else {
                icon.className = 'fas fa-info-circle me-2 text-info';
            }
        }
        
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
    }
}

// Initialize dashboard when page loads
console.log('Loading dashboard script...');
window.dashboard = new TrafficAnalysisDashboard();