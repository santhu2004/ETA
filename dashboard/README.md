# Encrypted Traffic Analysis Dashboard

A lightweight, attractive web-based GUI for the Encrypted Traffic Analysis System.

## 🎯 Features

### Main Dashboard
- **Live Traffic Capture**: Start/stop button with real-time status
- **Replay Simulation**: Test with simulated data
- **Live Packet Feed**: Real-time visualization of captured packets
- **Threat Detection**: Highlighted malicious packets with color coding
- **Statistics Dashboard**: Real-time metrics and system status

### Management Features
- **Blocked IPs Management**: View and unblock IPs
- **Detection Logs**: Recent threat detections with details
- **Data Export**: Export logs and blocked IPs in multiple formats
- **System Information**: Current configuration and status

### Visual Design
- **Clean Interface**: Modern, intuitive layout
- **Real-time Updates**: Live data refresh every 2 seconds
- **Color-coded Alerts**: Red for malicious, yellow for suspicious, green for safe
- **Responsive Design**: Works on desktop and mobile devices
- **Toast Notifications**: User-friendly feedback messages

## 🚀 Quick Start

### Prerequisites
- Python 3.7+ with virtual environment
- All CLI dependencies installed
- sudo permissions for live capture

### Installation

1. **Navigate to the dashboard directory:**
   ```bash
   cd dashboard
   ```

2. **Start the dashboard:**
   ```bash
   python start_dashboard.py
   ```

3. **Open your browser:**
   ```
   http://localhost:5000
   ```

### Alternative Manual Start

1. **Install dashboard dependencies:**
   ```bash
   source ../venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Start the Flask app:**
   ```bash
   python backend/app.py
   ```

## 🎮 Usage

### Starting Live Capture
1. Click **"Start Live Capture"** button
2. The system will request sudo permissions
3. Watch the live packet feed for real-time analysis
4. Click **"Stop Capture"** to stop monitoring

### Testing with Simulation
1. Click **"Replay Simulation"** button
2. The system generates test data and runs analysis
3. View results in the detection logs

### Managing Blocked IPs
1. View blocked IPs in the management table
2. Enter an IP address to unblock
3. Click **"Unblock"** to remove the block

### Exporting Data
1. Select data type (logs or blocks)
2. Choose format (JSON, CSV, or TXT)
3. Optionally specify time range in hours
4. Click **"Export"** to download data

## 🏗️ Architecture

### Backend (Flask)
- **REST API**: Wraps all CLI functionality
- **Real-time Status**: Live capture monitoring
- **Data Management**: Logs, blocks, and statistics
- **Export Functions**: Multiple format support

### Frontend (HTML/CSS/JS)
- **Bootstrap 5**: Modern UI framework
- **Font Awesome**: Professional icons
- **Custom CSS**: Traffic analysis styling
- **Vanilla JavaScript**: No heavy frameworks

### Integration
- **CLI Wrapper**: All functions call existing CLI commands
- **Sudo Handling**: Transparent permission management
- **Environment Setup**: Automatic virtual environment detection
- **Error Handling**: User-friendly error messages

## 📁 File Structure

```
dashboard/
├── backend/
│   └── app.py                 # Flask backend with REST API
├── frontend/
│   ├── templates/
│   │   └── index.html         # Main dashboard page
│   └── static/
│       ├── css/
│       │   └── dashboard.css   # Custom styling
│       └── js/
│           └── dashboard.js   # Frontend functionality
├── requirements.txt           # Dashboard dependencies
├── start_dashboard.py        # Startup script
└── README.md                 # This file
```

## 🔧 Configuration

The dashboard uses the same `config.yaml` as the CLI system:

```yaml
# Network interface for packet capture
interface: eth0

# Operation mode: simulate (default) or enforce
mode: simulate

# Paths configuration
paths:
  outputs_dir: outputs
  data_dir: outputs/data
  logs_dir: outputs/logs
  state_dir: outputs/state
  exports_dir: outputs/exports
```

## 🎨 Customization

### Styling
- Edit `frontend/static/css/dashboard.css` for custom colors and layouts
- Modify `frontend/templates/index.html` for UI changes
- Update `frontend/static/js/dashboard.js` for functionality changes

### API Endpoints
- Add new endpoints in `backend/app.py`
- Follow the existing pattern for CLI integration
- Use proper error handling and JSON responses

## 🚨 Security Notes

- **Sudo Required**: Live capture needs elevated permissions
- **Local Access**: Dashboard runs on localhost by default
- **Simulation Mode**: Safe testing without affecting real traffic
- **Data Privacy**: All analysis performed locally

## 🐛 Troubleshooting

### Common Issues

1. **"No packet capture engines available"**
   - Ensure virtual environment is activated
   - Check that PyShark/Scapy are installed
   - Use sudo for live capture

2. **Dashboard won't start**
   - Check Python version (3.7+)
   - Install dashboard dependencies
   - Verify project structure

3. **Live capture fails**
   - Ensure sudo permissions
   - Check network interface configuration
   - Verify capture engine availability

### Debug Mode
- Set `FLASK_ENV=development` for debug output
- Check browser console for JavaScript errors
- Monitor Flask logs for backend issues

## 🔄 Updates

The dashboard automatically reflects changes to:
- CLI functionality
- Configuration settings
- Detection rules
- System status

No restart required for most changes.

## 📊 Performance

- **Lightweight**: Minimal dependencies
- **Fast**: Real-time updates every 2 seconds
- **Efficient**: Reuses existing CLI infrastructure
- **Scalable**: Easy to extend with new features

## 🤝 Contributing

To add new features:
1. Update backend API in `app.py`
2. Add frontend UI in `index.html`
3. Implement JavaScript in `dashboard.js`
4. Style with CSS in `dashboard.css`
5. Test with both CLI and GUI

## 📄 License

Same as the main project - MIT License.
