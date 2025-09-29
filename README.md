# CCTV ML - Automated Vulnerability Assessment and Penetration Testing Tool

<div align="center">

![CCTV ML Logo](https://img.shields.io/badge/CCTV-ML-blue?style=for-the-badge&logo=security&logoColor=white)

**🔒 AI-Powered Security Testing for CCTV Cameras & DVRs 🔒**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-focused-red.svg)](https://github.com/aryamanpathak2022/cctv_ml)

</div>

---

## 🎯 Overview

**CCTV ML** is a specialized, AI-powered vulnerability assessment and penetration testing tool designed specifically for CCTV cameras, DVRs, and NVRs. It replaces slow, expensive manual security audits with continuous, automated monitoring capable of assessing millions of devices.

### 🚀 Key Features

- **🤖 AI-Powered Vulnerability Prediction**: First-of-its-kind zero-day vulnerability prediction for CCTV systems
- **🔍 Comprehensive Device Discovery**: Automated discovery and fingerprinting of CCTV devices across networks
- **⚡ Automated Exploitation**: Safe exploitation framework for vulnerability validation
- **🌍 Global Threat Intelligence**: Real-time correlation with global vulnerability databases
- **📊 Interactive Dashboard**: Cloud-based dashboard for vulnerability visualization and reporting
- **🔒 Security-First Design**: Built with safety modes and ethical testing principles

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CCTV ML Platform                        │
├─────────────────────────────────────────────────────────────┤
│  Web Dashboard  │  CLI Interface  │  REST API  │  Reports  │
├─────────────────────────────────────────────────────────────┤
│           Core Vulnerability Assessment Engine             │
├─────────────────────────────────────────────────────────────┤
│ Device Scanner │ AI Predictor │ Exploit Engine │ Database │
├─────────────────────────────────────────────────────────────┤
│   Network      │   Machine     │   Automated   │  Threat  │
│   Discovery    │   Learning    │   Exploitation│   Intel  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Network access to target CCTV devices

### Quick Install

```bash
# Clone the repository
git clone https://github.com/aryamanpathak2022/cctv_ml.git
cd cctv_ml

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Docker Installation (Coming Soon)

```bash
docker pull cctvml/vulnerability-scanner:latest
docker run -it cctvml/vulnerability-scanner
```

---

## 🚀 Quick Start

### Command Line Interface

```bash
# Run a comprehensive scan on a network range
cctv-scanner scan -t 192.168.1.0/24

# Discover CCTV devices only
cctv-scanner scan -t 192.168.1.100-200 --type discovery

# Run vulnerability assessment with AI predictions
cctv-scanner scan -t 10.0.0.0/24 --type vulnerability -o results.json

# Start the web dashboard
cctv-scanner dashboard
```

### Python API

```python
import asyncio
from cctv_ml import VulnerabilityAssessmentEngine

async def main():
    # Initialize the assessment engine
    engine = VulnerabilityAssessmentEngine()
    
    # Run comprehensive assessment
    results = await engine.run_full_assessment(['192.168.1.0/24'])
    
    print(f"Found {results['summary']['devices_discovered']} devices")
    print(f"Discovered {results['summary']['vulnerabilities_found']} vulnerabilities")

asyncio.run(main())
```

---

## 🎯 Supported Devices

### CCTV Cameras
- **Hikvision** (DS-2CD series, DS-2DE series)
- **Dahua** (IPC series, DH series)
- **Axis** (AXIS M series, AXIS P series)
- **Foscam** (FI series, R series)
- **TP-Link** (Tapo, Kasa series)
- **Ubiquiti** (UniFi Protect series)
- **Sony** (SNC series)
- **Panasonic** (WV series)
- **Generic IP Cameras**

### DVR/NVR Systems
- **Hikvision DVRs** (DS-7xxx series)
- **Dahua DVRs** (XVR series, NVR series)
- **Synology Surveillance Station**
- **QNAP QVR Pro**
- **Generic DVR Systems**

---

## 🔍 Vulnerability Detection

### Known Vulnerabilities
- **Authentication Bypass** (CVE-2017-7921, CVE-2019-3929)
- **Default Credentials** (Manufacturer-specific databases)
- **Remote Code Execution** (CVE-2020-25078, CVE-2021-33044)
- **Directory Traversal** (Path traversal attacks)
- **Command Injection** (CGI parameter injection)
- **Information Disclosure** (Configuration file exposure)

### AI-Predicted Vulnerabilities
- **Zero-day RCE Patterns** (ML-based prediction)
- **Authentication Weaknesses** (Behavioral analysis)
- **Protocol Vulnerabilities** (RTSP, HTTP analysis)
- **Firmware Vulnerabilities** (Version-based risk assessment)

---

## 📊 Web Dashboard

Access the interactive dashboard at `http://localhost:5000` after running:

```bash
cctv-scanner dashboard
```

### Dashboard Features
- **Real-time Vulnerability Monitoring**
- **Global Threat Map**
- **Device Inventory Management** 
- **Risk Assessment Reports**
- **Automated Scan Scheduling**
- **Threat Intelligence Integration**

---

## ⚙️ Configuration

### Environment Variables

```bash
export CCTV_LOG_LEVEL=INFO
export CCTV_DB_PATH=./vulnerability_db/cctv_vulns.db
export CCTV_MAX_SCANS=50
export CCTV_SAFE_MODE=true
export SHODAN_API_KEY=your_shodan_key
export CENSYS_API_ID=your_censys_id
```

### Configuration File

Create `config/custom.yaml`:

```yaml
scanning:
  max_concurrent_scans: 100
  timeout_seconds: 45

ai:
  prediction_threshold: 0.8
  max_predictions_per_device: 15

exploitation:
  enabled: true
  safe_mode: true
  
dashboard:
  host: '0.0.0.0'
  port: 8080
```

---

## 🔒 Security & Ethics

### Ethical Usage
- **Only scan systems you own or have explicit permission to test**
- **Use safe mode by default to prevent system damage**
- **Respect local laws and regulations**
- **Report discovered vulnerabilities responsibly**

### Safety Features
- **Safe Mode**: Prevents destructive exploitation attempts
- **Rate Limiting**: Prevents overwhelming target systems
- **Logging**: Comprehensive audit trail of all activities
- **Encryption**: Secure storage of sensitive scan results

---

## 📖 Documentation

### Command Reference

```bash
# Scan Commands
cctv-scanner scan -t <targets> [--type <scan_type>] [--output <file>]

# Device Management
cctv-scanner devices [--severity <level>]

# Reporting
cctv-scanner summary [--days <number>]

# Dashboard
cctv-scanner dashboard [--host <ip>] [--port <port>]
```

### API Documentation

Full API documentation is available at `http://localhost:5000/api/docs` when the dashboard is running.

---

## 🤝 Contributing

We welcome contributions from the security community!

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/aryamanpathak2022/cctv_ml.git
cd cctv_ml

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
python -m pytest cctv_ml/tests/

# Start development dashboard
python -m cctv_ml.dashboard.app
```

### Contribution Guidelines
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for complying with applicable laws and regulations. The developers assume no liability for misuse of this software.

---

## 🙏 Acknowledgments

- **MITRE Corporation** for CVE database
- **NIST** for vulnerability scoring standards
- **Security research community** for vulnerability discoveries
- **Open source contributors** who make this project possible

---

## 📞 Support

- **Documentation**: [https://cctvml.readthedocs.io](https://cctvml.readthedocs.io)
- **Issues**: [GitHub Issues](https://github.com/aryamanpathak2022/cctv_ml/issues)
- **Discussions**: [GitHub Discussions](https://github.com/aryamanpathak2022/cctv_ml/discussions)
- **Security Issues**: security@cctvml.com

---

<div align="center">

**Made with ❤️ for CCTV Security**

[⭐ Star this project](https://github.com/aryamanpathak2022/cctv_ml) | [🐛 Report Bug](https://github.com/aryamanpathak2022/cctv_ml/issues) | [✨ Request Feature](https://github.com/aryamanpathak2022/cctv_ml/issues)

</div>