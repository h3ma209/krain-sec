<p align="center">
  <img src="https://github.com/h3ma209/krain-sec/blob/master/icon.png" width="256"/>
</p>
<h1 align="center">Golang Cybersecurity Honeypot 🛡️</h1>

<p align="center">
  <strong>An advanced open-source honeypot framework built in Go for threat intelligence and attack analysis</strong>
</p>

---

**(IN DEVELOPMENT)**

## ✨ Features

- [x] **Honeypot**  
  A sophisticated honeypot that listens for suspicious connections and logs attacker activity with detailed analytics. Captures attack patterns, payloads, and behavioral data for comprehensive threat intelligence.

- [x] **Port Scanner Detection**  
  Advanced port scanning detection that identifies reconnaissance activities and logs scanning patterns to detect coordinated attacks.

- [ ] **SSH Brute-Force Trap**  
  Intelligent SSH honeypot that captures brute-force attempts, credential lists, and connection metadata while simulating realistic SSH responses.

- [ ] **Intrusion Detection System (IDS)**  
  Planned: A lightweight, high-performance IDS engine for real-time traffic monitoring and anomaly detection with customizable rules.

- [ ] **HTTP Honeypot Pages**  
  Planned: Dynamic fake HTTP endpoints with realistic web applications to attract and analyze web-based attacks including SQL injection, XSS, and directory traversal attempts.

- [ ] **Advanced Analytics Dashboard**  
  Planned: Real-time visualization dashboard for attack patterns, geographic distribution, and threat intelligence with exportable reports.

- [ ] **More Advanced Features Coming Soon...**  
  Future enhancements include:
  - Multi-protocol honeypots (FTP, Telnet, SMB)
  - Machine learning-based anomaly detection
  - Integration with threat intelligence feeds
  - Docker containerization for easy deployment
  - RESTful API for external integrations
  - Automated malware analysis sandbox
  - Custom alert notifications (Slack, Discord, email)

---

## 🚀 Getting Started

### Prerequisites
- Go 1.21 or higher
- Linux/Unix environment (recommended)
- Root privileges for low port binding

### Installation

**Clone and run:**
```bash
git clone https://github.com/h3ma209/krain-sec.git
cd krain-sec
go mod tidy
sudo go run main.go
```

### Configuration
The honeypot uses sensible defaults but can be configured from the main.go:
```
/main.go

honeypot.AddService("HTTP", 8080)
honeypot.AddService("SSH", 2222)

```

---

## 📊 Usage

Once running, the honeypot will:
- Listen on configured ports for incoming connections
- Log all interaction attempts with timestamps and source IPs
- Generate detailed reports of attack patterns(soon)
- Store captured data in structured CSV format

View logs in real-time in the CSV files

---

## 🤝 Contributing

We welcome contributions! Feel free to:
- Submit bug reports and feature requests
- Contribute code improvements
- Add new honeypot modules
- Improve documentation

---

## 📄 License

This project is open-source. Please see LICENSE file for details.

---

**⚠️ Disclaimer:** This tool is for educational and research purposes only. Deploy responsibly and in compliance with applicable laws and regulations.
