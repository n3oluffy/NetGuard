# 🛡️ NetGuard – Network Security Monitoring Tool

**Version:** 1.0  
**Language:** Python 3  
**Platform:** Kali Linux / Linux  
**Project Type:** Cybersecurity Portfolio Project

## 📌 Project Overview

NetGuard is a Python-based network security monitoring tool designed to help users identify network information, check host availability, scan TCP ports, analyze potential security risks, and generate security reports.

This project was developed as a hands-on cybersecurity learning project.

## 🚀 Features

- **Network Information:** Retrieve hostname and IP address.
- **IP Validation:** Validate IPv4 addresses.
- **Host Availability:** Check whether an authorized target is reachable.
- **Port Scanning:** Scan configured TCP ports.
- **Service Detection:** Identify services where supported by the scanner.
- **Security Analysis:** Analyze scan results using configured security rules.
- **Security Logging:** Record application activities.
- **TXT Reports:** Generate readable security reports.
- **CSV Reports:** Export scan results for further analysis.

## 🛠️ Technologies Used

- Python 3
- Kali Linux
- TCP/IP Networking
- Python Socket Programming
- Python Logging
- CSV and File Handling

## 📂 Project Structure

```text
NetGuard/
│
├── main.py
├── main.py.bak
├── README.md
├── requirements.txt
│
├── modules/
│
├── reports/
│
├── logs/
│
├── backups/
│
└── NetGuard_v1.1_backup.tar.gz
```

## ⚙️ Installation

### 1. Clone or download the project

### 2. Open the project directory

```bash
cd NetGuard
```

### 3. Check Python version

```bash
python3 --version
```

### 4. Run NetGuard

```bash
python3 main.py
```

No external Python packages are currently required.

## 💻 How to Use

After running the application, the main menu provides these options:

1. Network Information
2. Host Availability Check
3. Port Scanning & Security Analysis
4. View Security Reports
5. View Application Logs
6. Exit

Follow the on-screen instructions to perform the required operation.

Only scan systems you own or have explicit permission to test.

## 📊 Report Generation

NetGuard generates two types of reports:

- TXT – Human-readable security reports.
- CSV – Structured scan results.

Reports are stored in the `reports/` directory.

## 📝 Application Logs

Application activity is recorded in:

```text
logs/netguard.log
```

## 🔐 Security Disclaimer

NetGuard is developed for educational and authorized security testing purposes.

Users must only scan networks and devices they own or have explicit permission to assess.

The developer is not responsible for unauthorized or illegal use of this software.

## 🎯 Learning Objectives

This project demonstrates practical knowledge of:

- Python programming
- Network communication
- TCP port scanning
- IP address validation
- Basic security analysis
- Logging and reporting
- Cybersecurity tool development

## 👨‍💻 Project Information

**Project:** NetGuard  
**Category:** Cybersecurity / Network Security  
**Version:** 1.0  
**Environment:** Kali Linux  
**Programming Language:** Python 3

---

*Built as a practical cybersecurity learning and portfolio project.*
