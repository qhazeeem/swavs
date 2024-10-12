# SWAVS (Simple Web Application Vulnerability Scanner)

![SWAVS Banner](docs/images/banner.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

A lightweight, powerful web application vulnerability scanner focused on simplicity and efficiency.

## 🚀 Features

- 🔍 Comprehensive port scanning (1-1024)
- 🌐 Service detection and identification
- 🛡️ Operating system fingerprinting
- 🚨 Web vulnerability assessment including:
  - SQL Injection detection
  - XSS vulnerability checks
  - Directory traversal testing
  - Security headers analysis
  - SSL/TLS configuration checks
- 📊 Clean, formatted output
- ⚡ Multi-threaded scanning
- 🔒 OWASP Top 10 vulnerability checks

## 📋 Prerequisites

- Python 3.7 or higher
- Works on Linux, Windows, and macOS

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/qhazeem/swavs.git

# Navigate to project directory
cd swavs

# Install required packages
pip install -r requirements.txt

# Run the scanner
python -m swavs
```

## 💻 Usage

```bash
python -m swavs
```

You'll be prompted to enter the target host (IP address or domain name).

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and ethical testing purposes only. Always obtain proper authorization before scanning any systems you don't own or have explicit permission to test.

## 👥 Author

- [@qhazeem](https://github.com/qhazeem)

## 🌟 Show your support

Give a ⭐️ if this project helped you!
