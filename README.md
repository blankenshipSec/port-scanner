# 🔍 Port Scanner

> A fast, multithreaded CLI-based TCP port scanner for security reconnaissance.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Built by [blankenshipSec](https://github.com/blankenshipSec) | [Portfolio](https://jblankenship.me)

## ✨ Features

- **Multithreaded Scanning** — Scans multiple ports simultaneously for fast results
- **Banner Grabbing** — Attempts to identify services running on open ports
- **Common Port Defaults** — Includes 17 of the most security-relevant ports out of the box
- **Rich Terminal Output** — Color coded, formatted table display for clean readability
- **Export Results** — Save scan output to a text file for reporting
- **Flexible CLI** — Full control over target, port range, threads, and timeout

## 📋 Requirements

- Python 3.10+
- [rich](https://github.com/Textualize/rich)

Install dependencies:
```bash
pip install -r requirements.txt
```

## 🚀 Installation
```bash
git clone git@github.com:blankenshipSec/port-scanner.git
cd port-scanner
python -m venv venv
source venv/Scripts/activate  # Windows
pip install -r requirements.txt
```

## 🛠️ Usage
```bash
python scanner.py -t <target> [options]
```

### Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--target` | `-t` | Required | Target IP address or hostname |
| `--ports` | `-p` | `common` | Port range (e.g. `1-1000`) or `common` |
| `--threads` | None | `100` | Number of concurrent threads |
| `--timeout` | None | `1.0` | Connection timeout in seconds |
| `--output` | `-o` | None | Save results to a file |

### Examples
```bash
# Scan common ports on a target
python scanner.py -t 192.168.1.1

# Scan a specific port range
python scanner.py -t 192.168.1.1 -p 1-1000

# Scan with custom threads and timeout
python scanner.py -t 192.168.1.1 -p 1-65535 --threads 200 --timeout 0.5

# Save results to a file
python scanner.py -t 192.168.1.1 -o results.txt
```

## 📊 Example Output
```
blankenshipSec Port Scanner
For authorized use only.

Target: localhost (127.0.0.1)
Ports: 17 ports queued
Threads: 100
Timeout: 1.0s

Scanning 127.0.0.1... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

Scan Complete
Target: localhost
Open Ports: 2
Scanned: 17 ports
Duration: 1s

                      Open Ports
┏━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Port       ┃ State      ┃ Service         ┃ Banner ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ 135        │ open       │ RPC             │ N/A    │
│ 445        │ open       │ SMB             │ N/A    │
└────────────┴────────────┴─────────────────┴────────┘
```

## ⚠️ Known Limitations & Roadmap

### Current Limitations
- Banner grabbing uses a generic HTTP request and may not return banners for all services
- UDP scanning is not currently supported
- No OS detection

### Planned Improvements
- [ ] Improve banner grabbing with service-specific probes
- [ ] Add UDP port scanning
- [ ] Add OS fingerprinting
- [ ] Add CVE lookup for identified services
- [ ] Add JSON export format

## ⚖️ Legal Disclaimer

This tool is intended for **authorized security testing and educational purposes only**.
Scanning networks or systems without explicit permission is illegal and unethical.
The author assumes no liability for misuse of this tool.
Always obtain proper authorization before scanning any target.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

*Built with Python & [Rich](https://github.com/Textualize/rich) | [blankenshipSec](https://github.com/blankenshipSec)*