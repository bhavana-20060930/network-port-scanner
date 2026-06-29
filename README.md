# 🔍 Network Port Scanner

A clean, multithreaded **TCP port scanner** built in Python — scan a target IP for open ports, identify running services (HTTP, SSH, FTP…), and export results to TXT or CSV reports.

> Built as part of my cybersecurity learning journey. A great beginner-to-intermediate project covering sockets, threading, and TCP/IP fundamentals.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🎯 Single IP scanning | Provide any IP address or hostname |
| 📊 Port range control | Specify any `--start` and `--end` port |
| 🏷️ Service detection | Resolves well-known service names (HTTP, SSH, FTP…) |
| ⚡ Multithreaded | Concurrent scanning via `ThreadPoolExecutor` |
| 📁 Report export | Save results as `.txt` or `.csv` (or both) |
| 📡 Live progress | Real-time console progress while scanning |

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/network-port-scanner.git
cd network-port-scanner
```

### 2. (Optional) Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

### 3. No extra dependencies — uses Python standard library only!

---

## 🛠️ Usage

```bash
python scanner.py <target> [options]
```

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--start` | `-s` | `1` | Start port |
| `--end` | `-e` | `1024` | End port |
| `--timeout` | `-t` | `1.0` | Socket timeout (seconds) |
| `--threads` | `-T` | `100` | Max concurrent threads |
| `--format` | `-f` | `txt` | Report format: `txt`, `csv`, or `both` |
| `--output` | `-o` | `scan_results` | Output filename prefix |

### Examples

```bash
# Scan localhost, ports 1-1024 (default)
python scanner.py 127.0.0.1

# Scan a hostname, ports 20-100, save as CSV
python scanner.py scanme.nmap.org --start 20 --end 100 --format csv

# Scan with 200 threads and 0.5s timeout
python scanner.py 192.168.1.1 --threads 200 --timeout 0.5

# Save both TXT and CSV reports
python scanner.py 10.0.0.1 --format both --output my_scan
```

---

## 📄 Sample Output

```
==================================================
  Network Port Scanner
==================================================
  Target  : scanme.nmap.org (45.33.32.156)
  Ports   : 1 – 1024
  Threads : 100
  Timeout : 1.0s
==================================================

  Scanning port   443 … 1024/1024 done

  Scan completed in 12.34s
  Open ports found: 3

  PORT      STATUS      SERVICE
  ---------------------------------
  22        OPEN        ssh
  80        OPEN        http
  443       OPEN        https

  [+] TXT report saved → scan_results.txt
```

---

## 🧠 Concepts Covered

- **Socket Programming** — `socket.SOCK_STREAM`, `connect_ex()`, timeouts
- **TCP/IP** — How TCP handshakes work; open vs closed vs filtered ports
- **Multithreading** — `ThreadPoolExecutor` for concurrent port scanning
- **CLI Design** — `argparse` for professional command-line interfaces
- **File I/O** — Writing structured TXT and CSV reports

---

## ⚠️ Legal & Ethical Use

> **Only scan systems you own or have explicit permission to scan.**  
> Unauthorized port scanning may be illegal in your jurisdiction.  
> This tool is for educational purposes and authorized security assessments only.

---

## 📁 Project Structure

```
network-port-scanner/
│
├── scanner.py          # Main scanner — all logic lives here
├── scan_results.txt    # Example TXT report (generated after a scan)
├── scan_results.csv    # Example CSV report (generated after a scan)
└── README.md           # This file
```

---

## 🔮 Future Improvements

- [ ] UDP scanning support
- [ ] Banner grabbing (detect software versions)
- [ ] OS fingerprinting
- [ ] JSON report export
- [ ] GUI with Tkinter or a web dashboard

---

## 👤 Author

**Your Name**  
🌐 [LinkedIn](https://linkedin.com/in/yourprofile) | 💻 [GitHub](https://github.com/yourusername)

---

## 📜 License

MIT License — free to use, modify, and distribute.
