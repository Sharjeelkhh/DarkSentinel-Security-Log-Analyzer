# 🦾 DarkSentinel – Offensive Log Intelligence Toolkit

DarkSentinel is a Python-based offensive log analysis toolkit built for red team operators, threat hunters, and SOC analysts who want real intelligence — not bloated dashboards.  
It ingests Apache/Nginx access logs, detects attacker behavior, and outputs actionable findings through both a CLI and a dark red-team GUI.

---

## ⚡ Features

### 🚨 Attack Detection
DarkSentinel automatically identifies:

- SQL Injection attempts (`UNION`, `'`, `%27`, encoded payloads)
- XSS injection (`<script>`, HTML injection, encoded JS)
- Directory traversal attacks (`../`, `%2e%2e/`)
- Sensitive file probing (`/.env`, `/admin`, `/backup.zip`, `/phpinfo.php`)
- Automated scanner fingerprints (sqlmap, Nikto, curl fuzzing)
- Bursty 4xx/5xx error storms (indicating brute forcing or enumeration)

Each flagged event includes metadata explaining why it was detected.

---

## 🧠 Intelligence & Summaries

- Top attacking IPs  
- Most targeted paths  
- Status code distribution  
- HTTP methods breakdown  
- Timestamp-based filtering  
- Correlated suspicious activity summary  

---

## 🎯 Filtering Engine

Supports:

- Date/time ranges:  
  - `YYYY-MM-DD`  
  - `YYYY-MM-DD HH:MM:SS`  
  - ISO-8601 (`2025-08-20T13:56:00`)
- Filtering by IP
- Filtering by detection category
- Filtering by any combination of criteria

Pure Python — no external packages required.

---

## 📤 Export Formats

- **JSON** — structured machine-readable analysis  
- **TXT** — readable analyst-friendly report  
- **CSV** — filtered log events (SIEM-friendly)

---

## 🖥️ GUI (Dark Red-Team Theme)

A modern Tkinter/ttk GUI with:

- Black/red operator theme  
- Threat-colored table rows  
- Realtime filtering panel  
- Scrollable results  
- Easy file picker

Run:

```bash
python gui.py
```

---

## 🔧 CLI Mode (Automation & Headless Use)

```bash
python analyzer.py \
  --log sample_logs/sample_access.log \
  --out sample_report.json \
  --top 10 \
  --window 5 \
  --threshold 8
```

---

## 🗂 Project Structure

```
DarkSentinel/
├── analyzer.py                 # Core detection engine + exports
├── gui.py                      # Dark GUI frontend
├── main.py                     # Program launcher
├── sample_logs/
│   └── sample_access.log       # Example access log
├── sample_report.json          # Example JSON report
├── sample_report.txt           # Example text report
└── suspicious_log_report.csv   # Example suspicious event CSV
```

---

## 📦 Requirements

- Python 3.8+  
- Standard library only — no pip installs needed

---

## ❗ Troubleshooting

- Ensure logs are in Apache/Nginx **combined** format  
- Malformed lines are ignored safely  
- Large logs may take time — use filters  
- If GUI fails on Linux, install Tkinter  

---

## 🔥 License

MIT License (or any you choose).

---

## 🩸 Author

DarkSentinel – Red Team Edition  
© 2025
