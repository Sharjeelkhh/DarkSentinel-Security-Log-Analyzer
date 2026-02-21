import argparse
import json
import os
import re
import webbrowser
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# ---------------------------
# 1. Read log file events
# ---------------------------
def read_events(log_path):
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")
    
    events = []
    with open(log_path, "r", errors="ignore", encoding="utf-8") as f:
        for line in f:
            events.append(line.strip())
    return events


# ---------------------------
# 2. Parse log lines
# ---------------------------
def parse_log_line(line):
    # Basic Apache/Nginx-style log parsing
    match = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+|-) "(.*?)" "(.*?)"', line)
    if match:
        ip, dt_str, request, status, size, referrer, agent = match.groups()
        dt = datetime.strptime(dt_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        return {
            "ip": ip,
            "datetime": dt,
            "request": request,
            "status": status,
            "size": size,
            "referrer": referrer,
            "agent": agent
        }
    return None


# ---------------------------
# 3. Analyze logs
# ---------------------------
def analyze(log_path, top_n=10, window_minutes=5, threshold=10):
    events = read_events(log_path)
    parsed = [parse_log_line(e) for e in events]
    parsed = [p for p in parsed if p]

    ip_counter = Counter(p["ip"] for p in parsed)

    alerts = []
    window = timedelta(minutes=window_minutes)
    for ip, _ in ip_counter.items():
        timestamps = sorted([p["datetime"] for p in parsed if p["ip"] == ip])
        for i in range(len(timestamps)):
            count = sum(1 for t in timestamps if timestamps[i] <= t <= timestamps[i] + window)
            if count > threshold:
                alerts.append({"ip": ip, "count": count, "start": timestamps[i].isoformat()})
                break

    return {
        "total_events": len(parsed),
        "unique_ips": len(ip_counter),
        "top_ips": ip_counter.most_common(top_n),
        "alerts": alerts
    }


# ---------------------------
# 4. Export report
# ---------------------------
def export_report(report, output_path):
    if output_path.endswith(".json"):
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)
        print(f"✅ JSON report saved at {output_path}")

    elif output_path.endswith(".html"):
        html = f"""
        <html>
        <head>
            <title>Security Log Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
                th {{ background: #f4f4f4; }}
            </style>
        </head>
        <body>
            <h1>Security Log Analysis Report</h1>
            <p><b>Total Events:</b> {report['total_events']}</p>
            <p><b>Unique IPs:</b> {report['unique_ips']}</p>

            <h2>Top IPs</h2>
            <table>
                <tr><th>IP</th><th>Requests</th></tr>
                {''.join(f'<tr><td>{ip}</td><td>{count}</td></tr>' for ip, count in report['top_ips'])}
            </table>

            <h2>Alerts</h2>
            <table>
                <tr><th>IP</th><th>Request Count</th><th>Start Time</th></tr>
                {''.join(f'<tr><td>{a["ip"]}</td><td>{a["count"]}</td><td>{a["start"]}</td></tr>' for a in report['alerts'])}
            </table>
        </body>
        </html>
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"✅ HTML report saved at {output_path}")

        # 🔥 Auto-open in browser
        abs_path = os.path.abspath(output_path)
        webbrowser.open(f"file://{abs_path}")


# ---------------------------
# 5. Main CLI Entry Point
# ---------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Log Analyzer")
    parser.add_argument("--log", required=True, help="Path to the log file")
    parser.add_argument("--out", required=True, help="Path to output report (JSON or HTML)")
    parser.add_argument("--top", type=int, default=10, help="Number of top IPs")
    parser.add_argument("--window", type=int, default=5, help="Sliding window in minutes")
    parser.add_argument("--threshold", type=int, default=10, help="Request threshold for alerts")
    args = parser.parse_args()

    try:
        report = analyze(args.log, top_n=args.top, window_minutes=args.window, threshold=args.threshold)
        export_report(report, args.out)
    except Exception as e:
        print(f"❌ Error: {e}")
