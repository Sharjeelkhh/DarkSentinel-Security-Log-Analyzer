#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from analyzer import analyze, read_events, filter_events, export_json, export_csv, export_txt

APP_TITLE = "🔴 Security Log Analyzer (Red Team Edition)"

def pick_log():
    path = filedialog.askopenfilename(title="Select log file", filetypes=[("Logs","*.log *.txt"),("All files","*.*")])
    if path: logvar.set(path)

def run_analysis():
    path = logvar.get().strip()
    if not path:
        messagebox.showwarning("Select a log", "Please choose a log file first."); return
    try:
        report = analyze(path, top_n=int(topvar.get()), window_minutes=int(winvar.get()), threshold=int(thrvar.get()))
        render_report(report); current_report["data"] = report; status.set(f"Analyzed: {path}")
    except Exception as e:
        messagebox.showerror("Analysis failed", str(e))

def render_report(report: dict):
    out.delete(1.0, tk.END)
    out.insert(tk.END, "=== Security Log Analysis ===\n\n", "header")
    meta = report.get("metadata", {})
    out.insert(tk.END, f"Input: {meta.get('input_log','')} | Lines: {meta.get('total_lines','')}\n", "dim")
    out.insert(tk.END, f"Period: {meta.get('period_start','?')} → {meta.get('period_end','?')}\n\n", "dim")
    s = report.get("summary", {})
    out.insert(tk.END, "[Top IPs]\n", "section")
    for ip,c in s.get("top_ips", []): out.insert(tk.END, f"  - {ip}: {c}\n", "normal")
    out.insert(tk.END, "\n[Top Paths]\n", "section")
    for p,c in s.get("top_paths", []): out.insert(tk.END, f"  - {p}: {c}\n", "normal")
    out.insert(tk.END, "\n[Status Codes]\n", "section")
    for k,v in sorted(s.get("status_counts", {}).items()):
        tag = "green" if str(k).startswith("2") else "yellow" if str(k).startswith("4") else "red"
        out.insert(tk.END, f"  {k}: {v}\n", tag)
    out.insert(tk.END, "\n[Alerts]\n", "section")
    for k,v in report.get("alerts", {}).get("signatures", {}).items():
        out.insert(tk.END, f"  ⚠ {k} — {v.get('count',0)} hits\n", "red")
        for samp in v.get("samples", [])[:3]: out.insert(tk.END, f"     • {samp}\n", "dim")
    for b in report.get("alerts", {}).get("bursts", []):
        out.insert(tk.END, f"  ⚡ Bursty errors from {b.get('ip','?')} — {b.get('count_in_window',0)} in {b.get('window_minutes',0)}m\n", "yellow")

def parse_dt(s: str):
    s = s.strip()
    if not s: return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
        try: return datetime.strptime(s, fmt)
        except Exception: pass
    try: return datetime.fromisoformat(s)
    except Exception: raise ValueError("Use date format YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")

def load_events_for_filter():
    path = logvar.get().strip()
    if not path:
        messagebox.showwarning("Select a log", "Please choose a log file first."); return
    try:
        evs = read_events(path)
        filt = set()
        if var_sqli.get(): filt.add("sqli")
        if var_xss.get(): filt.add("xss")
        if var_trav.get(): filt.add("path_traversal")
        if var_sens.get(): filt.add("sensitive_path_probe")
        if var_scan.get(): filt.add("scanner_user_agent")
        evs2 = filter_events(evs, start=parse_dt(startvar.get()), end=parse_dt(endvar.get()), ip=(ipvar.get().strip() or None), event_types=filt if filt else None)
        populate_table(evs2); status.set(f"Filtered {len(evs2)} events"); current_events["data"] = evs2
    except Exception as e:
        messagebox.showerror("Filter error", str(e))

def populate_table(events):
    for i in table.get_children(): table.delete(i)
    for e in events:
        flags = "|".join(e.flags)
        row = (e.time.strftime("%Y-%m-%d %H:%M:%S"), e.ip, e.method, e.path, e.status, e.ua, flags)
        tag = ""
        if any(x in e.flags for x in ("sqli","xss","path_traversal")): tag = "critical"
        elif any(x in e.flags for x in ("sensitive_path_probe","scanner_user_agent")): tag = "warning"
        elif "error_4xx5xx" in e.flags: tag = "notice"
        table.insert("", "end", values=row, tags=(tag,))

def export_report(kind: str):
    if "data" not in current_report:
        messagebox.showwarning("No report", "Run analysis first."); return
    path = filedialog.asksaveasfilename(defaultextension=f".{kind}", filetypes=[(kind.upper(), f"*.{kind}"), ("All files","*.*")])
    if not path: return
    try:
        rep = current_report["data"]
        if kind == "json": export_json(rep, path)
        elif kind == "txt": export_txt(rep, path)
        else: messagebox.showerror("Unsupported", f"Unknown kind: {kind}"); return
        messagebox.showinfo("Saved", f"Report saved to:\n{path}")
    except Exception as e:
        messagebox.showerror("Save error", str(e))

def export_events_csv():
    if "data" not in current_events:
        messagebox.showwarning("No events", "Apply filters first to get events."); return
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv"), ("All files","*.*")])
    if not path: return
    try:
        export_csv(current_events["data"], path)
        messagebox.showinfo("Saved", f"Events CSV saved to:\n{path}")
    except Exception as e:
        messagebox.showerror("Save error", str(e))

root = tk.Tk(); root.title(APP_TITLE); root.geometry("1100x720"); root.configure(bg="#0d0f12")
style = ttk.Style(); style.theme_use("clam")
style.configure("TLabel", background="#0d0f12", foreground="#e8e8e8", font=("Consolas", 10))
style.configure("TButton", background="#1a1f29", foreground="#ffffff", font=("Consolas", 10), padding=6)
style.map("TButton", background=[("active","#ff4141")], foreground=[("active","#0d0f12")])
style.configure("TEntry", fieldbackground="#11161f", foreground="#e8e8e8")
style.configure("Treeview", background="#11161f", fieldbackground="#11161f", foreground="#e8e8e8", rowheight=24, font=("Consolas", 10))
style.configure("Treeview.Heading", background="#1a1f29", foreground="#e8e8e8", font=("Consolas", 10, "bold"))

frm_top = ttk.Frame(root); frm_top.pack(fill="x", padx=12, pady=10)
ttk.Label(frm_top, text="Log file:").pack(side="left")
logvar = tk.StringVar(); ttk.Entry(frm_top, textvariable=logvar, width=80).pack(side="left", padx=6)
ttk.Button(frm_top, text="Browse", command=pick_log).pack(side="left", padx=4)
ttk.Button(frm_top, text="Analyze", command=run_analysis).pack(side="left", padx=8)

frm_params = ttk.Frame(root); frm_params.pack(fill="x", padx=12, pady=6)
topvar = tk.StringVar(value="10"); winvar = tk.StringVar(value="5"); thrvar = tk.StringVar(value="10")
ttk.Label(frm_params, text="Top N:").pack(side="left"); ttk.Entry(frm_params, textvariable=topvar, width=6).pack(side="left", padx=4)
ttk.Label(frm_params, text="Window (min):").pack(side="left", padx=8); ttk.Entry(frm_params, textvariable=winvar, width=6).pack(side="left", padx=4)
ttk.Label(frm_params, text="Threshold:").pack(side="left", padx=8); ttk.Entry(frm_params, textvariable=thrvar, width=6).pack(side="left", padx=4)
ttk.Button(frm_params, text="Export JSON", command=lambda: export_report("json")).pack(side="right", padx=4)
ttk.Button(frm_params, text="Export TXT", command=lambda: export_report("txt")).pack(side="right", padx=4)

frm_filters = ttk.LabelFrame(root, text="Filters"); frm_filters.pack(fill="x", padx=12, pady=6)
ipvar = tk.StringVar(); startvar = tk.StringVar(); endvar = tk.StringVar()
ttk.Label(frm_filters, text="IP:").grid(row=0, column=0, padx=6, pady=4, sticky="w")
ttk.Entry(frm_filters, textvariable=ipvar, width=18).grid(row=0, column=1, padx=6, pady=4, sticky="w")
ttk.Label(frm_filters, text="Start (YYYY-MM-DD[ HH:MM:SS]):").grid(row=0, column=2, padx=6, pady=4, sticky="e")
ttk.Entry(frm_filters, textvariable=startvar, width=24).grid(row=0, column=3, padx=6, pady=4, sticky="w")
ttk.Label(frm_filters, text="End (YYYY-MM-DD[ HH:MM:SS]):").grid(row=0, column=4, padx=6, pady=4, sticky="e")
ttk.Entry(frm_filters, textvariable=endvar, width=24).grid(row=0, column=5, padx=6, pady=4, sticky="w")

var_sqli = tk.BooleanVar(value=True); var_xss = tk.BooleanVar(value=True); var_trav = tk.BooleanVar(value=True)
var_sens = tk.BooleanVar(value=True); var_scan = tk.BooleanVar(value=True)
ttk.Checkbutton(frm_filters, text="SQLi", variable=var_sqli).grid(row=1, column=0, padx=6, pady=4, sticky="w")
ttk.Checkbutton(frm_filters, text="XSS", variable=var_xss).grid(row=1, column=1, padx=6, pady=4, sticky="w")
ttk.Checkbutton(frm_filters, text="Traversal", variable=var_trav).grid(row=1, column=2, padx=6, pady=4, sticky="w")
ttk.Checkbutton(frm_filters, text="Sensitive Paths", variable=var_sens).grid(row=1, column=3, padx=6, pady=4, sticky="w")
ttk.Checkbutton(frm_filters, text="Scanner UA", variable=var_scan).grid(row=1, column=4, padx=6, pady=4, sticky="w")
ttk.Button(frm_filters, text="Apply Filters", command=load_events_for_filter).grid(row=1, column=5, padx=6, pady=4, sticky="e")

cols = ("time","ip","method","path","status","ua","flags")
table = ttk.Treeview(root, columns=cols, show="headings", height=14)
for c in cols:
    table.heading(c, text=c.upper())
    table.column(c, width=140 if c not in ("path","ua") else 300, anchor="w")
table.tag_configure("critical", background="#2b0e12", foreground="#ff6b6b")
table.tag_configure("warning", background="#2b2310", foreground="#ffd166")
table.tag_configure("notice", background="#14212b", foreground="#34d5ff")
table.pack(fill="both", expand=True, padx=12, pady=6)

ttk.Button(root, text="Export Filtered Events (CSV)", command=export_events_csv).pack(anchor="e", padx=12, pady=6)

out = scrolledtext.ScrolledText(root, wrap="word", height=12, bg="#11161f", fg="#e8e8e8", insertbackground="#e8e8e8", borderwidth=0, font=("Consolas", 10))
out.pack(fill="both", expand=False, padx=12, pady=6)
out.tag_config("header", foreground="#34d5ff", font=("Consolas", 13, "bold"))
out.tag_config("section", foreground="#8cf28c", font=("Consolas", 12, "bold"))
out.tag_config("normal", foreground="#e8e8e8")
out.tag_config("red", foreground="#ff6b6b")
out.tag_config("yellow", foreground="#ffd166")
out.tag_config("green", foreground="#8cf28c")
out.tag_config("dim", foreground="#9aa4b2")

status = tk.StringVar(value="Ready")
ttk.Label(root, textvariable=status).pack(anchor="w", padx=12, pady=(0,10))

current_report = {}
current_events = {}

root.mainloop()
