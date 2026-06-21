import os
import re
import time
import json
import threading
import requests
import csv
from datetime import datetime
from urllib.parse import urlparse
from tkinter import ttk, filedialog, messagebox
from dotenv import load_dotenv
from bs4 import BeautifulSoup
import customtkinter as ctk

# Configure appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("API_KEY")

# History file
HISTORY_FILE = "scan_history.json"

class IOCAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("️ IOC Analyzer Pro")
        self.geometry("1100x800")
        self.minsize(900, 700)
        
        if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
            messagebox.showerror("Error", "VirusTotal API key not configured!\nCreate a .env file with: VT_API_KEY=your_key_here")
            self.destroy()
            return
        
        self.results = []
        self.scan_history = []
        self.load_history()
        self.setup_ui()
    
    def load_history(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    self.scan_history = json.load(f)
            except:
                self.scan_history = []
        else:
            self.scan_history = []
    
    def save_history(self):
        try:
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.scan_history, f, indent=2, ensure_ascii=False)
        except:
            pass
    
    def add_to_history(self, scan_data):
        self.scan_history.append(scan_data)
        self.save_history()
    
    def setup_ui(self):
        # Main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # ==========================================
        # 1. TOP SECTION: Input (Always visible)
        # ==========================================
        input_frame = ctk.CTkFrame(main_container)
        input_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(input_frame, text="🛡️ IOC Analyzer Pro", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=5)
        
        # Mode selection
        mode_frame = ctk.CTkFrame(input_frame)
        mode_frame.pack(fill="x", padx=10, pady=5)
        
        self.mode_var = ctk.StringVar(value="url")
        ctk.CTkRadioButton(mode_frame, text="🌐 URL", variable=self.mode_var, value="url", 
                          command=self.switch_mode, font=ctk.CTkFont(size=11)).pack(side="left", padx=10)
        ctk.CTkRadioButton(mode_frame, text="📝 Text", variable=self.mode_var, value="text", 
                          command=self.switch_mode, font=ctk.CTkFont(size=11)).pack(side="left", padx=10)
        
        # URL input
        self.url_frame = ctk.CTkFrame(input_frame)
        self.url_entry = ctk.CTkEntry(self.url_frame, width=600, placeholder_text="https://malicious.com", 
                                     font=ctk.CTkFont(size=11))
        self.url_entry.pack(side="left", padx=10, pady=5)
        
        
        # Text input
        self.text_frame = ctk.CTkFrame(input_frame)
        self.text_input = ctk.CTkTextbox(self.text_frame, height=80, font=ctk.CTkFont(size=10))
        
        # Action Buttons
        btn_frame = ctk.CTkFrame(input_frame)
        btn_frame.pack(pady=5)
        
        ctk.CTkButton(btn_frame, text="🔍 Extract & Scan", command=self.extract_iocs_thread, 
                     width=150, height=32, font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=5)
        self.view_details_btn = ctk.CTkButton(btn_frame, text="📊 View Details", command=self.view_selected_details, 
                                             width=130, height=32, state="disabled", font=ctk.CTkFont(size=11))
        self.view_details_btn.pack(side="left", padx=5)
        
        self.switch_mode()
        
        # ==========================================
        # 2. MIDDLE SECTION: Results Table
        # ==========================================
        results_frame = ctk.CTkFrame(main_container)
        results_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        self.status_label = ctk.CTkLabel(results_frame, text="✅ Ready - Enter URL or text and click Extract", 
                                        font=ctk.CTkFont(size=11), anchor="w")
        self.status_label.pack(fill="x", padx=10, pady=(5, 0))
        
        table_container = ctk.CTkFrame(results_frame)
        table_container.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("IOC", "Type", "Mal", "Sus", "Harm", "Status")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", height=6)
        
        self.tree.heading("IOC", text="Indicator")
        self.tree.heading("Type", text="Type")
        self.tree.heading("Mal", text="🔴")
        self.tree.heading("Sus", text="🟡")
        self.tree.heading("Harm", text="🟢")
        self.tree.heading("Status", text="Status")
        
        self.tree.column("IOC", width=280, anchor="w")
        self.tree.column("Type", width=70, anchor="center")
        self.tree.column("Mal", width=50, anchor="center")
        self.tree.column("Sus", width=50, anchor="center")
        self.tree.column("Harm", width=50, anchor="center")
        self.tree.column("Status", width=100, anchor="center")
        
        scrollbar = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.tree.bind("<Double-1>", lambda e: self.view_selected_details())
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", 
                       fieldbackground="#2b2b2b", rowheight=25)
        style.configure("Treeview.Heading", background="#1f538d", foreground="white")

        # ==========================================
        # 3. EXPORT BUTTONS (Always visible below table)
        # ==========================================
        export_frame = ctk.CTkFrame(main_container)
        export_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(export_frame, text="💾 Export Options:", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=10)
        
        ctk.CTkButton(export_frame, text="📄 CSV", command=self.export_current_csv, width=80, height=28).pack(side="left", padx=5)
        ctk.CTkButton(export_frame, text="📋 JSON", command=self.export_current_json, width=80, height=28).pack(side="left", padx=5)
        ctk.CTkButton(export_frame, text="📝 TXT", command=self.export_ioc_list, width=80, height=28).pack(side="left", padx=5)
        
        # Highlighted HTML Button
        ctk.CTkButton(export_frame, text="📊 HTML Report", command=self.export_html_report, 
                     width=120, height=28, fg_color="#e67e22", hover_color="#d35400").pack(side="left", padx=5)
        
        # ==========================================
        # 4. BOTTOM SECTION: Log
        # ==========================================
        log_frame = ctk.CTkFrame(main_container, height=100)
        log_frame.pack(fill="x")
        
        ctk.CTkLabel(log_frame, text="📝 Activity Log", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=10, pady=(5, 0))
        
        self.log_text = ctk.CTkTextbox(log_frame, height=60, font=ctk.CTkFont(size=9, family="Consolas"))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0, 5))
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
    
    def switch_mode(self):
        if self.mode_var.get() == "url":
            self.text_frame.pack_forget()
            self.url_frame.pack(fill="x", padx=10, pady=5)
        else:
            self.url_frame.pack_forget()
            self.text_frame.pack(fill="x", padx=10, pady=5)
    
    def get_input_text(self):
        url_str = self.url_entry.get().strip()
        if not url_str.startswith("http"):
            url_str = "http://" + url_str
        
        try:
            headers = {"User-Agent": "Mozilla/5.0 Chrome/120.0.0.0"}
            response = requests.get(url_str, headers=headers, timeout=15, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            for element in soup(["script", "style"]):
                element.extract()
            return soup.get_text(separator=' ', strip=True)
        except Exception as e:
            self.log(f"️ Fetch error: {str(e)[:50]}")
            return None
    
    def extract_iocs(self, text):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|xyz|info|biz|co|uk|de|cn)\b'
        
        raw_ips = set(re.findall(ip_pattern, text))
        raw_domains = set(re.findall(domain_pattern, text))
        
        valid_ips = {ip for ip in raw_ips if all(0 <= int(o) <= 255 for o in ip.split('.')) 
                    and not ip.startswith(('192.168.', '10.', '172.16.'))}
        return valid_ips, raw_domains
    
    def extract_iocs_thread(self):
        self.view_details_btn.configure(state="disabled")
        threading.Thread(target=self._extract_iocs_worker, daemon=True).start()
    
    def _extract_iocs_worker(self):
        self.log("=" * 40)
        self.log("🚀 Starting scan...")
        
        ips = set()
        domains = set()
        
        if self.mode_var.get() == "url":
            url_str = self.url_entry.get().strip()
            if not url_str:
                self.log("❌ No URL")
                return
            if not url_str.startswith("http"):
                url_str = "http://" + url_str
            
            parsed = urlparse(url_str)
            if parsed.netloc:
                domains.add(parsed.netloc)
                self.log(f" Target: {parsed.netloc}")
            
            self.log(f"🌐 Fetching {url_str}...")
            text = self.get_input_text()
            if text:
                page_ips, page_domains = self.extract_iocs(text)
                ips.update(page_ips)
                domains.update(page_domains)
        else:
            text = self.text_input.get("1.0", "end").strip()
            if not text:
                self.log("❌ No text")
                return
            ips, domains = self.extract_iocs(text)
        
        all_iocs = [(ip, "IP") for ip in ips] + [(d, "Domain") for d in domains]
        
        if not all_iocs:
            self.log("⚠️ No IOCs found")
            return
        
        self.log(f"✅ Found {len(all_iocs)} IOCs")
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for ioc, ioc_type in all_iocs:
            self.tree.insert("", "end", values=(ioc[:40], ioc_type, "-", "-", "-", "⏳"))
            self.results.append({
                "ioc": ioc, "type": ioc_type, 
                "malicious": "-", "suspicious": "-", "harmless": "-", 
                "status": "Pending", "checked_at": timestamp,
                "last_analysis": "-", "details": {}
            })
        
        self.status_label.configure(text=f"🔎 Checking {len(all_iocs)} IOCs...")
        total_malicious = 0
        
        for i, (ioc, ioc_type) in enumerate(all_iocs):
            self.log(f"Checking {i+1}/{len(all_iocs)}: {ioc}")
            self.status_label.configure(text=f" {i+1}/{len(all_iocs)}: {ioc}")
            
            vt_result = self.check_virustotal(ioc, ioc_type)
            
            if vt_result["malicious"] != "-" and int(vt_result["malicious"]) > 0:
                total_malicious += 1
            
            item_id = self.tree.get_children()[i]
            self.tree.item(item_id, values=(
                ioc[:40], ioc_type, 
                vt_result["malicious"], vt_result["suspicious"], vt_result["harmless"], 
                vt_result["status"]
            ))
            
            self.results[i].update(vt_result)
            
            if i < len(all_iocs) - 1:
                time.sleep(15)
        
        scan_record = {
            "timestamp": datetime.now().isoformat(),
            "target": self.url_entry.get() if self.mode_var.get() == "url" else "Text Input",
            "type": "URL" if self.mode_var.get() == "url" else "Text",
            "total_iocs": len(all_iocs),
            "malicious_count": total_malicious,
            "results": self.results
        }
        self.add_to_history(scan_record)
        
        self.log(f"✅ Complete! Found {total_malicious} malicious")
        self.status_label.configure(text=f"✅ Done! {total_malicious} malicious IOCs found")
        self.view_details_btn.configure(state="normal")
    
    def check_virustotal(self, ioc, ioc_type):
        endpoint = 'ip_addresses' if ioc_type == 'IP' else 'domains'
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
        headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                stats = data['last_analysis_stats']
                
                last_analysis_date = data.get('last_analysis_date', 0)
                last_analysis = datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M') if last_analysis_date else "Unknown"
                
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "status": "✅",
                    "last_analysis": last_analysis,
                    "details": {
                        "categories": data.get('categories', {}),
                        "tags": data.get('tags', []),
                        "reputation": data.get('reputation', 0),
                        "detection_engines_full": data.get('last_analysis_results', {})
                    }
                }
            else:
                return {"malicious": 0, "suspicious": 0, "harmless": 0, "status": "❌", "last_analysis": "-", "details": {}}
        except:
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "status": "❌", "last_analysis": "-", "details": {}}
    
    def view_selected_details(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select an IOC to view details")
            return
        
        item = self.tree.item(selection[0])
        ioc = item['values'][0]
        
        result = next((r for r in self.results if r['ioc'] == ioc), None)
        if not result:
            return
        
        details_window = ctk.CTkToplevel(self)
        details_window.title(f"📊 Details: {ioc[:50]}")
        details_window.geometry("700x750")
        
        header = ctk.CTkFrame(details_window)
        header.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(header, text="️ Security Vendors Analysis", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        ctk.CTkLabel(header, text=f"{ioc}", font=ctk.CTkFont(size=12), wraplength=600).pack()
        
        summary = ctk.CTkFrame(details_window)
        summary.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(summary, text="📊 Summary", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        
        stats_frame = ctk.CTkFrame(summary)
        stats_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(stats_frame, text=f"🔴 Malicious: {result['malicious']}", font=ctk.CTkFont(size=12), text_color="#e74c3c").pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(stats_frame, text=f" Suspicious: {result['suspicious']}", font=ctk.CTkFont(size=12), text_color="#f39c12").pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(stats_frame, text=f"🟢 Clean: {result['harmless']}", font=ctk.CTkFont(size=12), text_color="#27ae60").pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(stats_frame, text=f"Last Analysis: {result['last_analysis']}", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=10, pady=2)
        
        engines_frame = ctk.CTkFrame(details_window)
        engines_frame.pack(fill="both", expand=True, padx=20, pady=10)
        ctk.CTkLabel(engines_frame, text="🔍 Vendor Detections (Single Column)", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        
        scroll_frame = ctk.CTkScrollableFrame(engines_frame, height=300)
        scroll_frame.pack(fill="both", expand=True, pady=5)
        
        detection_results = result['details'].get('detection_engines_full', {})
        
        if detection_results:
            for vendor_name, vendor_data in detection_results.items():
                category = vendor_data.get('category', 'undetected')
                result_text = vendor_data.get('result', '')
                
                if category == 'malicious':
                    bg_color = "#c0392b"
                    icon = "🔴"
                    status = "Malicious"
                elif category == 'suspicious':
                    bg_color = "#f39c12"
                    icon = "🟡"
                    status = "Suspicious"
                elif category == 'harmless':
                    bg_color = "#27ae60"
                    icon = "🟢"
                    status = "Clean"
                else:
                    bg_color = "#34495e"
                    icon = "⚪"
                    status = "Undetected"
                
                vendor_row = ctk.CTkFrame(scroll_frame, fg_color=bg_color)
                vendor_row.pack(fill="x", pady=1)
                
                ctk.CTkLabel(vendor_row, text=f"{icon} {vendor_name}", font=ctk.CTkFont(size=10, weight="bold"), anchor="w").pack(side="left", padx=10, pady=3)
                ctk.CTkLabel(vendor_row, text=status, font=ctk.CTkFont(size=10), anchor="e").pack(side="right", padx=10, pady=3)
                
                if result_text and result_text != 'undetected':
                    ctk.CTkLabel(scroll_frame, text=f"   → {result_text}", font=ctk.CTkFont(size=9), anchor="w", text_color="#95a5a6").pack(fill="x", padx=20, pady=(0, 2))

    # ==========================================
    # EXPORT FUNCTIONS
    # ==========================================
    
    def export_current_csv(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"scan_{timestamp}.csv")
        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=["ioc", "type", "malicious", "suspicious", "harmless", "status", "last_analysis"])
                    writer.writeheader()
                    for r in self.results:
                        writer.writerow({k: r[k] for k in ["ioc", "type", "malicious", "suspicious", "harmless", "status", "last_analysis"]})
                messagebox.showinfo("Success", "CSV exported")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def export_current_json(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"scan_{timestamp}.json")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Success", "JSON with full details exported")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def export_ioc_list(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"ioc_details_{timestamp}.txt")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("=" * 80 + "\n")
                    f.write(f"IOC Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 80 + "\n\n")
                    for r in self.results:
                        f.write(f"{'=' * 80}\nIOC: {r['ioc']}\nType: {r['type']}\nStatus: {r['status']}\n")
                        f.write(f"Last Analysis: {r['last_analysis']}\n\nDetection Summary:\n")
                        f.write(f"   Malicious: {r['malicious']}\n  🟡 Suspicious: {r['suspicious']}\n  🟢 Clean: {r['harmless']}\n")
                        if r['details']:
                            f.write(f"\nReputation Score: {r['details'].get('reputation', 0)}\n")
                            if r['details'].get('categories'):
                                f.write(f"Categories: {', '.join(r['details']['categories'].keys())}\n")
                            if r['details'].get('tags'):
                                f.write(f"Tags: {', '.join(r['details']['tags'])}\n")
                            detection_results = r['details'].get('detection_engines_full', {})
                            if detection_results:
                                f.write(f"\nDetailed Vendor Detections:\n{'-' * 80}\n")
                                malicious = [k for k, v in detection_results.items() if v.get('category') == 'malicious']
                                suspicious = [k for k, v in detection_results.items() if v.get('category') == 'suspicious']
                                if malicious:
                                    f.write(f"\n🔴 MALICIOUS ({len(malicious)}):\n")
                                    for vendor in malicious:
                                        result = detection_results[vendor].get('result', 'N/A')
                                        f.write(f"  • {vendor}: {result}\n")
                                if suspicious:
                                    f.write(f"\n🟡 SUSPICIOUS ({len(suspicious)}):\n")
                                    for vendor in suspicious:
                                        result = detection_results[vendor].get('result', 'N/A')
                                        f.write(f"  • {vendor}: {result}\n")
                        f.write("\n")
                messagebox.showinfo("Success", "TXT with full details exported")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def export_html_report(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results to export. Run a scan first!")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = filedialog.asksaveasfilename(defaultextension=".html", 
                                                initialfile=f"IOC_Report_{timestamp}.html",
                                                filetypes=[("HTML files", "*.html")])
        if not file_path:
            return
        
        try:
            malicious_count = sum(1 for r in self.results if r['malicious'] != '-' and int(r['malicious']) > 0)
            
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IOC Analysis Report - {timestamp}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #121212; color: #e0e0e0; }}
        h1 {{ color: #3498db; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #2ecc71; margin-top: 20px; font-size: 18px; }}
        .header-info {{ background: #1e1e1e; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
        .ioc-card {{ background: #1e1e1e; margin: 20px 0; padding: 20px; border-radius: 8px; border-left: 5px solid #3498db; }}
        .ioc-title {{ font-size: 20px; font-weight: bold; color: #3498db; margin-bottom: 10px; word-break: break-all; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; font-size: 14px; }}
        th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
        th {{ background: #2c3e50; color: white; }}
        .mal {{ color: #e74c3c; font-weight: bold; }}
        .sus {{ color: #f39c12; }}
        .clean {{ color: #27ae60; }}
        .vendor-mal {{ background: #c0392b; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .vendor-sus {{ background: #f39c12; color: black; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .vendor-clean {{ background: #27ae60; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .vendor-undetected {{ background: #34495e; color: #95a5a6; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .footer {{ margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🛡️ IOC Threat Intelligence Report</h1>
    <div class="header-info">
        <p><strong>📅 Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>📊 Total IOCs Analyzed:</strong> {len(self.results)} | <strong class="mal">🔴 Malicious Found:</strong> {malicious_count}</p>
    </div>
"""
            
            for r in self.results:
                border_color = "#e74c3c" if (r['malicious'] != '-' and int(r['malicious']) > 0) else "#27ae60"
                
                html += f"""
    <div class="ioc-card" style="border-left-color: {border_color};">
        <div class="ioc-title">📍 {r['ioc']}</div>
        <p><strong>Type:</strong> {r['type']} | <strong>Last Analysis:</strong> {r['last_analysis']} | <strong>Reputation:</strong> {r['details'].get('reputation', 0)}</p>
        
        <table>
            <tr><th> Malicious</th><th>🟡 Suspicious</th><th>🟢 Clean</th></tr>
            <tr>
                <td class="mal">{r['malicious']}</td>
                <td class="sus">{r['suspicious']}</td>
                <td class="clean">{r['harmless']}</td>
            </tr>
        </table>
"""
                
                if r['details'].get('categories'):
                    cats = ", ".join(r['details']['categories'].keys())
                    html += f"<p><strong>🏷️ Categories:</strong> {cats}</p>"
                
                if r['details'].get('tags'):
                    tags = ", ".join(r['details']['tags'])
                    html += f"<p><strong>🏷️ Tags:</strong> {tags}</p>"
                
                detection_results = r['details'].get('detection_engines_full', {})
                if detection_results:
                    html += "<h2>🔍 Security Vendor Detections</h2>"
                    html += "<table><tr><th>Security Vendor</th><th>Status</th><th>Result Details</th></tr>"
                    
                    sorted_vendors = sorted(detection_results.items(), 
                                            key=lambda x: 0 if x[1].get('category')=='malicious' else (1 if x[1].get('category')=='suspicious' else 2))
                    
                    for vendor, data in sorted_vendors:
                        category = data.get('category', 'undetected')
                        result_text = data.get('result', 'undetected')
                        
                        if category == 'malicious':
                            status_html = "<span class='vendor-mal'>Malicious</span>"
                        elif category == 'suspicious':
                            status_html = "<span class='vendor-sus'>Suspicious</span>"
                        elif category == 'harmless':
                            status_html = "<span class='vendor-clean'>Clean</span>"
                        else:
                            status_html = "<span class='vendor-undetected'>Undetected</span>"
                            
                        result_display = result_text if result_text and result_text != 'undetected' else "-"
                        html += f"<tr><td>{vendor}</td><td>{status_html}</td><td>{result_display}</td></tr>"
                    
                    html += "</table>"
                
                html += "</div>"
            
            html += f"""
    <div class="footer">
        <p>Generated by IOC Analyzer Pro | Data provided by VirusTotal API</p>
    </div>
</body>
</html>"""
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html)
            
            messagebox.showinfo("Success", f"✅ HTML Report exported successfully!\n\nSaved to:\n{file_path}")
            self.log(f" HTML Report exported: {file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export HTML:\n{str(e)}")

if __name__ == "__main__":
    app = IOCAnalyzerApp()
    app.mainloop()