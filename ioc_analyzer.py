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
        
        self.title("🛡️ IOC Analyzer Pro")
        self.geometry("1100x750")
        self.minsize(900, 650)
        
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
        self.refresh_history_list()
    
    def setup_ui(self):
        # Main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # TOP SECTION: Input (Always visible)
        self.setup_input_section(main_container)
        
        # MIDDLE SECTION: Results Table
        self.setup_results_section(main_container)
        
        # BOTTOM SECTION: Log
        self.setup_log_section(main_container)
        
        # Create tabs for History and Export
        self.notebook = ctk.CTkTabview(self)
        self.notebook.pack(fill="both", expand=False, padx=10, pady=(0, 10))
        self.notebook.pack_forget()  # Hide initially, show when needed
        
        self.history_tab = self.notebook.add("📋 History")
        self.export_tab = self.notebook.add("💾 Export")
        
        self.setup_history_tab_ui()
        self.setup_export_tab_ui()
    
    def setup_input_section(self, parent):
        input_frame = ctk.CTkFrame(parent)
        input_frame.pack(fill="x", pady=(0, 10))
        
        # Title
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
        self.text_input.pack(fill="x", padx=10, pady=5)
        
        # Buttons
        btn_frame = ctk.CTkFrame(input_frame)
        btn_frame.pack(pady=5)
        
        ctk.CTkButton(btn_frame, text="🔍 Extract & Scan", command=self.extract_iocs_thread, 
                     width=150, height=32, font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=5)
        self.view_details_btn = ctk.CTkButton(btn_frame, text="📊 View Details", command=self.view_selected_details, 
                                             width=130, height=32, state="disabled", font=ctk.CTkFont(size=11))
        self.view_details_btn.pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="📋 History", command=self.show_history, 
                     width=100, height=32, font=ctk.CTkFont(size=11)).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="💾 Export", command=self.show_export, 
                     width=100, height=32, font=ctk.CTkFont(size=11)).pack(side="left", padx=5)
        
        self.switch_mode()
    
    def setup_results_section(self, parent):
        results_frame = ctk.CTkFrame(parent)
        results_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Status bar
        self.status_label = ctk.CTkLabel(results_frame, text="✅ Ready - Enter URL or text and click Extract", 
                                        font=ctk.CTkFont(size=11), anchor="w")
        self.status_label.pack(fill="x", padx=10, pady=(5, 0))
        
        # Compact results table
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
        
        # Bind double-click
        self.tree.bind("<Double-1>", lambda e: self.view_selected_details())
        
        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", 
                       fieldbackground="#2b2b2b", rowheight=25)
        style.configure("Treeview.Heading", background="#1f538d", foreground="white")
    
    def setup_log_section(self, parent):
        log_frame = ctk.CTkFrame(parent, height=100)
        log_frame.pack(fill="x")
        
        ctk.CTkLabel(log_frame, text="📝 Activity Log", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=10, pady=(5, 0))
        
        self.log_text = ctk.CTkTextbox(log_frame, height=60, font=ctk.CTkFont(size=9, family="Consolas"))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0, 5))
    
    def setup_history_tab_ui(self):
        ctk.CTkLabel(self.history_tab, text="📋 Scan History", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        btn_frame = ctk.CTkFrame(self.history_tab)
        btn_frame.pack(pady=5)
        
        ctk.CTkButton(btn_frame, text="🔄 Refresh", command=self.refresh_history_list, width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🗑️ Clear", command=self.clear_history, width=100, fg_color="#c0392b").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="📤 Export All", command=self.export_all_history, width=120).pack(side="left", padx=5)
        
        columns = ("Date", "Target", "IOCs", "Malicious", "Status")
        self.history_tree = ttk.Treeview(self.history_tab, columns=columns, show="headings", height=12)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=150, anchor="center")
        self.history_tree.column("Target", width=350, anchor="w")
        
        self.history_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.history_tree.bind("<Double-1>", self.load_scan_from_history)
        
        self.refresh_history_list()
    
    def setup_export_tab_ui(self):
        ctk.CTkLabel(self.export_tab, text="💾 Export Options", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        export_frame = ctk.CTkFrame(self.export_tab)
        export_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        ctk.CTkButton(export_frame, text="📄 CSV (Basic)", command=self.export_current_csv, 
                     width=250, height=35).pack(pady=8)
        ctk.CTkButton(export_frame, text="📋 JSON (Full Details)", command=self.export_current_json, 
                     width=250, height=35).pack(pady=8)
        ctk.CTkButton(export_frame, text="📝 TXT (With Details)", command=self.export_ioc_list, 
                     width=250, height=35).pack(pady=8)
        ctk.CTkButton(export_frame, text="📊 HTML Report (With Details)", command=self.export_html_report, 
                     width=250, height=35).pack(pady=8)
        
        self.export_log = ctk.CTkTextbox(export_frame, height=150)
        self.export_log.pack(fill="both", expand=True, padx=10, pady=10)
        self.export_log.insert("1.0", "Export log will appear here...\n")
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
    
    def log_export(self, message):
        self.export_log.insert("end", f"{message}\n")
        self.export_log.see("end")
    
    def switch_mode(self):
        if self.mode_var.get() == "url":
            self.text_frame.pack_forget()
            self.url_frame.pack(fill="x", padx=10, pady=5)
        else:
            self.url_frame.pack_forget()
            self.text_frame.pack(fill="x", padx=10, pady=5)
    
    def show_history(self):
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.notebook.set("📋 History")
    
    def show_export(self):
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.notebook.set("💾 Export")
    
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
            self.log(f"⚠️ Fetch error: {str(e)[:50]}")
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
                self.log(f"🎯 Target: {parsed.netloc}")
            
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
        
        # Clear table
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
            self.status_label.configure(text=f"🔎 {i+1}/{len(all_iocs)}: {ioc}")
            
            vt_result = self.check_virustotal(ioc, ioc_type)
            
            if vt_result["malicious"] != "-" and vt_result["malicious"] > 0:
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
        
        # Add to history
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
        
        # Create details window
        details_window = ctk.CTkToplevel(self)
        details_window.title(f"📊 Details: {ioc[:50]}")
        details_window.geometry("700x750")
        
        # Header
        header = ctk.CTkFrame(details_window)
        header.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(header, text="🛡️ Security Vendors Analysis", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        ctk.CTkLabel(header, text=f"{ioc}", font=ctk.CTkFont(size=12), wraplength=600).pack()
        
        # Summary
        summary = ctk.CTkFrame(details_window)
        summary.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(summary, text="📊 Summary", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        
        stats_frame = ctk.CTkFrame(summary)
        stats_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(stats_frame, text=f"🔴 Malicious: {result['malicious']}", 
                    font=ctk.CTkFont(size=12), text_color="#e74c3c").pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(stats_frame, text=f"🟡 Suspicious: {result['suspicious']}", 
                    font=ctk.CTkFont(size=12), text_color="#f39c12").pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(stats_frame, text=f"🟢 Clean: {result['harmless']}", 
                    font=ctk.CTkFont(size=12), text_color="#27ae60").pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(stats_frame, text=f"Last Analysis: {result['last_analysis']}", 
                    font=ctk.CTkFont(size=11)).pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(stats_frame, text=f"Reputation: {result['details'].get('reputation', 0)}", 
                    font=ctk.CTkFont(size=11)).pack(anchor="w", padx=10, pady=2)
        
        # Categories
        if result['details'].get('categories'):
            cat_frame = ctk.CTkFrame(details_window)
            cat_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(cat_frame, text="🏷️ Categories", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
            cats = ", ".join(result['details']['categories'].keys())
            ctk.CTkLabel(cat_frame, text=cats, font=ctk.CTkFont(size=11), wraplength=600).pack(anchor="w", padx=10, pady=5)
        
        # Tags
        if result['details'].get('tags'):
            tag_frame = ctk.CTkFrame(details_window)
            tag_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(tag_frame, text="🏷️ Tags", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
            tags = ", ".join(result['details']['tags'])
            ctk.CTkLabel(tag_frame, text=tags, font=ctk.CTkFont(size=11), wraplength=600).pack(anchor="w", padx=10, pady=5)
        
        # Detection engines - SINGLE COLUMN
        engines_frame = ctk.CTkFrame(details_window)
        engines_frame.pack(fill="both", expand=True, padx=20, pady=10)
        ctk.CTkLabel(engines_frame, text="🔍 Vendor Detections", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        
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
                
                ctk.CTkLabel(vendor_row, text=f"{icon} {vendor_name}", font=ctk.CTkFont(size=10, weight="bold"), 
                           anchor="w").pack(side="left", padx=10, pady=3)
                ctk.CTkLabel(vendor_row, text=status, font=ctk.CTkFont(size=10), 
                           anchor="e").pack(side="right", padx=10, pady=3)
                
                if result_text and result_text != 'undetected':
                    ctk.CTkLabel(scroll_frame, text=f"   → {result_text}", font=ctk.CTkFont(size=9), 
                               anchor="w", text_color="#95a5a6").pack(fill="x", padx=20, pady=(0, 2))
    
    def refresh_history_list(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        for scan in reversed(self.scan_history):
            self.history_tree.insert("", "end", values=(
                scan['timestamp'][:19].replace('T', ' '),
                scan['target'][:50],
                scan['total_iocs'],
                scan['malicious_count'],
                "✅"
            ))
    
    def load_scan_from_history(self, event):
        selection = self.history_tree.selection()
        if not selection:
            return
        
        item = self.history_tree.item(selection[0])
        timestamp = item['values'][0].replace(' ', 'T')
        
        for scan in self.scan_history:
            if scan['timestamp'] == timestamp:
                for i in self.tree.get_children():
                    self.tree.delete(i)
                
                self.results = scan['results']
                
                for r in self.results:
                    self.tree.insert("", "end", values=(
                        r['ioc'][:40], r['type'],
                        r['malicious'], r['suspicious'], r['harmless'], r['status']
                    ))
                
                self.log(f"📋 Loaded scan from {timestamp}")
                self.status_label.configure(text=f"📋 Loaded: {scan['target']}")
                self.view_details_btn.configure(state="normal")
                break
    
    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all history?"):
            self.scan_history = []
            self.save_history()
            self.refresh_history_list()
    
    def export_all_history(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = filedialog.asksaveasfilename(defaultextension=".json", 
                                                initialfile=f"history_{timestamp}.json")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.scan_history, f, indent=2)
                messagebox.showinfo("Success", f"Exported {len(self.scan_history)} scans")
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def export_current_csv(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", 
                                                initialfile=f"scan_{timestamp}.csv")
        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=["ioc", "type", "malicious", "suspicious", 
                                                         "harmless", "status", "last_analysis"])
                    writer.writeheader()
                    for r in self.results:
                        writer.writerow({k: r[k] for k in ["ioc", "type", "malicious", "suspicious", 
                                                          "harmless", "status", "last_analysis"]})
                messagebox.showinfo("Success", "CSV exported")
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def export_current_json(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = filedialog.asksaveasfilename(defaultextension=".json", 
                                                initialfile=f"scan_{timestamp}.json")
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
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                initialfile=f"ioc_details_{timestamp}.txt")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("=" * 80 + "\n")
                    f.write(f"IOC Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    for r in self.results:
                        f.write(f"{'=' * 80}\n")
                        f.write(f"IOC: {r['ioc']}\n")
                        f.write(f"Type: {r['type']}\n")
                        f.write(f"Status: {r['status']}\n")
                        f.write(f"Last Analysis: {r['last_analysis']}\n")
                        f.write(f"\nDetection Summary:\n")
                        f.write(f"  🔴 Malicious: {r['malicious']}\n")
                        f.write(f"  🟡 Suspicious: {r['suspicious']}\n")
                        f.write(f"  🟢 Clean: {r['harmless']}\n")
                        
                        if r['details']:
                            f.write(f"\nReputation Score: {r['details'].get('reputation', 0)}\n")
                            
                            if r['details'].get('categories'):
                                f.write(f"Categories: {', '.join(r['details']['categories'].keys())}\n")
                            
                            if r['details'].get('tags'):
                                f.write(f"Tags: {', '.join(r['details']['tags'])}\n")
                            
                            # Full detection list
                            detection_results = r['details'].get('detection_engines_full', {})
                            if detection_results:
                                f.write(f"\nDetailed Vendor Detections:\n")
                                f.write("-" * 80 + "\n")
                                
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
                    
                    f.write("=" * 80 + "\n")
                    f.write(f"Total IOCs: {len(self.results)}\n")
                    f.write(f"Malicious: {sum(1 for r in self.results if r['malicious'] != '-' and r['malicious'] > 0)}\n")
                    f.write("=" * 80 + "\n")
                
                messagebox.showinfo("Success", "TXT with full details exported")
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def export_html_report(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = filedialog.asksaveasfilename(defaultextension=".html", 
                                                initialfile=f"report_{timestamp}.html")
        if file_path:
            try:
                malicious_count = sum(1 for r in self.results if r['malicious'] != '-' and r['malicious'] > 0)
                
                html = f"""<!DOCTYPE html>
<html>
<head>
    <title>IOC Analysis Report - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #fff; }}
        h1 {{ color: #3498db; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #2ecc71; margin-top: 30px; }}
        .ioc-card {{ background: #2c3e50; margin: 20px 0; padding: 20px; border-radius: 8px; }}
        .ioc-title {{ font-size: 18px; font-weight: bold; color: #3498db; margin-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
        th {{ background: #34495e; }}
        .mal {{ color: #e74c3c; font-weight: bold; }}
        .sus {{ color: #f39c12; }}
        .clean {{ color: #27ae60; }}
        .vendor-mal {{ background: #c0392b; color: white; padding: 3px 8px; border-radius: 3px; }}
        .vendor-sus {{ background: #f39c12; color: black; padding: 3px 8px; border-radius: 3px; }}
        .vendor-clean {{ background: #27ae60; color: white; padding: 3px 8px; border-radius: 3px; }}
        .vendor-undetected {{ background: #34495e; color: #95a5a6; padding: 3px 8px; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>🛡️ IOC Analysis Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Total IOCs:</strong> {len(self.results)} | <strong class="mal">Malicious:</strong> {malicious_count}</p>
"""
                
                for r in self.results:
                    html += f"""
    <div class="ioc-card">
        <div class="ioc-title">📍 {r['ioc']}</div>
        <p><strong>Type:</strong> {r['type']} | <strong>Last Analysis:</strong> {r['last_analysis']}</p>
        
        <table>
            <tr><th>🔴 Malicious</th><th>🟡 Suspicious</th><th>🟢 Clean</th><th>Reputation</th></tr>
            <tr>
                <td class="mal">{r['malicious']}</td>
                <td class="sus">{r['suspicious']}</td>
                <td class="clean">{r['harmless']}</td>
                <td>{r['details'].get('reputation', 0)}</td>
            </tr>
        </table>
"""
                    
                    if r['details'].get('categories'):
                        html += f"<p><strong>Categories:</strong> {', '.join(r['details']['categories'].keys())}</p>"
                    
                    if r['details'].get('tags'):
                        html += f"<p><strong>Tags:</strong> {', '.join(r['details']['tags'])}</p>"
                    
                    # Vendor detections
                    detection_results = r['details'].get('detection_engines_full', {})
                    if detection_results:
                        html += "<h2>🔍 Vendor Detections</h2><table><tr><th>Vendor</th><th>Status</th><th>Result</th></tr>"
                        
                        malicious_vendors = [(k, v) for k, v in detection_results.items() if v.get('category') == 'malicious']
                        suspicious_vendors = [(k, v) for k, v in detection_results.items() if v.get('category') == 'suspicious']
                        
                        for vendor, data in malicious_vendors:
                            result = data.get('result', 'N/A')
                            html += f"<tr><td>{vendor}</td><td><span class='vendor-mal'>Malicious</span></td><td>{result}</td></tr>"
                        
                        for vendor, data in suspicious_vendors:
                            result = data.get('result', 'N/A')
                            html += f"<tr><td>{vendor}</td><td><span class='vendor-sus'>Suspicious</span></td><td>{result}</td></tr>"
                        
                        html += "</table>"
                    
                    html += "</div>"
                
                html += """
</body>
</html>"""
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html)
                
                messagebox.showinfo("Success", "HTML report with full details exported")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = IOCAnalyzerApp()
    app.mainloop()