import customtkinter as ctk
import threading
import json
import asyncio
import os
from dotenv import load_dotenv

# Import our backend engines
from scanner import OmniScanner
from cve_mapper import CVEMapper
from ai_engine import AIEngine
from export import PDFExportEngine  # <-- New Import

# Load environment variables (.env)
load_dotenv()

# Force the "Stormtrooper" high-contrast aesthetic
ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("dark-blue") 

class OmniScanGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("OmniScan - Vulnerability Intelligence Platform")
        self.geometry("1100x700")
        
        # Initialize backend modules
        self.scanner = OmniScanner()
        self.mapper = CVEMapper()
        self.ai = AIEngine()
        self.exporter = PDFExportEngine() # <-- Initialize Exporter

        # State variables to hold data for the PDF
        self.current_ip = ""
        self.current_report = ""

        self._build_ui()

    def _build_ui(self):
        # Configure grid layout (1 row, 2 columns)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ================= Sidebar =================
        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color="#111111")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        # Shifted the weight down to row 5 to account for the new button
        self.sidebar_frame.grid_rowconfigure(5, weight=1) 

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="OmniScan", 
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#FFFFFF"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.ip_entry = ctk.CTkEntry(
            self.sidebar_frame, 
            placeholder_text="Target IP (e.g., 192.168.1.50)",
            fg_color="#222222",
            border_color="#555555"
        )
        self.ip_entry.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.scan_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Initiate Scan", 
            command=self.start_scan_thread,
            fg_color="#FFFFFF",
            text_color="#000000",
            hover_color="#CCCCCC",
            font=ctk.CTkFont(weight="bold")
        )
        self.scan_button.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        # --- NEW EXPORT BUTTON ---
        self.export_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Generate PDF Report", 
            command=self.export_pdf,
            fg_color="#333333",  
            text_color="#FFFFFF",
            hover_color="#555555",
            font=ctk.CTkFont(weight="bold"),
            state="disabled" # Disabled until a scan completes
        )
        self.export_button.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        # Moved status label to row 4
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Status: Idle", text_color="#888888")
        self.status_label.grid(row=4, column=0, padx=20, pady=5)

        # ================= Main View =================
        self.tabview = ctk.CTkTabview(self, fg_color="#181818", segmented_button_selected_color="#333333")
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.tabview.add("Terminal Logs")
        self.tabview.add("Enriched Data (CVEs)")
        self.tabview.add("AI Intelligence")

        # Terminal Tab
        self.terminal_box = ctk.CTkTextbox(self.tabview.tab("Terminal Logs"), font=("Consolas", 14), fg_color="#000000", text_color="#00FF00")
        self.terminal_box.pack(expand=True, fill="both", padx=10, pady=10)

        # CVE Tab
        self.cve_box = ctk.CTkTextbox(self.tabview.tab("Enriched Data (CVEs)"), font=("Consolas", 13), fg_color="#111111", text_color="#FFFFFF")
        self.cve_box.pack(expand=True, fill="both", padx=10, pady=10)

        # AI Tab
        self.ai_box = ctk.CTkTextbox(self.tabview.tab("AI Intelligence"), font=("Consolas", 14), fg_color="#111111", text_color="#FFFFFF", wrap="word")
        self.ai_box.pack(expand=True, fill="both", padx=10, pady=10)

    def log_terminal(self, message: str):
        """Helper to print logs safely to the GUI."""
        self.terminal_box.insert(ctk.END, message + "\n")
        self.terminal_box.see(ctk.END)

    def export_pdf(self):
        """Triggers the PDF generation using the stored data."""
        if not self.current_ip or not self.current_report:
            self.log_terminal("[!] Error: No scan data available to export.")
            return

        self.status_label.configure(text="Status: Generating PDF...")
        try:
            filepath = self.exporter.generate_pdf(self.current_ip, self.current_report)
            self.log_terminal(f"\n[+] SUCCESS: PDF Report saved to -> {filepath}")
            self.status_label.configure(text="Status: PDF Saved")
        except Exception as e:
            self.log_terminal(f"\n[!] PDF Generation Error: {str(e)}")
            self.status_label.configure(text="Status: Export Failed")

    def start_scan_thread(self):
        """Fires the whole process into a background thread so the GUI doesn't freeze."""
        target_ip = self.ip_entry.get()
        if not target_ip:
            self.log_terminal("[!] Error: No target IP provided.")
            return

        self.scan_button.configure(state="disabled", text="Scanning...")
        self.export_button.configure(state="disabled", fg_color="#333333", text_color="#FFFFFF") # Disable export on new scan
        self.status_label.configure(text="Status: Running Nmap...")
        self.terminal_box.delete("1.0", ctk.END)
        self.cve_box.delete("1.0", ctk.END)
        self.ai_box.delete("1.0", ctk.END)
        
        # Start background thread
        threading.Thread(target=self._run_full_pipeline, args=(target_ip,), daemon=True).start()

    def _run_full_pipeline(self, target_ip):
        """The core logic pipeline that runs in the background."""
        try:
            # Phase 1: Nmap Scan
            self.log_terminal(f"[*] Initializing Nmap scan against {target_ip}...")
            # We use a new event loop for the background thread's async call
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            raw_scan_data = loop.run_until_complete(self.scanner.run_scan_async(target_ip))
            
            self.log_terminal("[+] Nmap scan complete. Parsing data...")
            self.log_terminal(json.dumps(raw_scan_data, indent=2))

            # Phase 2: CVE Mapping
            self.status_label.configure(text="Status: Mapping CVEs...")
            self.log_terminal("\n[*] Cross-referencing identified services with CIRCL database...")
            enriched_data = self.mapper.enrich_scan_results(raw_scan_data)
            
            self.cve_box.insert(ctk.END, json.dumps(enriched_data, indent=4))
            self.log_terminal("[+] CVE Mapping complete. Data forwarded to AI engine.")

            # Phase 3: AI Intelligence
            self.status_label.configure(text="Status: AI Analyzing...")
            self.log_terminal("\n[*] Waking up DeepSeek engine for root-cause analysis...")
            
            ai_report = self.ai.analyze_vulnerabilities(enriched_data)
            self.ai_box.insert(ctk.END, ai_report)
            self.log_terminal("[+] AI Analysis complete. Check the AI Intelligence tab.")

            # --- NEW: Save state and enable export button ---
            self.current_ip = target_ip
            self.current_report = ai_report
            self.export_button.configure(state="normal", fg_color="#FFFFFF", text_color="#000000")

        except Exception as e:
            self.log_terminal(f"\n[!] Pipeline Error: {str(e)}")
        
        finally:
            # Reset UI state safely
            self.status_label.configure(text="Status: Idle")
            self.scan_button.configure(state="normal", text="Initiate Scan")

if __name__ == "__main__":
    app = OmniScanGUI()
    app.mainloop()
