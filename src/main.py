import customtkinter as ctk
import threading
import json
import asyncio
import os
import socket  # <-- NEW: Used for network discovery
from dotenv import load_dotenv

# Import our backend engines
from scanner import OmniScanner
from cve_mapper import CVEMapper
from ai_engine import AIEngine
from export import PDFExportEngine
from database import DatabaseManager

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
        self.exporter = PDFExportEngine()
        self.db = DatabaseManager()

        # State variables to hold data for the PDF
        self.current_ip = ""
        self.current_report = ""
        
        # Map to track dropdown strings to database IDs
        self.history_map = {}

        # Scan profile definitions: "Display Name" -> "flags"
        self.scan_profiles = {
            "Ping Sweep (-sn)":                "-sn",
            "Quick Scan (-F -T4)":             "-F -T4",
            "Standard SYN Scan (-sS -T4)":     "-sS -T4",
            "Service Detection (-sS -sV -T4)": "-sS -sV -T4",
            "Full Port Scan (-p- -T4)":        "-p- -T4",
            "Aggressive Scan (-A -T4)":        "-A -T4",
            "UDP Quick Scan (-sU -F -T4)":     "-sU -F -T4",
            "Intense Scan, No Ping (-Pn -A -T4)": "-Pn -A -T4",
            "Top 100 Ports (--top-ports 100 -T4)": "--top-ports 100 -T4",
            "Stealth SYN (-sS -T4 -f)":        "-sS -T4 -f",
        }

        self._build_ui()

    def _build_ui(self):
        # Configure grid layout (1 row, 2 columns)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ================= Sidebar =================
        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color="#111111")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        # Shifted the weight down to row 10 to account for new profile/port widgets
        self.sidebar_frame.grid_rowconfigure(10, weight=1) 

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

        # --- Auto-Scan Network Button ---
        self.auto_scan_button = ctk.CTkButton(
            self.sidebar_frame,
            text="Scan Current Network",
            command=self.start_auto_network_scan,
            fg_color="#444444", 
            text_color="#FFFFFF",
            hover_color="#555555",
            font=ctk.CTkFont(weight="bold")
        )
        self.auto_scan_button.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")

        # --- Scan Profile Dropdown ---
        profile_names = list(self.scan_profiles.keys())
        default_profile = "Service Detection (-sS -sV -T4)"
        self.scan_profile_dropdown = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=profile_names,
            fg_color="#222222",
            button_color="#333333",
            button_hover_color="#555555"
        )
        self.scan_profile_dropdown.set(default_profile)
        self.scan_profile_dropdown.grid(row=3, column=0, padx=20, pady=(10, 0), sticky="ew")

        # --- Custom Port Entry ---
        self.port_entry = ctk.CTkEntry(
            self.sidebar_frame,
            placeholder_text="Custom Ports (e.g., 80,443 or 1-1000)",
            fg_color="#222222",
            border_color="#555555"
        )
        self.port_entry.grid(row=4, column=0, padx=20, pady=(0, 10), sticky="ew")

        self.scan_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Initiate Scan", 
            command=self.start_scan_thread,
            fg_color="#FFFFFF",
            text_color="#000000",
            hover_color="#CCCCCC",
            font=ctk.CTkFont(weight="bold")
        )
        self.scan_button.grid(row=5, column=0, padx=20, pady=10, sticky="ew")

        self.export_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Generate PDF Report", 
            command=self.export_pdf,
            fg_color="#333333",  
            text_color="#FFFFFF",
            hover_color="#555555",
            font=ctk.CTkFont(weight="bold"),
            state="disabled"
        )
        self.export_button.grid(row=6, column=0, padx=20, pady=10, sticky="ew")

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Status: Idle", text_color="#888888")
        self.status_label.grid(row=7, column=0, padx=20, pady=5)

        self.history_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Scan History", 
            text_color="#FFFFFF", 
            font=ctk.CTkFont(weight="bold")
        )
        self.history_label.grid(row=8, column=0, padx=20, pady=(20, 0), sticky="w")

        self.history_dropdown = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["No history found"],
            command=self.load_historical_scan,
            fg_color="#222222",
            button_color="#333333",
            button_hover_color="#555555"
        )
        self.history_dropdown.grid(row=9, column=0, padx=20, pady=10, sticky="ew")
        
        # Populate history on launch
        self.refresh_history_dropdown()

        # ================= Main View =================
        self.tabview = ctk.CTkTabview(self, fg_color="#181818", segmented_button_selected_color="#333333")
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.tabview.add("Terminal Logs")
        self.tabview.add("Enriched Data (CVEs)")
        self.tabview.add("AI Intelligence")

        self.terminal_box = ctk.CTkTextbox(self.tabview.tab("Terminal Logs"), font=("Consolas", 14), fg_color="#000000", text_color="#00FF00")
        self.terminal_box.pack(expand=True, fill="both", padx=10, pady=10)

        self.cve_box = ctk.CTkTextbox(self.tabview.tab("Enriched Data (CVEs)"), font=("Consolas", 13), fg_color="#111111", text_color="#FFFFFF")
        self.cve_box.pack(expand=True, fill="both", padx=10, pady=10)

        self.ai_box = ctk.CTkTextbox(self.tabview.tab("AI Intelligence"), font=("Consolas", 14), fg_color="#111111", text_color="#FFFFFF", wrap="word")
        self.ai_box.pack(expand=True, fill="both", padx=10, pady=10)

    # --- NEW: Network Detection Logic ---
    def get_local_network(self) -> str:
        """Dynamically determines the local IP and assumes a /24 subnet mask."""
        try:
            # Connect a dummy UDP socket to Google's DNS to force the OS to pick an interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Drop the last octet and append .0/24 (e.g., 192.168.88.32 -> 192.168.88.0/24)
            subnet_prefix = ".".join(local_ip.split('.')[:3])
            return f"{subnet_prefix}.0/24"
        except Exception as e:
            self.log_terminal(f"[!] Network detection failed: {str(e)}")
            return ""

    def start_auto_network_scan(self):
        """Finds the network, populates the UI, and triggers the standard scan."""
        network_cidr = self.get_local_network()
        
        if not network_cidr:
            self.log_terminal("[!] Error: Could not determine local network routing.")
            return

        self.log_terminal(f"\n[*] Auto-detected local network: {network_cidr}")
        
        # Visually update the text box so you can see what is being scanned
        self.ip_entry.delete(0, ctk.END)
        self.ip_entry.insert(0, network_cidr)
        
        # Disable the auto-scan button while it runs to prevent double-clicks
        self.auto_scan_button.configure(state="disabled")
        
        # Fire the standard background threading process
        self.start_scan_thread()


    # --- Database Interaction Methods ---
    def refresh_history_dropdown(self):
        """Fetches history from DB and updates the UI dropdown."""
        scans = self.db.get_all_scans()
        if not scans:
            self.history_dropdown.configure(values=["No history found"])
            self.history_dropdown.set("No history found")
            return

        dropdown_values = []
        self.history_map.clear()
        for scan in scans:
            scan_id, ip, date = scan
            # Format: [ID] IP_Address - YYYY-MM-DD
            display_str = f"[{scan_id}] {ip} - {date.split(' ')[0]}" 
            dropdown_values.append(display_str)
            self.history_map[display_str] = scan_id

        self.history_dropdown.configure(values=dropdown_values)
        self.history_dropdown.set("Select a past scan...")

    def load_historical_scan(self, selected_str):
        """Fires when the user clicks a past scan in the dropdown."""
        if selected_str not in self.history_map:
            return

        scan_id = self.history_map[selected_str]
        scan_data = self.db.get_scan_by_id(scan_id)
        
        if not scan_data:
            return

        self.terminal_box.delete("1.0", ctk.END)
        self.cve_box.delete("1.0", ctk.END)
        self.ai_box.delete("1.0", ctk.END)

        self.log_terminal(f"[*] Loading historical scan ID {scan_id} from database...")
        
        # Populate UI
        self.current_ip = scan_data["target_ip"]
        self.current_report = scan_data["ai_report"]
        
        self.log_terminal(f"[+] Successfully loaded data for IP: {self.current_ip}")
        self.cve_box.insert(ctk.END, json.dumps(scan_data["raw_data"], indent=4))
        self.ai_box.insert(ctk.END, self.current_report)

        # Re-enable the PDF button for the loaded history
        self.export_button.configure(state="normal", fg_color="#FFFFFF", text_color="#000000")
        self.status_label.configure(text="Status: History Loaded")


    # --- Existing Methods ---
    def log_terminal(self, message: str):
        self.terminal_box.insert(ctk.END, message + "\n")
        self.terminal_box.see(ctk.END)

    def export_pdf(self):
        if not self.current_ip or not self.current_report:
            self.log_terminal("[!] Error: No scan data available to export.")
            return

        self.status_label.configure(text="Status: Generating PDF...")
        try:
            filepath = self.exporter.generate_pdf(self.current_ip, self.current_report)
            self.log_terminal(f"\n[+] SUCCESS: PDF Report saved to -> {filepath}")
            self.status_label.configure(text="Status: PDF Saved")
        except Exception as e:
            import traceback
            self.log_terminal(f"\n[!] PDF Generation Error: {str(e)}")
            self.log_terminal(f"[!] Full traceback:\n{traceback.format_exc()}")
            self.status_label.configure(text="Status: Export Failed")

    def start_scan_thread(self):
        target_ip = self.ip_entry.get()
        if not target_ip:
            self.log_terminal("[!] Error: No target IP provided.")
            return

        self.scan_button.configure(state="disabled", text="Scanning...")
        self.auto_scan_button.configure(state="disabled") # Disable auto-scan button too
        self.export_button.configure(state="disabled", fg_color="#333333", text_color="#FFFFFF")
        self.status_label.configure(text="Status: Running Nmap...")
        self.terminal_box.delete("1.0", ctk.END)
        self.cve_box.delete("1.0", ctk.END)
        self.ai_box.delete("1.0", ctk.END)
        
        threading.Thread(target=self._run_full_pipeline, args=(target_ip,), daemon=True).start()

    def _run_full_pipeline(self, target_ip):
        try:
            # Phase 1: Nmap Scan
            # Build the final flag string from profile selection + optional custom ports
            selected_profile = self.scan_profile_dropdown.get()
            flags = self.scan_profiles.get(selected_profile, "-sS -sV -T4")
            
            custom_ports = self.port_entry.get().strip()
            if custom_ports:
                flags += f" -p {custom_ports}"
            
            self.log_terminal(f"[*] Initiating Nmap scan against {target_ip} with flags: {flags}")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            raw_scan_data = loop.run_until_complete(self.scanner.run_scan_async(target_ip, flags))
            
            self.log_terminal("[+] Nmap scan complete. Parsing data...")

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
            self.log_terminal("[+] AI Analysis complete.")

            # Phase 4: Save & Enable PDF
            self.current_ip = target_ip
            self.current_report = ai_report
            self.export_button.configure(state="normal", fg_color="#FFFFFF", text_color="#000000")

            # --- NEW: Save to Database ---
            self.log_terminal("\n[*] Saving scan to local SQLite database...")
            self.db.save_scan(target_ip, enriched_data, ai_report)
            self.log_terminal("[+] Scan archived successfully.")
            
            # Safely tell the UI thread to update the dropdown menu
            self.after(0, self.refresh_history_dropdown)

        except Exception as e:
            self.log_terminal(f"\n[!] Pipeline Error: {str(e)}")
        
        finally:
            self.status_label.configure(text="Status: Idle")
            self.scan_button.configure(state="normal", text="Initiate Scan")
            self.auto_scan_button.configure(state="normal") # <-- Safety reset for new button

if __name__ == "__main__":
    app = OmniScanGUI()
    app.mainloop()