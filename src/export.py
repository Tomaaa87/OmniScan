from pathlib import Path
import re
from datetime import datetime
from fpdf import FPDF
from fpdf.enums import XPos, YPos

class OmniReport(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Font families are configured by PDFExportEngine._register_fonts().
        # These defaults (fpdf2 core fonts) always work without any TTF files.
        self.sans_family = "Helvetica"
        self.mono_family = "Courier"
        self.report_title = "OmniScan Vulnerability Intelligence Report"

    def header(self):
        # Professional header
        self.set_font(self.sans_family, "B", 18)
        self.set_text_color(30, 30, 30)
        self.cell(200, 10, text=self.report_title, border=0, align="C")
        self.ln(10)
        self.set_line_width(0.5)
        self.line(10, 22, 200, 22)
        self.ln(10)

    def footer(self):
        # Clean footer with page numbers
        self.set_y(-15)
        self.set_font(self.sans_family, "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(200, 10, text=f"Page {self.page_no()}/{{nb}}", align="C")

class PDFExportEngine:
    def __init__(self, output_dir="reports"):
        # Resolve the project root (parent of src/) using pathlib for robustness
        src_dir = Path(__file__).resolve().parent
        project_root = src_dir.parent
        self.output_dir = project_root / output_dir

    # Paths to system Unicode TTF fonts (available on Kali/Debian/Ubuntu)
    DEJAVU_SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    DEJAVU_SANS_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    DEJAVU_SANS_OBLIQUE = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"
    DEJAVU_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    DEJAVU_MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

    @staticmethod
    def _first_existing(paths):
        """Returns the first path that exists on disk, or None."""
        for p in paths:
            if p and Path(p).exists():
                return p
        return None

    def _register_fonts(self, pdf) -> dict:
        """Registers Unicode-capable TTF fonts when present, otherwise falls
        back to fpdf2's built-in core fonts. Returns {"sans", "mono"} family
        names ready for set_font() calls.
        """
        dejavu = "/usr/share/fonts/truetype/dejavu"
        win = "C:/Windows/Fonts"
        mac = "/System/Library/Fonts/Supplemental"

        sans = self._first_existing([
            f"{dejavu}/DejaVuSans.ttf",
            f"{win}/arial.ttf",
            f"{mac}/Arial.ttf",
        ])
        sans_b = self._first_existing([
            f"{dejavu}/DejaVuSans-Bold.ttf",
            f"{win}/arialbd.ttf",
            f"{mac}/Arial Bold.ttf",
        ])
        sans_i = self._first_existing([
            f"{dejavu}/DejaVuSans-Oblique.ttf",
            f"{win}/ariali.ttf",
            f"{mac}/Arial Italic.ttf",
        ])
        mono = self._first_existing([
            f"{dejavu}/DejaVuSansMono.ttf",
            f"{win}/consola.ttf",
            f"{mac}/Courier New.ttf",
        ])
        mono_b = self._first_existing([
            f"{dejavu}/DejaVuSansMono-Bold.ttf",
            f"{win}/consolab.ttf",
            f"{mac}/Courier New Bold.ttf",
        ])

        if sans:
            pdf.add_font("OmniSans", "", sans)
            pdf.add_font("OmniSans", "B", sans_b or sans)
            pdf.add_font("OmniSans", "I", sans_i or sans)
            sans_family = "OmniSans"
        else:
            sans_family = "Helvetica"

        if mono:
            pdf.add_font("OmniMono", "", mono)
            pdf.add_font("OmniMono", "B", mono_b or mono)
            mono_family = "OmniMono"
        else:
            mono_family = "Courier"

        return {"sans": sans_family, "mono": mono_family}

    def _clean_text(self, text: str) -> str:
        """Removes basic Markdown (like **bold**) for clean PDF rendering."""
        if not text:
            return "No report data provided."
        
        # Remove bold/italic markdown asterisks
        cleaned = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
        cleaned = re.sub(r'\*(.*?)\*', r'\1', cleaned)
        
        return cleaned

    def generate_pdf(self, target_ip: str, ai_report: str, file_path: str = None) -> str:
        """Generates the PDF and saves it to the specified path or auto-generates one."""
        import sys  # for stderr debug fallback
        
        def _log(msg):
            """Log to stderr so it appears even if the GUI log fails."""
            print(f"[PDFExport] {msg}", file=sys.stderr, flush=True)
        
        _log(f"generate_pdf called: ip={target_ip!r}, report_len={len(ai_report)}")
        _log(f"output_dir={self.output_dir}")
        
        # Step 1: Guarantee the output directory exists
        _log("Step 1: mkdir...")
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            _log(f"Step 1 OK: {self.output_dir} exists={self.output_dir.exists()}")
        except Exception as e:
            _log(f"Step 1 FAILED: {e}")
            raise

        # Step 2: Create PDF object
        _log("Step 2: creating OmniReport...")
        try:
            pdf = OmniReport()
            _log("Step 2 OK")
        except Exception as e:
            _log(f"Step 2 FAILED: {e}")
            raise
        
        # Step 3: Register fonts (Unicode TTF when available, core-font fallback otherwise)
        _log("Step 3: registering fonts...")
        try:
            fonts = self._register_fonts(pdf)
            _log("Step 3 OK")
        except Exception as e:
            _log(f"Step 3 FAILED: {e}")
            raise
        
        # Step 4: Build pages
        _log("Step 4: building pages...")
        try:
            pdf.alias_nb_pages()
            pdf.add_page()
            
            pdf.set_font(fonts["sans"], "B", 12)
            pdf.set_text_color(0, 51, 102) 
            pdf.cell(200, 8, text=f"Target Network/IP: {target_ip}")
            pdf.ln(8)
            
            scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            pdf.set_font(fonts["sans"], "", 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(200, 8, text=f"Scan Timestamp: {scan_date}")
            pdf.ln(12)
            
            pdf.set_font(fonts["sans"], "B", 14)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(200, 10, text="AI Root-Cause & Remediation Analysis")
            pdf.ln(10)

            pdf.set_font(fonts["mono"], "", 10) 
            pdf.set_text_color(0, 0, 0)
            
            cleaned_report = self._clean_text(ai_report)
            _log(f"Step 4a: cleaned_report_len={len(cleaned_report)}")
            
            pdf.multi_cell(0, 6, text=cleaned_report)
            _log("Step 4 OK")
        except Exception as e:
            _log(f"Step 4 FAILED: {e}")
            raise

        # Step 5: Determine filepath and save
        _log("Step 5: saving PDF...")
        try:
            if file_path:
                # Use the user-chosen path from the file dialog
                filepath = file_path
                # Ensure parent directory exists
                Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            else:
                # Auto-generate filename (fallback for programmatic use)
                safe_ip = target_ip.replace('.', '_').replace('/', '_').replace(':', '_')
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"OmniScan_{safe_ip}_{timestamp}.pdf"
                filepath = str(self.output_dir / filename)
            _log(f"Step 5a: filepath={filepath}")
            
            pdf.output(filepath)
            _log(f"Step 5 OK: file saved, size={Path(filepath).stat().st_size}")
        except Exception as e:
            _log(f"Step 5 FAILED: {e}")
            raise
        
        return filepath

    def generate_codebase_pdf(self, code_data: dict, ai_report: str,
                              red_team_mode: bool = False, file_path: str = None) -> str:
        """Generates a professional PDF report for a codebase (SAST) analysis.

        Args:
            code_data: Structured payload produced by CodeAnalyzer.scan_target()
                       (target, file_count, total_lines, files, ...).
            ai_report: The DeepSeek SAST analysis text.
            red_team_mode: If True, labels the report as Red Team (adversary emulation).
            file_path: Optional destination path. If omitted, an auto-generated
                       filename inside reports/ is used.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        pdf = OmniReport()
        pdf.report_title = "OmniScan Codebase Security Analysis Report"
        fonts = self._register_fonts(pdf)
        sans = fonts["sans"]
        mono = fonts["mono"]

        pdf.alias_nb_pages()
        pdf.add_page()

        # --- Target & metadata ---
        target = "Unknown target"
        if isinstance(code_data, dict):
            target = code_data.get("target", target)

        pdf.set_font(sans, "B", 12)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(200, 8, text=f"Target: {target}")
        pdf.ln(8)

        mode_label = "Red Team (Adversary Emulation)" if red_team_mode else "Blue Team (Defensive)"
        pdf.set_font(sans, "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(200, 8, text=f"Analysis Mode: {mode_label}")
        pdf.ln(6)
        pdf.cell(200, 8, text=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        pdf.ln(10)

        # --- Payload summary ---
        if isinstance(code_data, dict):
            pdf.set_font(sans, "B", 13)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(200, 8, text="Payload Summary")
            pdf.ln(8)

            pdf.set_font(sans, "", 10)
            pdf.set_text_color(0, 0, 0)
            summary = (
                f"Files analyzed: {code_data.get('file_count', 0)}"
                f"   |   Total lines: {code_data.get('total_lines', 0)}"
                f"   |   Truncated: {'Yes' if code_data.get('truncated') else 'No'}"
            )
            pdf.multi_cell(0, 6, text=summary, new_x=XPos.LEFT, new_y=YPos.NEXT)
            pdf.ln(6)

        # --- File inventory ---
        files = code_data.get("files", []) if isinstance(code_data, dict) else []
        if files:
            pdf.set_font(sans, "B", 13)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(200, 8, text="File Inventory")
            pdf.ln(8)

            pdf.set_font(mono, "", 9)
            pdf.set_text_color(60, 60, 60)
            for f in files:
                path = f.get("path", "")
                lines = f.get("lines", 0)
                truncated = "  [truncated]" if f.get("truncated") else ""
                pdf.multi_cell(0, 6, text=f"{path}  ({lines} lines){truncated}",
                               new_x=XPos.LEFT, new_y=YPos.NEXT)
            pdf.ln(4)

        # --- Deterministic pre-scan findings ---
        findings = code_data.get("findings", []) if isinstance(code_data, dict) else []
        if findings:
            pdf.set_font(sans, "B", 13)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(200, 8, text="Deterministic Pre-Scan Findings")
            pdf.ln(8)

            pdf.set_font(mono, "", 9)
            for f in findings:
                sev = str(f.get("severity", "UNKNOWN")).upper()
                name = f.get("name", "Finding")
                cwe = f.get("cwe", "")
                path = f.get("path", "")
                line = f.get("line", 0)
                match_text = self._clean_text(str(f.get("match", "")))
                if len(match_text) > 160:
                    match_text = match_text[:160] + "..."
                cwe_str = f" ({cwe})" if cwe else ""

                pdf.set_text_color(150, 20, 20)
                pdf.multi_cell(0, 6, text=f"[{sev}] {name}{cwe_str}",
                               new_x=XPos.LEFT, new_y=YPos.NEXT)
                pdf.set_text_color(60, 60, 60)
                pdf.multi_cell(0, 6, text=f"    {path}:{line}   {match_text}",
                               new_x=XPos.LEFT, new_y=YPos.NEXT)
            pdf.ln(4)

        # --- AI analysis body ---
        pdf.set_font(sans, "B", 14)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(200, 10, text="AI SAST Analysis")
        pdf.ln(10)

        pdf.set_font(mono, "", 10)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 6, text=self._clean_text(ai_report))

        # --- Save ---
        if file_path:
            filepath = file_path
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"OmniScan_Codebase_{timestamp}.pdf"
            filepath = str(self.output_dir / filename)

        pdf.output(filepath)
        return filepath