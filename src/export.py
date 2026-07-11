from pathlib import Path
import re
from datetime import datetime
from fpdf import FPDF

class OmniReport(FPDF):
    def header(self):
        # Professional Blue-Team Header
        self.set_font("DejaVuSans", "B", 18)
        self.set_text_color(30, 30, 30)
        self.cell(200, 10, text="OmniScan Vulnerability Intelligence Report", border=0, align="C")
        self.ln(10)
        self.set_line_width(0.5)
        self.line(10, 22, 200, 22)
        self.ln(10)

    def footer(self):
        # Clean footer with page numbers
        self.set_y(-15)
        self.set_font("DejaVuSans", "I", 8)
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
        
        # Step 3: Register fonts
        _log("Step 3: registering fonts...")
        font_map = [
            ("DejaVuSans", "", self.DEJAVU_SANS),
            ("DejaVuSans", "B", self.DEJAVU_SANS_BOLD),
            ("DejaVuSans", "I", self.DEJAVU_SANS_OBLIQUE),
            ("DejaVuMono", "", self.DEJAVU_MONO),
            ("DejaVuMono", "B", self.DEJAVU_MONO_BOLD),
        ]
        for family, style, font_path in font_map:
            if not Path(font_path).exists():
                raise FileNotFoundError(
                    f"Font file not found: {font_path}\n"
                    f"Install DejaVu fonts with: sudo apt install fonts-dejavu-core"
                )
            pdf.add_font(family, style, font_path)
        _log("Step 3 OK")
        
        # Step 4: Build pages
        _log("Step 4: building pages...")
        try:
            pdf.alias_nb_pages()
            pdf.add_page()
            
            pdf.set_font("DejaVuSans", "B", 12)
            pdf.set_text_color(0, 51, 102) 
            pdf.cell(200, 8, text=f"Target Network/IP: {target_ip}")
            pdf.ln(8)
            
            scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            pdf.set_font("DejaVuSans", "", 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(200, 8, text=f"Scan Timestamp: {scan_date}")
            pdf.ln(12)
            
            pdf.set_font("DejaVuSans", "B", 14)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(200, 10, text="AI Root-Cause & Remediation Analysis")
            pdf.ln(10)

            pdf.set_font("DejaVuMono", "", 10) 
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