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

    def generate_pdf(self, target_ip: str, ai_report: str) -> str:
        """Generates the PDF and saves it to the reports folder."""
        
        # Guarantee the output directory exists before writing
        self.output_dir.mkdir(parents=True, exist_ok=True)

        pdf = OmniReport()
        
        # Register Unicode-capable TTF fonts (supports special chars like em-dash, bullets, etc.)
        pdf.add_font("DejaVuSans", "", self.DEJAVU_SANS, uni=True)
        pdf.add_font("DejaVuSans", "B", self.DEJAVU_SANS_BOLD, uni=True)
        pdf.add_font("DejaVuSans", "I", self.DEJAVU_SANS_OBLIQUE, uni=True)
        pdf.add_font("DejaVuMono", "", self.DEJAVU_MONO, uni=True)
        pdf.add_font("DejaVuMono", "B", self.DEJAVU_MONO_BOLD, uni=True)
        
        pdf.alias_nb_pages()
        pdf.add_page()
        
        # Metadata Section
        pdf.set_font("DejaVuSans", "B", 12)
        pdf.set_text_color(0, 51, 102) 
        pdf.cell(200, 8, text=f"Target Network/IP: {target_ip}")
        pdf.ln(8)
        
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.set_font("DejaVuSans", "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(200, 8, text=f"Scan Timestamp: {scan_date}")
        pdf.ln(12)
        
        # Section Header
        pdf.set_font("DejaVuSans", "B", 14)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(200, 10, text="AI Root-Cause & Remediation Analysis")
        pdf.ln(10)

        # AI Report Body — monospace font for code/report readability
        pdf.set_font("DejaVuMono", "", 10) 
        pdf.set_text_color(0, 0, 0)
        
        cleaned_report = self._clean_text(ai_report)
        
        # Write the text with automatic line wrapping
        pdf.multi_cell(0, 6, text=cleaned_report)
        
        # Format filename
        safe_ip = target_ip.replace('.', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"OmniScan_{safe_ip}_{timestamp}.pdf"
        
        filepath = str(self.output_dir / filename)
        
        # Final save execution
        pdf.output(filepath)
        
        return filepath