import sqlite3
import json
from datetime import datetime
from pathlib import Path

class DatabaseManager:
    def __init__(self, db_name="data/omniscan.db"):
        # Resolve the project root and create a data/ folder to keep things clean
        src_dir = Path(__file__).resolve().parent
        project_root = src_dir.parent
        self.db_path = project_root / "data"
        self.db_path.mkdir(exist_ok=True)
        
        self.db_file = self.db_path / "omniscan.db"
        self._initialize_db()

    def _get_connection(self):
        """Creates and returns a connection to the SQLite database."""
        return sqlite3.connect(self.db_file)

    def _initialize_db(self):
        """Creates the required tables if they do not exist on first launch."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Table 1: Storing past network scans and AI reports
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    raw_data TEXT,
                    ai_report TEXT
                )
            ''')
            
            # Table 2: Local CVE caching to avoid CIRCL API rate limits
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cve_cache (
                    vendor_product TEXT PRIMARY KEY,
                    cve_data TEXT NOT NULL,
                    last_updated TEXT NOT NULL
                )
            ''')
            conn.commit()

    # ==========================================
    # CVE CACHE METHODS
    # ==========================================
    def get_cached_cve(self, vendor_product: str):
        """Retrieves cached CVEs for a specific product."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cve_data FROM cve_cache WHERE vendor_product = ?', (vendor_product,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None

    def save_cve_cache(self, vendor_product: str, cve_data: list):
        """Saves CIRCL API results to the local database."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cve_json = json.dumps(cve_data)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # INSERT OR REPLACE acts as an update if the product already exists
            cursor.execute('''
                INSERT OR REPLACE INTO cve_cache (vendor_product, cve_data, last_updated)
                VALUES (?, ?, ?)
            ''', (vendor_product, cve_json, timestamp))
            conn.commit()

    # ==========================================
    # SCAN HISTORY METHODS
    # ==========================================
    def save_scan(self, target_ip: str, raw_data: dict, ai_report: str):
        """Saves a fully completed scan into the history log."""
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        raw_json = json.dumps(raw_data)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_history (target_ip, scan_date, raw_data, ai_report)
                VALUES (?, ?, ?, ?)
            ''', (target_ip, scan_date, raw_json, ai_report))
            conn.commit()

    def get_all_scans(self) -> list:
        """Retrieves lightweight metadata for populating the UI sidebar."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Order by ID descending so the newest scans appear at the top
            cursor.execute('SELECT id, target_ip, scan_date FROM scan_history ORDER BY id DESC')
            return cursor.fetchall()

    def get_scan_by_id(self, scan_id: int) -> dict:
        """Loads all heavy data for a specific historical scan."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT target_ip, raw_data, ai_report FROM scan_history WHERE id = ?', (scan_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    "target_ip": row[0],
                    "raw_data": json.loads(row[1]),
                    "ai_report": row[2]
                }
            return {}

# Local Test Block
if __name__ == "__main__":
    db = DatabaseManager()
    print(f"[*] Database successfully initialized at: {db.db_file}")

    