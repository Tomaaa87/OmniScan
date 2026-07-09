import requests
import json
import logging
from database import DatabaseManager

class CVEMapper:
    def __init__(self):
        # Base URL for a free, unauthenticated CVE search API
        self.api_base_url = "https://cve.circl.lu/api/search/"
        
        # Connect to our new local SQLite database manager
        self.db = DatabaseManager()
        
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    def _query_cve_api(self, vendor_product: str) -> list:
        """Hits the external API or pulls from the local DB cache to fetch CVEs."""
        
        # 1. Check local SQLite cache first to prevent rate-limiting
        cached_data = self.db.get_cached_cve(vendor_product)
        if cached_data:
            logging.info(f"Database cache hit for {vendor_product}. Skipping API call.")
            return cached_data

        # 2. If not in the database, query the public API
        try:
            response = requests.get(f"{self.api_base_url}{vendor_product}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Extract just the CVE IDs and summaries
                cves = [{"id": item["id"], "summary": item["summary"]} for item in data.get("data", [])]
                
                # 3. Save the new data to the SQLite cache for the next time we see this service
                logging.info(f"Saving new CVE data for {vendor_product} to local database.")
                self.db.save_cve_cache(vendor_product, cves)
                
                return cves
            else:
                logging.warning(f"API returned status {response.status_code} for {vendor_product}")
                return []
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error querying CVE API: {e}")
            return []

    def enrich_scan_results(self, parsed_scan_data: dict) -> dict:
        """
        Iterates through the Nmap parsed results and attaches CVEs 
        to matching services using CPEs and fallback dictionaries.
        """
        enriched_data = parsed_scan_data.copy()

        for ip, host_data in enriched_data.items():
            for port_info in host_data.get("ports", []):
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                cpe = port_info.get("cpe", "") # <-- Extract the official CPE if Nmap found it

                # Layer 1: If Nmap provided a strict CPE (e.g., cpe:/a:apache:http_server:2.4.49)
                if cpe:
                    # Strip the 'cpe:/x:' prefix to get the clean search string for CIRCL
                    clean_cpe = cpe.split(':')
                    if len(clean_cpe) >= 4:
                        # Extract vendor and product (e.g., apache/http_server)
                        search_query = f"{clean_cpe[2]}/{clean_cpe[3]}"
                        logging.info(f"[*] CPE Match Found! Querying API for: {search_query} {version}")
                        port_info["vulnerabilities"] = self._query_cve_api(search_query)
                        continue # Skip to the next port if we got a CPE hit

                # Layer 2: If no CPE exists, fall back to our translation dictionary
                if product and product.lower() not in ["", "unknown"]:
                    raw_product = product.lower()
                    
                    # Nmap to CIRCL Translation Dictionary (Fallback)
                    product_map = {
                        "apache httpd": "apache/http_server",
                        "mikrotik routeros sshd": "mikrotik/routeros",
                        "mikrotik router ftpd": "mikrotik/routeros",
                        "openssh": "openbsd/openssh",
                        "vsftpd": "vsftpd",
                        "lighttpd": "lighttpd/lighttpd",
                        "nginx": "f5/nginx"
                    }
                    
                    search_query = product_map.get(raw_product, raw_product.replace(" ", "_"))
                    
                    logging.info(f"[*] Fallback Dictionary Query for: {search_query} {version}")
                    port_info["vulnerabilities"] = self._query_cve_api(search_query)
                else:
                    port_info["vulnerabilities"] = []

        return enriched_data

# Local Verification Block
if __name__ == "__main__":
    mapper = CVEMapper()
    
    mock_nmap_data = {
        "192.168.1.100": {
            "os_match": "Linux",
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.49",
                    "cpe": "cpe:/a:apache:http_server:2.4.49" # Added mock CPE to test new logic
                }
            ]
        }
    }
    
    print("[*] Starting database-backed CVE mapping test...")
    enriched_results = mapper.enrich_scan_results(mock_nmap_data)
    print(json.dumps(enriched_results, indent=4))