import requests
import json
import logging
from database import DatabaseManager

class CVEMapper:
    def __init__(self):
        # Updated to CIRCL's new Vulnerability-Lookup API
        self.api_base_url = "https://vulnerability.circl.lu/api/search/"
        
        # Connect to our new local SQLite database manager
        self.db = DatabaseManager()
        
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    def _query_cve_api(self, vendor_product: str) -> list:
        """Hits the external API or pulls from the local DB cache to fetch CVEs."""
        
        cached_data = self.db.get_cached_cve(vendor_product)
        if cached_data:
            logging.info(f"Database cache hit for {vendor_product}. Skipping API call.")
            return cached_data

        try:
            logging.info(f"[*] Reaching out to CIRCL API for: {vendor_product}")
            response = requests.get(f"{self.api_base_url}{vendor_product}", timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                
                if isinstance(data, dict):
                    # --- NEW: CIRCL's NVD 5.2 JSON Standard Parsing ---
                    if "results" in data and isinstance(data["results"], dict) and "nvd" in data["results"]:
                        for entry in data["results"]["nvd"]:
                            # Each entry is a list: ['cve-202x-xxxx', {metadata}]
                            if isinstance(entry, list) and len(entry) >= 2:
                                cve_id = str(entry[0]).upper()
                                cve_record = entry[1]
                                
                                # Extract description deeply nested in the NVD 5.2 container schema
                                summary = "Details available in NVD database."
                                try:
                                    descriptions = cve_record.get("containers", {}).get("cna", {}).get("descriptions", [])
                                    if descriptions and isinstance(descriptions, list):
                                        summary = descriptions[0].get("value", summary)
                                except Exception:
                                    pass
                                
                                cves.append({"id": cve_id, "summary": summary})

                    # --- FALLBACK: Aggressive Fuzzy Parsing ---
                    elif not cves:
                        items = []
                        for key in ["data", "results", "vulnerabilities", "items", "vulns", "cves", "entries"]:
                            if key in data and isinstance(data[key], list):
                                items.extend(data[key])
                        if not items:
                            items = [v for k, v in data.items() if isinstance(v, dict)]
                            
                        for item in items:
                            cve_id = item.get("id") or item.get("cve_id") or item.get("CVE") or item.get("name")
                            summary = item.get("summary") or item.get("description") or "No description provided."
                            if cve_id:
                                cves.append({"id": cve_id, "summary": summary})
                
                # --- VERIFICATION & CACHING ---
                if cves:
                    logging.info(f"[+] Successfully extracted {len(cves)} CVEs for {vendor_product}.")
                    self.db.save_cve_cache(vendor_product, cves)
                else:
                    logging.warning(f"[-] 200 OK, but NO CVEs parsed for {vendor_product}.")
                    logging.warning(f"[-] RAW JSON SNIPPET: {json.dumps(data)[:300]}")
                    
                return cves
            else:
                logging.warning(f"[!] API returned status {response.status_code} for {vendor_product}")
                return []
                
        except requests.exceptions.RequestException as e:
            logging.error(f"[!] Network error querying CVE API: {e}")
            return []

    def enrich_scan_results(self, parsed_scan_data: dict) -> dict:
        """
        Iterates through the Nmap parsed results and attaches CVEs 
        to matching services using CPEs and fallback dictionaries.
        """
        # Defensive: handle non-dict or error-dict input gracefully
        if not isinstance(parsed_scan_data, dict):
            logging.error(f"enrich_scan_results received non-dict: {type(parsed_scan_data).__name__}")
            return {"error": "Invalid scan data format"}

        if "error" in parsed_scan_data:
            logging.warning(f"enrich_scan_results received error payload: {parsed_scan_data['error']}")
            return parsed_scan_data

        enriched_data = parsed_scan_data.copy()

        for ip, host_data in enriched_data.items():
            # host_data must be a dict; skip non-dict entries
            if not isinstance(host_data, dict):
                logging.warning(f"Skipping non-dict host entry for IP {ip}: {type(host_data).__name__}")
                continue

            for port_info in host_data.get("ports", []):
                # port_info must be a dict; skip non-dict entries
                if not isinstance(port_info, dict):
                    logging.warning(f"Skipping non-dict port entry: {type(port_info).__name__}")
                    continue
                
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                cpe = port_info.get("cpe", "") # <-- Extract the official CPE if Nmap found it

                # Safety check: Sometimes Nmap returns CPE as a list instead of a string
                if isinstance(cpe, list) and len(cpe) > 0:
                    cpe = cpe[0]

                # Layer 1: If Nmap provided a strict CPE (e.g., cpe:/a:apache:http_server:2.4.49)
                if cpe and isinstance(cpe, str):
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