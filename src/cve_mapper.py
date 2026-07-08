import requests
import json
import logging

class CVEMapper:
    def __init__(self):
        # Base URL for a free, unauthenticated CVE search API
        # (Using circl.lu as a reliable educational standard)
        self.api_base_url = "https://cve.circl.lu/api/search/"
        
        # In-memory cache to prevent redundant API calls during development.
        # This will be replaced by our SQLite .db integration later.
        self._local_cache = {}
        
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    def _query_cve_api(self, vendor_product: str) -> list:
        """Hits the external API to fetch CVEs for a specific product."""
        if vendor_product in self._local_cache:
            logging.info(f"Cache hit for {vendor_product}")
            return self._local_cache[vendor_product]

        try:
            # Format the query string (e.g., "apache/http_server")
            response = requests.get(f"{self.api_base_url}{vendor_product}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Extract just the CVE IDs and summaries to keep the payload light
                cves = [{"id": item["id"], "summary": item["summary"]} for item in data.get("data", [])]
                
                # Store in cache
                self._local_cache[vendor_product] = cves
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
        to matching services.
        """
        enriched_data = parsed_scan_data.copy()

        for ip, host_data in enriched_data.items():
            for port_info in host_data.get("ports", []):
                product = port_info.get("product")
                version = port_info.get("version")

                # We can only map CVEs if we have a valid product name
                if product and product.lower() not in ["", "unknown"]:
                    # Create a search string. (Note: CIRCL API prefers vendor/product format, 
                    # but a direct product search works for demonstration).
                    search_query = product.lower().replace(" ", "_")
                    
                    logging.info(f"Looking up vulnerabilities for: {search_query} {version}")
                    cve_list = self._query_cve_api(search_query)
                    
                    # Attach the found vulnerabilities to the port data
                    port_info["vulnerabilities"] = cve_list
                else:
                    port_info["vulnerabilities"] = []

        return enriched_data

# Local Verification Block
if __name__ == "__main__":
    mapper = CVEMapper()
    
    # Mock data simulating the output from scanner.py
    mock_nmap_data = {
        "192.168.1.100": {
            "os_match": "Linux",
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.49"
                }
            ]
        }
    }
    
    print("[*] Starting local CVE mapping test...")
    enriched_results = mapper.enrich_scan_results(mock_nmap_data)
    print(json.dumps(enriched_results, indent=4))