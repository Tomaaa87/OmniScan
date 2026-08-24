import nmap
import json
import os
import shutil
import asyncio
from concurrent.futures import ThreadPoolExecutor


def _build_nmap_search_path():
    """Return candidate paths for the nmap executable, cross-platform.

    python-nmap does NOT search the system PATH itself — it only checks the
    literal paths passed in `nmap_search_path`. On Windows, nmap is commonly
    installed under Program Files and is usually not on PATH, so we add the
    standard Windows locations (and honor PATH via shutil.which).
    """
    candidates = []

    # 1. If nmap is already on PATH, prefer it (covers `nmap` / `nmap.exe`).
    in_path = shutil.which("nmap")
    if in_path:
        candidates.append(in_path)

    if os.name == "nt":
        # 2. Standard Windows Nmap installation locations.
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        candidates += [
            os.path.join(program_files, "Nmap", "nmap.exe"),
            os.path.join(program_files_x86, "Nmap", "nmap.exe"),
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        ]
    else:
        # Unix-like default locations.
        candidates += [
            "nmap",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/sw/bin/nmap",
            "/opt/local/bin/nmap",
        ]

    return candidates


class OmniScanner:
    def __init__(self):
        # Initialize the port scanner, pointing it at the nmap executable.
        self.nm = nmap.PortScanner(nmap_search_path=_build_nmap_search_path())
        # Thread pool executor to run synchronous nmap calls asynchronously
        self.executor = ThreadPoolExecutor(max_workers=2)

    def _execute_scan(self, target: str, arguments: str) -> dict:
        """Synchronous wrapper for nmap scanning execution."""
        try:
            self.nm.scan(hosts=target, arguments=arguments)
            # Use _scan_result dict directly — analysed_output does not exist in python-nmap
            result = self.nm._scan_result
            # Defensive: ensure we always return a dict
            if not isinstance(result, dict):
                return {"error": f"Unexpected scan result type: {type(result).__name__}"}
            return result
        except nmap.PortScannerError as e:
            # Catches nmap-level errors (invalid flags, permission denied, etc.)
            return {"error": f"Nmap argument error: {str(e)}. Check your flags and try again."}
        except nmap.PortScannerTimeout as e:
            return {"error": f"Scan timed out: {str(e)}"}
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}

    async def run_scan_async(self, target: str, flags: str) -> dict:
        """Runs the scan in a background thread to prevent UI lockup."""
        loop = asyncio.get_event_loop()
        raw_result = await loop.run_in_executor(
            self.executor, 
            self._execute_scan, 
            target, 
            flags
        )
        return self.parse_results(raw_result)

    def parse_results(self, raw_data: dict) -> dict:
        """Parses complex Nmap scan dictionary into structured, lightweight data."""
        # Defensive: handle case where raw_data is not a dict
        if not isinstance(raw_data, dict):
            return {"error": f"Invalid scan data type: {type(raw_data).__name__}"}

        if "error" in raw_data:
            return raw_data

        parsed_hosts = {}
        scan_data = raw_data.get("scan", {})

        for ip, host_info in scan_data.items():
            # Guard: host_info must be a dict
            if not isinstance(host_info, dict):
                continue

            parsed_hosts[ip] = {
                "hostnames": host_info.get("hostnames", []),
                "os_match": self._extract_os(host_info),
                "ports": []
            }

            # Loop through transport protocols (tcp, udp)
            for proto in ["tcp", "udp"]:
                if proto in host_info:
                    proto_data = host_info[proto]
                    if not isinstance(proto_data, dict):
                        continue
                    for port, port_data in proto_data.items():
                        # Guard: port_data must be a dict
                        if not isinstance(port_data, dict):
                            continue
                        # Extract NSE script outputs if present
                        nse_outputs = port_data.get('script', {})
                        if not isinstance(nse_outputs, dict):
                            nse_outputs = {}

                        parsed_hosts[ip]["ports"].append({
                            "port": port,
                            "protocol": proto,
                            "state": port_data.get("state"),
                            "service": port_data.get("name"),
                            "product": port_data.get("product"),
                            "version": port_data.get("version"),
                            "extrainfo": port_data.get("extrainfo"),
                            "nse_outputs": nse_outputs,
                            "vulnerabilities": []
                        })
        return parsed_hosts

    def _extract_os(self, host_info: dict) -> str:
        """Helper to safely extract the highest accuracy OS match."""
        os_matches = host_info.get("osmatch", [])
        if os_matches and isinstance(os_matches, list):
            first_match = os_matches[0]
            if isinstance(first_match, dict):
                return first_match.get("name", "Unknown OS")
        return "Unknown OS"

# Simple local verification block
if __name__ == "__main__":
    scanner = OmniScanner()
    print("[*] Starting local test scan on localhost...")
    # Using gather to demonstrate async handling
    results = asyncio.run(scanner.run_scan_async("127.0.0.1"))
    print(json.dumps(results, indent=4))
