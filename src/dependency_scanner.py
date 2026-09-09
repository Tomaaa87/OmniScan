"""Dependency vulnerability scanning via OSV.dev (free, keyless API).

Walks a project for manifest/lockfiles, extracts pinned package versions,
queries the OSV.dev batch endpoint for known vulnerabilities, and returns a
structured report. No API key or account is required.
"""

import json
import logging
import math
import os
import re

import requests


def cvss_base_score(vector: str):
    """Compute the CVSS v3.x base score from a vector string, or None."""
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None

    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    required = ("AV", "AC", "UI", "C", "I", "A")
    if not all(k in metrics for k in required):
        return None

    av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_values = {"L": 0.77, "H": 0.44}
    ui_values = {"N": 0.85, "R": 0.62}
    impact_values = {"H": 0.56, "L": 0.22, "N": 0.00}

    scope = metrics.get("S", "U")
    pr_values = (
        {"N": 0.85, "L": 0.62, "H": 0.27}
        if scope == "U"
        else {"N": 0.85, "L": 0.68, "H": 0.50}
    )

    av = av_values.get(metrics["AV"])
    ac = ac_values.get(metrics["AC"])
    ui = ui_values.get(metrics["UI"])
    c = impact_values.get(metrics["C"])
    i = impact_values.get(metrics["I"])
    a = impact_values.get(metrics["A"])
    pr = pr_values.get(metrics.get("PR"))

    if None in (av, ac, ui, c, i, a, pr):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    elif scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)

    return math.ceil(base * 10) / 10


def severity_from_score(score):
    """Map a CVSS base score to a qualitative severity label."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return None


class DependencyScanner:
    """Discovers manifests, parses pinned versions, and queries OSV.dev."""

    OSV_QUERY_URL = "https://api.osv.dev/v1/query"

    # filename -> parser method suffix (e.g. requirements.txt -> _parse_requirements)
    MANIFEST_FILENAMES = {
        "requirements.txt": "requirements",
        "package.json": "package_json",
        "package-lock.json": "package_lock",
        "pom.xml": "pom",
        "go.mod": "go_mod",
    }

    IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
                    "build", "dist", "target", ".idea", ".vscode"}

    def __init__(self):
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def scan_target(self, target_path: str) -> dict:
        """Scans a directory (or single manifest file) for vulnerable packages.

        Returns:
            {
                "target": <abs path>,
                "manifests": [<paths>],
                "packages": [
                    {"name", "ecosystem", "version", "source", "vulns": [...]},
                ],
                "summary": {"manifests_found", "packages_scanned", "vulnerable",
                            "total_vulns"},
            }
        """
        target_path = os.path.abspath(target_path)

        manifests = self._find_manifests(target_path)
        if not manifests:
            return {
                "target": target_path,
                "manifests": [],
                "packages": [],
                "summary": {
                    "manifests_found": 0,
                    "packages_scanned": 0,
                    "vulnerable": 0,
                    "total_vulns": 0,
                },
            }

        packages = []
        for path in manifests:
            rel = self._rel(path, target_path)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError as exc:
                logging.warning(f"[!] Could not read manifest {path}: {exc}")
                continue

            kind = self.MANIFEST_FILENAMES.get(os.path.basename(path))
            if not kind:
                continue
            parser = getattr(self, f"_parse_{kind}")
            packages.extend(parser(content, rel))

        # Deduplicate by (ecosystem, name, version).
        seen = set()
        unique = []
        for pkg in packages:
            key = (pkg["ecosystem"], pkg["name"], pkg["version"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(pkg)

        # Query OSV for every pinned package.
        vuln_map = self._query_osv(unique) if unique else {}

        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        packages_report = []
        vulnerable_count = 0
        total_vulns = 0

        for pkg in unique:
            key = f"{pkg['ecosystem']}:{pkg['name']}@{pkg['version']}"
            vulns = vuln_map.get(key, [])
            vulns.sort(key=lambda v: severity_rank.get(v.get("severity"), 4))
            if vulns:
                vulnerable_count += 1
                total_vulns += len(vulns)
            packages_report.append({
                "name": pkg["name"],
                "ecosystem": pkg["ecosystem"],
                "version": pkg["version"],
                "source": pkg["source"],
                "vulns": vulns,
            })

        # Vulnerable packages first, then by vuln count descending.
        packages_report.sort(key=lambda p: (0 if p["vulns"] else 1, -len(p["vulns"])))

        return {
            "target": target_path,
            "manifests": manifests,
            "packages": packages_report,
            "summary": {
                "manifests_found": len(manifests),
                "packages_scanned": len(unique),
                "vulnerable": vulnerable_count,
                "total_vulns": total_vulns,
            },
        }

    # ------------------------------------------------------------------ #
    # Manifest discovery
    # ------------------------------------------------------------------ #
    def _find_manifests(self, target_path: str) -> list:
        """Returns the manifest/lockfile paths for a directory or single file."""
        if os.path.isfile(target_path):
            if os.path.basename(target_path) in self.MANIFEST_FILENAMES:
                return [target_path]
            return []

        manifests = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS]
            for name in sorted(files):
                if name in self.MANIFEST_FILENAMES:
                    manifests.append(os.path.join(root, name))
        return manifests

    @staticmethod
    def _rel(path: str, target_path: str) -> str:
        try:
            return os.path.relpath(path, target_path)
        except ValueError:
            return path

    # ------------------------------------------------------------------ #
    # Manifest parsers (each returns [{"name","ecosystem","version","source"}])
    # ------------------------------------------------------------------ #
    def _parse_requirements(self, content: str, source: str) -> list:
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*===?\s*([^\s;#]+)", line)
            if match:
                name = match.group(1).lower()
                version = match.group(2)
                packages.append({"name": name, "ecosystem": "PyPI", "version": version, "source": source})
        return packages

    def _parse_package_json(self, content: str, source: str) -> list:
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return []
        packages = []
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, version in deps.items():
                if not isinstance(version, str):
                    continue
                version = version.strip()
                if re.fullmatch(r"\d+\.\d+\.\d+", version):
                    packages.append({"name": name, "ecosystem": "npm", "version": version, "source": source})
        return packages

    def _parse_package_lock(self, content: str, source: str) -> list:
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return []
        packages = []
        pkg_map = data.get("packages", {})
        if isinstance(pkg_map, dict):
            for key, meta in pkg_map.items():
                if not key or not isinstance(meta, dict):
                    continue
                version = meta.get("version")
                if not isinstance(version, str):
                    continue
                parts = key.split("node_modules/")
                if len(parts) < 2:
                    continue
                name = parts[-1].split("/")[0]
                if name and re.fullmatch(r"\d+\.\d+\.\d+", version):
                    packages.append({"name": name, "ecosystem": "npm", "version": version, "source": source})
        return packages

    def _parse_pom(self, content: str, source: str) -> list:
        packages = []
        for block in re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL):
            g = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", block)
            a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", block)
            v = re.search(r"<version>\s*([^<]+?)\s*</version>", block)
            if g and a and v:
                group = g.group(1).strip()
                artifact = a.group(1).strip()
                version = v.group(1).strip()
                if group and artifact and version and "${" not in version:
                    packages.append({
                        "name": f"{group}:{artifact}",
                        "ecosystem": "Maven",
                        "version": version,
                        "source": source,
                    })
        return packages

    def _parse_go_mod(self, content: str, source: str) -> list:
        packages = []
        # Single-line requires.
        for match in re.finditer(r"(?m)^require\s+([\w./\-]+)\s+(v[\w.\-+]+)", content):
            name, version = match.group(1), match.group(2)
            if not self._is_pseudo_go_version(version):
                packages.append({"name": name, "ecosystem": "Go", "version": version, "source": source})
        # require (...) blocks.
        for block in re.findall(r"(?m)^require\s*\(([^)]*)\)", content):
            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                match = re.match(r"([\w./\-]+)\s+(v[\w.\-+]+)", line)
                if match:
                    name, version = match.group(1), match.group(2)
                    if not self._is_pseudo_go_version(version):
                        packages.append({"name": name, "ecosystem": "Go", "version": version, "source": source})
        return packages

    @staticmethod
    def _is_pseudo_go_version(version: str) -> bool:
        """Go pseudo-versions look like v1.2.3-0.20210101000000-abcdef123456."""
        return bool(re.search(r"-\d{14}-", version))

    # ------------------------------------------------------------------ #
    # OSV API
    # ------------------------------------------------------------------ #
    def _query_osv(self, packages: list) -> dict:
        """Queries OSV.dev per package, returning a vuln map keyed by
        "ecosystem:name@version". The single query endpoint returns full vuln
        details (the batch endpoint only returns IDs)."""
        results = {}
        for pkg in packages:
            key = f"{pkg['ecosystem']}:{pkg['name']}@{pkg['version']}"
            query = {
                "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
                "version": pkg["version"],
            }
            try:
                response = requests.post(self.OSV_QUERY_URL, json=query, timeout=20)
                if response.status_code != 200:
                    logging.warning(f"[!] OSV returned status {response.status_code} for {key}")
                    results[key] = []
                    continue
                data = response.json()
                vulns = data.get("vulns", []) or []
                results[key] = [self._parse_vuln(v) for v in vulns]
            except requests.exceptions.RequestException as exc:
                logging.error(f"[!] OSV network error for {key}: {exc}")
                results[key] = []
        return results

    @staticmethod
    def _parse_vuln(vuln: dict) -> dict:
        """Normalizes a single OSV vulnerability record."""
        aliases = vuln.get("aliases", []) or []
        cve = next((a for a in aliases if str(a).upper().startswith("CVE-")), None)
        vid = cve or vuln.get("id", "unknown")

        summary = vuln.get("summary") or vuln.get("details") or "No description provided."

        # Severity: prefer a CVSS v3 vector, then database-specific severity.
        severity = None
        vector = None
        for sev in vuln.get("severity", []) or []:
            if not isinstance(sev, dict):
                continue
            if sev.get("type") == "CVSS_V3" and sev.get("score"):
                vector = sev["score"]
                severity = severity_from_score(cvss_base_score(vector))
                if severity:
                    break
        if not severity:
            db_specific = vuln.get("database_specific", {})
            if isinstance(db_specific, dict):
                raw = str(db_specific.get("severity", "")).upper()
                if raw == "MODERATE":
                    severity = "MEDIUM"
                elif raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity = raw
        severity = severity or "UNKNOWN"

        # First fixed version across affected ranges.
        fixed = None
        for affected in vuln.get("affected", []) or []:
            if not isinstance(affected, dict):
                continue
            for rng in affected.get("ranges", []) or []:
                if not isinstance(rng, dict):
                    continue
                for event in rng.get("events", []) or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        fixed = event["fixed"]
                        break
                if fixed:
                    break
            if fixed:
                break

        return {
            "id": vid,
            "summary": summary,
            "severity": severity,
            "cvss_vector": vector,
            "fixed": fixed,
        }


# Local Verification Block (no network)
if __name__ == "__main__":
    scanner = DependencyScanner()

    print("CVSS 9.8 vector ->", cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
    print("CVSS 4.3 vector ->", cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"))

    req = (
        "django==3.2.10\n"
        "requests[security]==2.28.0\n"
        "flask>=2.0\n"
        "# comment\n"
    )
    print("requirements:", scanner._parse_requirements(req, "requirements.txt"))

    pom = (
        "<dependency><groupId>org.apache.logging.log4j</groupId>"
        "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
    )
    print("pom:", scanner._parse_pom(pom, "pom.xml"))

    gomod = "require (\n\tgithub.com/gin-gonic/gin v1.7.4\n\tgolang.org/x/text v0.3.7\n)"
    print("go.mod:", scanner._parse_go_mod(gomod, "go.mod"))
