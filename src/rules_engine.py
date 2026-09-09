"""Deterministic, rule-based static analysis (secrets + insecure patterns).

This runs locally and instantly — no AI, no API call, and no data leaving the
machine — to catch obvious issues with exact file/line locations before the
DeepSeek pass. Findings are meant to be verified and contextualized by the AI,
not duplicated by it.
"""

import re


class RulesEngine:
    """Scans source text with regex rules and returns structured findings."""

    # Maximum findings retained per file to keep UI/prompt sizes bounded.
    MAX_FINDINGS_PER_FILE = 100

    RULES = [
        # ---------------- Secrets ----------------
        {
            "id": "R001",
            "name": "Hardcoded AWS Access Key",
            "category": "secret",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "pattern": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
            "description": "AWS access key ID embedded in source code.",
        },
        {
            "id": "R002",
            "name": "Hardcoded Google API Key",
            "category": "secret",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            "description": "Google API key embedded in source code.",
        },
        {
            "id": "R003",
            "name": "Hardcoded GitHub Token",
            "category": "secret",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "pattern": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
            "description": "GitHub personal access token embedded in source code.",
        },
        {
            "id": "R004",
            "name": "Hardcoded Slack Token",
            "category": "secret",
            "severity": "HIGH",
            "cwe": "CWE-798",
            "pattern": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
            "description": "Slack API token embedded in source code.",
        },
        {
            "id": "R005",
            "name": "Private Key Material",
            "category": "secret",
            "severity": "CRITICAL",
            "cwe": "CWE-321",
            "pattern": re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"),
            "description": "Private cryptographic key embedded in source code.",
        },
        {
            "id": "R006",
            "name": "Hardcoded Credential",
            "category": "secret",
            "severity": "HIGH",
            "cwe": "CWE-798",
            "pattern": re.compile(
                r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|token)\b"
                r"\s*[:=]\s*[\"'][^\"']{8,}[\"']"
            ),
            "description": "Credential-looking value assigned in source code.",
        },
        {
            "id": "R007",
            "name": "Credentials in URL",
            "category": "secret",
            "severity": "HIGH",
            "cwe": "CWE-798",
            "pattern": re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),
            "description": "URL containing embedded username:password credentials.",
        },

        # ---------------- Dangerous execution ----------------
        {
            "id": "R010",
            "name": "Use of eval()",
            "category": "pattern",
            "severity": "CRITICAL",
            "cwe": "CWE-95",
            "pattern": re.compile(r"(?i)\beval\s*\("),
            "description": "Dynamic code evaluation via eval().",
        },
        {
            "id": "R011",
            "name": "Use of exec()",
            "category": "pattern",
            "severity": "CRITICAL",
            "cwe": "CWE-95",
            "pattern": re.compile(r"(?i)\bexec\s*\("),
            "description": "Dynamic code execution via exec().",
        },
        {
            "id": "R012",
            "name": "Insecure Deserialization (pickle)",
            "category": "pattern",
            "severity": "CRITICAL",
            "cwe": "CWE-502",
            "pattern": re.compile(r"(?i)\bpickle\.loads\s*\("),
            "description": "Deserializing untrusted data with pickle.loads().",
        },
        {
            "id": "R013",
            "name": "Insecure Deserialization (yaml.load)",
            "category": "pattern",
            "severity": "HIGH",
            "cwe": "CWE-502",
            "pattern": re.compile(r"(?i)\byaml\.load\s*\("),
            "description": "yaml.load() may instantiate arbitrary objects; use yaml.safe_load().",
        },
        {
            "id": "R014",
            "name": "Shell Command Execution",
            "category": "pattern",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "pattern": re.compile(r"(?i)\bos\.system\s*\("),
            "description": "Shell command execution via os.system().",
        },
        {
            "id": "R015",
            "name": "Subprocess with shell=True",
            "category": "pattern",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "pattern": re.compile(r"(?i)\bsubprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
            "description": "Subprocess launched with shell=True.",
        },
        {
            "id": "R016",
            "name": "SQL String Concatenation",
            "category": "pattern",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "pattern": re.compile(r"(?i)[\"']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^\"']*[\"']\s*\+"),
            "description": "SQL statement built via string concatenation.",
        },
        {
            "id": "R017",
            "name": "SQL in f-string",
            "category": "pattern",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "pattern": re.compile(r"(?i)\bf[\"']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b"),
            "description": "SQL statement built via f-string interpolation.",
        },

        # ---------------- Weak crypto ----------------
        {
            "id": "R020",
            "name": "Weak Hash (MD5)",
            "category": "pattern",
            "severity": "MEDIUM",
            "cwe": "CWE-327",
            "pattern": re.compile(r"(?i)\b(?:hashlib\.)?md5\s*\("),
            "description": "MD5 is cryptographically broken.",
        },
        {
            "id": "R021",
            "name": "Weak Hash (SHA-1)",
            "category": "pattern",
            "severity": "MEDIUM",
            "cwe": "CWE-327",
            "pattern": re.compile(r"(?i)\b(?:hashlib\.)?sha1\s*\("),
            "description": "SHA-1 is cryptographically broken.",
        },
        {
            "id": "R022",
            "name": "Weak Cipher / ECB Mode",
            "category": "pattern",
            "severity": "MEDIUM",
            "cwe": "CWE-327",
            "pattern": re.compile(r"(?i)\b(?:DES|RC4|Blowfish|ECB)\b"),
            "description": "Use of a weak or deprecated cipher/mode.",
        },

        # ---------------- Web / misc ----------------
        {
            "id": "R030",
            "name": "DOM XSS via innerHTML",
            "category": "pattern",
            "severity": "HIGH",
            "cwe": "CWE-79",
            "pattern": re.compile(r"(?i)\.innerHTML\s*="),
            "description": "Assigning to innerHTML with untrusted data.",
        },
        {
            "id": "R031",
            "name": "DOM XSS via document.write",
            "category": "pattern",
            "severity": "MEDIUM",
            "cwe": "CWE-79",
            "pattern": re.compile(r"(?i)document\.write\s*\("),
            "description": "Writing untrusted data via document.write().",
        },
        {
            "id": "R032",
            "name": "Debug Mode Enabled",
            "category": "pattern",
            "severity": "LOW",
            "cwe": "CWE-489",
            "pattern": re.compile(r"(?i)\b(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG)\s*=\s*(?:True|1)\b"),
            "description": "Debug mode left enabled.",
        },
        {
            "id": "R033",
            "name": "Cleartext HTTP URL",
            "category": "pattern",
            "severity": "LOW",
            "cwe": "CWE-319",
            "pattern": re.compile(r"\bhttp://(?!localhost|127\.0\.0\.1)"),
            "description": "Hardcoded HTTP (cleartext) URL.",
        },
    ]

    def scan(self, content: str) -> list:
        """Returns a list of finding dicts for the given source text."""
        if not content:
            return []

        findings = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            for rule in self.RULES:
                for match in rule["pattern"].finditer(line):
                    findings.append({
                        "rule_id": rule["id"],
                        "name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "cwe": rule["cwe"],
                        "line": line_no,
                        "match": match.group(0),
                        "description": rule["description"],
                    })
                    if len(findings) >= self.MAX_FINDINGS_PER_FILE:
                        return findings
        return findings


# Local Verification Block
if __name__ == "__main__":
    engine = RulesEngine()

    sample = (
        'import os\n'
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'password = "supersecretvalue"\n'
        'result = eval(user_input)\n'
        'os.system("rm -rf /")\n'
        'q = "SELECT * FROM users WHERE id = " + uid\n'
        'h = hashlib.md5(data)\n'
        'debug = True\n'
    )

    import json
    print(json.dumps(engine.scan(sample), indent=2))
