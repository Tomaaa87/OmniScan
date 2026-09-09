import os

from rules_engine import RulesEngine


class CodeAnalyzer:
    """Scans source code in a directory (recursively) or a single file and
    bundles it into a compact, context-safe payload for AI security analysis.

    The produced payload is intentionally token-bounded so it can fit inside
    the DeepSeek context window without blowing up the API request.
    """

    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".ts", ".php", ".java", ".cpp", ".c", ".cs",
        ".go", ".html", ".sql", ".kt", ".sh",
    }

    # Directories that are pruned during traversal and never descended into.
    IGNORED_DIRS = {".git", "node_modules", "venv", "__pycache__", "build", "dist"}

    # Token budgets (rough estimate: ~4 characters per token).
    DEFAULT_MAX_FILE_CHARS = 12_000    # per-file snippet cap (~3k tokens)
    DEFAULT_MAX_TOTAL_CHARS = 120_000  # whole-payload cap (~30k tokens)

    def __init__(self, max_file_chars=None, max_total_chars=None):
        self.max_file_chars = max_file_chars or self.DEFAULT_MAX_FILE_CHARS
        self.max_total_chars = max_total_chars or self.DEFAULT_MAX_TOTAL_CHARS
        self.rules = RulesEngine()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def scan_target(self, target_path: str) -> dict:
        """Entry point: accepts a directory path or a single file path.

        Returns a structured dictionary:
            {
                "target": <absolute path>,
                "file_count": <number of files included in payload>,
                "total_files_found": <number of supported files discovered>,
                "total_lines": <sum of line counts>,
                "total_chars": <payload size in characters>,
                "truncated": <bool>,
                "files": [
                    {"path": ..., "lines": ..., "snippet": ..., "truncated": bool},
                    ...
                ]
            }
        On invalid targets, returns {"error": "..."}.
        """
        target_path = os.path.abspath(target_path)

        if os.path.isfile(target_path):
            files = self._collect_single_file(target_path)
        elif os.path.isdir(target_path):
            files = self._collect_directory(target_path)
        else:
            return {"error": f"Target does not exist: {target_path}"}

        return self.build_payload(files, target_path)

    def build_payload(self, files: list, target_path: str) -> dict:
        """Assembles the final structured payload, applying the global cap.

        Deterministic findings are aggregated across ALL discovered files (not
        just those that fit the token budget) into a flat list plus a severity
        summary.
        """
        total_lines = sum(f["lines"] for f in files)
        total_chars = 0
        truncated = False
        payload_files = []

        for f in files:
            snippet = f["snippet"]
            remaining = self.max_total_chars - total_chars

            if remaining <= 0:
                truncated = True
                break

            if len(snippet) > remaining:
                snippet = snippet[:remaining] + "\n... [payload truncated to fit AI context window]"
                truncated = True

            total_chars += len(snippet)
            payload_files.append({
                "path": f["path"],
                "lines": f["lines"],
                "snippet": snippet,
                "truncated": f["truncated"] or len(snippet) < len(f["snippet"]),
            })

        # Aggregate deterministic findings across all discovered files.
        all_findings = []
        for f in files:
            for finding in f.get("findings", []):
                finding = dict(finding)
                finding["path"] = f["path"]
                all_findings.append(finding)

        findings_summary = self._summarize_findings(all_findings)

        return {
            "target": target_path,
            "file_count": len(payload_files),
            "total_files_found": len(files),
            "total_lines": total_lines,
            "total_chars": total_chars,
            "truncated": truncated or any(f["truncated"] for f in files),
            "files": payload_files,
            "findings": all_findings,
            "findings_summary": findings_summary,
        }

    @staticmethod
    def _summarize_findings(findings: list) -> dict:
        """Counts findings by severity and returns a small summary dict."""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
        for f in findings:
            sev = str(f.get("severity", "")).upper()
            if sev in summary:
                summary[sev] += 1
            summary["total"] += 1
        return summary

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _collect_directory(self, directory: str) -> list:
        """Recursively walks a directory, pruning ignored folders in-place."""
        files = []
        for root, dirs, filenames in os.walk(directory):
            # Prune ignored directories so os.walk never descends into them.
            dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS]
            for name in sorted(filenames):
                path = os.path.join(root, name)
                if self._is_supported(path):
                    files.append(self._read_file(path))
        return files

    def _collect_single_file(self, file_path: str) -> list:
        if not self._is_supported(file_path):
            return []
        return [self._read_file(file_path)]

    def _is_supported(self, path: str) -> bool:
        ext = os.path.splitext(path)[1].lower()
        return ext in self.SUPPORTED_EXTENSIONS

    def _read_file(self, path: str) -> dict:
        """Reads a file, counts its lines, truncates the snippet, and runs
        the deterministic rule scan against the FULL file contents."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            return {
                "path": path,
                "lines": 0,
                "snippet": f"[!] Could not read file: {exc}",
                "truncated": False,
                "findings": [],
            }

        if content:
            lines = content.count("\n") + (0 if content.endswith("\n") else 1)
        else:
            lines = 0

        truncated = len(content) > self.max_file_chars
        snippet = content[:self.max_file_chars]
        if truncated:
            snippet += "\n... [file truncated — exceeds per-file token cap]"

        # Run deterministic rules on the complete file (not the truncated snippet).
        findings = self.rules.scan(content)

        return {
            "path": path,
            "lines": lines,
            "snippet": snippet,
            "truncated": truncated,
            "findings": findings,
        }


# Local Verification Block
if __name__ == "__main__":
    import json

    analyzer = CodeAnalyzer()
    # Point this at any local folder (or file) to preview the payload.
    sample = os.path.join(os.path.dirname(__file__), "code_analyzer.py")
    payload = analyzer.scan_target(sample)
    print(json.dumps(payload, indent=2))
