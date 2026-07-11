import os
import json
from openai import OpenAI

class AIEngine:
    def __init__(self):
        # Load the API key from environment variables for security
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            raise ValueError("DEEPSEEK_API_KEY environment variable is missing.")

        # Initialize the client pointing to DeepSeek's endpoint
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )

        # --- Blue Team (Default Defensive) System Prompt ---
        self.blue_team_prompt = (
            "You are the internal AI for OmniScan, a Blue Team vulnerability analysis tool. "
            "You will receive a JSON payload detailing open ports, services, and associated CVEs. "
            "Your tasks:\n"
            "1. Provide a concise, highly technical root-cause analysis of the vulnerabilities.\n"
            "2. Explain the risk context in a professional tone.\n"
            "3. Generate actionable remediation steps, including bash commands, firewall rules, or configuration changes.\n"
            "CRITICAL: Never generate offensive exploit payloads. Maintain an educational, defensive posture at all times."
        )

        # --- Red Team (Adversary Emulation) System Prompt ---
        self.red_team_prompt = (
            "You are the internal AI for OmniScan operating in RED TEAM / ADVERSARY EMULATION mode. "
            "You will receive a JSON payload detailing open ports, services, and associated CVEs. "
            "Your role is to provide an offensive security context for authorized penetration testing and threat emulation. "
            "Your tasks:\n"
            "1. EXPLOIT FEASIBILITY & MECHANICS: Explain the high-level technical root cause from an attacker's perspective "
            "(e.g., memory corruption, injection vectors, deserialization flaws, authentication bypass). Describe the impact "
            "if successfully exploited.\n"
            "2. WEAPONIZATION STATUS: State whether public Proof-of-Concept (PoC) code or Metasploit modules exist for the "
            "identified CVEs. Reference public repositories conceptually (such as Exploit-DB entries, GitHub PoCs, or "
            "packetstorm resources) — do NOT link directly to live exploit code.\n"
            "3. FRAMEWORK MAPPING: Explicitly map each vulnerability to its relevant MITRE ATT&CK Technique ID "
            "(e.g., T1190 - Exploit Public-Facing Application, T1059 - Command and Scripting Interpreter) and "
            "OWASP / OWASP Top 10 classification where applicable.\n"
            "4. PENETRATION TESTING METHODOLOGY REFERENCE: Contextualize the threat according to active validation "
            "testing standards (such as OWASP WSTG, PTES, or OSSTMM).\n"
            "CRITICAL GUARDRAIL: DO NOT generate weaponized exploit scripts, custom payloads, shellcode, or specific "
            "step-by-step bypass code. Focus entirely on feasibility analysis, severity mapping, and public threat "
            "intelligence context. All output must remain within authorized security assessment boundaries."
        )

    def analyze_vulnerabilities(self, enriched_scan_data: dict, red_team_mode: bool = False) -> str:
        """Sends the enriched scan data to DeepSeek for analysis.

        Args:
            enriched_scan_data: Dictionary of scan results keyed by host, containing ports,
                                services, versions, and mapped CVEs.
            red_team_mode: If False (default), uses a defensive Blue Team prompt focused on
                           remediation and hardening. If True, pivots to adversary emulation
                           context: exploit feasibility, PoC availability, MITRE ATT&CK /
                           OWASP mappings, and PTES/WSTG methodology references.
        """

        # Dynamically select the system prompt based on operational mode
        selected_prompt = self.red_team_prompt if red_team_mode else self.blue_team_prompt

        # Convert our Python dictionary into a formatted string for the AI to read
        user_prompt = f"Analyze the following network scan results:\n\n{json.dumps(enriched_scan_data, indent=2)}"

        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": selected_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.3,  # Keep it low so the AI is precise and analytical, not "creative"
                max_tokens=3000
            )

            return response.choices[0].message.content

        except Exception as e:
            return f"Error communicating with DeepSeek API: {str(e)}"

# Local Verification Block
if __name__ == "__main__":
    # To test this, temporarily set your key in the terminal before running:
    # export DEEPSEEK_API_KEY="your_key_here" (Linux/Mac)
    # setx DEEPSEEK_API_KEY "your_key_here" (Windows)

    engine = AIEngine()

    mock_data = {
        "192.168.1.50": {
            "ports": [
                {
                    "port": 21,
                    "service": "ftp",
                    "product": "vsftpd",
                    "version": "2.3.4",
                    "vulnerabilities": [{"id": "CVE-2011-2523", "summary": "Backdoor execution"}]
                }
            ]
        }
    }

    # --- Test 1: Default Blue Team (Defensive) Mode ---
    print("=" * 60)
    print("[*] BLUE TEAM MODE — Sending mock data to DeepSeek...")
    print("=" * 60)
    print(engine.analyze_vulnerabilities(mock_data))

    print("\n\n")

    # --- Test 2: Red Team (Adversary Emulation) Mode ---
    print("=" * 60)
    print("[*] RED TEAM MODE — Sending mock data to DeepSeek...")
    print("=" * 60)
    print(engine.analyze_vulnerabilities(mock_data, red_team_mode=True))