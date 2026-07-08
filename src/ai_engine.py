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
        
        # The core guardrail and persona for the AI
        self.system_prompt = (
            "You are the internal AI for OmniScan, a Blue Team vulnerability analysis tool. "
            "You will receive a JSON payload detailing open ports, services, and associated CVEs. "
            "Your tasks: \n"
            "1. Provide a concise, highly technical root-cause analysis of the vulnerabilities.\n"
            "2. Explain the risk context in a professional tone.\n"
            "3. Generate actionable remediation steps, including bash commands, firewall rules, or configuration changes.\n"
            "CRITICAL: Never generate offensive exploit payloads. Maintain an educational, defensive posture at all times."
        )

    def analyze_vulnerabilities(self, enriched_scan_data: dict) -> str:
        """Sends the enriched scan data to DeepSeek for analysis."""
        
        # Convert our Python dictionary into a formatted string for the AI to read
        user_prompt = f"Analyze the following network scan results:\n\n{json.dumps(enriched_scan_data, indent=2)}"

        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.3, # Keep it low so the AI is precise and analytical, not "creative"
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
    
    print("[*] Sending mock data to DeepSeek...")
    print(engine.analyze_vulnerabilities(mock_data))