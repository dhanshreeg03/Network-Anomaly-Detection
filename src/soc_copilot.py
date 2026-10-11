import os
import requests
import json
from typing import Dict, Any, List, Optional
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class SOCCopilot:
    """
    AI Security Operations Center (SOC) Copilot powered by Google Gemini API.
    Provides context-aware threat explanation, mitigation advice, and remediation playbooks.
    """
    
    GEMINI_MODELS = [
        "gemini-flash-latest",
        "gemini-pro-latest",
        "gemini-3.8-flash",
        "gemini-3.5-flash",
        "gemini-2.5-flash"
    ]
    
    def __init__(self, default_api_key: Optional[str] = None):
        self.default_api_key = default_api_key or os.getenv("GEMINI_API_KEY", "")

    def chat(self, user_message: str, flow_context: Optional[Dict[str, Any]] = None,
             api_key: Optional[str] = None, history: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """
        Sends a query to Gemini with rich telemetry and ML context.
        Falls back to local rule-based SOC expert intelligence if no key is configured.
        """
        active_key = api_key or self.default_api_key or os.getenv("GEMINI_API_KEY", "")
        
        system_prompt = self._build_system_prompt(flow_context)
        
        if active_key.strip():
            try:
                reply, model_used = self._call_gemini_api(user_message, system_prompt, active_key, history)
                return {
                    "reply": reply,
                    "provider": f"Google Gemini ({model_used})",
                    "status": "success"
                }
            except Exception as e:
                print(f"Gemini API error, falling back to local expert: {e}")
                fallback_reply = self._generate_local_expert_response(user_message, flow_context, str(e))
                return {
                    "reply": fallback_reply,
                    "provider": "CyberGuard Local SOC Expert (Gemini Fallback)",
                    "status": "fallback",
                    "error_detail": str(e)
                }
        else:
            fallback_reply = self._generate_local_expert_response(user_message, flow_context)
            return {
                "reply": fallback_reply,
                "provider": "CyberGuard Local SOC Expert (No API Key Configured)",
                "status": "local_expert"
            }

    def _build_system_prompt(self, flow_context: Optional[Dict[str, Any]] = None) -> str:
        prompt = (
            "You are CyberGuard AI Copilot, a Tier-3 Senior SOC Analyst and Network Security Specialist. "
            "You provide technical, concise, and actionable guidance regarding Network Intrusion Detection (NIDS), "
            "telemetry analysis, MITRE ATT&CK mapping, and firewall / iptables mitigation policies.\n\n"
        )
        
        if flow_context:
            prompt += "--- CURRENT NETWORK FLOW TELEMETRY CONTEXT ---\n"
            prompt += f"ML Classification: {flow_context.get('prediction', 'Unknown')}\n"
            prompt += f"Confidence Score: {flow_context.get('confidence_pct', 'N/A')}\n"
            prompt += f"Risk Severity: {flow_context.get('severity', 'N/A')}\n"
            
            profile = flow_context.get('traffic_profile', {})
            if profile:
                prompt += f"Protocol: {profile.get('protocol')} | Service: {profile.get('service')} | TCP Flags: {profile.get('tcp_flags')}\n"
                prompt += f"Packets/sec: {profile.get('packets_per_second')} | Bytes/sec: {profile.get('bytes_per_second')}\n"
                prompt += f"Src Bytes: {profile.get('src_bytes')} | Dst Bytes: {profile.get('dst_bytes')} | Src/Dst Ratio: {profile.get('src_dst_byte_ratio')}\n"
                
            exp = flow_context.get('explanation', {})
            if exp:
                prompt += f"XAI Rationale: {exp.get('natural_language_rationale', '')}\n"
                prompt += f"Top Decision Drivers: {', '.join(exp.get('top_risk_factors', []))}\n"
                
            cf = flow_context.get('counterfactual', {})
            if cf:
                prompt += f"Evasion Robustness Margin: {cf.get('evasion_robustness_margin', 'N/A')}/100 ({cf.get('evasion_risk_level', '')})\n"
                prompt += f"Counterfactual Delta Required: {json.dumps(cf.get('modifications_required', {}))}\n"
                
            prompt += "----------------------------------------------\n"
            prompt += "Use this flow context to answer questions specifically about this threat event when asked."
            
        return prompt

    def _call_gemini_api(self, user_message: str, system_prompt: str, api_key: str,
                         history: Optional[List[Dict[str, str]]] = None) -> tuple:
        contents = []
        # System instruction
        contents.append({
            "role": "user",
            "parts": [{"text": f"SYSTEM INSTRUCTION: {system_prompt}"}]
        })
        contents.append({
            "role": "model",
            "parts": [{"text": "Understood. I am ready to assist with SOC analysis, telemetry investigation, and remediation guidance."}]
        })
        
        # Add conversation history
        if history:
            for item in history[-6:]:  # Keep recent history
                role = "user" if item.get("role") == "user" else "model"
                contents.append({
                    "role": role,
                    "parts": [{"text": item.get("content", "")}]
                })
                
        # Current message
        contents.append({
            "role": "user",
            "parts": [{"text": user_message}]
        })
        
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 800
            }
        }
        
        headers = {"Content-Type": "application/json"}
        last_err = None

        for model_name in self.GEMINI_MODELS:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    return text, model_name
                else:
                    last_err = f"HTTP {response.status_code} on {model_name}"
            except Exception as ex:
                last_err = f"Request to {model_name} timed out or failed"

        raise RuntimeError(last_err or "Failed to communicate with any Gemini model endpoint.")

    def _generate_local_expert_response(self, query: str, context: Optional[Dict[str, Any]] = None,
                                        error_note: Optional[str] = None) -> str:
        """Rule-based local SOC analyst fallback when Gemini API key is missing or offline."""
        q = query.lower()
        pred = context.get('prediction', 'Normal') if context else 'Normal'
        sev = context.get('severity', 'Low') if context else 'Low'
        
        note = ""
        if error_note:
            note = f"\n\n*(Note: Gemini API call error: {error_note}. Switched to local rule-based SOC engine)*"
        elif not os.getenv("GEMINI_API_KEY"):
            note = "\n\n*(Tip: Add your `GEMINI_API_KEY` in the top right to enable full live Google Gemini AI capabilities)*"
            
        if "firewall" in q or "iptables" in q or "mitigat" in q or "block" in q:
            proto = context.get('traffic_profile', {}).get('protocol', 'TCP').lower() if context else 'tcp'
            flags = context.get('traffic_profile', {}).get('tcp_flags', 'SYN') if context else 'SYN'
            return (
                f"### Automated Incident Mitigation Policy\n"
                f"**Threat:** {pred} ({sev} Severity)\n\n"
                f"**1. Linux `iptables` Drop Directive:**\n"
                f"```bash\n"
                f"# Rate-limit or drop suspicious {proto.upper()} bursts\n"
                f"iptables -A INPUT -p {proto} --tcp-flags ALL {flags} -m limit --limit 50/s --limit-burst 100 -j ACCEPT\n"
                f"iptables -A INPUT -p {proto} --tcp-flags ALL {flags} -j DROP\n"
                f"```\n\n"
                f"**2. Containment Checklist:**\n"
                f"- Isolate source IP at the perimeter router or edge load balancer.\n"
                f"- Enable SYN-cookie protection (`sysctl -w net.ipv4.tcp_syncookies=1`).\n"
                f"- Inspect upstream NetFlow/IPFIX logs for distributed amplification."
                + note
            )
            
        elif "mitre" in q or "att&ck" in q or "tactic" in q:
            mitre_map = {
                "DoS": "**T1498: Network Denial of Service** (Impact) &mdash; Direct volumetric flood exhausting bandwidth or connection state tables.",
                "Probe": "**T1046: Network Service Discovery** (Reconnaissance) &mdash; Port scanning and service fingerprinting.",
                "Brute_Force": "**T1110: Brute Force** (Credential Access) &mdash; Repeated credential guessing against authentication daemons.",
                "Botnet": "**T1071: Application Layer Protocol** (Command & Control) &mdash; Beaconing telemetry to remote C2 infrastructure.",
                "Web_Attack": "**T1190: Exploit Public-Facing Application** (Initial Access) &mdash; Web payload injection or path traversal.",
                "Normal": "**Standard Telemetry** &mdash; No malicious ATT&CK tactic identified."
            }
            return (
                f"### MITRE ATT&CK Matrix Mapping\n"
                f"- **Classification:** {pred}\n"
                f"- **Technique Mapping:** {mitre_map.get(pred, 'T1499: Endpoint Denial of Service')}\n"
                f"- **Triage Priority:** {sev}\n"
                f"- **SOC Next Step:** Cross-reference endpoint EDR telemetry for process spawns associated with this network stream."
                + note
            )
            
        elif "why" in q or "explain" in q or "attribution" in q:
            exp = context.get('explanation', {}) if context else {}
            rationale = exp.get('natural_language_rationale', f"The flow was classified as {pred} based on anomalous feature velocity.")
            drivers = exp.get('top_risk_factors', ['packets_per_second', 'tcp_flags'])
            return (
                f"### Explainable AI Telemetry Rationale\n"
                f"**Prediction:** {pred} (Confidence: {context.get('confidence_pct', 'N/A') if context else 'N/A'})\n\n"
                f"{rationale}\n\n"
                f"**Primary Decision Drivers:**\n"
                + "\n".join([f"- {d}" for d in drivers])
                + note
            )
            
        else:
            return (
                f"### CyberGuard SOC Assistant\n"
                f"I am actively monitoring the current network telemetry. Currently analyzing **{pred}** traffic ({sev} severity).\n\n"
                f"You can ask me to:\n"
                f"1. **Generate Firewall & Mitigation Rules** (e.g., `iptables` / `nftables` commands)\n"
                f"2. **Explain Decision Attribution** (why the Random Forest model flagged specific features)\n"
                f"3. **Map to MITRE ATT&CK Framework** (techniques, tactics, and incident containment)\n"
                f"4. **Analyze Evasion Robustness** (counterfactual trajectory to make the flow compliant)"
                + note
            )
