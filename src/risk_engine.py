class RiskEngine:
    """Assigns severity and risk scores to network predictions."""
    
    SEVERITY_RULES = {
        "DoS": "Critical",
        "Botnet": "Critical",
        "Brute_Force": "High",
        "Web_Attack": "High",
        "Probe": "Medium",
        "Other": "Medium",
        "Normal": "Low"
    }
    
    @classmethod
    def get_severity(cls, attack_type: str) -> str:
        """Returns the severity based on predefined rules."""
        return cls.SEVERITY_RULES.get(attack_type, "Unknown")
