import pandas as pd
import os
from datetime import datetime
import uuid

class AlertManager:
    """Manages alert generation and persistence for the NIDS."""
    
    def __init__(self, log_path: str = "logs/alerts.csv"):
        self.log_path = log_path
        # Ensure the logs directory exists
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        # Initialize the CSV with headers if it doesn't exist
        if not os.path.exists(self.log_path):
            df = pd.DataFrame(columns=[
                "alert_id", "timestamp", "attack_type", "severity", "confidence", 
                "status", "source_info", "destination_info"
            ])
            df.to_csv(self.log_path, index=False)
            
    def generate_alert(self, attack_type: str, severity: str, confidence: float = None, 
                       src_info: str = "Not available in current flow dataset", 
                       dst_info: str = "Not available in current flow dataset"):
        
        # We only generate alerts for actual attacks, not "Normal" traffic
        if attack_type == "Normal":
            return
            
        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "severity": severity,
            "confidence": f"{confidence * 100:.2f}%" if confidence is not None else "N/A",
            "status": "New",
            "source_info": src_info,
            "destination_info": dst_info
        }
        
        # Append to CSV
        df = pd.DataFrame([alert])
        df.to_csv(self.log_path, mode='a', header=False, index=False)
        return alert

    def get_all_alerts(self) -> pd.DataFrame:
        """Retrieves all historical alerts."""
        if os.path.exists(self.log_path):
            return pd.read_csv(self.log_path)
        return pd.DataFrame()
        
    def get_recent_alerts(self, limit: int = 10) -> pd.DataFrame:
        """Retrieves the most recent alerts."""
        df = self.get_all_alerts()
        if not df.empty:
            # Sort by timestamp descending
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values(by='timestamp', ascending=False)
            return df.head(limit)
        return df
