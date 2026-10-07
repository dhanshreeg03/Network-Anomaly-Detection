import pandas as pd
import os
import uuid
from datetime import datetime

class HistoryManager:
    """Manages the storage and retrieval of analysis session history."""
    
    def __init__(self, log_path: str = "logs/analysis_history.csv"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        if not os.path.exists(self.log_path):
            df = pd.DataFrame(columns=[
                "analysis_id", "timestamp", "analysis_type", "total_flows",
                "normal_flows", "attacks_detected", "detection_rate", 
                "most_common_attack", "critical_threats", "file_name"
            ])
            df.to_csv(self.log_path, index=False)
            
    def log_session(self, analysis_type: str, total_flows: int,
                    normal_flows: int, attacks_detected: int, critical_threats: int,
                    most_common_attack: str, file_name: str = "N/A"):
        
        detection_rate = (attacks_detected / total_flows * 100) if total_flows > 0 else 0.0
        
        session = {
            "analysis_id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now().isoformat(),
            "analysis_type": analysis_type,
            "total_flows": total_flows,
            "normal_flows": normal_flows,
            "attacks_detected": attacks_detected,
            "detection_rate": f"{detection_rate:.1f}%",
            "most_common_attack": most_common_attack,
            "critical_threats": critical_threats,
            "file_name": file_name
        }
        df = pd.DataFrame([session])
        df.to_csv(self.log_path, mode='a', header=False, index=False)
        return session
        
    def get_all_history(self) -> pd.DataFrame:
        if os.path.exists(self.log_path):
            df = pd.read_csv(self.log_path)
            if not df.empty:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df = df.sort_values(by='timestamp', ascending=False)
            return df
        return pd.DataFrame()
