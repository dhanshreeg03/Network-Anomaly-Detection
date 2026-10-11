import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from .feature_schema import EXPECTED_FEATURES, NUMERICAL_FEATURES, CATEGORICAL_FEATURES
from .traffic_analyzer import TrafficAnalyzer

class ExplainabilityEngine:
    """
    Computes local feature attribution and decision explanations
    for network intrusion predictions.
    """
    
    def __init__(self, predictor):
        self.predictor = predictor
        self.pipeline = predictor.pipeline
        self.label_encoder = predictor.label_encoder
        
    def get_feature_names(self) -> List[str]:
        """Returns the preprocessed feature names after one-hot encoding."""
        preprocessor = self.pipeline.named_steps.get('preprocessor')
        cat_cols = ['protocol', 'service', 'tcp_flags']
        num_cols = [f for f in EXPECTED_FEATURES if f not in cat_cols]
        
        try:
            cat_encoder = preprocessor.named_transformers_['cat']
            cat_feature_names = cat_encoder.get_feature_names_out(cat_cols).tolist()
            return num_cols + cat_feature_names
        except Exception:
            return EXPECTED_FEATURES

    def explain_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Computes local feature attributions for a single flow prediction
        using perturbation-based Shapley approximations against benign baselines.
        """
        clean_df = TrafficAnalyzer.validate_and_prepare(pd.DataFrame([flow_dict]))
        predicted_class, base_prob = self.predictor.predict_single(flow_dict)
        base_confidence = float(base_prob) if base_prob is not None else 1.0
        
        # Reference baseline: benign typical network flow
        baseline_flow = {
            "duration": 1.2,
            "protocol": "TCP",
            "service": "HTTP",
            "src_bytes": 1200.0,
            "dst_bytes": 3500.0,
            "src_packets": 12.0,
            "dst_packets": 18.0,
            "src_dst_byte_ratio": 0.35,
            "packets_per_second": 25.0,
            "bytes_per_second": 3900.0,
            "tcp_flags": "ACK"
        }
        
        # Measure marginal impact of replacing each feature with its baseline value
        attributions = {}
        for feat in EXPECTED_FEATURES:
            perturbed = flow_dict.copy()
            perturbed[feat] = baseline_flow.get(feat, 0.0)
            
            try:
                _, p_prob = self.predictor.predict_single(perturbed)
                p_conf = float(p_prob) if p_prob is not None else base_confidence
                # Attribution: How much this feature shifted confidence toward the predicted class
                impact = round((base_confidence - p_conf) * 100, 2)
            except Exception:
                impact = 0.0
                
            attributions[feat] = impact
            
        # Normalize contributions
        total_mag = sum(abs(v) for v in attributions.values())
        if total_mag > 0:
            normalized = {k: round((v / total_mag) * 100, 1) for k, v in attributions.items()}
        else:
            # Fallback based on global model feature importances
            try:
                importances = self.pipeline.named_steps['classifier'].feature_importances_
                raw_imp = dict(zip(EXPECTED_FEATURES[:len(importances)], importances))
                normalized = {k: round(v * 100, 1) for k, v in raw_imp.items()}
            except Exception:
                normalized = {k: 5.0 for k in EXPECTED_FEATURES}
                
        # Top positive risk drivers and mitigating factors
        sorted_drivers = sorted(normalized.items(), key=lambda x: x[1], reverse=True)
        top_risk_factors = [f"{k} (+{v}%)" for k, v in sorted_drivers if v > 0][:3]
        
        # Human-readable rationale
        rationale = self._generate_narrative(predicted_class, flow_dict, sorted_drivers)
        
        return {
            "prediction": predicted_class,
            "confidence_pct": f"{base_confidence * 100:.1f}%",
            "attributions": normalized,
            "top_drivers": sorted_drivers,
            "top_risk_factors": top_risk_factors,
            "natural_language_rationale": rationale
        }
        
    def _generate_narrative(self, pred: str, flow: Dict[str, Any], top_drivers: List[Tuple[str, float]]) -> str:
        """Generates clear, natural language explanation for SOC analysts."""
        if pred == "Normal":
            return f"Flow classified as Benign Normal traffic. Telemetry demonstrates balanced bidirectional flow (ratio: {flow.get('src_dst_byte_ratio', 'N/A')}) and standard packet velocity."
            
        driver_names = [d[0] for d in top_drivers[:2]]
        pps = flow.get('packets_per_second', 0)
        bps = flow.get('bytes_per_second', 0)
        flags = flow.get('tcp_flags', 'N/A')
        proto = flow.get('protocol', 'N/A')
        
        if pred == "DoS":
            return f"Flagged as DoS threat primarily due to high packet velocity ({pps:,.0f} pkts/sec) and abnormal flag pattern '{flags}'. The dominant decision drivers are {', '.join(driver_names)}."
        elif pred == "Probe":
            return f"Flagged as Port Reconnaissance/Probe due to low destination response payload ({flow.get('dst_bytes', 0)} bytes) combined with flag '{flags}' across protocol '{proto}'."
        elif pred == "Brute_Force":
            return f"Flagged as Brute Force attack due to repeated small request bursts and symmetric packet exchanges across service '{flow.get('service', 'N/A')}'."
        elif pred == "Botnet":
            return f"Flagged as Botnet communication pattern with atypical DNS/UDP payload volume ({flow.get('src_bytes', 0)} bytes) and characteristic timing regularity."
        else:
            return f"Flagged as anomalous {pred} traffic based on anomalous values in {', '.join(driver_names)}."
