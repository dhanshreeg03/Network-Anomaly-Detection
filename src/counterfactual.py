import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from .feature_schema import EXPECTED_FEATURES, NUMERICAL_FEATURES, CATEGORICAL_OPTIONS
from .traffic_analyzer import TrafficAnalyzer

class CounterfactualEngine:
    """
    Computes minimal perturbation counterfactual explanations and 
    adversarial evasion robustness scores for network flow classifications.
    """
    
    def __init__(self, predictor):
        self.predictor = predictor
        
    def find_counterfactual(self, flow_dict: Dict[str, Any], target_class: str = "Normal") -> Dict[str, Any]:
        """
        Finds the minimal parameter modification required to transition a flow
        from its current classification to the desired target class (typically 'Normal').
        """
        orig_pred, orig_prob = self.predictor.predict_single(flow_dict)
        
        # If already target class, target the most prominent threat category instead
        if orig_pred == target_class:
            target_class = "DoS"
            
        # Candidates for individual feature perturbations
        candidate_values = {
            "src_packets": [15.0, 10.0, 20.0, 5.0, 85.0],
            "dst_packets": [20.0, 15.0, 25.0, 5.0, 2.0],
            "packets_per_second": [30.0, 50.0, 15.0, 200.0, 850.0],
            "bytes_per_second": [3500.0, 5000.0, 1200.0, 25000.0, 65000.0],
            "src_dst_byte_ratio": [0.4, 0.8, 1.0, 5.0, 25.0],
            "tcp_flags": ["ACK", "PSH-ACK", "SYN", "RST", "FIN-ACK"],
            "duration": [1.0, 0.5, 2.0, 0.05]
        }
        
        best_flow = None
        best_score = float('inf')
        best_mods = {}
        
        # 1. Single Feature Search
        for feat, values in candidate_values.items():
            for val in values:
                if flow_dict.get(feat) == val:
                    continue
                test_flow = flow_dict.copy()
                test_flow[feat] = val
                try:
                    pred, prob = self.predictor.predict_single(test_flow)
                    if pred == target_class:
                        cost = self._compute_perturbation_cost(flow_dict, test_flow)
                        if cost < best_score:
                            best_score = cost
                            best_flow = test_flow
                            best_mods = {
                                feat: {
                                    "original": flow_dict[feat],
                                    "counterfactual": val,
                                    "delta": f"{val - flow_dict[feat]:+}" if isinstance(val, (int, float)) else f"{flow_dict[feat]} -> {val}"
                                }
                            }
                except Exception:
                    continue

        # 2. Pairwise Feature Search (if single feature was insufficient)
        if best_flow is None:
            pairs = [
                ("src_packets", "dst_packets"),
                ("src_packets", "tcp_flags"),
                ("packets_per_second", "tcp_flags"),
                ("src_dst_byte_ratio", "src_packets"),
                ("bytes_per_second", "tcp_flags")
            ]
            for f1, f2 in pairs:
                for v1 in candidate_values[f1]:
                    for v2 in candidate_values[f2]:
                        test_flow = flow_dict.copy()
                        test_flow[f1] = v1
                        test_flow[f2] = v2
                        try:
                            pred, prob = self.predictor.predict_single(test_flow)
                            if pred == target_class:
                                cost = self._compute_perturbation_cost(flow_dict, test_flow)
                                if cost < best_score:
                                    best_score = cost
                                    best_flow = test_flow
                                    best_mods = {
                                        f1: {
                                            "original": flow_dict[f1],
                                            "counterfactual": v1,
                                            "delta": f"{v1 - flow_dict[f1]:+}" if isinstance(v1, (int, float)) else f"{flow_dict[f1]} -> {v1}"
                                        },
                                        f2: {
                                            "original": flow_dict[f2],
                                            "counterfactual": v2,
                                            "delta": f"{v2 - flow_dict[f2]:+}" if isinstance(v2, (int, float)) else f"{flow_dict[f2]} -> {v2}"
                                        }
                                    }
                        except Exception:
                            continue

        # 3. Fallback compound baseline
        if best_flow is None:
            best_flow = flow_dict.copy()
            best_flow["src_packets"] = 15.0
            best_flow["dst_packets"] = 20.0
            best_flow["tcp_flags"] = "ACK"
            best_flow["packets_per_second"] = 35.0
            for k in ["src_packets", "dst_packets", "tcp_flags", "packets_per_second"]:
                if flow_dict[k] != best_flow[k]:
                    best_mods[k] = {
                        "original": flow_dict[k],
                        "counterfactual": best_flow[k],
                        "delta": f"{best_flow[k] - flow_dict[k]:+}" if isinstance(best_flow[k], (int, float)) else f"{flow_dict[k]} -> {best_flow[k]}"
                    }

        cf_pred, cf_prob = self.predictor.predict_single(best_flow)
        cf_confidence = float(cf_prob) if cf_prob is not None else 0.0
        robustness_score = self._compute_evasion_margin(flow_dict, best_flow)

        return {
            "original_prediction": orig_pred,
            "target_prediction": target_class,
            "counterfactual_prediction": cf_pred,
            "counterfactual_confidence": f"{cf_confidence * 100:.1f}%",
            "modifications_required": best_mods,
            "num_features_modified": len(best_mods),
            "evasion_robustness_margin": robustness_score,
            "evasion_risk_level": "High Evasion Risk" if robustness_score < 30 else ("Moderate" if robustness_score < 65 else "Resilient / High Robustness"),
            "counterfactual_flow": best_flow
        }
        
    def _compute_perturbation_cost(self, orig: Dict[str, Any], cf: Dict[str, Any]) -> float:
        cost = 0.0
        for k, v in orig.items():
            if k in NUMERICAL_FEATURES:
                denom = max(abs(float(v)), 1.0)
                cost += abs(float(v) - float(cf[k])) / denom
            elif v != cf[k]:
                cost += 1.0
        return cost

    def _compute_evasion_margin(self, orig: Dict[str, Any], cf: Dict[str, Any]) -> float:
        cost = self._compute_perturbation_cost(orig, cf)
        margin = min(100.0, round(cost * 30.0, 1))
        return margin
