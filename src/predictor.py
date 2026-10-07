import joblib
import pandas as pd
import numpy as np
from typing import Tuple, List, Union
from .traffic_analyzer import TrafficAnalyzer, DataValidationError
from .feature_schema import EXPECTED_FEATURES

class Predictor:
    """Central engine for loading the ML pipeline and generating predictions."""
    
    def __init__(self, model_path: str = "models/nids_pipeline.pkl", encoder_path: str = "models/label_encoder.pkl"):
        self.model_path = model_path
        self.encoder_path = encoder_path
        self.pipeline = None
        self.label_encoder = None
        self._load_model()
        
    def _load_model(self):
        try:
            self.pipeline = joblib.load(self.model_path)
            # The label encoder might not exist separately if target mapping wasn't complex,
            # but we load it since we created it in Phase 1.
            try:
                self.label_encoder = joblib.load(self.encoder_path)
            except FileNotFoundError:
                self.label_encoder = None
        except FileNotFoundError:
            raise RuntimeError(f"Could not load the saved pipeline from {self.model_path}. Ensure it exists.")
            
    def predict_batch(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict a batch of flows. Returns (predictions, probabilities)."""
        # Validate and sanitize features
        clean_df = TrafficAnalyzer.validate_and_prepare(df)
        
        # Predict using the loaded pipeline (this applies scaling & encoding automatically)
        preds = self.pipeline.predict(clean_df)
        
        if self.label_encoder:
            preds = self.label_encoder.inverse_transform(preds)
            
        # Get probabilities if the model supports it
        probs = None
        if hasattr(self.pipeline, "predict_proba"):
            probs = self.pipeline.predict_proba(clean_df)
            probs = np.max(probs, axis=1) # Get the confidence of the predicted class
            
        return preds, probs
    
    def predict_single(self, flow_data: dict) -> Tuple[str, Union[float, None]]:
        """Predict a single flow from a dictionary."""
        df = pd.DataFrame([flow_data])
        preds, probs = self.predict_batch(df)
        return preds[0], probs[0] if probs is not None else None
