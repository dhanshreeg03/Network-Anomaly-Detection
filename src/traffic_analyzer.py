import pandas as pd
import numpy as np
from .feature_schema import EXPECTED_FEATURES

class DataValidationError(Exception):
    pass

class TrafficAnalyzer:
    """Validates and sanitizes network flow data before prediction."""
    
    @staticmethod
    def validate_and_prepare(df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            raise DataValidationError("Input dataframe is empty.")
            
        # Strip forbidden features if they accidentally slip in
        forbidden_features = ['ID', 'attack_type']
        for f in forbidden_features:
            if f in df.columns:
                df = df.drop(columns=[f])
                
        # Check for missing required features
        missing = [f for f in EXPECTED_FEATURES if f not in df.columns]
        if missing:
            raise DataValidationError(f"Missing required model features: {', '.join(missing)}")
            
        # Reorder to ensure exact matching schema
        df = df[EXPECTED_FEATURES].copy()
        
        # Check for nulls
        if df.isnull().values.any():
            missing_counts = df.isnull().sum()
            missing_cols = missing_counts[missing_counts > 0].index.tolist()
            raise DataValidationError(f"Null values found in columns: {missing_cols}")
            
        # Check numeric constraints
        num_cols = df.select_dtypes(include=[np.number]).columns
        for col in num_cols:
            if np.isinf(df[col]).any():
                raise DataValidationError(f"Infinite values found in column: {col}")
            if (df[col] < 0).any():
                raise DataValidationError(f"Negative values found in column: {col}. Network features cannot be negative.")
                
        return df
