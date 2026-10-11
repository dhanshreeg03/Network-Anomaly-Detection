import pandas as pd
import numpy as np
import os
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import LabelEncoder

def main():
    print("=== DATA VALIDATION & LEAKAGE INVESTIGATION ===")
    data_path = 'data/cyberguard_synthetic_demo (1).csv' if os.path.exists('data/cyberguard_synthetic_demo (1).csv') else 'cyberguard_synthetic_demo (1).csv'
    df = pd.read_csv(data_path)
    
    # 1. Duplicates check
    print("\n--- Duplicate Analysis ---")
    exact_dupes = df.duplicated().sum()
    print(f"Exact duplicate rows: {exact_dupes}")
    
    # Check duplicates without ID
    df_no_id = df.drop(columns=['ID']) if 'ID' in df.columns else df.copy()
    feature_dupes = df_no_id.duplicated().sum()
    print(f"Duplicate feature vectors (ignoring ID): {feature_dupes}")
    
    # Conflicting labels check
    features_only = df_no_id.drop(columns=['attack_type'])
    duplicates_mask = features_only.duplicated(keep=False)
    if duplicates_mask.any():
        dup_rows = df_no_id[duplicates_mask]
        conflicts = dup_rows.groupby(list(features_only.columns))['attack_type'].nunique()
        print(f"Feature vectors with conflicting labels: {(conflicts > 1).sum()}")
    else:
        print("Feature vectors with conflicting labels: 0")

    # 2. Mutual Information
    print("\n--- Mutual Information Analysis ---")
    X = df_no_id.drop(columns=['attack_type'])
    y = df_no_id['attack_type']
    
    # encode categoricals for MI
    X_mi = X.copy()
    for col in X_mi.select_dtypes(include=['object']):
        X_mi[col] = LabelEncoder().fit_transform(X_mi[col])
        
    y_encoded = LabelEncoder().fit_transform(y)
    mi = mutual_info_classif(X_mi, y_encoded, random_state=42)
    mi_series = pd.Series(mi, index=X.columns).sort_values(ascending=False)
    print("Mutual Information of Features with Target:")
    print(mi_series)

    # 3. Numeric features min/max/mean/median by class
    print("\n--- Numeric Features Breakdown by Class ---")
    num_cols = X.select_dtypes(include=['int64', 'float64']).columns
    for col in num_cols:
        print(f"\nFeature: {col}")
        stats = df_no_id.groupby('attack_type')[col].agg(['min', 'max', 'mean', 'median'])
        print(stats)
        
        # Check for perfect thresholds
        for cls in stats.index:
            c_min = stats.loc[cls, 'min']
            c_max = stats.loc[cls, 'max']
            # Find overlap with other classes
            other_stats = stats.drop(index=cls)
            overlap = False
            for o_cls in other_stats.index:
                if not (c_max < other_stats.loc[o_cls, 'min'] or c_min > other_stats.loc[o_cls, 'max']):
                    overlap = True
                    break
            if not overlap:
                print(f"  --> ALERT: {cls} has NO OVERLAP with any other class for '{col}' (range {c_min} to {c_max})")

    # 4. Categorical distributions
    print("\n--- Categorical Features Breakdown by Class ---")
    cat_cols = X.select_dtypes(include=['object']).columns
    for col in cat_cols:
        crosstab = pd.crosstab(df_no_id[col], df_no_id['attack_type'])
        print(f"\nFeature: {col}")
        print(crosstab)
        
        # Check for unique categorical values
        for cls in crosstab.columns:
            for val in crosstab.index:
                if crosstab.loc[val, cls] > 0 and crosstab.loc[val].sum() == crosstab.loc[val, cls]:
                    print(f"  --> ALERT: Value '{val}' in '{col}' exclusively identifies '{cls}'")

if __name__ == '__main__':
    main()
