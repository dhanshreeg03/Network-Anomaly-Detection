import pandas as pd
import numpy as np

# Load the dataset
df = pd.read_csv('cyberguard_synthetic_demo (1).csv')

print("=== DATASET SHAPE ===")
print(df.shape)
print("\n=== DATASET INFO ===")
df.info()

print("\n=== FIRST 5 ROWS ===")
print(df.head())

print("\n=== MISSING VALUES ===")
print(df.isnull().sum()[df.isnull().sum() > 0])

print("\n=== TARGET DISTRIBUTION ===")
target_col = [col for col in df.columns if 'attack' in col.lower() or 'label' in col.lower() or 'class' in col.lower()]
if target_col:
    target = target_col[0]
    print(f"Assuming target column is: {target}")
    print(df[target].value_counts())
    
    # Check for perfect correlations (artificially generated labels)
    numeric_df = df.select_dtypes(include=[np.number])
    if target in numeric_df.columns:
        corrs = numeric_df.corr()[target].abs().sort_values(ascending=False)
        print("\n=== CORRELATIONS WITH TARGET ===")
        print(corrs.head(10))
else:
    print("Could not find an obvious target column.")
    print("Columns:", df.columns)
