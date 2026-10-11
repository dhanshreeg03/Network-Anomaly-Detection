import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate, RandomizedSearchCV
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (RandomForestClassifier, ExtraTreesClassifier, 
                              GradientBoostingClassifier, HistGradientBoostingClassifier)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             classification_report, confusion_matrix)
import warnings
import os
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings('ignore')

def get_preprocessor(X):
    num_cols = X.select_dtypes(include=['int64', 'float64']).columns.tolist()
    cat_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()
    
    numeric_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, num_cols),
            ('cat', categorical_transformer, cat_cols)
        ]
    )
    return preprocessor

def main():
    print("=== MODEL COMPARISON AND VALIDATION ===")
    data_path = 'data/cyberguard_synthetic_demo (1).csv' if os.path.exists('data/cyberguard_synthetic_demo (1).csv') else 'cyberguard_synthetic_demo (1).csv'
    df = pd.read_csv(data_path)
    
    # Drop artificial features
    # ID is sequential identifier
    # src_packets has a perfect deterministic boundary (59-112 for DoS, <=45 for others)
    df = df.drop(columns=['ID', 'src_packets'])
    
    X = df.drop(columns=['attack_type'])
    y = df['attack_type']
    
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Hold out 20% for FINAL test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    preprocessor = get_preprocessor(X_train)
    
    # Models to evaluate
    models = {
        'Logistic Regression': LogisticRegression(class_weight='balanced', random_state=42, max_iter=1000),
        'Decision Tree': DecisionTreeClassifier(class_weight='balanced', random_state=42),
        'Random Forest': RandomForestClassifier(class_weight='balanced', random_state=42),
        'Extra Trees': ExtraTreesClassifier(class_weight='balanced', random_state=42),
        'KNN': KNeighborsClassifier(),
        'SVM': SVC(class_weight='balanced', random_state=42),
        'Gradient Boosting': GradientBoostingClassifier(random_state=42),
        'HistGradientBoosting': HistGradientBoostingClassifier(random_state=42),
        'XGBoost': XGBClassifier(random_state=42, eval_metric='mlogloss')
    }
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = ['accuracy', 'precision_macro', 'recall_macro', 'f1_macro', 'f1_weighted']
    
    results = []
    
    print("\nRunning Cross-Validation for Models...")
    for name, model in models.items():
        pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', model)
        ])
        
        cv_res = cross_validate(pipeline, X_train, y_train, cv=cv, scoring=scoring, n_jobs=-1)
        
        results.append({
            'Model': name,
            'CV Accuracy': cv_res['test_accuracy'].mean(),
            'CV Macro Precision': cv_res['test_precision_macro'].mean(),
            'CV Macro Recall': cv_res['test_recall_macro'].mean(),
            'CV Macro F1': cv_res['test_f1_macro'].mean(),
            'CV Weighted F1': cv_res['test_f1_weighted'].mean()
        })
        print(f"Finished {name}")
        
    results_df = pd.DataFrame(results).sort_values(by='CV Macro F1', ascending=False)
    print("\n--- MODEL COMPARISON TABLE ---")
    print(results_df.to_string(index=False))
    
    # Hyperparameter Tuning for top 2 models
    top_2_names = results_df['Model'].head(2).tolist()
    print(f"\n--- TUNING TOP 2 MODELS: {top_2_names} ---")
    
    best_pipelines = {}
    
    for name in top_2_names:
        print(f"Tuning {name}...")
        base_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', models[name])
        ])
        
        param_grid = {}
        if name == 'Random Forest':
            param_grid = {
                'classifier__n_estimators': [50, 100, 200],
                'classifier__max_depth': [None, 10, 20],
                'classifier__min_samples_split': [2, 5, 10]
            }
        elif name == 'Extra Trees':
            param_grid = {
                'classifier__n_estimators': [50, 100, 200],
                'classifier__max_depth': [None, 10, 20],
                'classifier__min_samples_split': [2, 5, 10]
            }
        elif name == 'HistGradientBoosting':
            param_grid = {
                'classifier__learning_rate': [0.01, 0.1, 0.2],
                'classifier__max_iter': [100, 200],
                'classifier__max_depth': [None, 10, 20]
            }
        elif name == 'XGBoost':
            param_grid = {
                'classifier__n_estimators': [50, 100, 200],
                'classifier__learning_rate': [0.01, 0.1, 0.2],
                'classifier__max_depth': [3, 5, 7]
            }
        elif name == 'Decision Tree':
             param_grid = {
                'classifier__max_depth': [None, 10, 20, 30],
                'classifier__min_samples_split': [2, 5, 10]
            }
        elif name == 'Logistic Regression':
            param_grid = {
                'classifier__C': [0.1, 1.0, 10.0]
            }
        else:
            param_grid = {} # Fallback
            
        search = RandomizedSearchCV(base_pipeline, param_grid, n_iter=10, cv=cv, scoring='f1_macro', n_jobs=-1, random_state=42)
        search.fit(X_train, y_train)
        
        print(f"Best parameters for {name}: {search.best_params_}")
        print(f"Best CV Macro F1: {search.best_score_:.4f}")
        best_pipelines[name] = search.best_estimator_
        
    # Final Model Selection
    print("\n--- FINAL MODEL EVALUATION ---")
    best_name = top_2_names[0]
    final_model = best_pipelines[best_name]
    print(f"Selected Final Model: {best_name}")
    
    y_pred = final_model.predict(X_test)
    
    # Calculate metrics
    print(f"\nFinal Test Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"Final Test Macro Precision: {precision_score(y_test, y_pred, average='macro'):.4f}")
    print(f"Final Test Macro Recall: {recall_score(y_test, y_pred, average='macro'):.4f}")
    print(f"Final Test Macro F1: {f1_score(y_test, y_pred, average='macro'):.4f}")
    print(f"Final Test Weighted Precision: {precision_score(y_test, y_pred, average='weighted'):.4f}")
    print(f"Final Test Weighted Recall: {recall_score(y_test, y_pred, average='weighted'):.4f}")
    print(f"Final Test Weighted F1: {f1_score(y_test, y_pred, average='weighted'):.4f}")
    
    target_names = le.inverse_transform(np.unique(y_encoded))
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=target_names))
    
    print("\n--- Confusion Matrix ---")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=target_names, yticklabels=target_names)
    plt.title(f'Confusion Matrix on Test Set ({best_name})')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.tight_layout()
    os.makedirs('outputs/evaluation', exist_ok=True)
    plt.savefig('outputs/evaluation/confusion_matrix_final.png')

if __name__ == '__main__':
    main()
