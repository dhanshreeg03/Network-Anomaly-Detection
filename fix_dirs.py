import os, shutil

# Fix the 'data' and 'models' files created mistakenly
if os.path.isfile('data'):
    os.rename('data', 'temp_data.csv')
if os.path.isfile('models'):
    os.rename('models', 'temp_models.pkl')

os.makedirs('data', exist_ok=True)
os.makedirs('models', exist_ok=True)

if os.path.exists('temp_data.csv'):
    shutil.move('temp_data.csv', 'data/cyberguard_synthetic_demo (1).csv')
if os.path.exists('temp_models.pkl'):
    shutil.move('temp_models.pkl', 'models/nids_pipeline.pkl')
if os.path.exists('label_encoder.pkl'):
    shutil.move('label_encoder.pkl', 'models/label_encoder.pkl')
if os.path.exists('nids_pipeline.pkl'):
    shutil.move('nids_pipeline.pkl', 'models/nids_pipeline.pkl')
if os.path.exists('cyberguard_synthetic_demo (1).csv'):
    shutil.move('cyberguard_synthetic_demo (1).csv', 'data/cyberguard_synthetic_demo (1).csv')

print("Fixed directories and files.")
