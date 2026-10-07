# Network Anomaly Detection

## 1. Overview
This is a machine-learning-based Network Intrusion Detection System (NIDS) designed to analyze network-flow data and classify traffic into different attack categories. This system serves as an offline/user-initiated network traffic analysis tool to help understand and identify suspicious activities.

## 2. Key Features
- **Detection**: 
  - **Single Flow**: Analyze one network flow manually.
  - **CSV Analysis**: Analyze multiple network flows using a batch dataset.
- **Investigation**: 
  - **Suspicious Flows**: Filter and examine detected anomalies.
  - **Attack Explorer**: Deep dive into specific attack types and their characteristics.
  - **What-If Analysis**: Explore how changes in traffic characteristics affect classification through an interactive simulation.
- **Analytics**: 
  - **Attack Comparison**: Compare distributions of different attack types.
  - **Attack Fingerprints**: Understand typical metric values for a given attack profile.
  - **Attack Ranking**: View top detected attack categories.

## 3. Attack Classes
The system is capable of detecting various types of attacks along with normal traffic:
- Normal
- DoS
- Probe
- Botnet
- Brute Force
- Web Attack
- Other

*(Note: The exact attacks detected depend on the provided dataset)*

## 4. System Workflow / Architecture
```text
User Traffic Input (Single Flow or CSV)
        ↓
Data Validation (Schema & Type Checking)
        ↓
Preprocessing (Encoding & Scaling)
        ↓
ML Classification (Predictor Engine)
        ↓
Attack Type Prediction
        ↓
Risk / Severity Assessment
        ↓
Investigation & Analytics
        ↓
Dashboard
```

## 5. Machine Learning Approach
The system utilizes a trained Machine Learning pipeline for classification. Based on cross-validation and hyperparameter tuning, a **Random Forest** model was selected as the final classifier due to its robust performance on complex, non-linear network data, outperforming other tree-based and linear algorithms.

## 6. Model Evaluation
The final Random Forest model achieved the following performance on the hold-out test set:
- **Test Accuracy**: 93.00%
- **Test Macro F1**: 88.69%

*(Note: These performance metrics are based on the synthetic training dataset and do not represent real-world NIDS performance on live networks.)*

## 7. Input Features
The model analyzes the following 11 network flow features:
- `duration`
- `protocol`
- `service`
- `src_bytes`
- `dst_bytes`
- `src_packets`
- `dst_packets`
- `src_dst_byte_ratio`
- `packets_per_second`
- `bytes_per_second`
- `tcp_flags`

## 8. Dashboard
The interactive dashboard is built using Streamlit and provides a dynamic interface to perform traffic detection, view detailed reports, investigate specific flows, and analyze aggregate metrics.

## 9. Technology Stack
- **Python**: Core programming language
- **Pandas & NumPy**: Data manipulation and numerical operations
- **Scikit-learn**: Machine learning model building and preprocessing
- **Streamlit**: Interactive web dashboard
- **Plotly**: Interactive data visualizations
- **Joblib**: Model serialization

## 10. Project Structure
```text
Network-Anomaly-Detection/
│
├── dashboard/           # Streamlit app and UI components
├── src/                 # Core prediction, risk, and analysis logic
├── models/              # Serialized ML pipeline and encoders
├── data/                # Sample datasets for testing
├── logs/                # Application logs
├── outputs/             # Generated plots (e.g., confusion matrix)
├── README.md            # Project documentation
├── requirements.txt     # Python dependencies
├── .gitignore           # Git ignore rules
└── LICENSE              # MIT License
```

## 11. Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/dhanshreeg03/Network-Anomaly-Detection.git
   cd Network-Anomaly-Detection
   ```
2. Create and activate a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 12. Running the Application
To start the NIDS dashboard, run:
```bash
streamlit run dashboard/app.py
```
Then, open the provided local URL in your web browser.

## 13. Dataset
The project utilizes a synthetic dataset (`cyberguard_synthetic_demo (1).csv`) for demonstration and evaluation purposes. The dataset consists of predefined features that mimic network flow statistics.

## 14. Limitations
- **Offline Analysis Only**: This system does not perform real-time packet capture or live network monitoring. It processes pre-captured or manually inputted flow data.
- **Synthetic Data**: The model is trained on a synthetic dataset, meaning its real-world accuracy may vary.

## 15. Future Improvements
- Integration with live network capture tools (e.g., Zeek, Wireshark/pcap).
- Support for streaming data architectures (e.g., Kafka).
- Expanding the dataset to include modern real-world attacks.
- Advanced deep learning approaches for zero-day attack detection.

## 16. Author
**Dhanshree Gedam**  
[GitHub Profile](https://github.com/dhanshreeg03)
