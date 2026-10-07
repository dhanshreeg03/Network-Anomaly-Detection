import pytest
import pandas as pd
from src.predictor import Predictor
from src.traffic_analyzer import DataValidationError
from src.risk_engine import RiskEngine

def test_model_loads():
    predictor = Predictor(model_path="models/nids_pipeline.pkl", encoder_path="models/label_encoder.pkl")
    assert predictor.pipeline is not None
    assert predictor.label_encoder is not None

def test_single_prediction():
    predictor = Predictor(model_path="models/nids_pipeline.pkl", encoder_path="models/label_encoder.pkl")
    # Provide a dummy benign input
    flow = {
        "duration": 0,
        "protocol": "TCP",
        "service": "HTTP",
        "src_bytes": 215,
        "dst_bytes": 456,
        "src_packets": 3,
        "dst_packets": 4,
        "src_dst_byte_ratio": 0.47,
        "packets_per_second": 10.0,
        "bytes_per_second": 200.0,
        "tcp_flags": "ACK"
    }
    pred, prob = predictor.predict_single(flow)
    assert isinstance(pred, str)
    if prob is not None:
        assert 0.0 <= prob <= 1.0

def test_batch_prediction():
    predictor = Predictor(model_path="models/nids_pipeline.pkl", encoder_path="models/label_encoder.pkl")
    df = pd.DataFrame([{
        "duration": 0,
        "protocol": "TCP",
        "service": "HTTP",
        "src_bytes": 215,
        "dst_bytes": 456,
        "src_packets": 3,
        "dst_packets": 4,
        "src_dst_byte_ratio": 0.47,
        "packets_per_second": 10.0,
        "bytes_per_second": 200.0,
        "tcp_flags": "ACK"
    }])
    preds, probs = predictor.predict_batch(df)
    assert len(preds) == 1
    if probs is not None:
        assert 0.0 <= probs[0] <= 1.0

def test_severity_mapping():
    assert RiskEngine.get_severity("Normal") == "Low"
    assert RiskEngine.get_severity("DoS") == "Critical"
    assert RiskEngine.get_severity("Probe") == "Medium"
    assert RiskEngine.get_severity("Unknown_Attack") == "Unknown"

def test_invalid_input_error():
    predictor = Predictor(model_path="models/nids_pipeline.pkl", encoder_path="models/label_encoder.pkl")
    flow = {"duration": 0, "protocol": "TCP"}
    with pytest.raises(DataValidationError):
        predictor.predict_single(flow)
