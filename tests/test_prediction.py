import unittest
import pandas as pd
from src.predictor import Predictor
from src.traffic_analyzer import DataValidationError
from src.risk_engine import RiskEngine

class TestPredictionPipeline(unittest.TestCase):
    def setUp(self):
        self.predictor = Predictor(model_path="models/nids_pipeline.pkl", encoder_path="models/label_encoder.pkl")

    def test_model_loads(self):
        self.assertIsNotNone(self.predictor.pipeline)
        self.assertIsNotNone(self.predictor.label_encoder)

    def test_single_prediction(self):
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
        pred, prob = self.predictor.predict_single(flow)
        self.assertIsInstance(pred, str)
        if prob is not None:
            self.assertTrue(0.0 <= prob <= 1.0)

    def test_batch_prediction(self):
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
        preds, probs = self.predictor.predict_batch(df)
        self.assertEqual(len(preds), 1)
        if probs is not None:
            self.assertTrue(0.0 <= probs[0] <= 1.0)

    def test_severity_mapping(self):
        self.assertEqual(RiskEngine.get_severity("Normal"), "Low")
        self.assertEqual(RiskEngine.get_severity("DoS"), "Critical")
        self.assertEqual(RiskEngine.get_severity("Probe"), "Medium")
        self.assertEqual(RiskEngine.get_severity("Unknown_Attack"), "Unknown")

    def test_invalid_input_error(self):
        flow = {"duration": 0, "protocol": "TCP"}
        with self.assertRaises(DataValidationError):
            self.predictor.predict_single(flow)

if __name__ == "__main__":
    unittest.main()
