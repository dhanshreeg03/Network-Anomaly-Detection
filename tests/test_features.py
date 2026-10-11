import unittest
import pandas as pd
from src.traffic_analyzer import TrafficAnalyzer, DataValidationError

class TestFeatureValidation(unittest.TestCase):
    def test_feature_validation_valid(self):
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
        validated_df = TrafficAnalyzer.validate_and_prepare(df)
        self.assertFalse(validated_df.empty)
        self.assertEqual(len(validated_df.columns), 11)

    def test_feature_validation_missing(self):
        df = pd.DataFrame([{
            "duration": 0,
            "protocol": "TCP"
        }])
        with self.assertRaises(DataValidationError):
            TrafficAnalyzer.validate_and_prepare(df)

if __name__ == "__main__":
    unittest.main()
