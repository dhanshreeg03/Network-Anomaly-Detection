import pytest
import pandas as pd
from src.traffic_analyzer import TrafficAnalyzer, DataValidationError

def test_feature_validation_valid():
    analyzer = TrafficAnalyzer()
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
    # Should not raise exception
    validated_df = analyzer.prepare_features(df)
    assert not validated_df.empty

def test_feature_validation_missing():
    analyzer = TrafficAnalyzer()
    df = pd.DataFrame([{
        "duration": 0,
        "protocol": "TCP"
    }])
    with pytest.raises(DataValidationError):
        analyzer.prepare_features(df)
