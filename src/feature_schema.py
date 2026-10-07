# Feature schema expected by the Phase 1 final trained model.
# Note: 'ID' is permanently excluded.

EXPECTED_FEATURES = [
    "duration",
    "protocol",
    "service",
    "src_bytes",
    "dst_bytes",
    "src_packets",
    "dst_packets",
    "src_dst_byte_ratio",
    "packets_per_second",
    "bytes_per_second",
    "tcp_flags"
]

CATEGORICAL_FEATURES = [
    "protocol",
    "service",
    "tcp_flags"
]

NUMERICAL_FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_packets",
    "dst_packets",
    "src_dst_byte_ratio",
    "packets_per_second",
    "bytes_per_second"
]

# Provide fallback options for UI dropdowns
CATEGORICAL_OPTIONS = {
    "protocol": ["TCP", "UDP", "ICMP", "DNS"],
    "service": ["HTTP", "HTTPS", "DNS", "FTP", "SSH", "TELNET", "ICMP", "OTHER"],
    "tcp_flags": ["ACK", "SYN", "FIN", "RST", "PSH-ACK", "SYN-ACK", "FIN-ACK", "SYN-RST"]
}
