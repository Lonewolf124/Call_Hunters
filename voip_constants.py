#!/usr/bin/env python3
"""
VoIP Constants and Configuration
Defines ignored columns, categorical columns, and default values
"""

def get_ignored_columns():
    """Return list of columns that should always be ignored during feature processing"""
    return [
        'call_id', 
        'call_duration', 
        'caller_ip', 
        'callee_ip', 
        'start_time', 
        'end_time', 
        'is_anomaly'
    ]

def get_categorical_columns():
    """Return list of categorical columns"""
    return [
        'codec_type',
        'call_termination_method',
        'response_code_variety'
    ]

# Fixed defaults for when reference data is unavailable
FIXED_DEFAULTS = {
    # Numeric defaults
    'avg_jitter': 45.5,
    'packet_loss_percent': 0.5,
    'packets_per_second': 80.15,
    'bytes_per_second': 5049.58,
    'setup_time': 150.0,
    'retransmission_count': 2,
    'concurrent_calls': 1,
    'jitter_variance': 12.5,
    'port_range_used': 2,
    'peak_bandwidth': 8000.0,
    'talk_silence_ratio': 75.0,
    'hour': 12,
    'day_of_week': 0,
    'quality_score': 85.0,
    'bandwidth_efficiency': 8000.0,
    'avg_packet_size': 160.0,
    
    # Categorical defaults  
    'codec_type': 'G.711',
    'call_termination_method': 'Normal',
    'response_code_variety': '200'
}
