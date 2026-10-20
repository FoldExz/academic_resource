"""
pipeline package
================
Final production pipeline for eBPF/XDP DDoS Detection.
"""

import sys
from . import sampling

# Register aliases for seamless joblib unpickling
sys.modules["ddos_pipeline"] = sys.modules[__name__]
sys.modules["ddos_pipeline.rs_sampling"] = sampling
sys.modules["ddos_pipeline.rs_cv"] = sampling
