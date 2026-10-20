"""
config.py
=========
Global configuration and hyperparameters for the eBPF/XDP DDoS Detection Pipeline.
Final Production Version (1-Second Continuous Temporal Window).
Supports Environment Variables (.env) for dynamic deployment and GitHub repository sharing.
"""

import os
from pathlib import Path

# Base Repository Path
BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv(dotenv_path: Path):
    """Zero-dependency .env loader."""
    if not dotenv_path.exists():
        return
    try:
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                os.environ.setdefault(k, v)
    except Exception:
        pass


# Load .env if present
_load_dotenv(BASE_DIR / ".env")

# Configurable Paths via Environment Variables (with relative defaults)
PCAP_DIR = Path(os.getenv("PCAP_DIR", str(BASE_DIR / "pcap"))).resolve()
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data"))).resolve()
MODELS_DIR = Path(os.getenv("MODELS_DIR", str(BASE_DIR / "models"))).resolve()
PLOTS_DIR = Path(os.getenv("PLOTS_DIR", str(BASE_DIR / "plots"))).resolve()
TABLES_DIR = Path(os.getenv("TABLES_DIR", str(BASE_DIR / "tables"))).resolve()

# Fallback for PCAP_DIR if local pcap/ link is not available
if not PCAP_DIR.exists() and (BASE_DIR.parent / "Percobaan_01_Okt" / "PCAP_filtered").exists():
    PCAP_DIR = (BASE_DIR.parent / "Percobaan_01_Okt" / "PCAP_filtered").resolve()

# Traffic Classes
CLASS_NAMES = [
    "Normal",
    "ARP Flood",
    "ICMP Flood",
    "SYN Flood",
    "UDP Flood",
    "DNS Amplification",
]

# The 9 In-Kernel Verified Features
FEATURE_COLS = [
    "packet_rate",
    "byte_rate",
    "arp_count",
    "syn_count",
    "udp_count",
    "icmp_count",
    "dns_count",
    "avg_packet_size",
    "unique_src_ip",
]

# PCAP Source Definitions (relative to PCAP_DIR)
PCAP_FILES = {
    "benign_extra": ("TRex/benign_extra.pcap", 0, "Normal"),
    "benign_cic_full": (["01-12/BENIGN.pcap", "03-11/BENIGN.pcap"], 0, "Normal"),
    "arp_flood": ("TRex/arp_flood.pcap", 1, "ARP Flood"),
    "icmp_flood": ("TRex/icmp_flood.pcap", 2, "ICMP Flood"),
    "syn_flood": (["01-12/Syn.pcap", "03-11/Syn.pcap"], 3, "SYN Flood"),
    "udp_flood": (["01-12/DrDoS_UDP.pcap", "03-11/UDP.pcap"], 4, "UDP Flood"),
    "dns_amp": (["01-12/DrDoS_DNS.pcap"], 5, "DNS Amplification"),
}

# Windowing Configuration
WINDOW_NS = int(os.getenv("WINDOW_NS", "1000000000"))  # 1-second continuous window

# DNS Reflection Response Ports (CIC-DDoS2019 dataset-specific correction)
DNS_REFLECT_PORTS = frozenset({634, 512, 530, 564, 900})

# HyperLogLog (HLL) Cardinality Estimation Parameters (RFC 5234 / Zhang et al.)
HLL_M = 256
HLL_B = 8
HLL_ALPHA = 0.7213 / (1.0 + 1.079 / HLL_M)

# Protocol Constants
ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_VLAN = 0x8100
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
TCP_SYN = 0x02
TCP_ACK = 0x10
PORT_DNS = 53

# Fixed-Point Quantization Settings (MLP)
QUANTIZATION_SCALE = 16384  # Q14 enlargement factor (2^14)

# Selected Production Model Configurations (Passing eBPF Verifier O2 and O3)
SELECTED_CONFIGS = {
    "DT": "b-S1::d06",    # Decision Tree: max_depth=6, class_weight='balanced'
    "RF": "c-S2::d8n3",   # Random Forest: max_depth=8, n_estimators=3
    "MLP": "a::16",       # Quantized MLP: 1 hidden layer x 16 neurons, Q14
}
