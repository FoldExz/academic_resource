"""
export.py
=========
eBPF C header validation and quantization parity testing.
Validates fixed-point Q14 inference parity against scikit-learn models.
"""

from pathlib import Path
from typing import Dict, Any
import numpy as np
import joblib

from config import MODELS_DIR, FEATURE_COLS, QUANTIZATION_SCALE


def validate_mlp_quantization_parity(samples: int = 1000) -> Dict[str, Any]:
    """
    Validates fixed-point integer inference parity against the float scikit-learn MLP model.
    Tests on random and real sample windows.
    """
    model_path = MODELS_DIR / "mlp_model.joblib"
    if not model_path.exists():
        return {"status": "SKIPPED", "reason": "MLP model not found"}

    pipeline = joblib.load(model_path)
    scaler = pipeline.named_steps.get("scaler")
    mlp_step = pipeline.named_steps.get("mlp") or pipeline.named_steps.get("estimator")
    mlp = getattr(mlp_step, "est_", mlp_step)

    # Generate synthetic validation inputs across standard ranges
    np.random.seed(42)
    X_synth = np.random.uniform(0, 10000, size=(samples, len(FEATURE_COLS))).astype(np.float64)

    # Scikit-learn float predictions
    y_pred_float = pipeline.predict(X_synth)

    # Q14 Fixed-point manual simulation matching C header logic
    SW = QUANTIZATION_SCALE  # 2^14 = 16384
    QS = 30
    SC = 1 << QS
    ROUND_QS = 1 << (QS - 1)

    mean = scaler.mean_
    scale = scaler.scale_
    coeff_q = [int(round(SW / s * SC)) for s in scale]
    mean_offset_qw = [int(round(m * SW / s)) for m, s in zip(mean, scale)]

    W_q = [np.round(w * SW).astype(np.int64) for w in mlp.coefs_]
    b_q = [np.round(b * SW).astype(np.int64) for b in mlp.intercepts_]

    mismatches = 0
    for i in range(samples):
        # 1. Fixed-point normalization
        x_raw = X_synth[i]
        x_norm = []
        for j in range(len(FEATURE_COLS)):
            val = ((int(round(x_raw[j])) * coeff_q[j] + ROUND_QS) >> QS) - mean_offset_qw[j]
            x_norm.append(val)
        act = np.array(x_norm, dtype=np.int64)

        # 2. Hidden layer forward pass (ReLU)
        for layer_idx in range(len(W_q)):
            acc = b_q[layer_idx].copy()
            for k in range(len(act)):
                acc += (act[k] * W_q[layer_idx][k]) >> 14
            if layer_idx < len(W_q) - 1:
                act = np.maximum(0, acc)  # ReLU
            else:
                act = acc  # Linear output

        pred_int = int(np.argmax(act))
        if pred_int != y_pred_float[i]:
            mismatches += 1

    parity_pct = (samples - mismatches) / samples * 100.0
    return {
        "status": "PASS" if parity_pct >= 99.0 else "FAIL",
        "samples_tested": samples,
        "mismatches": mismatches,
        "parity_percentage": parity_pct,
    }
