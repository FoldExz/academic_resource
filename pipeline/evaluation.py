"""
evaluation.py
=============
Evaluation metrics calculation for multi-class and binary attack detection.
"""

from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, accuracy_score

from config import CLASS_NAMES


def evaluate_predictions(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    """
    Computes full multi-class and binary detection metrics:
    - Macro-average Recall, Precision, F1
    - Multiclass & Binary Accuracy
    - FPR (False Positive Rate on Normal traffic)
    - TNR (True Negative Rate)
    - ADR (Attack Detection Rate / Macro Recall on Attack Classes)
    - 6x6 Confusion Matrix
    """
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(CLASS_NAMES))))
    
    # Multiclass macro metrics
    prec_arr, rec_arr, f1_arr, supp_arr = precision_recall_fscore_support(
        y_true, y_pred, labels=list(range(len(CLASS_NAMES))), zero_division=0
    )
    
    macro_recall = float(np.mean(rec_arr))
    macro_precision = float(np.mean(prec_arr))
    macro_f1 = float(np.mean(f1_arr))
    acc_mc = float(accuracy_score(y_true, y_pred))

    # Binary metrics (Class 0 = Normal/Negative, Classes 1..5 = Attack/Positive)
    y_true_bin = (y_true > 0).astype(int)
    y_pred_bin = (y_pred > 0).astype(int)

    tn = int(np.sum((y_true_bin == 0) & (y_pred_bin == 0)))
    fp = int(np.sum((y_true_bin == 0) & (y_pred_bin == 1)))
    fn = int(np.sum((y_true_bin == 1) & (y_pred_bin == 0)))
    tp = int(np.sum((y_true_bin == 1) & (y_pred_bin == 1)))

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    tnr = float(tn / (fp + tn)) if (fp + tn) > 0 else 1.0
    acc_bin = float((tp + tn) / (tp + tn + fp + fn))

    # Attack Detection Rate (ADR): Average recall across attack classes (1..5)
    adr = float(np.mean(rec_arr[1:]))

    # Per-class recall dictionary
    per_class_recall = {CLASS_NAMES[i]: float(rec_arr[i]) for i in range(len(CLASS_NAMES))}

    return {
        "metrics": {
            "accuracy_multiclass": acc_mc,
            "precision": macro_precision,
            "recall": macro_recall,
            "f1": macro_f1,
            "accuracy_binary": acc_bin,
            "fpr": fpr,
            "tnr": tnr,
            "adr": adr,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        },
        "per_class_recall": per_class_recall,
        "confusion_matrix": cm.tolist(),
    }
