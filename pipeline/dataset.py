"""
dataset.py
==========
Dataset loading, feature preparation, and temporal locked split loader.
Final Version: Clean, continuous 1-second temporal windows.
"""

from pathlib import Path
from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd

from config import DATA_DIR, FEATURE_COLS, CLASS_NAMES


def get_canonical_dataset_path() -> Path:
    p = DATA_DIR / "dataset_window_1s.csv"
    if p.exists():
        return p
    return DATA_DIR / "dataset_canonical.csv"


def get_split_path() -> Path:
    return DATA_DIR / "split_locked_temporal.npz"


def load_dataset() -> pd.DataFrame:
    """Loads the 1-second window dataset."""
    csv_path = get_canonical_dataset_path()
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found at: {csv_path}")
    return pd.read_csv(csv_path)



def load_split_indices() -> Tuple[np.ndarray, np.ndarray]:
    """
    Loads the locked 80/20 temporal split indices.
    Returns:
        (train_indices, test_indices)
    """
    split_path = get_split_path()
    if not split_path.exists():
        raise FileNotFoundError(f"Split file not found at: {split_path}")
    data = np.load(split_path)
    return data["train_idx"], data["test_idx"]


def get_train_test_data() -> Tuple[pd.DataFrame, pd.DataFrame, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Returns:
        (df_train, df_test, X_train, y_train, X_test, y_test)
    """
    df = load_dataset()
    train_idx, test_idx = load_split_indices()

    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_test = df.iloc[test_idx].reset_index(drop=True)

    X_train = df_train[FEATURE_COLS].values.astype(np.float32)
    y_train = df_train["label"].values.astype(np.int64)

    X_test = df_test[FEATURE_COLS].values.astype(np.float32)
    y_test = df_test["label"].values.astype(np.int64)

    return df_train, df_test, X_train, y_train, X_test, y_test


def get_dataset_statistics() -> Dict[str, Any]:
    """Computes distribution statistics for the full dataset, train, and test sets."""
    df = load_dataset()
    train_idx, test_idx = load_split_indices()

    df_train = df.iloc[train_idx]
    df_test = df.iloc[test_idx]

    stats = {
        "total_windows": len(df),
        "train_windows": len(df_train),
        "test_windows": len(df_test),
        "train_ratio": len(df_train) / len(df),
        "test_ratio": len(df_test) / len(df),
        "classes": {},
    }

    for idx, cname in enumerate(CLASS_NAMES):
        tot_c = int((df["label"] == idx).sum())
        tr_c = int((df_train["label"] == idx).sum())
        te_c = int((df_test["label"] == idx).sum())
        stats["classes"][cname] = {
            "total": tot_c,
            "train": tr_c,
            "test": te_c,
            "test_pct": (te_c / tot_c * 100) if tot_c else 0.0,
        }

    return stats
