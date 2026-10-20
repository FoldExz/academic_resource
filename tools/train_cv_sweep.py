#!/usr/bin/env python3
"""
tools/train_cv_sweep.py
=======================
Skrip Pelatihan & Cross-Validation Sweep 434 Kandidat eBPF.
Merekonstruksi dan menjalankan sweep StratifiedGroupKFold temporal 60s
terhadap 434 variasi arsitektur x skenario resampling (a, b-S1..S3, c-S1..S3)
untuk Decision Tree, Random Forest, dan MLP.

Output:
  - models/cv_summary.json (Catatan lengkap 434 kandidat CV)
  - models/cv_results/*.csv
  - models/*.joblib (Model terbaik hasil seleksi)
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Sequence

import numpy as np
import pandas as pd
import joblib

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold
from sklearn.metrics import f1_score, recall_score, make_scorer
from imblearn.pipeline import Pipeline
from imblearn.under_sampling import RandomUnderSampler

# Setup root path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pipeline
from config import (
    BASE_DIR,
    DATA_DIR,
    MODELS_DIR,
    CLASS_NAMES,
    FEATURE_COLS,
    WINDOW_NS,
)
from pipeline.sampling import (
    SCENARIOS,
    KeepFraction,
    GrowMultiplier,
    WindowSMOTE,
    scenario_size_table,
    BalancedWeightFit,
)

CONFIG_ORDER = ["a", "b-S1", "c-S1", "b-S2", "c-S2", "b-S3", "c-S3"]

# Arsitektur sweep identik dengan cv_summary.json (Total 62 arsitektur x 7 skenario = 434 kandidat)
DT_SWEEP_DEPTHS = list(range(1, 31))  # 30 arsitektur
RF_SWEEP_VARIANTS = [                 # 19 arsitektur
    {"max_depth": d, "n_estimators": 10} for d in [3, 5, 7, 9, 10, 12, 15]
] + [
    {"max_depth": 8, "n_estimators": n} for n in [1, 3, 5, 10, 20, 30]
] + [
    {"max_depth": 15, "n_estimators": 20}, {"max_depth": 15, "n_estimators": 50},
    {"max_depth": 20, "n_estimators": 20}, {"max_depth": 20, "n_estimators": 50},
    {"max_depth": 25, "n_estimators": 50}, {"max_depth": 30, "n_estimators": 100},
]
MLP_SWEEP_VARIANTS = [                # 13 arsitektur
    (2,), (4,), (8,), (16,), (32,),
    (2, 2), (4, 4), (8, 8), (16, 16),
    (16, 16, 16), (32, 32, 32), (32, 32, 32, 32), (64, 64, 64, 64),
]


def _min_recall(y_true, y_pred) -> float:
    return float(recall_score(y_true, y_pred, labels=np.unique(y_true), average=None, zero_division=0).min())


def _normal_fpr(y_true, y_pred) -> float:
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    m = y_true == 0
    return float((y_pred[m] != 0).mean()) if m.any() else float("nan")


SCORING = {
    "macro_f1": make_scorer(f1_score, average="macro", zero_division=0),
    "macro_recall": make_scorer(recall_score, average="macro", zero_division=0),
    "min_recall": make_scorer(_min_recall),
    "normal_fpr": make_scorer(_normal_fpr),
}


def legacy_candidate_grids() -> dict:
    result = {"DT": {}, "RF": {}, "MLP": {}}
    for depth in DT_SWEEP_DEPTHS:
        arch = f"d{depth:02d}"
        result["DT"][arch] = {
            "dt__max_depth": [depth],
            "dt__min_samples_split": [2],
            "dt__min_samples_leaf": [1],
            "dt__criterion": ["gini"],
        }
    for variant in RF_SWEEP_VARIANTS:
        arch = f"d{variant['max_depth']}n{variant['n_estimators']}"
        result["RF"][arch] = {
            "rf__n_estimators": [variant["n_estimators"]],
            "rf__max_depth": [variant["max_depth"]],
            "rf__min_samples_split": [2],
            "rf__min_samples_leaf": [1],
        }
    for layers in MLP_SWEEP_VARIANTS:
        arch = "x".join(str(n) for n in layers)
        result["MLP"][arch] = {
            "mlp__estimator__hidden_layer_sizes": [layers],
            "mlp__estimator__activation": ["relu"],
            "mlp__estimator__alpha": [0.001],
            "mlp__estimator__learning_rate_init": [0.01],
        }
    return result


def config_spec(tag: str):
    scenario_name = tag.split("::", 1)[0]
    if scenario_name == "a":
        return None, True
    kind, level = scenario_name.split("-")
    return SCENARIOS[level], kind == "c"


def build_pipeline(model: str, tag: str, seed: int, feature_names: Sequence[str]) -> Pipeline:
    scenario, use_weight = config_spec(tag)
    steps = []
    if scenario is not None:
        steps.append(("under", RandomUnderSampler(
            sampling_strategy=KeepFraction(scenario.keep), random_state=seed)))
        steps.append(("smote", WindowSMOTE(
            sampling_strategy=GrowMultiplier(scenario.grow),
            feature_names=list(feature_names), random_state=seed)))
    cw = "balanced" if use_weight else None
    if model == "DT":
        steps.append(("dt", DecisionTreeClassifier(random_state=seed, class_weight=cw)))
    elif model == "RF":
        steps.append(("rf", RandomForestClassifier(random_state=seed, class_weight=cw, n_jobs=1)))
    elif model == "MLP":
        steps.append(("scaler", StandardScaler()))
        steps.append(("mlp", BalancedWeightFit(
            MLPClassifier(max_iter=2000, random_state=seed, early_stopping=True),
            balanced=use_weight)))
    return Pipeline(steps)


def make_group_ids(df: pd.DataFrame, block_seconds: int = 60) -> np.ndarray:
    block_id = df["window_id"] // block_seconds
    key = df["pcap_source"].astype(str) + "::" + block_id.astype(str)
    _, grp = np.unique(key, return_inverse=True)
    return grp


def fold_scores(cv_results: dict, metric: str) -> np.ndarray:
    keys = sorted((k for k in cv_results if k.startswith("split") and k.endswith(f"_test_{metric}")),
                  key=lambda k: int(k[len("split"):].split("_")[0]))
    return np.column_stack([np.asarray(cv_results[k], dtype=float) for k in keys])


def select_best_mean(rows: List[dict], metric: str = "macro_recall") -> dict:
    means = np.array([np.mean(r["fold_scores"][metric]) for r in rows])
    fpr_means = np.array([np.mean(r["fold_scores"]["normal_fpr"]) for r in rows])
    order_idx = sorted(range(len(rows)), key=lambda i: (-means[i], fpr_means[i]))
    best = order_idx[0]
    return dict(best_tag=rows[best]["tag"], chosen_tag=rows[best]["tag"],
                best_mean=float(means[best]), best_fpr=float(fpr_means[best]))


def _jsonable(d: dict) -> dict:
    return {k: (list(v) if isinstance(v, tuple) else (v.item() if hasattr(v, "item") else v))
            for k, v in d.items()}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Reproduce 434-Candidate CV Sweep")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--cv-seed", type=int, default=7)
    parser.add_argument("--seed", type=int, default=3759629523)
    parser.add_argument("--block-seconds", type=int, default=60)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument("--quick", action="store_true", help="Run sanity check on first 3 candidates only")
    args = parser.parse_args()

    print("================================================================================")
    print(" eBPF DDoS Detection -- 434-Candidate CV Sweep Orchestrator")
    print("================================================================================")
    print(f"Dataset Path : {DATA_DIR / 'dataset_window_1s.csv'}")
    print(f"Split File   : {DATA_DIR / 'split_locked_temporal.npz'}")
    print(f"Folds        : {args.folds} (StratifiedGroupKFold, {args.block_seconds}s temporal blocks)")
    print(f"CV Seed      : {args.cv_seed} | Model Seed: {args.seed}")

    df = pd.read_csv(DATA_DIR / "dataset_window_1s.csv")
    z = np.load(DATA_DIR / "split_locked_temporal.npz", allow_pickle=True)
    tr = z["train_idx"].astype(int)

    X = df[FEATURE_COLS].to_numpy(dtype=np.float64)
    y = df["label"].to_numpy(dtype=int)
    groups = make_group_ids(df, args.block_seconds)

    X_tr, y_tr, g_tr = X[tr], y[tr], groups[tr]

    sgkf = StratifiedGroupKFold(n_splits=args.folds, shuffle=True, random_state=args.cv_seed)
    cv_splits = list(sgkf.split(X_tr, y_tr, g_tr))

    legacy_grids = legacy_candidate_grids()
    tags_by_model = {
        model: [f"{scenario}::{arch}" for arch in grids for scenario in CONFIG_ORDER]
        for model, grids in legacy_grids.items()
    }

    total_candidates = sum(len(t) for t in tags_by_model.values())
    print(f"Total Sweep Candidates: {total_candidates} candidates across DT, RF, MLP")

    if args.quick:
        print("[QUICK MODE] Restricting to 1 candidate per model for sanity testing")
        tags_by_model = {m: tags_by_model[m][:1] for m in tags_by_model}

    out_models_dir = MODELS_DIR / "sweep_models"
    out_results_dir = MODELS_DIR / "cv_results"
    out_models_dir.mkdir(parents=True, exist_ok=True)
    out_results_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for model in ["DT", "RF", "MLP"]:
        grids = legacy_grids[model]
        model_tags = tags_by_model[model]
        for idx_tag, tag in enumerate(model_tags, 1):
            arch = tag.split("::", 1)[1]
            scenario = tag.split("::", 1)[0]
            grid = grids[arch]
            if model == "MLP":
                grid = {k.replace("mlp__", "mlp__estimator__", 1): v for k, v in grid.items()}

            print(f"[{model}] ({idx_tag}/{len(model_tags)}) Evaluating {tag} ...", flush=True)
            t0 = time.time()
            gs = GridSearchCV(
                build_pipeline(model, tag, args.seed, FEATURE_COLS),
                grid,
                scoring=SCORING,
                refit="macro_recall",
                cv=cv_splits,
                n_jobs=args.n_jobs,
                error_score="raise"
            )
            gs.fit(X_tr, y_tr)
            i = gs.best_index_
            res = gs.cv_results_
            fs = {m: fold_scores(res, m)[i].tolist() for m in SCORING}
            row = dict(
                model=model,
                tag=tag,
                architecture=arch,
                scenario=scenario,
                chosen_params=_jsonable(res["params"][i]),
                argmax_params=_jsonable(res["params"][i]),
                fold_scores=fs,
                seconds=round(time.time() - t0, 1)
            )
            for m in SCORING:
                row[f"cv_{m}_mean"] = float(np.mean(fs[m]))
                row[f"cv_{m}_std"] = float(np.std(fs[m], ddof=1))
            rows.append(row)

            # Simpan ringkasan per model
            safe_tag = tag.replace("::", "__")
            pd.DataFrame(res).drop(columns=["params"]).assign(
                params=[str(p) for p in res["params"]]
            ).to_csv(out_results_dir / f"{model}_{safe_tag}.csv", index=False)
            joblib.dump(gs.best_estimator_, out_models_dir / f"{model}_{safe_tag}.joblib")

    # Hitung Best Selections
    selections = {}
    for m in ["DT", "RF", "MLP"]:
        model_rows = [r for r in rows if r["model"] == m]
        if model_rows:
            sel = select_best_mean(model_rows)
            selections[m] = sel
            for r in model_rows:
                r["config_selected_best_mean"] = (r["tag"] == sel["chosen_tag"])

    summary = {
        "protocol": "locked_temporal_outer_split_raw_no_quota_grouped_60s_cv",
        "args": {
            "seed": args.seed,
            "features": FEATURE_COLS,
            "block_seconds": args.block_seconds,
            "folds": args.folds,
            "cv_seed": args.cv_seed,
            "legacy_sweep": True,
            "candidate_count": len(rows),
        },
        "split_file": "data/split_locked_temporal.npz",
        "rows": rows,
        "selections": selections,
    }

    summary_target = MODELS_DIR / "cv_summary_reproduced.json"
    with open(summary_target, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[DONE] Rekonstruksi sweep selesai. Tersimpan di {summary_target}")


if __name__ == "__main__":
    main()
