"""
generate_final_plots_and_tables.py
===================================
Generates publication-quality, standalone figures (PNG 300 DPI + PDF)
and tables (CSV + Markdown) for the eBPF/XDP DDoS Detection System.
No comparison with previous exploratory runs.
"""

import os
import json
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Set publication style
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "font.size": 9,
    "axes.titlesize": 10,
    "axes.labelsize": 9,
    "xtick.labelsize": 8.5,
    "ytick.labelsize": 8.5,
    "legend.fontsize": 8.5,
    "axes.linewidth": 0.8,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.05,
})

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
PLOTS_DIR = BASE_DIR / "plots"
TABLES_DIR = BASE_DIR / "tables"

PLOTS_DIR.mkdir(parents=True, exist_ok=True)
TABLES_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------
# 1. Load Evaluation Data
# ---------------------------------------------------------
eval_path = MODELS_DIR / "evaluation_report.json"
with open(eval_path, "r", encoding="utf-8") as f:
    report = json.load(f)

CLASSES = [
    "Normal",
    "ARP Flood",
    "ICMP Flood",
    "SYN Flood",
    "UDP Flood",
    "DNS Amplification",
]
SHORT_CLASSES = ["Normal", "ARP", "ICMP", "SYN", "UDP", "DNS-Amp"]
MODELS = ["DT", "RF", "MLP"]
MODEL_NAMES = {
    "DT": "Decision Tree (b-S1::d06)",
    "RF": "Random Forest (c-S2::d8n3)",
    "MLP": "Quantized MLP (a::16)",
}
COLORS = {
    "DT": "#0072B2",   # Okabe-Ito Blue
    "RF": "#009E73",   # Okabe-Ito Bluish Green
    "MLP": "#D55E00",  # Okabe-Ito Vermilion
}

# ---------------------------------------------------------
# 2. Generate Tables
# ---------------------------------------------------------
print("Generating publication tables...")

# Table 1: Overall Performance Metrics
t1_rows = []
for m in MODELS:
    met = report["models"][m]["metrics"]
    t1_rows.append({
        "Model": m,
        "Configuration": report["selected_configs"][m],
        "Macro Recall (%)": met["recall"] * 100,
        "Macro F1 (%)": met["f1"] * 100,
        "Multiclass Accuracy (%)": met["accuracy_multiclass"] * 100,
        "Attack Detection Rate (ADR, %)": met["adr"] * 100,
        "False Positive Rate (FPR, %)": met["fpr"] * 100,
        "True Negative Rate (TNR, %)": met["tnr"] * 100,
        "True Positives (TP)": met["tp"],
        "True Negatives (TN)": met["tn"],
        "False Positives (FP)": met["fp"],
        "False Negatives (FN)": met["fn"],
    })
df_t1 = pd.DataFrame(t1_rows)
df_t1.to_csv(TABLES_DIR / "table1_overall_performance.csv", index=False)

# Table 2: Per-Class Metrics
t2_rows = []
for idx, cls in enumerate(CLASSES):
    dt_cm = np.array(report["models"]["DT"]["confusion_matrix"])
    rf_cm = np.array(report["models"]["RF"]["confusion_matrix"])
    mlp_cm = np.array(report["models"]["MLP"]["confusion_matrix"])
    
    supp = int(dt_cm[idx].sum())
    
    dt_rec = dt_cm[idx, idx] / supp if supp else 1.0
    rf_rec = rf_cm[idx, idx] / supp if supp else 1.0
    mlp_rec = mlp_cm[idx, idx] / supp if supp else 1.0
    
    dt_prec = dt_cm[idx, idx] / dt_cm[:, idx].sum() if dt_cm[:, idx].sum() else 1.0
    rf_prec = rf_cm[idx, idx] / rf_cm[:, idx].sum() if rf_cm[:, idx].sum() else 1.0
    mlp_prec = mlp_cm[idx, idx] / mlp_cm[:, idx].sum() if mlp_cm[:, idx].sum() else 1.0
    
    dt_f1 = 2 * dt_prec * dt_rec / (dt_prec + dt_rec) if (dt_prec + dt_rec) else 0.0
    rf_f1 = 2 * rf_prec * rf_rec / (rf_prec + rf_rec) if (rf_prec + rf_rec) else 0.0
    mlp_f1 = 2 * mlp_prec * mlp_rec / (mlp_prec + mlp_rec) if (mlp_prec + mlp_rec) else 0.0
    
    t2_rows.append({
        "Class": cls,
        "Support": supp,
        "DT Recall (%)": dt_rec * 100,
        "DT Precision (%)": dt_prec * 100,
        "DT F1 (%)": dt_f1 * 100,
        "RF Recall (%)": rf_rec * 100,
        "RF Precision (%)": rf_prec * 100,
        "RF F1 (%)": rf_f1 * 100,
        "MLP Recall (%)": mlp_rec * 100,
        "MLP Precision (%)": mlp_prec * 100,
        "MLP F1 (%)": mlp_f1 * 100,
    })
df_t2 = pd.DataFrame(t2_rows)
df_t2.to_csv(TABLES_DIR / "table2_per_class_metrics.csv", index=False)

# Table 3: eBPF Verifier Complexity
t3_rows = [
    {
        "Model": "Decision Tree",
        "Config": "b-S1::d06 (max_depth=6)",
        "Bytecode Insns": 102,
        "Processed Insns": 403,
        "Verifier States": 34,
        "O2 Verifier Status": "PASS",
        "O3 Verifier Status": "PASS",
        "Stack Usage (bytes)": "< 128",
        "Header Size (bytes)": 2473,
    },
    {
        "Model": "Random Forest",
        "Config": "c-S2::d8n3 (depth=8, trees=3)",
        "Bytecode Insns": 204,
        "Processed Insns": 5152,
        "Verifier States": 325,
        "O2 Verifier Status": "PASS",
        "O3 Verifier Status": "PASS",
        "Stack Usage (bytes)": "< 256",
        "Header Size (bytes)": 7866,
    },
    {
        "Model": "Quantized MLP",
        "Config": "a::16 (1x16 neurons, Q14)",
        "Bytecode Insns": 338,
        "Processed Insns": 7139,
        "Verifier States": 80,
        "O2 Verifier Status": "PASS",
        "O3 Verifier Status": "PASS",
        "Stack Usage (bytes)": "< 192",
        "Header Size (bytes)": 4578,
    },
]
df_t3 = pd.DataFrame(t3_rows)
df_t3.to_csv(TABLES_DIR / "table3_ebpf_complexity.csv", index=False)

# Markdown Summary
md_summary = f"""# Final System Performance & eBPF Verification Summary

## 1. Overall Performance on Locked Outer-Test Set (34,995 1s Windows)

| Model | Architecture / Config | Macro Recall | Macro F1 | Multiclass Acc | ADR (Attack Recall) | FPR (False Alarm) | Verifier Status |
|---|---|---|---|---|---|---|---|
| **Decision Tree (DT)** | `b-S1::d06` (depth 6) | **99.9975%** | **99.9953%** | **99.9914%** | **100.0000%** | 0.0149% | PASS (O2 & O3) |
| **Random Forest (RF)** | `c-S2::d8n3` (8 depth, 3 trees) | 99.7855% | 99.8870% | 99.9829% | 99.9865% | 0.0199% | PASS (O2 & O3) |
| **Quantized MLP** | `a::16` (1x16, Q14 fixed-point) | 99.5777% | 99.7857% | 99.9886% | 99.9731% | **0.0000%** | PASS (O2 & O3) |

> **Key Findings:**
> - **Decision Tree** achieves the highest Macro Recall (**99.9975%**) and detects **100% of all attack instances** across all 5 DDoS classes (FN = 0), with only 3 false alarms out of 20,142 normal windows.
> - **Quantized MLP** achieves **zero false alarms** (FPR = 0.0000%, 100% specificity on benign traffic).
> - All 3 models pass Linux 6.8 kernel eBPF verifier under both `-O2` and `-O3` compilation flags.

## 2. Per-Class Recall & Support

| Traffic Class | Support (Windows) | DT Recall | RF Recall | MLP Recall |
|---|---|---|---|---|
| **Normal (Benign)** | 20,142 | 99.99% | 99.98% | **100.00%** |
| **ARP Flood** | 7,240 | **100.00%** | **100.00%** | **100.00%** |
| **ICMP Flood** | 7,120 | **100.00%** | **100.00%** | **100.00%** |
| **SYN Flood** | 145 | **100.00%** | **100.00%** | **100.00%** |
| **UDP Flood** | 227 | **100.00%** | 99.56% | 99.12% |
| **DNS Amplification** | 121 | **100.00%** | 99.17% | 98.35% |

## 3. In-Kernel eBPF Verifier Complexity (Kernel 6.8)

| Model | Bytecode Insns | Verifier Processed Insns | Verifier Limit | States | Verifier Safety Margin |
|---|---|---|---|---|---|
| **DT (`b-S1::d06`)** | 102 | 403 | 1,000,000 | 34 | **99.96%** |
| **RF (`c-S2::d8n3`)** | 204 | 5,152 | 1,000,000 | 325 | **99.48%** |
| **MLP (`a::16`)** | 338 | 7,139 | 1,000,000 | 80 | **99.29%** |
"""
with open(TABLES_DIR / "tables_summary.md", "w", encoding="utf-8") as f:
    f.write(md_summary)

# ---------------------------------------------------------
# 3. Generate Standalone Figures
# ---------------------------------------------------------
print("Generating publication figures...")

# Figure 1: Overall Performance Comparison
fig, ax = plt.subplots(figsize=(6.5, 3.2), dpi=300)
metrics_to_plot = ["Macro Recall", "Macro F1", "Multiclass Acc", "ADR"]
x = np.arange(len(metrics_to_plot))
bar_width = 0.25

for i, m in enumerate(MODELS):
    met = report["models"][m]["metrics"]
    vals = [
        met["recall"] * 100,
        met["f1"] * 100,
        met["accuracy_multiclass"] * 100,
        met["adr"] * 100,
    ]
    offset = (i - 1) * bar_width
    bars = ax.bar(
        x + offset, vals, width=bar_width, label=MODEL_NAMES[m],
        color=COLORS[m], edgecolor="black", linewidth=0.5, alpha=0.9
    )
    for bar in bars:
        h = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2, h + 0.03,
            f"{h:.2f}%", ha="center", va="bottom", fontsize=6.5, rotation=0
        )

ax.set_ylabel("Metric Score (%)", fontweight="bold")
ax.set_title("Overall Detection Performance on Locked Outer-Test Set (N = 34,995)", pad=12, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels(metrics_to_plot, fontweight="bold")
ax.set_ylim(99.0, 100.2)
ax.grid(axis="y", linestyle="--", alpha=0.4)
ax.legend(loc="lower right", framealpha=0.9)
fig.savefig(PLOTS_DIR / "fig1_model_comparison.png")
fig.savefig(PLOTS_DIR / "fig1_model_comparison.pdf")
plt.close(fig)

# Figure 2: Per-Class Recall Comparison
fig, ax = plt.subplots(figsize=(7.2, 3.4), dpi=300)
x_cls = np.arange(len(SHORT_CLASSES))
bar_w = 0.25

for i, m in enumerate(MODELS):
    recs = [df_t2.loc[df_t2["Class"] == c, f"{m} Recall (%)"].values[0] for c in CLASSES]
    offset = (i - 1) * bar_w
    bars = ax.bar(
        x_cls + offset, recs, width=bar_w, label=MODEL_NAMES[m],
        color=COLORS[m], edgecolor="black", linewidth=0.5, alpha=0.9
    )
    for bar in bars:
        h = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2, h + 0.08,
            f"{h:.1f}%", ha="center", va="bottom", fontsize=6.2, rotation=0
        )

ax.set_ylabel("Per-Class Recall (%)", fontweight="bold")
ax.set_title("Per-Class Detection Recall Across Traffic Types", pad=12, fontweight="bold")
ax.set_xticks(x_cls)
ax.set_xticklabels([f"{c}\n(N={df_t2.loc[df_t2['Class']==cls_name, 'Support'].values[0]:,})" 
                    for c, cls_name in zip(SHORT_CLASSES, CLASSES)], fontsize=7.5)
ax.set_ylim(97.0, 100.5)
ax.grid(axis="y", linestyle="--", alpha=0.4)
ax.legend(loc="lower left", framealpha=0.9)
fig.savefig(PLOTS_DIR / "fig2_per_class_recall.png")
fig.savefig(PLOTS_DIR / "fig2_per_class_recall.pdf")
plt.close(fig)

# Figure 3: Standalone Confusion Matrices (3-panel)
fig, axes = plt.subplots(1, 3, figsize=(12, 3.8), dpi=300)
for idx, m in enumerate(MODELS):
    ax = axes[idx]
    cm = np.array(report["models"][m]["confusion_matrix"])
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100
    
    # Custom annotations: count + percentage
    annot_labels = np.empty_like(cm, dtype=object)
    for r in range(cm.shape[0]):
        for c in range(cm.shape[1]):
            val = cm[r, c]
            pct = cm_norm[r, c]
            if val > 0:
                annot_labels[r, c] = f"{val:,}\n({pct:.1f}%)" if pct < 99.95 else f"{val:,}\n(100%)"
            else:
                annot_labels[r, c] = "0"

    sns.heatmap(
        cm_norm, ax=ax, annot=annot_labels, fmt="", cmap="Blues",
        cbar=False, annot_kws={"size": 6.8}, vmin=0, vmax=100,
        xticklabels=SHORT_CLASSES, yticklabels=SHORT_CLASSES if idx == 0 else False,
        linewidths=0.5, linecolor="#e0e0e0"
    )
    ax.set_title(f"({chr(97+idx)}) {MODEL_NAMES[m]}", fontweight="bold", pad=8)
    ax.set_xlabel("Predicted Class", fontweight="bold")
    if idx == 0:
        ax.set_ylabel("True Class", fontweight="bold")
    ax.set_xticklabels(SHORT_CLASSES, rotation=35, ha="right")

fig.suptitle("Confusion Matrix Heatmaps on Locked Outer-Test Set (N = 34,995)", fontsize=11, fontweight="bold", y=1.03)
fig.savefig(PLOTS_DIR / "fig3_confusion_matrices.png")
fig.savefig(PLOTS_DIR / "fig3_confusion_matrices.pdf")
plt.close(fig)

# Figure 4: Complexity vs Performance Tradeoff
fig, ax = plt.subplots(figsize=(5.5, 3.2), dpi=300)
insns = [102, 204, 338]
recalls = [report["models"][m]["metrics"]["recall"] * 100 for m in MODELS]
f1s = [report["models"][m]["metrics"]["f1"] * 100 for m in MODELS]

for i, m in enumerate(MODELS):
    ax.scatter(insns[i], recalls[i], s=120, color=COLORS[m], edgecolor="black", linewidth=1.0, zorder=5, label=f"{m} Recall")
    ax.scatter(insns[i], f1s[i], s=100, color=COLORS[m], marker="s", edgecolor="black", linewidth=1.0, alpha=0.7, zorder=5, label=f"{m} F1")
    ax.annotate(
        f"{m} ({report['selected_configs'][m]})\n{insns[i]} insns",
        (insns[i], recalls[i]), textcoords="offset points", xytext=(0, 8),
        ha="center", fontsize=7.5, fontweight="bold", color=COLORS[m]
    )

ax.set_xlabel("eBPF Bytecode Instruction Count (insn)", fontweight="bold")
ax.set_ylabel("Score (%)", fontweight="bold")
ax.set_title("In-Kernel Instruction Count vs Macro Metric Tradeoff", pad=12, fontweight="bold")
ax.set_ylim(99.4, 100.1)
ax.set_xlim(50, 400)
ax.grid(True, linestyle="--", alpha=0.4)
handles, labels = ax.get_legend_handles_labels()
# Keep distinct legend
ax.legend(
    [handles[0], handles[1]], ["Macro Recall", "Macro F1 Score"],
    loc="lower left", framealpha=0.9
)
fig.savefig(PLOTS_DIR / "fig4_complexity_vs_recall.png")
fig.savefig(PLOTS_DIR / "fig4_complexity_vs_recall.pdf")
plt.close(fig)

# Figure 5: eBPF Verifier Instruction Envelope
fig, ax = plt.subplots(figsize=(6.2, 3.0), dpi=300)
models_list = ["DT (b-S1::d06)", "RF (c-S2::d8n3)", "MLP (a::16)"]
proc_insns = [403, 5152, 7139]
colors_bar = [COLORS["DT"], COLORS["RF"], COLORS["MLP"]]

y_pos = np.arange(len(models_list))
bars = ax.barh(y_pos, proc_insns, height=0.45, color=colors_bar, edgecolor="black", linewidth=0.6)

# Verifier 1,000,000 limit line
ax.axvline(1000000, color="red", linestyle="--", linewidth=1.2, label="Linux 6.8 Verifier Limit (1,000,000)")
ax.set_xscale("log")
ax.set_xlim(10, 3000000)

for bar in bars:
    w = bar.get_width()
    ax.text(w * 1.3, bar.get_y() + bar.get_height() / 2, f"{int(w):,} proc insns (PASS)",
            va="center", ha="left", fontsize=7.5, fontweight="bold")

ax.set_yticks(y_pos)
ax.set_yticklabels(models_list, fontweight="bold")
ax.set_xlabel("Verifier Processed Instructions (Log Scale)", fontweight="bold")
ax.set_title("Linux Kernel eBPF Verifier Complexity vs 1M Instruction Limit", pad=12, fontweight="bold")
ax.grid(axis="x", linestyle="--", alpha=0.4)
ax.legend(loc="lower right", framealpha=0.9)
fig.savefig(PLOTS_DIR / "fig5_ebpf_verifier_envelope.png")
fig.savefig(PLOTS_DIR / "fig5_ebpf_verifier_envelope.pdf")
plt.close(fig)

print("All publication figures and tables generated successfully in plots/ and tables/.")
