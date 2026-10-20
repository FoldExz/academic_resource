# Artifact Evaluation & Reproducibility Guide

This document provides step-by-step instructions for reproducing the experiments and validating claims presented in the paper, structured according to **ACM / IEEE Artifact Evaluation Badging Guidelines**.

---

## 🏆 Badging Target
* **Artifacts Available:** All datasets, feature extractors, trained models, C headers, and verification logs are publicly hosted.
* **Artifacts Evaluated – Functional:** The codebase includes automated test harnesses, verification scripts, and environment checkers.
* **Results Replicated:** All 5 publication figures and 3 paper tables can be regenerated with exact numerical precision.

---

## 🚀 Quick Start (Estimated Time: 5 Minutes)

### Step 1: Environment Setup
```bash
git clone https://github.com/<username>/xdp-ebpf-ddos.git
cd xdp-ebpf-ddos

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Validate System Environment (Linux Only)
```bash
bash tools/env_check.sh
```

### Step 3: Run Model Evaluation on Locked Test Set
```bash
python main.py eval
```
**Expected Output:**
* Decision Tree: `Macro Recall = 99.9975%`, `ADR = 100.00%`
* Random Forest: `Macro Recall = 99.7855%`, `ADR = 99.9865%`
* Quantized MLP: `Macro Recall = 99.5777%`, `FPR = 0.0000%`
* Quantization Parity: `PASS (100.00%)`

### Step 4: Re-generate Publication Figures & Tables
```bash
python main.py plots
```
Generates all 5 vector figures (PDF & PNG) in `plots/` and LaTeX tables in `docs/paper/tables_latex.tex`.

---

## 🔬 In-Kernel eBPF Verifier Reproduction

### Run Automated BPF Verifier Batch Test:
```bash
# On Linux Kernel 6.8+
sudo bash tools/ebpf_verifier_batch.sh
```
Verifies bytecode instruction counts and stack usage under `-O2` and `-O3` optimization levels.

---

## 📦 Packaging Models for Deployment
To package the verified in-kernel models and configs for testbed deployment:
```bash
python tools/package_models.py --output ebpf_models_bundle.zip
```
