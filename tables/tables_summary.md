# Final System Performance & eBPF Verification Summary

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
