# International Paper Outline & Structure

## Title: Line-Rate In-Kernel DDoS Mitigation via Verifier-Constrained Machine Learning in eBPF/XDP

**Target Venues:** IEEE INFOCOM / IEEE Transactions on Network and Service Management (TNSM) / ACM CCS / USENIX Security

---

### Abstract
Distributed Denial of Service (DDoS) attacks targeting multi-gigabit networks overwhelm conventional user-space intrusion detection systems (IDS) due to memory buffer exhaustion and context-switching overheads. In-kernel packet processing with Extended Berkeley Packet Filter (eBPF) and eXpress Data Path (XDP) enables line-rate packet filtering; however, embedding complex machine learning (ML) models inside the Linux kernel is severely constrained by strict verification safety rules (512-byte stack limits, no floating-point arithmetic, and instruction complexity bounds). This paper proposes a novel **verifier-constrained machine learning framework** for line-rate DDoS detection and multi-tier mitigation in eBPF/XDP. We introduce: (1) an offline-to-online consistent feature extraction architecture operating over 1-second sliding windows, (2) a two-stage model selection pipeline that enforces Linux eBPF verifier passability under both `-O2` and `-O3` optimizations alongside macro-average recall optimization, and (3) a Q14 fixed-point quantized neural network achieving 100.00% numerical parity with standard floating-point models while maintaining a 0.0000% False Positive Rate. Evaluated on a 10GbE testbed and 187,132 continuous network windows across five attack vectors (ARP, ICMP, SYN, UDP floods, and DNS Amplification), our Decision Tree achieves 99.9975% Macro Recall with 100.00% Attack Detection Rate (ADR) and sub-microsecond packet latency, dramatically outperforming Suricata and Snort 3 under saturated link loads.

---

### Section Structure
1. **Introduction**
   - Growth of volumetric and multi-vector DDoS (Fortinet / Cloudflare 2025/2026 reports)
   - Limitations of traditional user-space IPS (Snort 3, Suricata) and late-stack firewalls (iptables/nftables)
   - Promise and challenges of eBPF/XDP: Safety verification vs model expressiveness
   - Summary of key contributions
2. **Threat Model & Background**
   - Multi-layer DDoS vectors: L2 (ARP Flood), L3 (ICMP Flood), L4 (SYN Flood, UDP Flood, DNS Amplification)
   - eBPF Virtual Machine, XDP Ingress Hook, and Verifier Verification Guarantees
   - Motivation for Macro-Recall Optimization in Security Applications (Sommer & Paxson, 2010)
3. **System Architecture & In-Kernel Design**
   - Two-tier packet processing: Fast-Path vs Slow-Path
   - Lockless per-CPU feature extraction and HyperLogLog Cardinality Estimation
   - Periodic BPF Timer Aggregation and Heavy-Hitter (Top-128) bounded loop inference
   - Multi-tier Mitigation Action State Machine (PASS, THROTTLE, BLACKLIST, DROP)
4. **Verifier-Constrained Machine Learning Pipeline**
   - Feature engineering & sliding temporal windowing
   - Temporal 80/20 partitioning and avoiding cross-fold data leakage
   - Hyperparameter sweep across 434 model variations with 7 class-weighting strategies
   - Two-stage verifier constraint filter (O2 & O3 bpftool validation)
   - Q14 Fixed-Point Quantization without floating-point instructions
5. **Experimental Evaluation**
   - Testbed setup: 10GbE bare metal (Intel X540-T2) & Virtual environments
   - Classification accuracy across 34,995 locked test windows
   - Ablation study: Impact of sustained-burst idle trimming
   - Packet processing latency: Fast Path vs Slow Path vs Baselines
   - Line-rate throughput and CPU core scaling (RSS)
   - Time-to-Mitigation (TTM) across attack classes
6. **Related Work**
   - Programmable data plane security (P4 vs eBPF)
   - ML inference in embedded/kernel spaces (emlearn, quantization)
   - Comparative evaluation with existing literature
7. **Conclusion & Future Directions**
   - Summary of findings
   - Roadmap toward SmartNIC hardware offload
