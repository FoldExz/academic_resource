# Academic Resource: eBPF/XDP DDoS Detection Machine Learning Pipeline

Repository ini berisi artefak akademik, pipeline ekstraksi fitur, model terlatih, data evaluasi, dan log verifikasi kernel Linux untuk Proyek Akhir:  
**"Sistem Deteksi dan Mitigasi DDoS Menggunakan Machine Learning Berbasis eBPF/XDP"**  
Program Studi Sarjana Terapan Teknik Komputer, Departemen Teknik Informatika dan Komputer, Politeknik Elektronika Negeri Surabaya (PENS), 2026.

Penulis: **Ihsanta Zaki Sanjaya** (NRP 322600058)  
Dosen Pembimbing:
1. Maretha Ruswiansari, S.ST, MT
2. Reni Soelistijorini, B.Eng., MT

---

## Ringkasan Proyek

Repositori ini memfokuskan pada evaluasi offline dan kelayakan in-kernel dari model *supervised machine learning* yang diekspor ke kode C untuk dijalankan pada lingkungan data plane kernel Linux (eBPF/XDP) dengan batasan verifier kernel 6.8+.

### Karakteristik Teknis
* **Temporal Windowing**: 1 detik continuous streaming window (`window_ns = 1,000,000,000 ns`).
* **Fitur In-Kernel (9 Fitur)**:
  1. `packet_rate`: Jumlah paket per detik.
  2. `byte_rate`: Jumlah byte per detik.
  3. `arp_count`: Hitungan frame ARP (L2).
  4. `syn_count`: Hitungan paket TCP SYN tanpa ACK (L4).
  5. `udp_count`: Hitungan datagram UDP (L4).
  6. `icmp_count`: Hitungan paket ICMP echo/reply (L3).
  7. `dns_count`: Hitungan trafik UDP port 53 & reflection response ports (512, 530, 564, 634, 900).
  8. `avg_packet_size`: Rata-rata ukuran paket (`byte_rate / packet_rate`).
  9. `unique_src_ip`: Estimasi kardinalitas IP sumber unik menggunakan HyperLogLog ($m = 256$, $\alpha \approx 0.7183$).
* **Batasan eBPF Verifier**:
  * Stack memory $\le 512$ byte.
  * Kompleksitas eksekusi statis $\le 1.000.000$ instruksi terproses.
  * Nol operasi *floating-point* (menggunakan fixed-point Q14 untuk model neural network).
  * Terverifikasi lolos uji verifier Linux 6.8 pada opsi optimasi `-O2` dan `-O3`.

---

## Hasil Evaluasi Model

Evaluasi dilakukan pada partisi data uji terkunci (*locked outer-test set*, 20% kronologis akhir, $N = 34.995$ window):

### 1. Performa Klasifikasi Keseluruhan

| Model | Konfigurasi / Arsitektur | Macro Recall | Macro F1 | Akurasi Multiclass | Attack Recall (ADR) | False Positive (FPR) | Status Verifier |
|---|---|---|---|---|---|---|---|
| **Decision Tree (DT)** | `b-S1::d06` (max_depth=6) | **99.9975%** | **99.9953%** | **99.9914%** | **100.0000%** | 0.0149% | PASS (O2 & O3) |
| **Random Forest (RF)** | `c-S2::d8n3` (depth=8, 3 trees) | 99.7855% | 99.8870% | 99.9829% | 99.7466% | 0.0199% | PASS (O2 & O3) |
| **Quantized MLP** | `a::16` (1x16, Q14 int32) | 99.5777% | 99.7857% | 99.9886% | 99.4932% | **0.0000%** | PASS (O2 & O3) |

### 2. Recall per Kelas Serangan

| Kelas Trafik | Jumlah Sampel Uji | DT Recall | RF Recall | MLP Recall | Keterangan Profil Trafik |
|---|---|---|---|---|---|
| **Normal (Benign)** | 20.142 | 99.99% | 99.98% | **100.00%** | CIC-DDoS2019 Benign + TRex Enterprise LAN |
| **ARP Flood** | 7.240 | **100.00%** | **100.00%** | **100.00%** | Stateless crafted ARP frame |
| **ICMP Flood** | 7.120 | **100.00%** | **100.00%** | **100.00%** | Echo request flooding |
| **SYN Flood** | 145 | **100.00%** | **100.00%** | **100.00%** | TCP SYN half-open flood |
| **UDP Flood** | 227 | **100.00%** | 99.56% | 99.12% | High-rate UDP datagram flood |
| **DNS Amplification** | 121 | **100.00%** | 99.17% | 98.35% | Reflection responses (dataset-specific artifact ports) |

### 3. Kompleksitas Verifier eBPF (Kernel Linux 6.8)

| Model | Bytecode Insns | Verifier Processed Insns | Batas Verifier | States | Safety Margin | Estimasi Stack |
|---|---|---|---|---|---|---|
| **DT (`b-S1::d06`)** | 102 | 403 | 1.000.000 | 34 | 99.96% | < 128 bytes |
| **RF (`c-S2::d8n3`)** | 204 | 5.152 | 1.000.000 | 325 | 99.48% | < 256 bytes |
| **MLP (`a::16`)** | 338 | 7.139 | 1.000.000 | 80 | 99.29% | < 192 bytes |

---

## Struktur Direktori

```text
academic_resource/
├── config.py                           # Konfigurasi global, pemetaan port, dan konstanta HLL
├── generate_final_plots_and_tables.py  # Skrip pembuatan grafik vektor dan tabel publikasi
├── main.py                             # CLI orchestrator (view, eval, plots, summary)
├── requirements.txt                    # Dependensi Python
├── .env.example                        # Template environment variable
├── .gitignore                          # Konfigurasi ignore git
│
├── data/                               # Dataset fitur terekstraksi & split temporal
│   ├── dataset_window_1s.csv           # Dataset window 1 detik (187.132 baris)
│   ├── dataset_canonical.csv           # Dataset kanonikal
│   ├── split_locked_temporal.npz       # Indeks partisi temporal terkunci (80% train, 20% test)
│   ├── arp_flood.csv                   # Ekstraksi per kelas
│   ├── icmp_flood.csv
│   ├── syn_flood.csv
│   ├── udp_flood.csv
│   ├── dns_amp.csv
│   ├── benign_cic_full.csv
│   ├── benign_extra.csv
│   └── tables/                         # Distribusi data per sumber PCAP
│
├── models/                             # Bobot model dan C header in-kernel
│   ├── dt_model.joblib                 # Serialisasi Scikit-learn Decision Tree
│   ├── dt_final.h                      # Export C header Decision Tree (b-S1::d06)
│   ├── rf_model.joblib                 # Serialisasi Scikit-learn Random Forest
│   ├── rf_final.h                      # Export C header Random Forest (c-S2::d8n3)
│   ├── mlp_model.joblib                # Serialisasi Scikit-learn MLP
│   ├── mlp_final.h                     # Export C header MLP kuantisasi Q14 fixed-point
│   ├── mlp_weights_final.json          # Bobot float32 asli
│   ├── mlp_weights_final_quantized.json# Bobot terkuantisasi int32 Q14
│   ├── cv_selection_constrained.json   # Manifest seleksi model lolos verifier
│   ├── cv_summary.json                 # Ringkasan hasil sweep 434 variasi model
│   ├── evaluation_report.json          # Laporan metrik numerik lengkap
│   ├── verifier_results_O2.txt         # Log bpftool verifier level -O2
│   └── verifier_results_O3.txt         # Log bpftool verifier level -O3
│
├── pipeline/                           # Modul inti Python
│   ├── dataset.py                      # Parser dataset & partisi indeks
│   ├── evaluation.py                   # Kalkulator metrik klasifikasi multiclass & biner
│   ├── export.py                       # Validasi kesetaraan kuantisasi C vs Python
│   ├── export_trees.py                 # Generator C header struktur pohon keputusan
│   ├── sampling.py                     # Modul stratified & class-weighting
│   └── ui.py                           # Tampilan terminal visualizer
│
├── plots/                              # Grafik hasil evaluasi (300 DPI PNG & PDF)
│   ├── fig0_pcap_temporal_distribution_before_vs_after.png
│   ├── fig1_model_comparison.{png,pdf}
│   ├── fig2_per_class_recall.{png,pdf}
│   ├── fig3_confusion_matrices.{png,pdf}
│   ├── fig4_complexity_vs_recall.{png,pdf}
│   ├── fig5_ebpf_verifier_envelope.{png,pdf}
│   └── temporal_before_after/          # Audit pemotongan tail idle pada PCAP
│
├── tables/                             # Tabel metrik ringkasan (CSV & Markdown)
│   ├── table1_overall_performance.csv
│   ├── table2_per_class_metrics.csv
│   ├── table3_ebpf_complexity.csv
│   └── tables_summary.md
│
├── tools/                              # Utilitas pengujian dan audit
│   ├── test_header_parity.py           # Validasi paritas C vs Scikit-learn
│   └── train_cv_sweep.py               # Skrip sweep cross-validation
│
└── docs/                               # Naskah akademik
    ├── proposal/                       # Dokumen proposal penelitian
    └── paper/                          # Draf paper dan tabel LaTeX
```

---

## Petunjuk Penggunaan & Reproduksi

### 1. Instalasi Lingkungan
Pastikan menggunakan Python 3.10 atau 3.11:

```bash
# Buat dan aktifkan virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Instal dependensi
pip install -r requirements.txt
```

### 2. Re-evaluasi Model pada Data Uji Terkunci
Menjalankan evaluasi ketiga model pada 34.995 data uji terkunci serta memvalidasi kesetaraan prediksi fixed-point C vs Scikit-learn:

```bash
python main.py eval
```

### 3. Pembuatan Ulang Gambar & Tabel Publikasi
Menghasilkan ulang seluruh file gambar vektor (300 DPI PNG dan PDF) di folder `plots/` serta tabel di `tables/`:

```bash
python main.py plots
```

### 4. Menampilkan Ringkasan Metrik
Menampilkan tabel ringkasan evaluasi dan envelope verifier di terminal:

```bash
python main.py summary
```

---

## Catatan Ilmiah & Keterbatasan

1. **Metrik Seleksi (Macro-Average Recall)**: Mengingat dampak kegagalan deteksi (false negative) pada NIPS jauh lebih fatal dibanding false alarm, seleksi model mengutamakan Macro Recall untuk memastikan kelas minoritas (SYN, UDP, DNS) tetap terdeteksi secara reliabel pada data yang tidak seimbang.
2. **Kuantisasi Q14 Fixed-Point**: MLP diimplementasikan tanpa float menggunakan format Q14 (faktor skala 16.384) dan koefisien scaler Q30, menghasilkan paritas numerik 100% terhadap model floating-point Python scikit-learn.
3. **Artefak Dataset DNS Amplification**: Analisis payload CIC-DDoS2019 menunjukkan bahwa paket dengan label DrDoS_DNS pada dataset menggunakan port refleksi non-standar (misal port 634 dengan payload NTP monlist). Model mendeteksi pola berbasis kuota port tersebut sesuai karakteristik dataset benchmark.
4. **Pembagian Temporal 80/20**: Pembagian data dilakukan secara kronologis berurutan waktu (bukan random shuffle) untuk mencerminkan kondisi operasional jaringan sesungguhnya dan mencegah kebocoran data (*temporal data leakage*).

---

## Lisensi & Atribusi

Proyek ini berada di bawah lisensi MIT License. Ditujukan untuk keperluan riset akademis, audit reproduktibilitas penelitian, dan rujukan implementasi machine learning pada eBPF/XDP.
