# Catatan Revisi Proposal — Sistem Aktual vs Tertulis

> Dokumen ini merangkum gap antara proposal saat ini dengan implementasi aktual
> untuk keperluan revisi sebelum submission paper internasional.
> Model final yang dipilih: **Run 4** (min_pkt = 0, 34.995 window test).

---

## 1. KRITIS — Berbeda Secara Teknis

### 1.1  Kriteria Seleksi Model (§3.2.4b, §3.4)

| | Proposal | Aktual |
|---|---|---|
| **Tertulis** | `GridSearchCV` terhadap **macro-average F1 Score** | Seleksi berdasarkan **macro-average Recall** (CV + locked test) |
| **Justifikasi aktual** | Al-Dunainawi et al. (2023) [IEEE Access]: pada sistem DDoS, missed detection berakibat destruktif menjenuhkan buffer/link target; Hider et al. (2023) [IEEE Access]: evaluasi multi-vektor dataset CIC-DDoS mengevaluasi macro-recall terhadap attack classes | |
| **Revisi** | Di §2.2.9 tetap singkat (rumus & definisi umum). Justifikasi NIPS (+ sitasi Al-Dunainawi & Hider 2023) diletakkan di Bab 3 (§3.2.4b & §3.4, Tabel 3.11) sebagai dasar metodologi seleksi model. |

### 1.2  Batas Hyperparameter MLP (§3.2.4, Tabel 3.5)

| | Proposal | Aktual |
|---|---|---|
| **Tertulis** | "Maks 2 hidden layer × 8 neuron/layer, arsitektur 9→8→8→6" | Model terpilih Run 4: `a::16` = **1 hidden layer × 16 neuron** (9→16→6) |
| **Revisi** | Update Tabel 3.5: `neuron/layer ≤ 16` untuk 1-layer, `≤ 8` untuk 2-layer |
| | Tambahkan catatan: batas verifier bukan nilai tunggal — bergantung pada jumlah layer; 1×16 dan 2×8 keduanya lolos verifier |

### 1.3  Pre-processing: min_pkt Threshold (§3.2.3a)

| | Proposal | Aktual |
|---|---|---|
| **Tertulis** | "Window dengan jumlah paket kurang dari 5 dibuang" | Run 4 final: **min_pkt = 0**, semua window diproses |
| **Justifikasi aktual** | min_pkt=0 identik dengan perilaku sistem in-kernel (tidak ada pre-filter window di XDP); lebih jujur secara ilmiah |
| **Revisi** | Hapus total kalimat filter min_pkt=5 dari §3.2.3a tanpa perlu menyebut histori threshold eksplorasi lama. Langsung nyatakan pembuangan hanya untuk NaN/infinite. |

### 1.4  Metode Train/Test Split (§3.2.4b)

| | Proposal | Aktual |
|---|---|---|
| **Tertulis** | "Stratified group split berdasarkan sesi atau sumber PCAP asal untuk mencegah data leakage" | **Temporal split 80/20 locked** berdasarkan window_id urutan waktu; 80% awal → train, 20% akhir → test |
| **Revisi** | Ganti menjadi: "Temporal 80/20 split — 80% window awal dijadikan train partition (digunakan untuk 5-fold grouped temporal CV), 20% akhir dijadikan locked test partition yang tidak disentuh selama seleksi model" |

---

## 2. PERLU DITAMBAH — Kontribusi Metodologis Belum Masuk Proposal

### 2.1  eBPF Verifier sebagai Hard Constraint Pemilihan Model (§3.2.4)

Proposal saat ini menyebut verifier hanya sebagai "estimasi awal" di §2.2.5b dan §3.2.4.
Kenyataannya, verifier menjadi **filter wajib dua tahap**:

```
Fase 1: CV 5-fold pada 434 kandidat → skor CV (macro-recall)
Fase 2: Kompilasi & verifikasi eBPF (O2 + O3) → PASS/FAIL per kandidat
Seleksi: pilih kandidat dengan recall CV tertinggi yang PASS keduanya
```

Ini adalah **kontribusi metodologis** — belum ada di literatur yang dikaji.
Perlu masuk sebagai sub-tahap tersendiri di Gambar 3.3 dan §3.2.4b.

### 2.2  Pipeline Seleksi 2-Tahap dengan cv_selection_constrained (§3.2.4b)

Tambahkan algoritma ringkas:
1. Jalankan CV sweep → simpan `sweep_results.json`
2. Compile semua kandidat ke `.h` → simpan ke `model_variations_research/`
3. Jalankan eBPF verifier (bpftool O2 + O3) → simpan `verifier_results.txt`
4. Filter kandidat: pertahankan hanya yang PASS verifier
5. Dari kandidat lolos, pilih model dengan **macro-recall CV tertinggi**
6. Evaluasi pada locked 20% test set → `evaluation_report.json`

### 2.3  Grouped Temporal CV (§3.2.4b)

Proposal hanya menyebut "cross-validation 5-fold". Perlu dieksplisitkan:
- Tipe: **StratifiedGroupKFold** dengan blok temporal 60 detik
- Tujuan: mencegah temporal data leakage antara fold
- Grouping: window_id dibagi menjadi blok 60-detik, setiap blok selalu masuk ke fold yang sama

### 2.4  7 Skenario Class Weight (§3.2.4)

Sweep mencakup 7 strategi class weight handling:
- `a`: `class_weight=None` (default)
- `b-S1..S3`: `class_weight='balanced'` + 3 variasi attack_quota downsampling
- `c-S1..S3`: custom weight dict + 3 variasi attack_quota

Perlu disebutkan minimal sebagai variabel eksperimen di §3.2.4 atau Tabel 3.5.

---

## 3. MINOR — Update Angka / Kalimat

| Lokasi | Yang Perlu Diupdate |
|---|---|
| Tabel 3.5, kolom "Estimasi Instruksi" MLP | Isi dengan angka aktual dari `bpftool` (bukan estimasi) setelah pengujian |
| §2.2.5b, kuantisasi MLP | Sebutkan format spesifik: **Q14 fixed-point** (enlargement factor = 2^14 = 16384) mengikuti Zhang et al. [13] |
| §2.2.9 | Tambah definisi **macro-average Recall** dan jelaskan mengapa diprioritaskan atas akurasi untuk konteks NIPS |
| §3.2.4 Gambar 3.3 | Update diagram alur untuk mencerminkan 2-tahap seleksi (CV + verifier filter) |
| §2.2.9.h ADR | Pastikan definisi ADR konsisten dengan macro-recall: ADR = rata-rata recall per attack class |

---

## 4. PILIHAN: Ablation Study (Opsional untuk Paper Internasional)

Perbandingan Run 3 (min_pkt=5) vs Run 4 (min_pkt=0) bisa dijadikan **ablation study minor**
di §4 (Eksperimen dan Analisis) untuk menunjukkan dampak threshold pada:
- Jumlah window tersedia
- Distribusi kelas
- Recall model akhir

Ini menambah novelty tanpa mengubah klaim utama.

---

## 5. Model Final Terpilih (Run 4, untuk §4 dan §5)

| Model | Arsitektur | CV Recall | Test Recall | FPR | eBPF Verifier |
|---|---|---|---|---|---|
| **DT** | depth=6, scenario=b-S1 | ~99.8% | **99.9975%** | 0.015% | O2 ✅ O3 ✅ |
| **RF** | depth=8, n=3, scenario=c-S2 | ~99.7% | 99.79% | 0.020% | O2 ✅ O3 ✅ |
| **MLP** | 1×16, scenario=a | ~99.4% | 99.58% | 0.000% | O2 ✅ O3 ✅ |

> Semua model lolos eBPF verifier O2 dan O3. FPR nol pada MLP berarti tidak ada
> trafik normal yang salah diklasifikasi sebagai serangan pada locked test 20%.
> Sisa false negative (< 1%) adalah window transisi dengan packet rate rendah yang
> jatuh di bawah threshold natural Normal, bukan cross-class confusion.
