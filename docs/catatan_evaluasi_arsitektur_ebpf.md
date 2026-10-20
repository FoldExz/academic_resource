# Catatan Evaluasi Kritis Arsitektur eBPF/XDP & Roadmap Tulis Ulang Data Plane

Dokumen ini merangkum hasil audit teknis mendalam terhadap implementasi arsitektur data plane (kernel) dan control plane (userspace) untuk keperluan penulisan ulang (*clean rewrite*), dengan tetap mempertahankan pipeline ML, dataset, model yang telah lolos verifier, dan proposal sebagai panduan ilmiah.

---

## 1. Identifikasi Cacat Fatal pada Implementasi Kernel Sebelumnya

Audit kompilasi menggunakan Clang 18.1.3 dan verifier Linux kernel menemukan rantai kegagalan struktural berikut:

### 1.1 Dual Program XDP & Isolasi Map
* **Masalah**: `xdp_prog.c` dan `bpf_timer.c` dipisah menjadi dua objek `.o` yang berbeda. Dalam eBPF, setiap file objek yang dimuat secara independen akan membuat instance BPF map baru di kernel, kecuali jika map tersebut di-pin ke BPF Virtual File System (`/sys/fs/bpf`).
* **Dampak**: Satu interface jaringan Linux tidak dapat menampung dua program XDP secara langsung tanpa dispatcher. Program timer yang dimuat terpisah tidak pernah melihat statistik paket yang dihitung oleh program parser.
* **Solusi**: Satukan seluruh logika pemrosesan paket (L2–L4 parse, trusted bypass, fast path, slow path) dan registrasi `bpf_timer` ke dalam **SATU file kompilasi objek (`ddos.bpf.c`)**.

### 1.2 Kegagalan Logika Top-128 Heavy Hitters & Agregasi Lintas-Core
* **Masalah**: Peta `top_ips_map` dideklarasikan tetapi tidak pernah ditulis oleh parser maupun timer. Timer mengiterasi array kosong.
* **Masalah**: Statistik paket disimpan dalam `BPF_MAP_TYPE_PERCPU_HASH` untuk menghindari kontensi core saat Receive Side Scaling (RSS) aktif. Namun, pada saat window berakhir, tidak ada kode yang menjumlahkan counter dari masing-masing CPU core (`bpf_map_lookup_percpu_elem` atau bounded loop).
* **Solusi**: Implementasikan agregasi lintas-core yang benar di dalam konteks timer, kemudian lakukan seleksi top-128 berbasis packet count sebelum memanggil inferensi ML.

### 1.3 Counter Window Tidak Pernah Direset (Akumulasi Tak Terbatas)
* **Masalah**: Tidak ada operasi penghapusan atau reset elemen (`bpf_map_delete_elem`) pada `ip_window_stats_map`.
* **Dampak**: Window 1 detik yang seharusnya mengukur statistik laju per detik berubah menjadi counter kumulatif tak terbatas sepanjang sistem berjalan, merusak seluruh asumsi statistik ML (packet rate, byte rate).
* **Solusi**: Bersihkan atau reset counter IP setelah inferensi window selesai.

### 1.4 Inkonsistensi Parameter HyperLogLog (HLL)
* **Masalah**: Kernel stub menggunakan $m = 16$ register, sedangkan implementasi offline di `config.py` dan `feature_extractor.py` menggunakan $m = 256$ register.
* **Masalah**: Rumus kalkulasi leading zeros dan harmonic mean di C mengandung bug matematis ($1 \ll (32 - \text{reg})$ alih-alih $2^{-\text{reg}}$) dan risiko division by zero.
* **Solusi**: Samakan $m = 256$ antara kernel C header (`hll.h`) dan pipeline Python, dengan lookup table aproksimasi floating point integer fixed-point.

### 1.5 Penamaan Fungsi Inferensi Model
* **Masalah**: Header C hasil ekspor `emlearn` menghasilkan nama fungsi unik sesuai variasi kandidat:
  * Decision Tree: `dt_bS1_d06_predict(features, 9)`
  * Random Forest: `rf_cS2_d8n3_predict(features, 9)`
  * Quantized MLP: `mlp_a_16_normalize(raw, norm)` dan `mlp_a_16_predict(norm)`
* **Dampak**: Pemanggilan nama fungsi generik (`dt_final_predict`) menyebabkan kegagalan kompilasi Clang.

### 1.6 Kontrol Konfigurasi `system_config`
* **Masalah**: Lookup pada BPF map bertipe `ARRAY` di kernel Linux **tidak pernah mengembalikan NULL** (kernel mengembalikan pointer ke memori teralokasi yang terisi nol). Ekspresi `cfg ? cfg->window_ns : DEFAULT` selalu membaca nilai 0.
* **Solusi**: Inisialisasi map konfigurasi dengan nilai default langsung saat deklarasi kernel atau dipastikan di-seed oleh userspace loader sebelum XDP di-attach ke interface.

---

## 2. Pembersihan Komponen Palsu / Stub

Seluruh komponen berikut telah dihapus dari repositori `Final/`:
1. `bpf/` : Program XDP ganda, timer rusak, dan kalkulasi HLL salah.
2. `daemon/` : Loader berbasis string `shell=True`, monitor dengan loop `sleep(1)` palsu, dan Prometheus exporter dengan angka statis dummy.
3. `experiments/` : Skrip benchmark latency, throughput, CPU, dan TTM yang memuat angka buatan statis (bukan alat ukur nyata).
4. `baselines/` & `traffic_gen/` : Template parsial yang belum tervalidasi di hardware.

---

## 3. Struktur Target untuk Tulis Ulang Data Plane & Control Plane

Sesuai evaluasi arsitektur bersih, implementasi kernel dan userspace ke depan akan mengikuti blueprint berikut:

```text
bpf/
  ddos.bpf.c              # SATU translation unit objek: parser, fast-path, slow-path, dan timer
  common.h                # Struktur data & enum (shared antara kernel dan userspace)
  maps.h                  # Definisi BPF maps tunggal yang konsisten
  features.h              # Definisi 9 indeks fitur yang 100% selaras dengan FEATURE_COLS
  hll.h                   # Estimator HyperLogLog integer m=256 yang identik dengan offline
  models/                 # Header model C terverifikasi (dt_final.h, rf_final.h, mlp_final.h)

daemon/
  ddosctl.py              # Loader & runtime controller menggunakan libbpf/bpftool API resmi
  alerts.py               # Konsumen BPF Ring Buffer berbasis epoll asli (non-blocking)
  metrics.py              # Exporter telemetri yang membaca langsung counter dari BPF map nyata

tests/
  test_header_parity.py   # Uji kesetaraan C (dikompilasi gcc) vs scikit-learn (SUDAH ADA)
  test_features_parity.py # Validasi vektor fitur kernel vs ekstraksi offline
  test_verifier.sh        # Script sertifikasi eBPF verifier (-O2 & -O3 bpftool)
```

---

## 4. Komponen yang 100% Tetap Dipertahankan (Integritas Penelitian)

Semua komponen ilmiah berikut **tetap utuh dan menjadi aset utama**:
1. **Model & Verifikasi**: `models/*.joblib`, `models/*_final.h`, `cv_summary.json`, `evaluation_report.json`, dan log sertifikasi `verifier_results_O2/O3.txt`.
2. **Dataset & Split**: `data/dataset_window_1s.csv` (187.132 window), `split_locked_temporal.npz` (34.995 locked test).
3. **Pipeline Core**: `pipeline/dataset.py`, `pipeline/sampling.py`, `pipeline/evaluation.py`, `pipeline/export_trees.py`.
4. **Tooling & Paritas**: `tools/test_header_parity.py` dan `tools/ebpf_verifier_batch.sh`.
5. **Gambar & Tabel Publikasi**: Seluruh gambar vektor 300 DPI (`plots/`) dan tabel metrik (`tables/`).
6. **Proposal & Panduan**: `docs/proposal/proposal.md` dan `docs/proposal/proposal_revision_notes.md`.
