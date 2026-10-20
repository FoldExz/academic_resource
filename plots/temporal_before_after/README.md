# Ringkasan Komparasi Audit Temporal: BEFORE vs AFTER Trim

Dokumen ini mendokumentasikan perbandingan lengkap profil temporal seluruh sumber PCAP antara dataset sebelum trimming (`dataset_window_1s_backup_pretrim.csv`) dan sesudah trimming (`dataset_window_1s.csv`).

---

## 1. Tabel Komparasi Statistik Seluruh Sumber

| No | Sumber PCAP | Status | Total Windows (Bfr $\rightarrow$ Aft) | Train Windows (Bfr $\rightarrow$ Aft) | Test Windows (Bfr $\rightarrow$ Aft) | Test Mean PPS (Bfr $\rightarrow$ Aft) | Catatan Perubahan |
|---|---|:---:|:---:|:---:|:---:|:---:|---|
| 1 | **`syn_flood_03-11_Syn`** | **DI-TRIM** | 6.826 $\rightarrow$ **690** | 5.200 $\rightarrow$ **430** | 1.626 $\rightarrow$ **260** | 5.5 $\rightarrow$ **7.312,3** pps | **6.136 baris ekor idle dibuang.** Test set semula 100% idle kini murni serangan aktif. |
| 2 | **`udp_flood_03-11_UDP`** | **DI-TRIM** | 955 $\rightarrow$ **732** | 693 $\rightarrow$ **435** | 262 $\rightarrow$ **297** | 8.786,5 $\rightarrow$ **16.216,2** pps | **223 baris ekor idle dibuang.** Test set bersih dari ekor idle 18%. |
| 3 | **`udp_flood_01-12_UDP`** | Tetap | 1.532 $\rightarrow$ 1.532 | 1.294 $\rightarrow$ 1.338 | 238 $\rightarrow$ 194 | 5.715,9 $\rightarrow$ 1.192,2 pps | Idle berada di awal (t 0-1000) pada partisi Train; serangan utama ada di Test. |
| 4 | **`syn_flood_01-12_Syn`** | Tetap | 238 $\rightarrow$ 238 | 238 $\rightarrow$ 238 | 0 $\rightarrow$ 0 | N/A | Durasinya pendek, seluruh window masuk Train. |
| 5 | **`dns_amp`** | Tetap | 1.485 $\rightarrow$ 1.485 | 1.485 $\rightarrow$ 1.485 | 0 $\rightarrow$ 0 | N/A | Stabil, seluruhnya masuk Train. |
| 6 | **`icmp_flood`** | Tetap | 35.540 $\rightarrow$ 35.540 | 28.372 $\rightarrow$ 28.234 | 7.168 $\rightarrow$ 7.306 | 8.214,1 $\rightarrow$ 8.242,7 pps | Rasio seimbang sempurna (~8.200 pps). |
| 7 | **`arp_flood`** | Tetap | 36.120 $\rightarrow$ 36.120 | 35.048 $\rightarrow$ 35.048 | 1.072 $\rightarrow$ 1.072 | 100,0 $\rightarrow$ 100,0 pps | Sangat stabil dan periodik (100 pps konstan). |
| 8 | **`benign_cic_full_01-12`** | Tetap | 50.242 $\rightarrow$ 50.242 | 40.509 $\rightarrow$ 40.509 | 9.733 $\rightarrow$ 9.733 | 15,2 $\rightarrow$ 15,2 pps | Background normal stabil (~15 pps). |
| 9 | **`benign_cic_full_03-11`** | Tetap | 57.404 $\rightarrow$ 57.404 | 46.199 $\rightarrow$ 46.199 | 11.205 $\rightarrow$ 11.205 | 15,2 $\rightarrow$ 15,2 pps | Background normal stabil (~15 pps). |
| 10 | **`benign_extra`** | Tetap | 5.372 $\rightarrow$ 5.372 | 0 $\rightarrow$ 0 | 5.372 $\rightarrow$ 5.372 | 57,7 $\rightarrow$ 57,7 pps | Seluruhnya dialokasikan ke Test evaluasi independen. |

---

## 2. File Visualisasi yang Dihasilkan

Grafik perbandingan resolusi tinggi tersimpan di folder ini (`plots/temporal_before_after/`):

1. **Overview Lengkap Seluruh Sumber:**
   - [`overview_all_sources_before_vs_after.png`](./overview_all_sources_before_vs_after.png)
   - Menampilkan 2 kolom bersandingan (Kiri: Sebelum Trim vs Kanan: Sesudah Trim) untuk ke-10 sumber PCAP.
2. **Side-by-Side Zoom SYN Flood 03-11:**
   - [`compare_syn_flood_03-11.png`](./compare_syn_flood_03-11.png)
   - Memperlihatkan terbuangnya 6.136 detik idle dan naiknya Test Mean dari 5.5 pps ke 7.312 pps.
3. **Side-by-Side Zoom UDP Flood 03-11:**
   - [`compare_udp_flood_03-11.png`](./compare_udp_flood_03-11.png)
   - Memperlihatkan terbuangnya 223 detik idle tail dan naiknya Test Mean dari 8.786 pps ke 16.216 pps.
4. **Side-by-Side Profil UDP Flood 01-12:**
   - [`compare_udp_flood_01-12.png`](./compare_udp_flood_01-12.png)
   - Memperlihatkan profil t=0 s.d. 1000 (fase jeda stand-by) dan posisi split temporal.

