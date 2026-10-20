/*
 * xdp_model_stub.c — Minimal XDP program untuk eBPF verifier testing.
 *
 * Tujuan: memvalidasi bahwa model header (.h dari emlearn / kuantisasi int32)
 * dapat dikompilasi dan LOLOS eBPF verifier tanpa perlu sistem NIPS penuh.
 * Program HANYA di-load (bpftool prog load), tidak pernah di-attach ke NIC.
 *
 * Compile manual (contoh satu model, ganti -O2 dengan -O3 untuk level lain),
 * flag sama dengan ebpf_verifier_batch.sh:
 *   clang -O2 -fno-builtin-memset -target bpf \
 *         -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
 *         -DMODEL_H='"dt_final.h"' -DMODEL_TYPE_DT=1 \
 *         -DMODEL_PREDICT_FN=dt_final_predict \
 *         -c xdp_model_stub.c -o dt_final.o
 *   sudo bpftool -d prog load dt_final.o /sys/fs/bpf/dt_final 2>&1 | grep processed
 *
 * N_FEATURES = 9 (FEATURE_COLS di config.py; tcp_other_count TIDAK dipakai model):
 *   [0] packet_rate   [1] byte_rate   [2] arp_count   [3] syn_count
 *   [4] udp_count     [5] icmp_count  [6] dns_count
 *   [7] avg_packet_size               [8] unique_src_ip
 * Bisa di-override: -DN_FEATURES=<n>.
 *
 * Fitur dibaca dari byte awal paket lewat pointer volatile (nilai tidak diketahui
 * compiler/verifier, jadi semua cabang model ikut ditelusuri). Ini bukan parsing
 * header asli, hanya untuk verifier check.
 */

#include <linux/types.h>   /* __u32/__u64 — harus ada SEBELUM bpf_helpers.h */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

/* MODEL_H didefinisikan via -DMODEL_H='"filename.h"' saat compile */
#ifndef MODEL_H
#error "Tentukan -DMODEL_H='\"nama_header.h\"' saat kompilasi"
#endif
#include MODEL_H

/* Jumlah fitur (harus == len(FEATURE_COLS) di pipeline = 9) */
#ifndef N_FEATURES
#define N_FEATURES 9
#endif

/* Minimal bytes paket: N_FEATURES x 4 byte */
#define MIN_PKT_BYTES (N_FEATURES * (int)sizeof(int32_t))

/* ─────────────────────────────────────────────────────────────────────────── */
/* DT / RF : emlearn menghasilkan fungsi {name}_predict(features, n_features)  */
/* ─────────────────────────────────────────────────────────────────────────── */
#if defined(MODEL_TYPE_DT) || defined(MODEL_TYPE_RF)

#ifndef MODEL_PREDICT_FN
#error "Tambahkan -DMODEL_PREDICT_FN=nama_fungsi_predict (contoh: dt_final_predict)"
#endif

SEC("xdp")
int xdp_ddos_detect(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Bounds check wajib sebelum akses memori (verifier requirement) */
    if (data + MIN_PKT_BYTES > data_end)
        return XDP_PASS;

    /* Baca dummy fitur dari payload awal paket */
    volatile __u32 *raw = data;
    int32_t features[N_FEATURES];
    for (int i = 0; i < N_FEATURES; i++)
        features[i] = (int32_t)raw[i];

    /* Panggil fungsi prediksi model — verifier trace semua branch di sini */
    int32_t label = MODEL_PREDICT_FN(features, N_FEATURES);

    /* 0 = Normal → PASS; 1-5 = Attack → DROP */
    return (label == 0) ? XDP_PASS : XDP_DROP;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* MLP : header kita menghasilkan {name}_normalize() + {name}_predict()        */
/* ─────────────────────────────────────────────────────────────────────────── */
#elif defined(MODEL_TYPE_MLP)

/* MODEL_NORMALIZE_FN opsional: bila header tidak punya *_normalize(), raw dipakai langsung. */
#ifndef MODEL_PREDICT_FN
#error "Tambahkan -DMODEL_PREDICT_FN=nama_fungsi_predict (contoh: mlp_8_8_predict)"
#endif

SEC("xdp")
int xdp_ddos_detect(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + MIN_PKT_BYTES > data_end)
        return XDP_PASS;

    volatile __u32 *raw_pkt = data;
    int32_t raw[N_FEATURES];
    for (int i = 0; i < N_FEATURES; i++)
        raw[i] = (int32_t)raw_pkt[i];

#ifdef MODEL_NORMALIZE_FN
    /* Langkah 1: StandardScaler dalam integer arithmetic */
    int32_t norm[N_FEATURES];
    MODEL_NORMALIZE_FN(raw, norm);

    /* Langkah 2: MLP forward pass Q14 */
    int32_t label = MODEL_PREDICT_FN(norm);
#else
    int32_t label = MODEL_PREDICT_FN(raw);
#endif

    return (label == 0) ? XDP_PASS : XDP_DROP;
}

#else
#error "Tentukan salah satu: -DMODEL_TYPE_DT=1, -DMODEL_TYPE_RF=1, atau -DMODEL_TYPE_MLP=1"
#endif

char _license[] SEC("license") = "GPL";
