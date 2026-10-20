// Auto-generated MLP Q14/Q30 fixed-point header — mlp_a_16
// FIX-9: port langsung dari mlp_quantize.py asli (skema Zhang dkk.).
// StandardScaler diintegerkan penuh -- tidak ada operasi floating-point
// (Subbab 2.2.5b: eBPF verifier melarang floating-point).
//
// Usage:
//   int32_t norm[MLP_A_16_N_FEATURES];
//   mlp_a_16_normalize(raw, norm);
//   int32_t cls = mlp_a_16_predict(norm);
//
#ifndef MLP_A_16_H
#define MLP_A_16_H

#include <stdint.h>

#define MLP_A_16_QW_SHIFT   14   /* bobot / aktivasi  */
#define MLP_A_16_QS_SHIFT   30   /* koefisien scaler  */
#define MLP_A_16_ROUND_QS   ((int64_t)1 << (MLP_A_16_QS_SHIFT - 1))

#define MLP_A_16_N_FEATURES 9
#define MLP_A_16_N_OUTPUTS  6

/* coeff_q[i] = round(SW / scale[i] * SC) */
static const int64_t mlp_a_16_coeff_q[9] = {
    4358306664, 11152810, 446387779361, 11756816168, 8267553898, 5427820231, 578460519078, 81023408763, 2473628539531
};

/* mean_offset_qw[i] = round(mean[i] * SW / scale[i]) */
static const int32_t mlp_a_16_mean_offset_qw[9] = {
    7446, 2453, 8092, 999, 1476, 7693, 795, 9624, 24913
};

static const int32_t mlp_a_16_W0[144] = {
    3649, 431, 4668, -6849, -5955, 4926, -6556, 5578, 295, -13961, 3310, -22805, -6591, -4857, 7043, -30050, -3571, 5941, 216, 5997, -5721, 120, 13091, 8200, 11075, 10855, 11773, -14771, 2155, 5276, -5211, -26763, -22498, -46, -15046, -5264, 2601, -7976, 13226, 1951, 18819, -12013, -3307, 8377, 3998, -8507, -3646, 8919, -17572, 5759, 7459, 2057, 3419, -809, 3063, 7978, -3303, 2329, 9327, -16520, 3881, -18527, 3866, 379, -24566, 1765, -10143, -20568, -2896, 675, 6241, -4482, -2526, -8698, 16196, -21061, -5820, 5550, 7840, -13929, 6748, -1882, 13423, 12243, 15396, -9649, -3557, 10049, -5588, -12957, -5518, -20642, 2009, -20055, -8325, -19474, -2307, 14127, -9578, 4878, -1149, -2773, 5579, -8090, 4999, 5371, -10366, -129, -437, 2934, -6200, 1936, -4942, -2956, -13966, 18135, -2761, 1193, 10022, -6389, -669, 772, 1690, -274, 2246, -3768, 6700, -2534, 8244, 273, 4380, 11310, 9529, -8585, 2104, 4677, 6511, -203, -10801, 11881, -2787, -17544, -3916, 3716
};
static const int32_t mlp_a_16_b0[16] = {
    22782, 908, 15574, -2208, -8074, -1087, 5225, 9808, -2093, 9482, 1893, 9108, -8911, 24840, 7943, 12849
};

static const int32_t mlp_a_16_W1[96] = {
    4759, -24652, 22077, -8213, -19418, -11926, -11990, -5785, -12061, 3820, -3290, 7669, -8370, -8583, 7438, 289, -12986, -8042, 14098, -18298, 7679, -3268, -14338, -22799, 1852, 4190, 8698, -3704, 4534, -2657, -4039, -13286, -12351, -3949, -2594, -3994, -13946, 12511, -7798, -6236, 1040, 12278, -9122, 228, 10746, 7510, -11072, -6756, -23451, 4572, 620, -12416, -11464, 1934, 13262, -11655, -9294, 783, -9855, 6356, -9766, -6345, -6336, 7869, 7367, 3442, 7787, 16150, -24007, -11994, -7690, -23695, 2298, 4255, 1215, -2895, -87, -857, 11202, -11280, -13819, -14368, 9904, -3488, 3521, -164, -8770, -1348, 7797, -8464, 5114, 6137, -14685, -14570, -22641, 609
};
static const int32_t mlp_a_16_b1[6] = {
    11364, -4579, -1664, -7731, -521, -13837
};

/* Terapkan StandardScaler dalam integer arithmetic (tanpa float). */
static inline void mlp_a_16_normalize(const int32_t *raw, int32_t *out) {
    for (int i = 0; i < MLP_A_16_N_FEATURES; i++) {
        out[i] = (int32_t)(((int64_t)raw[i] * mlp_a_16_coeff_q[i] + MLP_A_16_ROUND_QS)
                  >> MLP_A_16_QS_SHIFT) - mlp_a_16_mean_offset_qw[i];
    }
}

/* MLP forward pass. features[] harus output dari mlp_a_16_normalize(). */
static inline int32_t mlp_a_16_predict(const int32_t *features) {
    int64_t act_in[16];
    int64_t act_out[16];
    int64_t acc;

    /* Layer 0: 9 -> 16 */
    for (int i = 0; i < 16; i++) {
        acc = (int64_t)mlp_a_16_b0[i];
        for (int j = 0; j < 9; j++)
            acc += ((int64_t)features[j] * (int64_t)mlp_a_16_W0[j * 16 + i]) >> MLP_A_16_QW_SHIFT;
        act_out[i] = (acc > 0) ? acc : 0;  /* ReLU */
    }
    for (int i = 0; i < 16; i++) act_in[i] = act_out[i];

    /* Layer 1: 16 -> 6 */
    for (int i = 0; i < 6; i++) {
        acc = (int64_t)mlp_a_16_b1[i];
        for (int j = 0; j < 16; j++)
            acc += ((int64_t)act_in[j] * (int64_t)mlp_a_16_W1[j * 6 + i]) >> MLP_A_16_QW_SHIFT;
        act_out[i] = acc;  /* logit */
    }

    /* argmax */
    int64_t max_val = act_out[0];
    int32_t max_idx = 0;
    for (int i = 1; i < MLP_A_16_N_OUTPUTS; i++) {
        if (act_out[i] > max_val) { max_val = act_out[i]; max_idx = i; }
    }
    return max_idx;
}

#endif /* MLP_A_16_H */