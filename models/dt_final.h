/* Dihasilkan oleh tools/export_trees.py dari dt_model.joblib -- JANGAN disunting manual. */
#ifndef DT_FINAL_H
#define DT_FINAL_H
#include <stdint.h>

static inline int32_t dt_bS1_d06_tree_0(const int32_t *f) {
  if (f[0] <= 76) {
    if (f[2] <= 53) {
      if (f[2] <= 44) {
        return 0;
      } else {
        if (f[8] <= 11) {
          return 0;
        } else {
          return 1;
        }
      }
    } else {
      return 1;
    }
  } else {
    if (f[2] <= 64) {
      if (f[5] <= 1350) {
        if (f[8] <= 1) {
          if (f[7] <= 229) {
            return 3;
          } else {
            if (f[7] <= 466) {
              return 4;
            } else {
              return 5;
            }
          }
        } else {
          return 0;
        }
      } else {
        return 2;
      }
    } else {
      return 1;
    }
  }
}

static inline int32_t dt_bS1_d06_predict(const int32_t *features, int32_t features_length) {
    (void)features_length;
    int32_t votes[6] = {0};
    votes[dt_bS1_d06_tree_0(features)] += 1;
    int32_t best = 0, bv = votes[0];
    for (int32_t c = 1; c < 6; c++) { if (votes[c] > bv) { best = c; bv = votes[c]; } }
    return best;
}
#endif /* DT_FINAL_H */
