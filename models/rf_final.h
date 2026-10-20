/* Dihasilkan oleh tools/export_trees.py dari rf_model.joblib -- JANGAN disunting manual. */
#ifndef RF_FINAL_H
#define RF_FINAL_H
#include <stdint.h>

static inline int32_t rf_cS2_d8n3_tree_0(const int32_t *f) {
  if (f[2] <= 57) {
    if (f[0] <= 1033) {
      if (f[8] <= 18) {
        return 0;
      } else {
        if (f[7] <= 61) {
          if (f[8] <= 19) {
            return 1;
          } else {
            return 0;
          }
        } else {
          return 0;
        }
      }
    } else {
      if (f[8] <= 15) {
        if (f[7] <= 466) {
          if (f[4] <= 541) {
            if (f[3] <= 2581) {
              return 0;
            } else {
              return 3;
            }
          } else {
            return 4;
          }
        } else {
          if (f[8] <= 3) {
            return 5;
          } else {
            return 0;
          }
        }
      } else {
        if (f[7] <= 101) {
          return 2;
        } else {
          return 0;
        }
      }
    }
  } else {
    return 1;
  }
}

static inline int32_t rf_cS2_d8n3_tree_1(const int32_t *f) {
  if (f[2] <= 58) {
    if (f[3] <= 2611) {
      if (f[4] <= 259) {
        if (f[5] <= 1362) {
          if (f[7] <= 479) {
            if (f[8] <= 18) {
              return 0;
            } else {
              if (f[7] <= 61) {
                if (f[1] <= 1530) {
                  return 0;
                } else {
                  return 1;
                }
              } else {
                return 0;
              }
            }
          } else {
            if (f[6] <= 645) {
              return 0;
            } else {
              return 5;
            }
          }
        } else {
          return 2;
        }
      } else {
        if (f[6] <= 13) {
          if (f[6] <= 4) {
            return 4;
          } else {
            if (f[7] <= 924) {
              return 4;
            } else {
              return 5;
            }
          }
        } else {
          if (f[4] <= 22523) {
            if (f[4] <= 10628) {
              if (f[7] <= 542) {
                return 4;
              } else {
                return 5;
              }
            } else {
              return 5;
            }
          } else {
            return 4;
          }
        }
      }
    } else {
      return 3;
    }
  } else {
    return 1;
  }
}

static inline int32_t rf_cS2_d8n3_tree_2(const int32_t *f) {
  if (f[2] <= 57) {
    if (f[1] <= 831664) {
      if (f[5] <= 1380) {
        if (f[6] <= 688) {
          if (f[3] <= 2604) {
            if (f[0] <= 1026) {
              return 0;
            } else {
              if (f[7] <= 330) {
                return 0;
              } else {
                return 4;
              }
            }
          } else {
            return 3;
          }
        } else {
          return 5;
        }
      } else {
        return 2;
      }
    } else {
      if (f[3] <= 8117) {
        if (f[6] <= 13) {
          if (f[4] <= 1022) {
            return 0;
          } else {
            if (f[3] <= 1) {
              return 4;
            } else {
              if (f[7] <= 927) {
                return 4;
              } else {
                return 5;
              }
            }
          }
        } else {
          if (f[7] <= 442) {
            return 4;
          } else {
            return 5;
          }
        }
      } else {
        return 3;
      }
    }
  } else {
    return 1;
  }
}

static inline int32_t rf_cS2_d8n3_predict(const int32_t *features, int32_t features_length) {
    (void)features_length;
    int32_t votes[6] = {0};
    votes[rf_cS2_d8n3_tree_0(features)] += 1;
    votes[rf_cS2_d8n3_tree_1(features)] += 1;
    votes[rf_cS2_d8n3_tree_2(features)] += 1;
    int32_t best = 0, bv = votes[0];
    for (int32_t c = 1; c < 6; c++) { if (votes[c] > bv) { best = c; bv = votes[c]; } }
    return best;
}
#endif /* RF_FINAL_H */
