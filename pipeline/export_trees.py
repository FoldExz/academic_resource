#!/usr/bin/env python3
"""
export_trees.py -- eksporter header C integer-exact untuk DT/RF scikit-learn.

KENAPA ADA: emlearn.convert() menulis threshold float sebagai integer dengan
pemotongan (76.5 -> 76) lalu memakai '<'. Untuk fitur integer, aturan sklearn
"x <= thr" ekuivalen persis dengan "x <= floor(thr)". Header lama memakai
"x < trunc(thr)" sehingga salah di batas (mis. unique_src_ip <= 1.5 menjadi
unique_src_ip < 1, dan semua SYN/UDP/DNS dengan unique_src_ip == 1 jatuh ke Normal).

TIDAK mengubah model: hanya membaca estimator dari joblib dan menulis ulang
struktur pohonnya apa adanya (fitur, threshold, kelas daun).

Semantik voting RF disamakan dengan header emlearn yang sudah ada: hard vote,
seri dimenangkan indeks kelas terkecil.
"""
import sys, math, argparse
from pathlib import Path
import numpy as np
import joblib

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    import pipeline  # noqa: F401  (shim unpickle joblib repo)
except Exception:
    pass


def emit_tree(tree, name, indent=2):
    t = tree.tree_
    lines = [f"static inline int32_t {name}(const int32_t *f) {{"]

    def rec(n, d):
        pad = " " * (indent * (d + 1))
        if t.children_left[n] == -1:
            cls = int(np.argmax(t.value[n][0]))
            lines.append(f"{pad}return {cls};")
            return
        feat = int(t.feature[n])
        thr = float(t.threshold[n])
        ithr = math.floor(thr)  # x <= thr  <=>  x <= floor(thr)  (x integer)
        lines.append(f"{pad}if (f[{feat}] <= {ithr}) {{")
        rec(int(t.children_left[n]), d + 1)
        lines.append(f"{pad}}} else {{")
        rec(int(t.children_right[n]), d + 1)
        lines.append(f"{pad}}}")

    rec(0, 0)
    lines.append("}")
    return "\n".join(lines)


def emit_header(pipe_path, step, prefix, n_classes, guard):
    p = joblib.load(pipe_path)
    est = p.named_steps[step]
    trees = list(est.estimators_) if hasattr(est, "estimators_") else [est]
    out = [f"/* Dihasilkan oleh tools/export_trees.py dari {Path(pipe_path).name} -- JANGAN disunting manual. */",
           f"#ifndef {guard}", f"#define {guard}", "#include <stdint.h>", ""]
    for i, tr in enumerate(trees):
        out.append(emit_tree(tr, f"{prefix}_tree_{i}"))
        out.append("")
    out.append(f"static inline int32_t {prefix}_predict(const int32_t *features, int32_t features_length) {{")
    out.append("    (void)features_length;")
    out.append(f"    int32_t votes[{n_classes}] = {{0}};")
    for i in range(len(trees)):
        out.append(f"    votes[{prefix}_tree_{i}(features)] += 1;")
    out.append("    int32_t best = 0, bv = votes[0];")
    out.append(f"    for (int32_t c = 1; c < {n_classes}; c++) {{ if (votes[c] > bv) {{ best = c; bv = votes[c]; }} }}")
    out.append("    return best;")
    out.append("}")
    out.append(f"#endif /* {guard} */")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--models-dir", default=str(ROOT / "models"))
    ap.add_argument("--out-dir", default=str(ROOT / "models"))
    a = ap.parse_args()
    md, od = Path(a.models_dir), Path(a.out_dir)
    od.mkdir(parents=True, exist_ok=True)
    (od / "dt_final.h").write_text(emit_header(md / "dt_model.joblib", "dt", "dt_bS1_d06", 6, "DT_FINAL_H"))
    (od / "rf_final.h").write_text(emit_header(md / "rf_model.joblib", "rf", "rf_cS2_d8n3", 6, "RF_FINAL_H"))
    print("OK ->", od)
