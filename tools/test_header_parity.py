#!/usr/bin/env python3
"""Parity header C (dikompilasi gcc) vs sklearn pada SELURUH dataset 1 s.
Input C = pemotongan ke int32 (semantik kernel). Input sklearn = float asli."""
import sys, subprocess, textwrap, argparse
from pathlib import Path
import numpy as np, pandas as pd, joblib
ap = argparse.ArgumentParser()
ap.add_argument("--repo", required=True); ap.add_argument("--dt-header", required=True)
ap.add_argument("--rf-header", required=True); ap.add_argument("--mlp-header", required=True)
ap.add_argument("--tag", default="header")
a = ap.parse_args(); repo = Path(a.repo); sys.path.insert(0, str(repo))
import pipeline  # noqa
from config import FEATURE_COLS
from sklearn.metrics import recall_score
df = pd.read_csv(repo / "data/dataset_window_1s.csv")
z = np.load(repo / "data/split_locked_temporal.npz", allow_pickle=True)
X = df[FEATURE_COLS].values.astype(np.float32); y = df["label"].values
Xi = np.trunc(X).astype(np.int64)
tmp = Path("/tmp/par2"); tmp.mkdir(exist_ok=True)
np.savetxt(tmp / "X.txt", Xi, fmt="%d")
(tmp / "h.c").write_text(textwrap.dedent(f'''
#include <stdio.h>
#include <stdint.h>
#include "{a.dt_header}"
#include "{a.rf_header}"
#include "{a.mlp_header}"
int main(){{ int32_t f[9], n[9];
 while(1){{ for(int i=0;i<9;i++){{ long long v; if(scanf("%lld",&v)!=1) return 0; f[i]=(int32_t)v; }}
  mlp_a_16_normalize(f,n);
  printf("%d %d %d\\n", dt_bS1_d06_predict(f,9), rf_cS2_d8n3_predict(f,9), mlp_a_16_predict(n)); }} }}'''))
r = subprocess.run(f"gcc -O1 -w -o {tmp}/h {tmp}/h.c", shell=True, capture_output=True, text=True)
assert r.returncode == 0, r.stderr
out = subprocess.run(f"{tmp}/h < {tmp}/X.txt", shell=True, capture_output=True, text=True).stdout.split("\n")
P = np.array([list(map(int, l.split())) for l in out if l.strip()])
te = np.zeros(len(df), bool); te[z["test_idx"]] = True
print(f"== {a.tag}: N={len(df)}  test={te.sum()}")
for j, n in enumerate(["dt", "rf", "mlp"]):
    pf = joblib.load(repo / f"models/{n}_model.joblib").predict(X)
    for nm, m in (("semua", np.ones(len(df), bool)), ("test", te)):
        mm = int((P[m, j] != pf[m]).sum())
        print(f"{n:3s} {nm:5s} mismatch C-vs-sklearn: {mm:6d} ({100*mm/m.sum():.4f}%)  macro-recall C={recall_score(y[m],P[m,j],average='macro'):.5f} sklearn={recall_score(y[m],pf[m],average='macro'):.5f}")
