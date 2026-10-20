"""rs_sampling.py -- undersampling / SMOTE building blocks for the 1-second window features.

Both samplers are imblearn samplers: inside an imblearn Pipeline they run in `fit` only,
so predict/score on a validation or test fold is never resampled.

WindowSMOTE differs from the plain SMOTE example in two deliberate ways:
  1. It interpolates the ADDITIVE counters (protocol counts, 'other', bytes, unique sources)
     and then RE-DERIVES packet_rate and avg_packet_size, so derived features stay
     consistent (avg_packet_size == byte_rate / packet_rate exactly, packet_rate == the
     sum of its parts).  A convex combination of such counters is again a valid counter set.
  2. Only values that are genuinely integer counts are rounded (protocol counts, 'other',
     unique_src_ip).  byte_rate and avg_packet_size are continuous and are NOT rounded.
Neighbour search runs in a standardised log1p space (the counters span 1 .. 1e8, raw
Euclidean distance would be decided by byte_rate alone); interpolation itself is linear in
the raw counter space, so the segment between two real windows is a real segment.
"""
from __future__ import annotations

import warnings
from numbers import Integral
from dataclasses import dataclass
from typing import Dict, Mapping, Sequence

import numpy as np
import pandas as pd
from imblearn.over_sampling.base import BaseOverSampler
from sklearn.neighbors import NearestNeighbors
from sklearn.utils import check_random_state
from sklearn.utils._param_validation import Interval

COUNT_FEATURES = ("arp_count", "syn_count", "udp_count", "icmp_count", "dns_count")
SUPPORTED_FEATURES = frozenset(COUNT_FEATURES) | {
    "packet_rate", "byte_rate", "avg_packet_size", "unique_src_ip"}


# ---------------------------------------------------------------- strategies (picklable)
class KeepFraction:
    """Undersampling strategy: keep round(n_c * fraction) rows of each listed class."""

    def __init__(self, fractions: Mapping[int, float]):
        for c, f in fractions.items():
            if not 0 < f <= 1:
                raise ValueError(f"keep fraction for class {c} must be in (0, 1], got {f}")
        self.fractions = {int(c): float(f) for c, f in fractions.items()}

    def __call__(self, y) -> Dict[int, int]:
        classes, counts = np.unique(y, return_counts=True)
        n = dict(zip(classes.tolist(), counts.tolist()))
        return {c: max(1, int(round(n[c] * f))) for c, f in self.fractions.items() if c in n}

    def __repr__(self):
        return f"KeepFraction({self.fractions})"


class GrowMultiplier:
    """Over-sampling strategy: grow each listed class to round(n_c * multiplier) rows.

    multiplier 2 == Chawla et al. 'SMOTE 100%' (one synthetic row per original row).
    """

    def __init__(self, multipliers: Mapping[int, float]):
        for c, m in multipliers.items():
            if m < 1:
                raise ValueError(f"multiplier for class {c} must be >= 1, got {m}")
        self.multipliers = {int(c): float(m) for c, m in multipliers.items()}

    def __call__(self, y) -> Dict[int, int]:
        classes, counts = np.unique(y, return_counts=True)
        n = dict(zip(classes.tolist(), counts.tolist()))
        return {c: int(round(n[c] * m)) for c, m in self.multipliers.items()
                if c in n and int(round(n[c] * m)) > n[c]}

    def __repr__(self):
        return f"GrowMultiplier({self.multipliers})"


def smote_percent(multiplier: float) -> int:
    """Chawla et al. (2002) 'N%' for a total-size multiplier: x2 -> 100, x4 -> 300."""
    return int(round((multiplier - 1) * 100))


# ---------------------------------------------------------------------------- scenarios
@dataclass(frozen=True)
class Scenario:
    name: str
    keep: Mapping[int, float]   # class -> fraction RETAINED by random undersampling
    grow: Mapping[int, float]   # class -> total-size multiplier by SMOTE (2 == SMOTE 100%)


# 0 Normal, 1 ARP, 2 ICMP | 3 SYN, 4 UDP, 5 DNS-Amp.  "down 25%" == keep 75%.
# ASSUMPTION: the S3 row in the proposal table lists only two multipliers; all three
# minority classes are x4 here.  Edit this dict if the intended S3 differs.
SCENARIOS: Dict[str, Scenario] = {
    "S1": Scenario("S1", keep={0: .75, 1: .75, 2: .75}, grow={3: 2, 4: 2, 5: 2}),
    "S2": Scenario("S2", keep={0: .50, 1: .50, 2: .50}, grow={3: 2, 4: 4, 5: 4}),
    "S3": Scenario("S3", keep={0: .25, 1: .25, 2: .25}, grow={3: 4, 4: 4, 5: 4}),
}


def scenario_size_table(y: Sequence[int]) -> pd.DataFrame:
    """Class sizes (and imbalance ratio) after each scenario, from a label vector."""
    classes, counts = np.unique(np.asarray(y), return_counts=True)
    base = dict(zip(classes.tolist(), counts.tolist()))
    rows = {"original": dict(base)}
    for name, sc in SCENARIOS.items():
        after = dict(base)
        for c, n in KeepFraction(sc.keep)(np.asarray(y)).items():
            after[c] = n
        for c, n in GrowMultiplier(sc.grow)(np.repeat(classes, [after[c] for c in classes])).items():
            after[c] = n
        rows[name] = after
    t = pd.DataFrame(rows).T[sorted(base)]
    t["imbalance_ratio"] = (t.max(axis=1) / t.min(axis=1)).round(1)
    t["max_synthetic_share_%"] = [
        0.0 if k == "original" else round(100 * max(
            1 - base[c] / t.loc[k, c] for c in SCENARIOS[k].grow if c in base), 1)
        for k in t.index]
    return t


# ----------------------------------------------------------------------------- SMOTE
class _Layout:
    """Maps feature columns <-> the additive counter basis."""

    def __init__(self, names: Sequence[str]):
        names = list(names)
        unknown = set(names) - SUPPORTED_FEATURES
        missing = ({"packet_rate", "byte_rate"} | set(COUNT_FEATURES)) - set(names)
        if unknown or missing:
            raise ValueError(f"WindowSMOTE cannot handle features: unknown={sorted(unknown)} "
                             f"missing={sorted(missing)}")
        self.names = names
        self.ix = {n: i for i, n in enumerate(names)}
        self.has_uniq = "unique_src_ip" in self.ix
        self.has_avg = "avg_packet_size" in self.ix

    def to_basis(self, X: np.ndarray) -> np.ndarray:
        counts = X[:, [self.ix[c] for c in COUNT_FEATURES]]
        other = X[:, self.ix["packet_rate"]] - counts.sum(axis=1)
        if np.any(other < -1e-9):
            raise ValueError("packet_rate is smaller than the sum of protocol counts; "
                             "WindowSMOTE needs packet_rate >= arp+syn+udp+icmp+dns")
        cols = [counts, np.maximum(other, 0)[:, None], X[:, [self.ix["byte_rate"]]]]
        if self.has_uniq:
            cols.append(X[:, [self.ix["unique_src_ip"]]])
        return np.hstack(cols)

    def from_basis(self, B: np.ndarray) -> np.ndarray:
        counts = np.clip(np.rint(B[:, :5]), 0, None)          # integer counters
        other = np.clip(np.rint(B[:, 5]), 0, None)
        packets = counts.sum(axis=1) + other
        zero = packets == 0                                     # degenerate; keep >= 1 packet
        other[zero] = 1
        packets[zero] = 1
        byte_rate = np.clip(B[:, 6], 0, None)                   # continuous: NOT rounded
        out = np.zeros((len(B), len(self.names)))
        out[:, self.ix["packet_rate"]] = packets
        out[:, self.ix["byte_rate"]] = byte_rate
        for j, c in enumerate(COUNT_FEATURES):
            out[:, self.ix[c]] = counts[:, j]
        if self.has_avg:
            out[:, self.ix["avg_packet_size"]] = byte_rate / packets   # derived, NOT rounded
        if self.has_uniq:
            out[:, self.ix["unique_src_ip"]] = np.maximum(np.rint(B[:, 7]), 1)
        return out


def _balanced_base_indices(n_c: int, n_new: int, rng) -> np.ndarray:
    """Chawla's N%: every original row seeds floor(n_new/n_c) samples; the remainder is random."""
    full, rest = divmod(n_new, n_c)
    parts = [np.tile(np.arange(n_c), full)]
    if rest:
        parts.append(rng.choice(n_c, size=rest, replace=False))
    return np.concatenate(parts)


class WindowSMOTE(BaseOverSampler):
    """SMOTE for 1-second window features (see module docstring).  Use inside imblearn Pipeline."""

    _parameter_constraints: dict = {
        **BaseOverSampler._parameter_constraints,
        "feature_names": [list, tuple, None],
        "k_neighbors": [Interval(Integral, 1, None, closed="left")],
    }

    def __init__(self, *, sampling_strategy="auto", feature_names=None, k_neighbors=5,
                 random_state=None):
        super().__init__(sampling_strategy=sampling_strategy)
        self.feature_names = feature_names
        self.k_neighbors = k_neighbors
        self.random_state = random_state

    def _fit_resample(self, X, y):
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y)
        if self.feature_names is None or len(self.feature_names) != X.shape[1]:
            raise ValueError("feature_names must list every column of X, in order")
        layout = _Layout(self.feature_names)
        rng = check_random_state(self.random_state)

        B = layout.to_basis(X)
        Z = np.log1p(B)
        sd = Z.std(axis=0)
        sd[sd == 0] = 1.0
        Z = (Z - Z.mean(axis=0)) / sd                           # metric space for neighbours only

        X_parts, y_parts = [X], [y]
        for cls, n_new in self.sampling_strategy_.items():
            if n_new <= 0:
                continue
            idx = np.flatnonzero(y == cls)
            n_c = len(idx)
            base = _balanced_base_indices(n_c, n_new, rng)
            Bc = B[idx]
            if n_c < 2:
                warnings.warn(f"class {cls} has {n_c} sample(s): SMOTE falls back to replication")
                B_new = Bc[base]
            else:
                k = min(int(self.k_neighbors), n_c - 1)
                nn = NearestNeighbors(n_neighbors=k + 1).fit(Z[idx])
                nbr = nn.kneighbors(Z[idx], return_distance=False)[:, 1:]
                pick = nbr[base, rng.randint(0, k, size=len(base))]
                lam = rng.uniform(size=(len(base), 1))
                B_new = Bc[base] + lam * (Bc[pick] - Bc[base])
            X_parts.append(layout.from_basis(B_new))
            y_parts.append(np.full(len(base), cls, dtype=y.dtype))
        return np.vstack(X_parts), np.concatenate(y_parts)


from sklearn.base import BaseEstimator, ClassifierMixin, clone
from sklearn.utils.class_weight import compute_sample_weight


class BalancedWeightFit(ClassifierMixin, BaseEstimator):
    """Compute 'balanced' sample weights INSIDE fit, from the y that fit actually receives."""

    _DELEGATED = frozenset({"coefs_", "intercepts_", "n_iter_", "n_layers_", "n_outputs_",
                            "loss_", "best_loss_", "activation", "hidden_layer_sizes",
                            "n_features_in_", "out_activation_"})

    def __init__(self, estimator=None, balanced=True):
        self.estimator = estimator
        self.balanced = balanced

    def fit(self, X, y):
        self.est_ = clone(self.estimator)
        if self.balanced:
            self.fit_sample_weight_ = compute_sample_weight("balanced", y)
            self.est_.fit(X, y, sample_weight=self.fit_sample_weight_)
        else:
            self.fit_sample_weight_ = None
            self.est_.fit(X, y)
        self.classes_ = self.est_.classes_
        return self

    def predict(self, X):
        import numpy as _np
        with _np.errstate(under="ignore", over="ignore"):
            return self.est_.predict(X)

    def predict_proba(self, X):
        return self.est_.predict_proba(X)

    def __getattr__(self, name):
        if name in BalancedWeightFit._DELEGATED and "est_" in self.__dict__:
            return getattr(self.__dict__["est_"], name)
        raise AttributeError(name)

