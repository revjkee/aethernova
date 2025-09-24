# SPDX-License-Identifier: MIT
"""
VeilMind Synthetic Tabular Data Generator
Industrial module for generating realistic synthetic tabular datasets.

Key features
- Declarative spec (Pydantic v2): columns, distributions, constraints, missingness
- Deterministic RNG with seed; per-column substreams for reproducibility
- Numeric correlations via Gaussian copula (Cholesky factorization)
- Conditional dependencies:
    * Linear numeric dependency with Gaussian noise
    * Conditional categorical probabilities on a parent categorical column
- Constraints: min/max, rounding, unique, casting, clipping
- Missingness per column
- Batch streaming to keep memory bounded
- Optional exports:
    * to_pandas() if pandas installed
    * to_csv(), to_parquet() if pandas/pyarrow installed
- Logging and invariants validation

Usage example
-------------
from veilmind.synthetic.tabular import (
    TableSpec, ColumnSpec, Dist, NumericLinearDependency, CategoricalConditional, TabularSynthesizer
)

spec = TableSpec(
    rows=100_000,
    columns=[
        ColumnSpec(
            name="age",
            dtype="int",
            distribution=Dist.normal(mu=40, sigma=12, clip_min=18, clip_max=90),
            rounding=0,
            unique=False,
            missing_rate=0.01
        ),
        ColumnSpec(
            name="income",
            dtype="float",
            distribution=Dist.lognormal(mu=10.5, sigma=0.6, clip_min=0),
            depends_on=NumericLinearDependency(parents=["age"], weights=[800.0], bias=-5000.0, noise_sigma=5000.0)
        ),
        ColumnSpec(
            name="segment",
            dtype="category",
            distribution=Dist.categorical({"A":0.5,"B":0.3,"C":0.2}),
            missing_rate=0.0
        ),
        ColumnSpec(
            name="offer",
            dtype="category",
            distribution=Dist.categorical({"none": 1.0}),
            conditional=CategoricalConditional(
                parent="segment",
                table={"A":{"gold":0.6,"silver":0.3,"none":0.1},
                       "B":{"silver":0.5,"none":0.5},
                       "C":{"none":1.0}}
            )
        ),
    ],
    correlations={
        # desired Pearson correlations among numeric base columns (existing or subset)
        # applies only to columns whose distribution supports ppf; others ignored
        ("age","income"): 0.35
    },
    primary_key=None
)
syn = TabularSynthesizer(spec, seed=42)
df = syn.generate(rows=10_000, return_df=True)  # pandas DataFrame if pandas installed
syn.to_csv("out.csv", rows=50_000, batch_size=10_000)

Notes
- Correlations are honored for numeric columns whose distributions implement ppf()
  (normal, uniform, lognormal, exponential). Others are sampled independently.
- Unique constraints on small discrete domains may exhaust attempts; the generator will
  suffix collisions with incremental counters to proceed.
- This module does not learn distributions from real data; it uses explicit specs.
"""

from __future__ import annotations

import math
import os
import logging
from typing import Any, Dict, List, Mapping, Optional, Tuple, Iterable, Union, Sequence
from dataclasses import dataclass

try:
    import numpy as np
except Exception as e:  # pragma: no cover
    raise RuntimeError("numpy is required for veilmind.synthetic.tabular") from e

try:
    import pandas as pd  # type: ignore
    _HAS_PANDAS = True
except Exception:  # pragma: no cover
    _HAS_PANDAS = False

_HAS_PYARROW = False
try:  # optional parquet export
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore
    _HAS_PYARROW = True
except Exception:  # pragma: no cover
    _HAS_PYARROW = False

from pydantic import BaseModel, Field, field_validator, model_validator, ValidationError

logger = logging.getLogger("veilmind.synthetic.tabular")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# ----------------------------- Distributions ----------------------------------

class Distribution(BaseModel):
    kind: str

    # Sampling interface
    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:  # abstract
        raise NotImplementedError

    # Probability integral transform inverse. If not implemented, returns None.
    def ppf(self, u: np.ndarray) -> Optional[np.ndarray]:
        return None

    # Optional clipping after draw
    clip_min: Optional[float] = None
    clip_max: Optional[float] = None

    def _apply_clip(self, arr: np.ndarray) -> np.ndarray:
        if self.clip_min is not None:
            arr = np.maximum(arr, self.clip_min)
        if self.clip_max is not None:
            arr = np.minimum(arr, self.clip_max)
        return arr


class Normal(Distribution):
    kind: str = "normal"
    mu: float = 0.0
    sigma: float = 1.0

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        x = rng.normal(self.mu, self.sigma, size=n)
        return self._apply_clip(x)

    def ppf(self, u: np.ndarray) -> Optional[np.ndarray]:
        # Inverse CDF for normal via scipy-free approximation using erfinv
        # erfinv(x) = inverse error function; numpy has special.erfinv via scipy not available.
        # Use rational approximation (Winitzki) for erfinv.
        x = 2.0 * u - 1.0
        # Winitzki approximation
        a = 0.147
        sgn = np.sign(x)
        ln = np.log(1.0 - x * x)
        erfinv = sgn * np.sqrt(
            np.sqrt((2/(math.pi*a) + ln/2)**2 - ln/a) - (2/(math.pi*a) + ln/2)
        )
        z = np.sqrt(2.0) * erfinv
        return self.mu + self.sigma * z


class Uniform(Distribution):
    kind: str = "uniform"
    low: float = 0.0
    high: float = 1.0

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        x = rng.uniform(self.low, self.high, size=n)
        return self._apply_clip(x)

    def ppf(self, u: np.ndarray) -> Optional[np.ndarray]:
        return self.low + (self.high - self.low) * u


class LogNormal(Distribution):
    kind: str = "lognormal"
    mu: float = 0.0
    sigma: float = 1.0

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        x = rng.lognormal(self.mu, self.sigma, size=n)
        return self._apply_clip(x)

    def ppf(self, u: np.ndarray) -> Optional[np.ndarray]:
        # exp(N(mu, sigma^2)). Use normal PPF then exp
        base = Normal(mu=self.mu, sigma=self.sigma)
        z = base.ppf(u)
        assert z is not None
        return np.exp(z)


class Exponential(Distribution):
    kind: str = "exponential"
    lam: float = 1.0  # rate

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        x = rng.exponential(1.0 / max(1e-12, self.lam), size=n)
        return self._apply_clip(x)

    def ppf(self, u: np.ndarray) -> Optional[np.ndarray]:
        return -np.log(1.0 - np.clip(u, 1e-12, 1 - 1e-12)) / max(1e-12, self.lam)


class Poisson(Distribution):
    kind: str = "poisson"
    lam: float = 1.0

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        x = rng.poisson(lam=max(1e-12, self.lam), size=n).astype(float)
        return self._apply_clip(x)


class Bernoulli(Distribution):
    kind: str = "bernoulli"
    p: float = 0.5

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        return (rng.random(size=n) < self.p).astype(float)


class Beta(Distribution):
    kind: str = "beta"
    a: float = 2.0
    b: float = 5.0

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        return rng.beta(self.a, self.b, size=n)

    # No ppf without scipy; will not be used for copula


class Categorical(Distribution):
    kind: str = "categorical"
    # mapping value -> prob (will be normalized)
    probs: Dict[str, float] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _norm(self) -> "Categorical":
        if not self.probs:
            raise ValueError("categorical distribution requires non-empty probs")
        s = sum(max(0.0, float(v)) for v in self.probs.values())
        if s <= 0:
            raise ValueError("categorical probabilities must sum to > 0")
        self.probs = {k: float(v) / s for k, v in self.probs.items()}
        return self

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        keys = list(self.probs.keys())
        p = np.array([self.probs[k] for k in keys], dtype=float)
        idx = rng.choice(len(keys), size=n, p=p)
        out = np.array([keys[i] for i in idx], dtype=object)
        return out


# Helper factory
class Dist:
    @staticmethod
    def normal(mu: float = 0.0, sigma: float = 1.0, clip_min: float | None = None, clip_max: float | None = None) -> Normal:
        return Normal(mu=mu, sigma=sigma, clip_min=clip_min, clip_max=clip_max)

    @staticmethod
    def uniform(low: float = 0.0, high: float = 1.0) -> Uniform:
        return Uniform(low=low, high=high)

    @staticmethod
    def lognormal(mu: float = 0.0, sigma: float = 1.0, clip_min: float | None = None, clip_max: float | None = None) -> LogNormal:
        return LogNormal(mu=mu, sigma=sigma, clip_min=clip_min, clip_max=clip_max)

    @staticmethod
    def exponential(lam: float = 1.0, clip_min: float | None = None, clip_max: float | None = None) -> Exponential:
        return Exponential(lam=lam, clip_min=clip_min, clip_max=clip_max)

    @staticmethod
    def poisson(lam: float = 1.0) -> Poisson:
        return Poisson(lam=lam)

    @staticmethod
    def bernoulli(p: float = 0.5) -> Bernoulli:
        return Bernoulli(p=p)

    @staticmethod
    def beta(a: float = 2.0, b: float = 5.0) -> Beta:
        return Beta(a=a, b=b)

    @staticmethod
    def categorical(probs: Mapping[str, float]) -> Categorical:
        return Categorical(probs=dict(probs))


# -------------------------- Dependencies and rules ----------------------------

class NumericLinearDependency(BaseModel):
    parents: List[str] = Field(default_factory=list)
    weights: List[float] = Field(default_factory=list)
    bias: float = 0.0
    noise_sigma: float = 0.0  # added Gaussian noise

    @model_validator(mode="after")
    def _check(self) -> "NumericLinearDependency":
        if len(self.parents) != len(self.weights):
            raise ValueError("parents and weights must have same length")
        return self


class CategoricalConditional(BaseModel):
    parent: str
    # mapping parent_value -> probs mapping of child values
    table: Dict[str, Dict[str, float]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _norm_rows(self) -> "CategoricalConditional":
        for k, row in self.table.items():
            s = sum(max(0.0, float(v)) for v in row.values())
            if s <= 0:
                raise ValueError(f"conditional row {k} has zero mass")
            self.table[k] = {kk: float(v)/s for kk, v in row.items()}
        return self


# ------------------------------- Column spec ----------------------------------

class ColumnSpec(BaseModel):
    name: str
    dtype: str  # "int" | "float" | "bool" | "str" | "datetime" | "category"
    distribution: Distribution
    rounding: Optional[int] = None  # digits for float; 0 means int-like rounding
    missing_rate: float = 0.0
    unique: bool = False
    min_value: Optional[float] = None
    max_value: Optional[float] = None

    # Dependencies
    depends_on: Optional[NumericLinearDependency] = None
    conditional: Optional[CategoricalConditional] = None

    @field_validator("dtype")
    @classmethod
    def _dtype_ok(cls, v: str) -> str:
        allowed = {"int", "float", "bool", "str", "datetime", "category"}
        if v not in allowed:
            raise ValueError(f"dtype must be one of {allowed}")
        return v

    @model_validator(mode="after")
    def _validate_conditional(self) -> "ColumnSpec":
        if self.conditional and self.dtype != "category":
            raise ValueError("conditional is only valid for dtype='category'")
        if self.missing_rate < 0 or self.missing_rate > 1:
            raise ValueError("missing_rate must be in [0,1]")
        return self


class TableSpec(BaseModel):
    rows: int
    columns: List[ColumnSpec]
    # Pairwise target correlations for numeric columns: map of (colA,colB) -> r
    correlations: Dict[Tuple[str, str], float] = Field(default_factory=dict)
    primary_key: Optional[str] = None

    @model_validator(mode="after")
    def _names_unique(self) -> "TableSpec":
        names = [c.name for c in self.columns]
        if len(names) != len(set(names)):
            raise ValueError("column names must be unique")
        if self.primary_key and self.primary_key not in names:
            raise ValueError("primary_key must refer to an existing column")
        for (a, b), r in self.correlations.items():
            if a == b:
                raise ValueError("self-correlation not allowed")
            if abs(r) >= 1:
                raise ValueError("correlation magnitude must be < 1")
            if a not in names or b not in names:
                raise ValueError(f"correlation refers to unknown columns: {(a,b)}")
        return self


# ------------------------------- Synthesizer ----------------------------------

@dataclass
class _ColRuntime:
    spec: ColumnSpec
    rng: np.random.Generator
    values: Optional[np.ndarray] = None
    unique_set: Optional[set] = None


class TabularSynthesizer:
    def __init__(self, spec: TableSpec, seed: Optional[int] = None) -> None:
        self.spec = spec
        base_seed = int(seed if seed is not None else 0)
        self.rng = np.random.default_rng(base_seed)
        # Per-column RNG streams to keep reproducibility stable if generation order changes
        self._col_rngs: Dict[str, np.random.Generator] = {
            c.name: np.random.default_rng(self.rng.integers(0, 2**63 - 1)) for c in self.spec.columns
        }
        # Determine numeric columns eligible for copula
        self._copula_cols = [
            c.name for c in self.spec.columns
            if c.dtype in {"int", "float"} and hasattr(c.distribution, "ppf") and callable(getattr(c.distribution, "ppf"))
        ]

    # -------------------------- Public API --------------------------

    def generate(self, rows: Optional[int] = None, return_df: bool = False):
        n = int(rows if rows is not None else self.spec.rows)
        cols = {c.name: None for c in self.spec.columns}

        # 1) Generate base numeric columns with optional correlations
        self._generate_numeric_with_copula(n, cols)

        # 2) Generate other columns independently
        for c in self.spec.columns:
            if cols[c.name] is not None:
                continue
            cols[c.name] = self._draw_independent(c, n)

        # 3) Apply conditional categorical dependencies
        for c in self.spec.columns:
            if c.conditional:
                cols[c.name] = self._apply_categorical_conditional(c, cols, n)

        # 4) Apply numeric linear dependencies
        for c in self.spec.columns:
            if c.depends_on:
                cols[c.name] = self._apply_numeric_linear_dep(c, cols, n)

        # 5) Post-process: rounding, type cast, clip, min/max, unique, missingness
        for c in self.spec.columns:
            cols[c.name] = self._postprocess_column(c, cols[c.name], n)

        if return_df:
            if not _HAS_PANDAS:
                raise RuntimeError("pandas is not installed; set return_df=False or install pandas")
            return pd.DataFrame(cols)
        return cols

    def stream_batches(self, rows: Optional[int] = None, batch_size: int = 50_000):
        total = int(rows if rows is not None else self.spec.rows)
        done = 0
        while done < total:
            take = min(batch_size, total - done)
            chunk = self.generate(rows=take, return_df=_HAS_PANDAS)
            done += take
            yield chunk

    # Exports
    def to_pandas(self, rows: Optional[int] = None):
        return self.generate(rows=rows, return_df=True)

    def to_csv(self, path: str, rows: Optional[int] = None, batch_size: int = 100_000) -> None:
        total = int(rows if rows is not None else self.spec.rows)
        if not _HAS_PANDAS:
            raise RuntimeError("pandas is required to export CSV")
        wrote_header = False
        with open(path, "w", encoding="utf-8", newline="") as f:
            for df in self.stream_batches(rows=total, batch_size=batch_size):
                assert _HAS_PANDAS
                df.to_csv(f, index=False, header=not wrote_header)
                wrote_header = True

    def to_parquet(self, path: str, rows: Optional[int] = None, batch_size: int = 100_000) -> None:
        if not _HAS_PYARROW:
            raise RuntimeError("pyarrow is required to export Parquet")
        total = int(rows if rows is not None else self.spec.rows)
        writer = None
        try:
            for df in self.stream_batches(rows=total, batch_size=batch_size):
                if _HAS_PANDAS:
                    table = pa.Table.from_pandas(df)
                else:
                    # convert dict of arrays to table
                    arrays = [pa.array(df[k]) for k in df.keys()]  # type: ignore
                    table = pa.Table.from_arrays(arrays, names=list(df.keys()))  # type: ignore
                if writer is None:
                    writer = pq.ParquetWriter(path, table.schema)
                writer.write_table(table)
        finally:
            if writer is not None:
                writer.close()

    # ------------------------ Core generation steps ------------------------

    def _generate_numeric_with_copula(self, n: int, cols: Dict[str, Optional[np.ndarray]]) -> None:
        # Select subset of numeric copula columns actually referenced by correlations
        corr_pairs = {(a, b): r for (a, b), r in self.spec.correlations.items()
                      if a in self._copula_cols and b in self._copula_cols}
        if not corr_pairs:
            # independent draw for numerics supporting ppf, but no joint correlation requested
            for c in self.spec.columns:
                if c.name in self._copula_cols:
                    cols[c.name] = self._draw_independent(c, n)
            return

        # Build correlation matrix
        names = sorted({name for pair in corr_pairs.keys() for name in pair})
        idx = {name: i for i, name in enumerate(names)}
        R = np.eye(len(names), dtype=float)
        for (a, b), r in corr_pairs.items():
            i, j = idx[a], idx[b]
            R[i, j] = R[j, i] = float(r)
        # Make R positive definite (nearby) via eigenvalue clipping if needed
        eigvals, eigvecs = np.linalg.eigh(R)
        eigvals = np.clip(eigvals, 1e-6, None)
        R = (eigvecs @ np.diag(eigvals) @ eigvecs.T).astype(float)

        # Cholesky factor
        L = np.linalg.cholesky(R)

        rng = self._col_rngs[names[0]]  # any seeded stream; we only need randomness source
        # Draw independent standard normals
        Z = rng.normal(size=(n, len(names)))
        # Impose correlation
        Zc = Z @ L.T  # correlated standard normals

        # Transform each to target marginal via PIT
        U = 0.5 * (1.0 + erf(Zc / np.sqrt(2.0)))
        for k, name in enumerate(names):
            colspec = self._get_col(name)
            ppf = colspec.distribution.ppf
            if not callable(ppf):
                # fallback independent sampling if ppf not available
                cols[name] = self._draw_independent(colspec, n)
                continue
            x = ppf(U[:, k])
            x = colspec.distribution._apply_clip(x)
            cols[name] = x

        # Fill remaining copula-eligible columns not in the correlation graph
        for c in self.spec.columns:
            if c.name in self._copula_cols and c.name not in names:
                cols[c.name] = self._draw_independent(c, n)

    def _draw_independent(self, c: ColumnSpec, n: int) -> np.ndarray:
        rng = self._col_rngs[c.name]
        arr = c.distribution.sample(rng, n)
        return arr

    def _apply_numeric_linear_dep(self, c: ColumnSpec, cols: Dict[str, np.ndarray], n: int) -> np.ndarray:
        dep = c.depends_on
        assert dep is not None
        X = np.zeros(n, dtype=float)
        for w, parent in zip(dep.weights, dep.parents):
            if parent not in cols or cols[parent] is None:
                raise ValueError(f"dependency parent {parent} not generated")
            X += float(w) * cols[parent].astype(float)
        rng = self._col_rngs[c.name]
        if dep.noise_sigma > 0:
            X += rng.normal(0.0, dep.noise_sigma, size=n)
        X += dep.bias
        return X

    def _apply_categorical_conditional(self, c: ColumnSpec, cols: Dict[str, np.ndarray], n: int) -> np.ndarray:
        cond = c.conditional
        assert cond is not None
        parent = cond.parent
        if parent not in cols or cols[parent] is None:
            raise ValueError(f"conditional parent {parent} not generated")
        parent_vals = cols[parent].astype(object)
        out = np.empty(n, dtype=object)
        rng = self._col_rngs[c.name]
        # default row if parent value missing in table -> back to base categorical
        base = c.distribution if isinstance(c.distribution, Categorical) else None
        base_keys = list(base.probs.keys()) if base else None
        base_p = np.array([base.probs[k] for k in base_keys], dtype=float) if base else None

        for i in range(n):
            pval = str(parent_vals[i])
            row = cond.table.get(pval)
            if row is None:
                if base is None:
                    raise ValueError(f"no conditional row for {pval} and no base categorical")
                idx = rng.choice(len(base_keys), p=base_p)
                out[i] = base_keys[idx]
                continue
            keys = list(row.keys())
            p = np.array([row[k] for k in keys], dtype=float)
            idx = rng.choice(len(keys), p=p)
            out[i] = keys[idx]
        return out

    def _postprocess_column(self, c: ColumnSpec, arr: np.ndarray, n: int) -> np.ndarray:
        out = arr.copy()

        # Apply min/max constraints
        if c.min_value is not None:
            out = np.where(out < c.min_value, c.min_value, out)
        if c.max_value is not None:
            out = np.where(out > c.max_value, c.max_value, out)

        # Rounding and dtype casting
        if c.dtype in {"int", "bool"} or (c.rounding is not None and c.rounding == 0):
            out = np.rint(out).astype(int)
            if c.dtype == "bool":
                out = out.astype(bool)
        elif c.rounding is not None and c.dtype == "float":
            out = np.round(out.astype(float), int(c.rounding))

        # Unique enforcement
        if c.unique:
            out = self._enforce_unique(c.name, out)

        # Missingness
        if c.missing_rate > 0.0:
            rng = self._col_rngs[c.name]
            mask = rng.random(size=n) < c.missing_rate
            out = out.astype(object)
            out[mask] = None

        # Category dtype normalization
        if c.dtype == "category":
            out = out.astype(object)
        return out

    def _enforce_unique(self, name: str, arr: np.ndarray) -> np.ndarray:
        seen = set()
        out = arr.astype(object)
        for i, v in enumerate(out):
            key = v
            if key not in seen:
                seen.add(key)
                continue
            # collision; append incremental suffix
            base = str(v)
            k = 1
            candidate = f"{base}-{k}"
            while candidate in seen:
                k += 1
                candidate = f"{base}-{k}"
            out[i] = candidate
            seen.add(candidate)
        return out

    def _get_col(self, name: str) -> ColumnSpec:
        for c in self.spec.columns:
            if c.name == name:
                return c
        raise KeyError(name)


# ------------------------------- Math helpers ---------------------------------

def erf(x: np.ndarray) -> np.ndarray:
    """
    Numerical approximation of error function using Abramowitz and Stegun formula 7.1.26.
    """
    # constants
    a1 = 0.254829592
    a2 = -0.284496736
    a3 = 1.421413741
    a4 = -1.453152027
    a5 = 1.061405429
    p = 0.3275911

    sign = np.sign(x)
    x = np.abs(x)
    t = 1.0 / (1.0 + p * x)
    y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * np.exp(-x * x)
    return sign * y


__all__ = [
    "Distribution",
    "Normal",
    "Uniform",
    "LogNormal",
    "Exponential",
    "Poisson",
    "Bernoulli",
    "Beta",
    "Categorical",
    "Dist",
    "NumericLinearDependency",
    "CategoricalConditional",
    "ColumnSpec",
    "TableSpec",
    "TabularSynthesizer",
]
