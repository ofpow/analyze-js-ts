"""
Join the constructs extracted by extract_js_features.py with the Semgrep results and
answer three questions:

  1. ERROR BIAS   - are the snippets Semgrep could not analyze (excluded from the
                    defect rates) richer in modern / specific constructs?
  2. ASSOCIATION  - at snippet level, which constructs are associated with which CWE
                    (or Semgrep rule)? Fisher exact test + BH correction, and an odds
                    ratio adjusted for snippet length (logistic regression).
  3. CO-LOCATION  - when a snippet has both the construct and the CWE, is the construct
                    actually on the lines flagged by Semgrep, more often than chance?

Usage:
    python analyze_features_vs_semgrep.py \
        --features js_single_snippets_ago26 \
        --semgrep js_single_snippets_ago26_semgrep_results_batch_*.json \
        [--unit cwe|rule] [--min-support 20] [--min-target 10] [--outdir results]

--features is the prefix used by extract_js_features.py (it reads <prefix>_snippets.csv
and <prefix>_features_long.csv). --semgrep accepts ALL batch files (the batch loop of
process_semgrep_results_js.py always re-reads the same file; this script does not).

Definitions mirror process_semgrep_results_js.py: a snippet with any Semgrep error is
excluded; findings without a CWE are ignored; findings are deduplicated on
(snippet, CWEs, severity, matched lines). Use --keep-partial-parsing to also analyze
snippets whose only errors are partial-parsing ones (sensitivity analysis).
"""

import argparse
import glob
import json
import math
import os
import re
import sys
import warnings
from collections import defaultdict, Counter

import numpy as np
import pandas as pd
from scipy.stats import fisher_exact

try:
    import statsmodels.api as sm
    HAVE_SM = True
except ImportError:
    HAVE_SM = False

ES_ORDER = ["none", "ES2015", "ES2016", "ES2017", "ES2018", "ES2019", "ES2020",
            "ES2021", "ES2022", "ES2023", "ES2024", "ES2025"]
ID_RE = re.compile(r"_(\d+)\.(js|jsx|ts|tsx)$")
CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Semgrep loading
# ---------------------------------------------------------------------------
def snippet_id(path):
    m = ID_RE.search(path or "")
    return int(m.group(1)) if m else None


def error_type(err):
    t = err.get("type")
    if isinstance(t, list):
        t = t[0] if t else "unknown"
    return str(t or "unknown")


def load_semgrep(files, keep_partial):
    scanned, errored, err_types = set(), set(), defaultdict(set)
    raw_results = []
    for fn in files:
        with open(fn, encoding="utf-8") as f:
            data = json.load(f)
        unmatched = []
        for p in data["paths"]["scanned"]:
            sid = snippet_id(p)
            if sid is not None:
                scanned.add(sid)
            else:
                unmatched.append(p)
        if unmatched:
            sys.exit(f"{fn}: {len(unmatched)} scanned files do not match the expected "
                     f"'<prefix>_<n>.js|jsx|ts|tsx' naming (e.g. {unmatched[0]}). "
                     f"They would be silently dropped: check the file names.")
        for e in data.get("errors", []):
            sid = snippet_id(e.get("path"))
            if sid is None:  # rule/config errors, not tied to a snippet
                continue
            err_types[sid].add(error_type(e))
        raw_results.extend(data.get("results", []))

    for sid, types in err_types.items():
        if keep_partial and all("partial" in t.lower() for t in types):
            continue
        errored.add(sid)

    findings, seen = [], set()
    for r in raw_results:
        sid = snippet_id(r.get("path"))
        if sid is None or sid in errored:
            continue
        extra = r.get("extra", {})
        cwes = extra.get("metadata", {}).get("cwe")
        if not cwes:
            continue
        if isinstance(cwes, str):
            cwes = [cwes]
        cwe_ids = sorted({f"CWE-{m}" for c in cwes for m in CWE_RE.findall(c)})
        if not cwe_ids:
            continue
        key = (sid, tuple(cwe_ids), extra.get("severity", ""), extra.get("lines", "").strip())
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "snippet_id": sid,
            "check_id": r.get("check_id", ""),
            "rule": r.get("check_id", "").split(".")[-1],
            "cwes": cwe_ids,
            "severity": extra.get("severity", ""),
            "start": r["start"]["line"],
            "end": r["end"]["line"],
        })
    return scanned, errored, err_types, findings


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------
def bh(pvals):
    p = np.asarray(pvals, dtype=float)
    n = len(p)
    if n == 0:
        return p
    order = np.argsort(p)
    ranked = p[order] * n / (np.arange(n) + 1)
    q = np.minimum.accumulate(ranked[::-1])[::-1]
    out = np.empty(n)
    out[order] = np.minimum(q, 1.0)
    return out


def odds_ratio(a, b, c, d):
    """Haldane-Anscombe corrected OR for [[a, b], [c, d]]."""
    return ((a + .5) * (d + .5)) / ((b + .5) * (c + .5))


def two_by_two(x, y):
    a = int(((x == 1) & (y == 1)).sum())
    b = int(((x == 1) & (y == 0)).sum())
    c = int(((x == 0) & (y == 1)).sum())
    d = int(((x == 0) & (y == 0)).sum())
    return a, b, c, d


def adjusted_or(y, x, log_loc):
    """OR of feature x on outcome y, adjusted for log(LOC). Returns (OR, p) or (nan, nan)."""
    if not HAVE_SM:
        return math.nan, math.nan
    X = sm.add_constant(np.column_stack([x, log_loc]).astype(float))
    try:
        with warnings.catch_warnings():
            # separation / non-convergence -> unreliable estimate -> NaN
            warnings.simplefilter("error")
            res = sm.Logit(y.astype(float), X).fit(disp=0, maxiter=200)
        return float(np.exp(res.params[1])), float(res.pvalues[1])
    except Exception:
        return math.nan, math.nan


def parse_spans(s):
    if not isinstance(s, str) or not s:
        return []
    out = []
    for part in s.split(";"):
        a, b = part.split("-")
        out.append((int(a), int(b)))
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features", required=True, help="prefix used by extract_js_features.py")
    ap.add_argument("--semgrep", required=True, nargs="+", help="Semgrep JSON file(s); globs accepted")
    ap.add_argument("--unit", choices=["cwe", "rule"], default="cwe")
    ap.add_argument("--min-support", type=int, default=20, help="min snippets with the feature")
    ap.add_argument("--min-target", type=int, default=10, help="min snippets with the CWE/rule")
    ap.add_argument("--include-modules", action="store_true", help="also test imported modules as features")
    ap.add_argument("--keep-partial-parsing", action="store_true")
    ap.add_argument("--outdir", default="feature_analysis")
    args = ap.parse_args()

    files = sorted({f for pat in args.semgrep for f in glob.glob(pat)})
    if not files:
        sys.exit("No Semgrep JSON file found")
    os.makedirs(args.outdir, exist_ok=True)
    tag = os.path.basename(args.features) + f"_{args.unit}"

    snippets = pd.read_csv(f"{args.features}_snippets.csv")
    long = pd.read_csv(f"{args.features}_features_long.csv")
    scanned, errored, err_types, findings = load_semgrep(files, args.keep_partial_parsing)

    # ---------------- sanity check on the numbering ----------------
    missing = scanned - set(snippets.snippet_id)
    if missing:
        sys.exit(f"{len(missing)} scanned snippet ids are not in the features file: "
                 f"check that both scripts ran on the same CSV / language / mode")
    snippets = snippets[snippets.snippet_id.isin(scanned)].copy()
    snippets = snippets.copy()  # defragment
    snippets["semgrep_error"] = snippets.snippet_id.isin(errored).astype(int)
    snippets["error_types"] = snippets.snippet_id.map(lambda s: ";".join(sorted(err_types.get(s, []))))
    catalog_feats = [c for c in snippets.columns if c not in {
        "snippet_id", "loc", "lines_total", "bytes", "ts_parse_error", "ts_error_ratio", "max_es_version",
        "es_era", "content_kind",
        "n_distinct_features", "n_modern_features_es2017plus", "n_legacy_features", "n_modules", "modules",
        "semgrep_error", "error_types"}]

    feature_cols = list(catalog_feats)
    if args.include_modules:
        mods = long[long.category == "module"]
        top = mods.feature.value_counts()
        top = top[top >= args.min_support].index
        new_cols = {}
        for m in top:
            ids = set(mods.loc[mods.feature == m, "snippet_id"])
            new_cols[m] = snippets.snippet_id.isin(ids).astype(int)
            feature_cols.append(m)
        snippets = pd.concat([snippets, pd.DataFrame(new_cols, index=snippets.index)], axis=1)

    meta = long.drop_duplicates("feature").set_index("feature")[["es_version", "category"]]

    n_scanned = len(snippets)
    print(f"Semgrep files: {len(files)} | scanned: {n_scanned} | errors: {len(errored)} "
          f"| findings (CWE, dedup): {len(findings)}")

    # =====================================================================
    # 1. ERROR BIAS
    # =====================================================================
    rows = []
    err = snippets.semgrep_error
    for f in feature_cols:
        x = snippets[f]
        if x.sum() < args.min_support:
            continue
        a, b, c, d = two_by_two(x, err)
        _, p = fisher_exact([[a, b], [c, d]])
        rows.append({
            "feature": f, "es_version": meta.es_version.get(f, "api"), "category": meta.category.get(f, "module"),
            "n_with_feature": a + b,
            "error_rate_with": a / (a + b) if a + b else math.nan,
            "error_rate_without": c / (c + d) if c + d else math.nan,
            "odds_ratio": odds_ratio(a, b, c, d), "p": p,
        })
    eb = pd.DataFrame(rows)
    if not eb.empty:
        eb["q_bh"] = bh(eb.p)
        eb = eb.sort_values(["q_bh", "odds_ratio"], ascending=[True, False])
    eb.to_csv(os.path.join(args.outdir, f"{tag}_1_error_bias.csv"), index=False)

    # error type counts
    et = Counter(t for s in errored for t in err_types.get(s, []))
    pd.DataFrame(et.most_common(), columns=["semgrep_error_type", "n_snippets"]).to_csv(
        os.path.join(args.outdir, f"{tag}_1_error_types.csv"), index=False)

    # =====================================================================
    # 2. SUMMARY BY ES VERSION + targets
    # =====================================================================
    fdf = pd.DataFrame(findings)
    if fdf.empty:
        sys.exit("No CWE findings in the analyzed snippets")
    if args.unit == "cwe":
        fdf = fdf.explode("cwes").rename(columns={"cwes": "target"})
    else:
        fdf["target"] = fdf["rule"]

    analyzed = snippets[snippets.semgrep_error == 0].copy()
    issues_per_snippet = pd.DataFrame(findings).groupby("snippet_id").size() if findings else pd.Series(dtype=int)
    analyzed["n_issues"] = analyzed.snippet_id.map(issues_per_snippet).fillna(0).astype(int)
    analyzed["defective"] = (analyzed.n_issues > 0).astype(int)

    summ = []
    for v in ES_ORDER:
        sub_all = snippets[snippets.max_es_version == v]
        sub = analyzed[analyzed.max_es_version == v]
        if len(sub_all) == 0:
            continue
        summ.append({
            "max_es_version": v, "n_scanned": len(sub_all),
            "semgrep_error_rate": sub_all.semgrep_error.mean(),
            "n_analyzed": len(sub), "defect_rate": sub.defective.mean() if len(sub) else math.nan,
            "issues_per_kloc": sub.n_issues.sum() / max(sub["loc"].sum(), 1) * 1000 if len(sub) else math.nan,
            "median_loc": sub_all["loc"].median(),
        })
    pd.DataFrame(summ).to_csv(os.path.join(args.outdir, f"{tag}_2_by_es_version.csv"), index=False)

    def group_summary(col):
        out = []
        for k, sub_all in snippets.groupby(col):
            sub = analyzed[analyzed[col] == k]
            out.append({col: k, "n_scanned": len(sub_all),
                        "semgrep_error_rate": sub_all.semgrep_error.mean(),
                        "n_analyzed": len(sub),
                        "defect_rate": sub.defective.mean() if len(sub) else math.nan,
                        "issues_per_kloc": sub.n_issues.sum() / max(sub["loc"].sum(), 1) * 1000 if len(sub) else math.nan,
                        "median_loc": sub_all["loc"].median()})
        return pd.DataFrame(out)
    era = group_summary("es_era") if "es_era" in snippets else pd.DataFrame()
    kind = group_summary("content_kind") if "content_kind" in snippets else pd.DataFrame()
    era.to_csv(os.path.join(args.outdir, f"{tag}_2_by_era.csv"), index=False)
    kind.to_csv(os.path.join(args.outdir, f"{tag}_2_by_content_kind.csv"), index=False)

    target_sets = fdf.groupby("target").snippet_id.apply(set)
    target_sets = target_sets[target_sets.map(len) >= args.min_target]

    # =====================================================================
    # 3. ASSOCIATION feature x target (snippet level, analyzed snippets only)
    # =====================================================================
    log_loc = np.log1p(analyzed["loc"].to_numpy())
    rows = []
    for tgt, ids in target_sets.items():
        y = analyzed.snippet_id.isin(ids).astype(int)
        for f in feature_cols:
            x = analyzed[f]
            if x.sum() < args.min_support or x.sum() == len(x):
                continue
            a, b, c, d = two_by_two(x, y)
            if a == 0 and c == 0:
                continue
            _, p = fisher_exact([[a, b], [c, d]])
            rows.append({
                "target": tgt, "feature": f,
                "es_version": meta.es_version.get(f, "api"), "category": meta.category.get(f, "module"),
                "n_feature": a + b, "n_target": a + c, "n_both": a,
                "p_target_given_feature": a / (a + b), "p_target_given_no_feature": c / (c + d) if c + d else math.nan,
                "odds_ratio": odds_ratio(a, b, c, d), "p": p,
            })
    assoc = pd.DataFrame(rows)
    if not assoc.empty:
        assoc["q_bh"] = bh(assoc.p)
        # length-adjusted OR only where it matters (significant raw associations)
        adj_or, adj_p = [], []
        y_cache = {}
        for _, r in assoc.iterrows():
            if r.q_bh < 0.05 and r.n_both >= 5:
                y = y_cache.setdefault(r.target, analyzed.snippet_id.isin(target_sets[r.target]).astype(int).to_numpy())
                o, pv = adjusted_or(y, analyzed[r.feature].to_numpy(), log_loc)
            else:
                o, pv = math.nan, math.nan
            adj_or.append(o)
            adj_p.append(pv)
        assoc["odds_ratio_adj_loc"] = adj_or
        assoc["p_adj_loc"] = adj_p
        assoc = assoc.sort_values(["q_bh", "odds_ratio"], ascending=[True, False])
    assoc.to_csv(os.path.join(args.outdir, f"{tag}_3_association.csv"), index=False)

    # =====================================================================
    # 4. CO-LOCATION: is the construct on the flagged lines?
    # =====================================================================
    spans = defaultdict(dict)  # snippet -> feature -> [(s, e)]
    for r in long[long.spans.notna()].itertuples():
        spans[r.snippet_id][r.feature] = parse_spans(r.spans)
    lines_total = snippets.set_index("snippet_id").lines_total.to_dict()

    acc = defaultdict(lambda: [0, 0, 0, 0.0])  # n_findings, n_overlap, n_start_in, expected_start_in
    for fr in fdf[fdf.target.isin(target_sets.index)].itertuples():
        feats = spans.get(fr.snippet_id, {})
        L = max(lines_total.get(fr.snippet_id, 1), 1)
        span_len = fr.end - fr.start + 1
        for f, sp in feats.items():
            if f not in catalog_feats:
                continue
            k = acc[(fr.target, f)]
            k[0] += 1
            k[1] += any(s <= fr.end and e >= fr.start for s, e in sp)
            k[2] += any(fr.start <= s <= fr.end for s, _ in sp)
            # chance that at least one of the construct's start lines falls in the span
            # if start lines were placed uniformly in the snippet
            pr = min(span_len / L, 1.0)
            k[3] += 1 - (1 - pr) ** len(sp)
    rows = []
    for (tgt, f), (n, ov, st, exp) in acc.items():
        if n < 5:
            continue
        rows.append({
            "target": tgt, "feature": f, "es_version": meta.es_version.get(f, ""),
            "n_findings_in_snippets_with_feature": n,
            "overlap_rate": ov / n,  # feature span overlaps flagged lines (includes enclosing constructs)
            "start_on_flagged_lines_rate": st / n,
            "expected_start_rate_by_chance": exp / n,
            "colocation_lift": (st / n) / (exp / n) if exp > 0 else math.nan,
        })
    coloc = pd.DataFrame(rows)
    if not coloc.empty:
        coloc = coloc.sort_values(["target", "colocation_lift"], ascending=[True, False])
    coloc.to_csv(os.path.join(args.outdir, f"{tag}_4_colocation.csv"), index=False)

    # =====================================================================
    # Console summary
    # =====================================================================
    pd.set_option("display.width", 200)
    pd.set_option("display.max_colwidth", 40)
    print("\n[1] Error bias - features over-represented in snippets Semgrep could not analyze (q<0.05):")
    if not eb.empty:
        s = eb[(eb.q_bh < 0.05) & (eb.odds_ratio > 1)].head(15)
        print(s[["feature", "es_version", "n_with_feature", "error_rate_with", "error_rate_without", "odds_ratio", "q_bh"]]
              .to_string(index=False, float_format=lambda v: f"{v:.3g}") if len(s) else "  none")
    print("\n[2] By highest ES version used:")
    print(pd.DataFrame(summ).to_string(index=False, float_format=lambda v: f"{v:.3g}"))
    if not era.empty:
        print("\n[2b] By era:")
        print(era.to_string(index=False, float_format=lambda v: f"{v:.3g}"))
    if not kind.empty:
        print("\n[2c] By content kind (non-'code' snippets are likely not JS):")
        print(kind.to_string(index=False, float_format=lambda v: f"{v:.3g}"))
    print(f"\n[3] Strongest positive associations feature -> {args.unit} (q<0.05, OR>1):")
    if not assoc.empty:
        s = assoc[(assoc.q_bh < 0.05) & (assoc.odds_ratio > 1)].sort_values("odds_ratio", ascending=False).head(25)
        print(s[["target", "feature", "es_version", "n_both", "odds_ratio", "odds_ratio_adj_loc", "q_bh"]]
              .to_string(index=False, float_format=lambda v: f"{v:.3g}") if len(s) else "  none")
    print(f"\nAll tables written to {args.outdir}/")
    if not HAVE_SM:
        print("statsmodels not installed: length-adjusted odds ratios were skipped (pip install statsmodels)")


if __name__ == "__main__":
    main()
