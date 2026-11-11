#!/usr/bin/env bash
# Pipeline starting from EXISTING Semgrep JSON files (Semgrep is not re-run):
#   tables (3 variants) -> construct extraction -> construct/CWE analysis.
#
# Usage, from the folder that contains the 4 Python scripts:
#     bash run_from_json.sh <snippets.csv> <folder_with_semgrep_jsons>
# Example:
#     bash run_from_json.sh snippets_ago26.csv ./semgrep_json
#
# Expected JSON names (as written by run_semgrep_js.py):
#     <js|ts>_<single|multi>_<csv_stem>_semgrep_results_batch_1.json
# Everything is written to a new folder results_<date>_<time>/ ; inputs are never modified.
set -euo pipefail

CSV="${1:?usage: bash run_from_json.sh <snippets.csv> <folder_with_semgrep_jsons>}"
JDIR="${2:?usage: bash run_from_json.sh <snippets.csv> <folder_with_semgrep_jsons>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CSV="$(cd "$(dirname "$CSV")" && pwd)/$(basename "$CSV")"
JDIR="$(cd "$JDIR" && pwd)"
STEM="$(basename "${CSV%.*}")"
OUT="$HERE/results_$(date +%Y%m%d_%H%M)"
PY="${PYTHON:-python3}"

fail() { echo; echo "STOP: $*" >&2; exit 1; }

echo "== 0. Checks"
[ -f "$CSV" ] || fail "CSV not found: $CSV"
for f in process_semgrep_results_js.py extract_js_features.py analyze_features_vs_semgrep.py; do
    [ -f "$HERE/$f" ] || fail "missing $f next to run_from_json.sh"
done
grep -q "merge-same-location" "$HERE/process_semgrep_results_js.py"  || fail "process_semgrep_results_js.py is an OLD version (no --merge-same-location)."
grep -q "await_in_fragment"   "$HERE/extract_js_features.py"         || fail "extract_js_features.py is an OLD version."
grep -q "jsx|ts|tsx"          "$HERE/analyze_features_vs_semgrep.py"  || fail "analyze_features_vs_semgrep.py is an OLD version."
$PY -c "import tree_sitter, tree_sitter_javascript, tree_sitter_typescript, pandas, scipy, statsmodels" 2>/dev/null \
    || fail "missing packages: $PY -m pip install tree-sitter tree-sitter-javascript tree-sitter-typescript pandas scipy statsmodels"

mkdir -p "$OUT"
cp "$HERE"/process_semgrep_results_js.py "$HERE"/extract_js_features.py "$HERE"/analyze_features_vs_semgrep.py "$OUT/"
cd "$OUT"
echo "   output folder: $OUT"
DONE=()

for LANG in javascript typescript; do
  for MODE in single multi; do
    SUF=$([ "$LANG" = javascript ] && echo js || echo ts)
    P="${SUF}_${MODE}_${STEM}"
    JSON="${P}_semgrep_results_batch_1.json"
    echo
    echo "================ $LANG $MODE ================"
    if [ ! -f "$JDIR/$JSON" ]; then
        echo "   (skipped: $JSON not found in $JDIR)"
        continue
    fi
    [ -f "$JDIR/${P}_semgrep_results_batch_2.json" ] && fail "$P has more than one batch: not supported by the table script"
    # The table script derives the file suffix from the FIRST character of the JSON name,
    # so it must receive a bare file name: link the JSON into the output folder.
    ln -sf "$JDIR/$JSON" "$JSON"

    $PY - "$JSON" "$SUF" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1])); s = d["paths"]["scanned"]
n_tsx = sum(p.endswith(".tsx") for p in s)
print(f"   scanned files: {len(s)} | of which .tsx: {n_tsx} | Semgrep errors: {len(d['errors'])} | raw findings: {len(d['results'])}")
if sys.argv[2] == "ts" and n_tsx == 0:
    sys.exit("STOP: this TypeScript JSON contains no .tsx file. It was produced by the OLD run_semgrep_js.py, "
             "which saves JSX snippets as .ts so Semgrep fails on them. Re-run Semgrep for TypeScript with the "
             "new run_semgrep_js.py (see README, section 'TypeScript JSONs').")
EOF

    echo "== 1. Tables (original / merged / merged without detect-object-injection)"
    $PY process_semgrep_results_js.py "$JSON" 1                         > "${P}_tables_original.txt" 2>&1
    $PY process_semgrep_results_js.py "$JSON" 1 --merge-same-location   > "${P}_tables_merged.txt" 2>&1
    $PY process_semgrep_results_js.py "$JSON" 1 --merge-same-location \
        --exclude-rule detect-object-injection                          > "${P}_tables_merged_noOI.txt" 2>&1
    for v in original merged merged_noOI; do
        printf "   %-12s " "$v"; grep -E "^(defective|issues):" "${P}_tables_${v}.txt" | tr '\n' ' '; echo
    done

    echo "== 2. Construct extraction"
    $PY extract_js_features.py "$CSV" "$LANG" "$MODE" > "${P}_features_log.txt" 2>&1 \
        || { tail -5 "${P}_features_log.txt"; fail "extraction failed"; }

    echo "== 3. Construct/CWE analysis"
    if [ "$SUF" = ts ]; then TH="--min-support 10 --min-target 5"; else TH=""; fi
    for UNIT in cwe rule; do
        $PY analyze_features_vs_semgrep.py --features "$P" --semgrep "$JSON" --include-modules $TH --unit $UNIT \
            > "${P}_analysis_${UNIT}_log.txt" 2>&1 || { tail -5 "${P}_analysis_${UNIT}_log.txt"; fail "analysis failed ($UNIT)"; }
    done
    head -1 "${P}_analysis_cwe_log.txt" | sed 's/^/   /'
    DONE+=("$P")
  done
done

[ ${#DONE[@]} -gt 0 ] || fail "no JSON found in $JDIR with the expected names (see README)"
echo
echo "== 4. Packaging"
cd "$HERE"
zip -qr "$(basename "$OUT").zip" "$(basename "$OUT")" -x "*.json" -x "*_features_long.csv"
echo "DONE for: ${DONE[*]}"
echo "Results: $(basename "$OUT")/   (zip without the large files: $(basename "$OUT").zip)"
