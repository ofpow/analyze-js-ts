# Semgrep JS/TS analysis — from Semgrep JSON to tables and construct/CWE analysis

This package takes the Semgrep results you already have (one JSON per configuration) and produces:

1. **The result tables** (scanned / clean / defective / errors / issues, severity, top-10 CWEs), in three variants:
   - `original`: same counting as the tables we used so far;
   - `merged`: findings reported by several rules on the **same lines** of a snippet are counted once;
   - `merged_noOI`: as `merged`, without the `detect-object-injection` rule (sensitivity analysis).
2. **Construct extraction**: about 110 language features per snippet (ES2015–ES2025 constructs, legacy idioms, TypeScript constructs, JSX, security sinks/sources, imported modules), with the lines where each occurs.
3. **Construct/CWE analysis**: which constructs are associated with which CWEs and Semgrep rules, and whether they actually sit on the lines Semgrep flags.

Semgrep is **not** re-run. The only exception is TypeScript JSONs produced by the old script (see [TypeScript JSONs](#typescript-jsons)).

---

## 1. What you need

Put these files in **one clean folder**:

| File | Role |
|---|---|
| `run_from_json.sh` | runs the whole pipeline starting from your JSONs |
| `process_semgrep_results_js.py` | builds the tables (now with `--merge-same-location` and `--exclude-rule`) |
| `extract_js_features.py` | extracts the language constructs from the snippets |
| `analyze_features_vs_semgrep.py` | joins constructs and Semgrep findings, runs the statistics |
| `run_semgrep_js.py` | only needed if you have to re-run Semgrep for TypeScript |
| `snippets_ago26.csv` | the dataset the JSONs were produced from |

Your Semgrep JSONs can stay in their own folder, for example `semgrep_json/`.

> **Check the file names.** Browsers rename repeated downloads (`process_semgrep_results_js (1).py`). Remove the suffix, otherwise the folder may still contain an old version under the right name. The script checks this and stops with `STOP: ... is an OLD version` if needed.

### JSON names

The JSONs must have the names written by `run_semgrep_js.py`:

```
js_single_snippets_ago26_semgrep_results_batch_1.json
js_multi_snippets_ago26_semgrep_results_batch_1.json
ts_single_snippets_ago26_semgrep_results_batch_1.json
ts_multi_snippets_ago26_semgrep_results_batch_1.json
```

They must come from **the same CSV** you pass to the script: snippets are identified by their position in the filtered CSV, so a JSON from a different CSV cannot be matched. Missing configurations are skipped.

---

## 2. Setup (once)

On macOS with Homebrew Python, packages cannot be installed globally; use a virtual environment inside the folder:

```bash
cd path/to/the/folder
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install tree-sitter tree-sitter-javascript tree-sitter-typescript pandas scipy statsmodels
```

(Add `semgrep` to the list only if you need to re-run Semgrep for TypeScript.)

In every new terminal, activate the environment again before running anything:

```bash
cd path/to/the/folder
source .venv/bin/activate
```

---

## 3. Run

```bash
PYTHON=python bash run_from_json.sh snippets_ago26.csv ./semgrep_json
```

The second argument is the folder containing the JSONs. The script:

- checks the script versions, the installed packages and the JSON names;
- for each configuration (JS/TS × single/multi):
  1. builds the three table variants;
  2. extracts the constructs;
  3. runs the analysis by CWE and by Semgrep rule;
- writes everything to a new folder `results_<date>_<time>/` (your inputs are never modified);
- creates `results_<date>_<time>.zip` with all results except the large files (JSONs and per-line feature lists).

It stops with a `STOP:` message explaining what to fix if anything is wrong. It takes a few minutes; there is no Semgrep step.

---

## 4. Outputs

All in `results_<date>_<time>/`, one set per configuration (`<P>` = e.g. `js_single_snippets_ago26`).

### Tables

| File | Content |
|---|---|
| `<P>_tables_original.txt` | tables as computed so far |
| `<P>_tables_merged.txt` | same-location findings counted once |
| `<P>_tables_merged_noOI.txt` | as above, without `detect-object-injection` |

Each file prints scanned / clean / defective / errors / issues, the top-10 CWEs, and the issues by severity (ERROR / WARNING / INFO).

Notes for reading them:
- In `merged`, a finding can carry **several CWEs** (e.g. `Math.random()` is tagged both CWE-327 and CWE-338 by two rulesets). Both CWEs are still listed in the top-10, so the CWE column does not sum to `issues`. Severity counts, instead, sum to `issues`.
- `defective` and `errors` are percentages of `scanned`. For comparisons, also compute `defective / (scanned − errors)`, i.e. on analyzable snippets only.

### Construct extraction

| File | Content |
|---|---|
| `<P>_snippets.csv` | one row per snippet: LOC, highest ES version used (`max_es_version`), era (`es_era`), content type (`content_kind`), one 0/1 column per construct |
| `<P>_feature_catalog.csv` | list of constructs with ES version, description and number of snippets containing it |

### Analysis (`feature_analysis/`)

Each table exists for `cwe` (by CWE) and `rule` (by Semgrep rule, i.e. `check_id`; preferable for interpretation).

| File | Question it answers |
|---|---|
| `<P>_<unit>_1_error_bias.csv` | Are snippets excluded for Semgrep errors richer in some constructs? |
| `<P>_<unit>_1_error_types.csv` | Which Semgrep error types caused the exclusions |
| `<P>_<unit>_2_by_era.csv` | Error rate, defect rate, issues/KLOC and median LOC by ECMAScript era |
| `<P>_<unit>_2_by_es_version.csv` | Same, by highest ES version used |
| `<P>_<unit>_2_by_content_kind.csv` | Same, by content type (snippets that are HTML/JSON/shell rather than JS) |
| `<P>_<unit>_3_association.csv` | Are snippets with construct X more often affected by CWE/rule Y? |
| `<P>_<unit>_4_colocation.csv` | When X and Y co-occur, is X on the lines flagged by Semgrep? |

**How to read table 3.** `odds_ratio` > 1 means positive association; `q_bh` is the p-value corrected for multiple testing (keep rows with `q_bh` < 0.05); `odds_ratio_adj_loc` is the odds ratio adjusted for snippet length. If it is much lower than `odds_ratio`, the association was mostly due to longer snippets containing more of everything.

**How to read table 4.** `start_on_flagged_lines_rate` is how often the construct starts on the flagged lines; `colocation_lift` compares it with what chance would give. Well above 1 means the construct takes part in the finding; around 0 means it is merely in the same snippet, so a table-3 association is likely due to the domain (e.g. "it is an Express app").

Table 3 and table 4 should be read together: an association counts only if the construct is also on the finding lines.

---

## TypeScript JSONs

The old `run_semgrep_js.py` wrote every TypeScript snippet to a `.ts` file. Snippets containing JSX (React components) must be `.tsx`, otherwise Semgrep's parser fails and they are **excluded as errors**: in our data this was 78% of the TypeScript errors (error rate 36% → 9% in single, 48% → 27% in multi after the fix).

`run_from_json.sh` checks this. If a TypeScript JSON contains no `.tsx` file, it stops with:

```
STOP: this TypeScript JSON contains no .tsx file. It was produced by the OLD run_semgrep_js.py ...
```

In that case, re-run Semgrep **for TypeScript only** with the new `run_semgrep_js.py` (it requires `semgrep` in the virtual environment and an internet connection for the rule registry; it can take a long time):

```bash
python -m pip install semgrep
semgrep --version > semgrep_version.txt                # record the version for the paper
python run_semgrep_js.py snippets_ago26.csv typescript single
python run_semgrep_js.py snippets_ago26.csv typescript multi
```

Then move the two new `ts_*_semgrep_results_batch_1.json` files into your JSON folder, replacing the old ones, and run `run_from_json.sh` again. JavaScript JSONs do not need to be re-run.

---

## Running the steps by hand (optional)

`run_from_json.sh` only chains these commands. Run them **from the folder that contains the JSON** (the table script reads the file extension from the first character of the JSON name, so it must receive a bare file name, not a path).

```bash
P=js_single_snippets_ago26
J=${P}_semgrep_results_batch_1.json

# tables
python process_semgrep_results_js.py $J 1
python process_semgrep_results_js.py $J 1 --merge-same-location
python process_semgrep_results_js.py $J 1 --merge-same-location --exclude-rule detect-object-injection

# constructs (same language/mode as the JSON)
python extract_js_features.py snippets_ago26.csv javascript single

# analysis
python analyze_features_vs_semgrep.py --features $P --semgrep $J --include-modules
python analyze_features_vs_semgrep.py --features $P --semgrep $J --include-modules --unit rule
```

For TypeScript add `--min-support 10 --min-target 5` to the analysis commands (fewer analyzable snippets).

---

## Pitfalls

- **The second argument of `process_semgrep_results_js.py` must be `1`.** The script re-reads the same file once per batch, so a higher value duplicates every count. With fewer than 20,000 snippets there is a single batch.
- **Old script versions.** Check with `grep -c "merge-same-location" process_semgrep_results_js.py` (must be > 0). `run_from_json.sh` does this for all scripts.
- **Do not paste file names into the terminal.** To see a file use `cat file.txt`.
- **Semgrep version.** Registry rules change over time, so results produced on different days can differ slightly. Record `semgrep --version` together with the JSONs. Our reference run used Semgrep 1.182.0.

---

## Reference results (Semgrep 1.182.0, dataset `snippets_ago26`)

Use these to check your run. Small differences are expected if your JSONs were produced with a different Semgrep version or on a different day.

| | js single | js multi | ts single | ts multi |
|---|---|---|---|---|
| scanned | 4756 | 8825 | 1570 | 3366 |
| errors | 349 | 1846 | 140 | 898 |
| defective (original / merged) | 1019 | 1777 | 247 | 457 |
| issues — original | 1431 | 2492 | 334 | 586 |
| issues — merged | 1257 | 2219 | 284 | 517 |
| defective — merged_noOI | 576 | 1009 | 119 | 203 |
| issues — merged_noOI | 710 | 1281 | 134 | 228 |

`scanned` must match exactly: it depends only on the CSV and the mode. If it does not, the JSON comes from a different CSV or configuration.
