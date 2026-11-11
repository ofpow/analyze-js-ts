# run with snippets_ago26.csv from dataset_ago26.zip

import json
import os
import subprocess
import time
import argparse
import shutil
import pprint
import csv
import sys

csv.field_size_limit(sys.maxsize)

# TypeScript snippets containing JSX must be written as .tsx, otherwise Semgrep's
# TypeScript parser fails on them (in the ago26 run this caused ~78% of the TS errors).
# Decision: parse with the TS and TSX grammars (tree-sitter) and keep the one with
# fewer error bytes; .ts wins ties, so "<T>x" type assertions stay valid.
try:
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language as _Lang, Parser as _Parser
    _TS = _Parser(_Lang(_tsts.language_typescript()))
    _TSX = _Parser(_Lang(_tsts.language_tsx()))
except ImportError:
    _TS = _TSX = None


def _error_bytes(root):
    total, stack = 0, [root]
    while stack:
        n = stack.pop()
        if n.type == "ERROR" or n.is_missing:
            total += max(n.end_byte - n.start_byte, 1)
        elif n.has_error:
            stack.extend(n.children)
    return total


def suffix_for(code, file_suffix):
    if file_suffix != 'ts':
        return file_suffix
    if _TS is None:
        sys.exit("pip install tree-sitter tree-sitter-typescript (needed to route JSX snippets to .tsx)")
    b = code.encode('utf-8')
    ts_root = _TS.parse(b).root_node
    if not ts_root.has_error:
        return 'ts'
    return 'tsx' if _error_bytes(_TSX.parse(b).root_node) < _error_bytes(ts_root) else 'ts'

def split_csv_to_js_files(csv_file, output_prefix, lang, single_or_multi, file_suffix, lines_per_file=1, files_per_batch=20000):
    start_time = time.time()

    outputs = []
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['linguaggio'].casefold() != lang.casefold():
                continue
            if row['risposte_alternative'] != 'si':
                outputs.append(row['codice_risposta'])
            else:
                if single_or_multi == 'multi':
                    try:
                        snippet_list = json.loads(row['codice_risposta'])
                        outputs.append('\n'.join(snippet_list))
                    except Exception:
                        print('malformed')

    total_lines = len(outputs)
    total_files = total_lines // lines_per_file
    total_batches = (total_files + files_per_batch - 1) // files_per_batch

    print(f"Total lines: {total_lines}, Total files: {total_files}, Total batches: {total_batches}")

    split_times = []
    semgrep_times = []
    delete_times = []

    temp_dir = f"{output_prefix}_tempfiles"
    os.makedirs(temp_dir, exist_ok=True)

    for batch in range(total_batches):
        print(f"Processing batch {batch + 1}/{total_batches}")
        batch_start_index = batch * files_per_batch * lines_per_file
        batch_end_index = min((batch + 1) * files_per_batch * lines_per_file, total_lines)
        batch_outputs = outputs[batch_start_index:batch_end_index]

        num_files = (batch_end_index - batch_start_index) // lines_per_file

        # 1. Write the batch files
        batch_split_start = time.time()
        for i in range(num_files):
            start_index = batch_start_index + i * lines_per_file
            end_index = start_index + lines_per_file
            chunk = batch_outputs[start_index - batch_start_index:end_index - batch_start_index]

            snippet_suffix = suffix_for(''.join(chunk), file_suffix)
            output_file = os.path.join(temp_dir, f"{output_prefix}_{start_index+1}.{snippet_suffix}")
            with open(output_file, 'w', encoding='utf-8') as f_out:
                for line in chunk:
                    f_out.write(line)
        batch_split_end = time.time()
        split_times.append(batch_split_end - batch_split_start)

        # 2. Run Semgrep on the batch
        json_filename = f"{output_prefix}_semgrep_results_batch_{batch+1}.json"
        batch_semgrep_time = run_semgrep_analysis(json_filename, temp_dir, lang, file_suffix)
        semgrep_times.append(batch_semgrep_time)

        # 3. Clean up only this batch's files
        batch_delete_start = time.time()
        for filename in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, filename)
            if file_path.endswith((f".{file_suffix}", f".{file_suffix}x")) and os.path.isfile(file_path):
                os.remove(file_path)
        batch_delete_end = time.time()
        delete_times.append(batch_delete_end - batch_delete_start)

    # Final full clean-up
    shutil.rmtree(temp_dir)

    end_time = time.time()
    split_json_time = end_time - start_time
    return split_json_time, split_times, semgrep_times, delete_times

def run_semgrep_analysis(json_filename, target_dir, lang, file_suffix):
    start_time = time.time()

    print(f"Running Semgrep analysis on {target_dir} and saving results to {json_filename}...")
    semgrep_command = [
        "semgrep", "scan",
        "--verbose",
        "--output", json_filename,
        "--json",
        "--no-git-ignore",
        "--max-memory=30000",
        "--max-target-bytes=1000000",
        "--timeout-threshold", "10",
        "--timeout", "60",
        "--metrics", "off",
        "--include", f"*.{file_suffix}",  # only scan JS/TS files
        "--include", f"*.{file_suffix}x",  # ... and TSX/JSX files
        "--config", "p/trailofbits",
        "--config", "p/default",
        "--config", "p/comment",
        "--config", f"p/{lang}",
        "--config", "p/cwe-top-25",
        "--config", "p/owasp-top-ten",
        "--config", "p/r2c-security-audit",
        "--config", "p/insecure-transport",
        "--config", "p/secrets",
        "--config", "p/findsecbugs",
        "--config", "p/gitlab",
        "--config", "p/mobsfscan",
        "--config", "p/command-injection",
        "--config", "p/sql-injection",
        "--config", "p/nodejsscan",
        "--config", "p/xss",
        "--config", "p/react",
        "--jobs", "20",
        target_dir
    ]
    
    subprocess.run(semgrep_command, check=True)

    end_time = time.time()
    run_semgrep_time = end_time - start_time
    return run_semgrep_time

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process csv file and run Semgrep analysis.')
    parser.add_argument('csv_file', type=str, help='The path to the csv file.')
    parser.add_argument('language', choices=['javascript', 'typescript'], help='the language to analyze')
    parser.add_argument('single_or_multi', choices=['single', 'multi'], help='analyze only single snippets or concatenate multi-snippets together')

    args = parser.parse_args()

    if args.language == 'javascript':
        file_suffix = 'js'
    else:
        file_suffix = 'ts'

    csv_filename = os.path.basename(args.csv_file)
    output_prefix = f'{file_suffix}_{args.single_or_multi}_{os.path.splitext(csv_filename)[0]}'

    start_time = time.time()
    split_csv_time, split_times, semgrep_times, delete_times = split_csv_to_js_files(args.csv_file, output_prefix, args.language, args.single_or_multi, file_suffix)

    end_time = time.time()
    total_time = end_time - start_time

    print(f"Total execution time: {total_time:.2f} seconds ({total_time/60:.2f} minutes)")

    print("\nDetailed timings per batch:")
    for i, (split_time, semgrep_time, delete_time) in enumerate(zip(split_times, semgrep_times, delete_times), start=1):
        print(f"Batch {i}: Semgrep time: {semgrep_time:.2f} s, Batch cleanup time: {delete_time:.2f} s")
