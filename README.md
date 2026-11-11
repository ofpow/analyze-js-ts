# Analyzing security of AI-Generated Javascript and Typescript
This repo contains code to run semgrep over Javascript and Typescript snippets. Currently we have a dataset from AI web chats, and one from agentic sessions.

## Included Scripts
```scripts/run_semgrep_js.py``` will take a csv and language, and run semgrep on the snippets, outputting a json file with the semgrep results.

```scripts/run_from_json.sh``` takes a csv and directory with semgrep results and produces a results table, feature construct analysis, and mapping to vulnerabilities. 
Other scripts are called by run_from_json.sh.

## AI Web Chat
In the file dataset_ago26.zip, run semgrep on snippet_ago26.csv.

## Agentic
In the file snippet_javascript_typescript.csv.zip, run semgrep on snippet_javascript_typescript.csv. The parse rate for the javascript in this dataset is low, so to increase, run agentic/classify.py to create a classified subset with more definite results.
