import csv
import sys
import re
import os
csv.field_size_limit(sys.maxsize)

print('----original----')
with open('snippet_javascript_typescript.csv', 'r') as f:
    x = {}
    reader = csv.DictReader(f)
    for row in reader:
        x[row['linguaggio']] = x.get(row['linguaggio'], 0) + 1

    for k, v in x.items():
        print(k, v)
print('----classified----')
with open('classified_agentic_snippets.csv', 'r') as f:
    x = {}
    reader = csv.DictReader(f)
    for row in reader:
        x[row['linguaggio']] = x.get(row['linguaggio'], 0) + 1

    for k, v in x.items():
        print(k, v)
