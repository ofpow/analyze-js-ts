from datasets import load_dataset, load_from_disk, Dataset
from pprint import pprint
import csv

#dataset = load_dataset("Nan-Do/code-search-net-javascript", split="train")
#dataset.save_to_disk("./codesearchnetjs")
#print('done downloading')

dataset = load_from_disk('./codesearchnetjs').select(range(10000))
print(dataset)

csvs = []

for i, datum in enumerate(dataset):
    entry = {
        'riga_id': i,
        'codice_risposta': datum['code'],
        'risposte_alternative': 'no',
        'linguaggio': datum['language']
    }
    csvs.append(entry)

with open('out.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=csvs[0].keys())
    writer.writeheader()
    writer.writerows(csvs)
