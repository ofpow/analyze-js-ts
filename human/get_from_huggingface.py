from datasets import load_dataset, load_from_disk, Dataset
from pprint import pprint
import csv

#stream = load_dataset("bigcode/the-stack", data_dir="data/javascript", split="train", streaming=True)
#subset_iterable = stream.take(10000)
#dataset = Dataset.from_generator(lambda: (yield from subset_iterable))
#dataset.save_to_disk("./the-stack-js")
#print('done downloading')

dataset = load_from_disk('./the-stack-js').select(range(3000))
print(dataset)

csvs = []

for i, datum in enumerate(dataset):
    entry = {
        'riga_id': i,
        'codice_risposta': datum['content'],
        'risposte_alternative': 'no',
        'linguaggio': datum['lang']
    }
    csvs.append(entry)

with open('out.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=csvs[0].keys())
    writer.writeheader()
    writer.writerows(csvs)
