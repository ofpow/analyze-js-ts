import csv
import json
import sys
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript
from tree_sitter import Language, Parser
import gc

import argparse
from tqdm import tqdm
from pprint import pprint

csv.field_size_limit(sys.maxsize)

TS_LANGUAGE = Language(tstypescript.language_typescript())
ts_parser = Parser(TS_LANGUAGE)

JS_LANGUAGE = Language(tsjavascript.language())
js_parser = Parser(JS_LANGUAGE)

def extract_functions(code, language):
    source = code.encode("utf-8")
    #tree = js_parser.parse(source)
    if language == 'javascript':
        tree = js_parser.parse(source)
    elif language == 'typescript':
        tree = ts_parser.parse(source)
    else:
        print(f'cant parse language {language}')

    functions = []

    def get_text(node):
        return source[node.start_byte:node.end_byte].decode("utf-8")

    def walk(node):
        function_types = {
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
            "generator_function",
            "generator_function_declaration",
        }

        if node.type in function_types:
            name = None

            # Named function or generator
            name_node = node.child_by_field_name("name")
            if name_node:
                name = get_text(name_node)

            # Arrow/function expression assigned to a variable
            if not name and node.parent:
                parent = node.parent

                if parent.type == "variable_declarator":
                    name_node = parent.child_by_field_name("name")
                    if name_node:
                        name = get_text(name_node)

                elif parent.type == "assignment_expression":
                    name_node = parent.child_by_field_name("left")
                    if name_node:
                        name = get_text(name_node)

            # Class/object method name
            if not name and node.type == "method_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = get_text(name_node)

            functions.append({
                "name": name or "<anonymous>",
                "type": node.type,
                "start_line": node.start_point.row + 1,
                "end_line": node.end_point.row + 1,
                "source": get_text(node)
            })

        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return functions

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('csv_file', type=str, help='The path to the csv file.')
args = arg_parser.parse_args()

snippets = []
with open(args.csv_file, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['linguaggio'] == 'javascript' or row['linguaggio'] == 'typescript':
            snippets.append(row)
print(len(snippets))
malformed = 0
for snippet in snippets:
    if snippet['risposte_alternative'] == 'si':
        continue
        try:
            snippet_list = json.loads(snippet['codice_risposta'])
            snippet['codice_risposta'] = '\n'.join(snippet_list)
        except json.decoder.JSONDecodeError:
            print('malformed:')
            pprint(snippet)
gc.disable()
functions = []
for snippet in tqdm(snippets):
    extracted_funcs = extract_functions(snippet['codice_risposta'], snippet['linguaggio'])
    for func in extracted_funcs:
        snippet_copy = snippet.copy()
        snippet_copy['codice_risposta'] = func['source']
        snippet_copy['risposte_alternative'] = 'no'
        functions.append(snippet_copy)
with open('extracted_functions.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=functions[0].keys())
    writer.writeheader()
    writer.writerows(functions)
print(f'wrote {len(functions)} functions')
