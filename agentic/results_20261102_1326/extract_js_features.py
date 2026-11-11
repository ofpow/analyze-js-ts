"""
Extract language constructs (by ECMAScript version), legacy idioms, TypeScript-specific
constructs and security-relevant APIs/sinks from the JS/TS snippets of the dataset.

The snippet numbering is IDENTICAL to run_semgrep_js.py (same CSV filtering, same
single/multi logic, snippet_id = position in the filtered list + 1), so the output
joins 1:1 with the "path" number used in process_semgrep_results_js.py.

Parsing uses tree-sitter, which is error tolerant: snippets that Semgrep could not
analyze still get their features extracted. This is needed to check whether parse
errors are correlated with modern syntax (selection bias).

Usage:
    python extract_js_features.py snippets_ago26.csv javascript single
    python extract_js_features.py snippets_ago26.csv typescript multi

Outputs (same prefix as run_semgrep_js.py, e.g. js_single_snippets_ago26):
    <prefix>_features_long.csv   one row per (snippet, feature): count + line spans "start-end;..."
    <prefix>_snippets.csv        one row per snippet: LOC, parse status, ES summary,
                                 one 0/1 column per feature
    <prefix>_feature_catalog.csv the catalog used (feature -> version, category, detection)
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict

import tree_sitter_javascript as ts_js
import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Parser

csv.field_size_limit(sys.maxsize)

# ---------------------------------------------------------------------------
# Feature catalog
#   version : ES edition that introduced it ("legacy" = pre-ES2015 idiom still valid,
#             "ts" = TypeScript-only, "api" = library/platform API or security sink)
#   category: syntax | builtin | legacy | ts | jsx | api
#   method  : ast   = detected from the syntax tree (exact)
#             name  = detected from identifier/method names, no type information
#                     (heuristic: e.g. ".at(" may be a user-defined method)
# ---------------------------------------------------------------------------
CATALOG = {
    # --- legacy idioms (valid today, typical of pre-ES2015 code) ---
    "var_declaration":        ("legacy", "legacy", "ast", "var declarations"),
    "arguments_object":       ("legacy", "legacy", "ast", "use of the implicit 'arguments' object"),
    "loose_equality":         ("legacy", "legacy", "ast", "== / != comparisons"),
    "commonjs_require":       ("legacy", "legacy", "ast", "require(...) calls"),
    "commonjs_exports":       ("legacy", "legacy", "ast", "module.exports / exports.x"),
    "prototype_manipulation": ("legacy", "legacy", "ast", "X.prototype.y = ... / X.prototype = ..."),
    "function_expression":    ("legacy", "legacy", "ast", "anonymous function expressions (pre-arrow callbacks)"),
    "with_statement":         ("legacy", "legacy", "ast", "with (...) statements"),
    # --- ES2015 ---
    "let_const":              ("ES2015", "syntax", "ast", "let / const declarations"),
    "arrow_function":         ("ES2015", "syntax", "ast", "arrow functions"),
    "class":                  ("ES2015", "syntax", "ast", "class declarations/expressions"),
    "template_literal":       ("ES2015", "syntax", "ast", "template strings"),
    "template_interpolation": ("ES2015", "syntax", "ast", "template strings with ${...}"),
    "tagged_template":        ("ES2015", "syntax", "ast", "tagged templates (tag`...`)"),
    "destructuring":          ("ES2015", "syntax", "ast", "object/array destructuring patterns"),
    "array_spread":           ("ES2015", "syntax", "ast", "spread in arrays and calls"),
    "rest_parameters":        ("ES2015", "syntax", "ast", "rest parameters / array rest"),
    "default_parameters":     ("ES2015", "syntax", "ast", "default parameter values"),
    "for_of":                 ("ES2015", "syntax", "ast", "for...of loops"),
    "generator":              ("ES2015", "syntax", "ast", "generator functions / yield"),
    "es_modules":             ("ES2015", "syntax", "ast", "import / export statements"),
    "shorthand_property":     ("ES2015", "syntax", "ast", "shorthand properties / methods"),
    "computed_property":      ("ES2015", "syntax", "ast", "computed property names"),
    "new_target":             ("ES2015", "syntax", "ast", "new.target"),
    "regex_flag_u_y":         ("ES2015", "syntax", "ast", "regex flags u / y"),
    "promise":                ("ES2015", "builtin", "name", "Promise constructor / static methods"),
    "map_set_symbol":         ("ES2015", "builtin", "name", "Map, Set, WeakMap, WeakSet, Symbol, Proxy, Reflect"),
    # --- ES2016 ---
    "exponent_operator":      ("ES2016", "syntax", "ast", "** and **="),
    # --- ES2017 ---
    "async_function":         ("ES2017", "syntax", "ast", "async functions / arrows / methods"),
    "await":                  ("ES2017", "syntax", "ast", "await expressions"),
    "object_entries_values":  ("ES2017", "builtin", "name", "Object.entries / Object.values / getOwnPropertyDescriptors"),
    "string_pad":             ("ES2017", "builtin", "name", "padStart / padEnd"),
    # --- ES2018 ---
    "object_spread":          ("ES2018", "syntax", "ast", "spread in object literals"),
    "object_rest":            ("ES2018", "syntax", "ast", "rest in object patterns"),
    "for_await_of":           ("ES2018", "syntax", "ast", "for await...of"),
    "regex_named_groups":     ("ES2018", "syntax", "ast", "regex (?<name>...)"),
    "regex_lookbehind":       ("ES2018", "syntax", "ast", "regex (?<=...) / (?<!...)"),
    "regex_flag_s":           ("ES2018", "syntax", "ast", "regex dotAll flag s"),
    "promise_finally":        ("ES2018", "builtin", "name", ".finally(...)"),
    # --- ES2019 ---
    "optional_catch_binding": ("ES2019", "syntax", "ast", "catch { } without parameter"),
    "array_flat":             ("ES2019", "builtin", "name", ".flat() / .flatMap()"),
    "object_from_entries":    ("ES2019", "builtin", "name", "Object.fromEntries"),
    "string_trim_start_end":  ("ES2019", "builtin", "name", "trimStart / trimEnd"),
    # --- ES2020 ---
    "optional_chaining":      ("ES2020", "syntax", "ast", "?."),
    "nullish_coalescing":     ("ES2020", "syntax", "ast", "??"),
    "bigint":                 ("ES2020", "syntax", "ast", "BigInt literals (1n) / BigInt()"),
    "dynamic_import":         ("ES2020", "syntax", "ast", "import(...)"),
    "import_meta":            ("ES2020", "syntax", "ast", "import.meta"),
    "global_this":            ("ES2020", "builtin", "name", "globalThis"),
    "promise_all_settled":    ("ES2020", "builtin", "name", "Promise.allSettled"),
    "string_match_all":       ("ES2020", "builtin", "name", ".matchAll(...)"),
    # --- ES2021 ---
    "logical_assignment":     ("ES2021", "syntax", "ast", "??= ||= &&="),
    "numeric_separator":      ("ES2021", "syntax", "ast", "1_000_000"),
    "string_replace_all":     ("ES2021", "builtin", "name", ".replaceAll(...)"),
    "promise_any":            ("ES2021", "builtin", "name", "Promise.any"),
    "weakref":                ("ES2021", "builtin", "name", "WeakRef / FinalizationRegistry"),
    # --- ES2022 ---
    "class_fields":           ("ES2022", "syntax", "ast", "public class fields"),
    "private_members":        ("ES2022", "syntax", "ast", "#private fields/methods"),
    "private_in_check":       ("ES2022", "syntax", "ast", "#x in obj"),
    "class_static_block":     ("ES2022", "syntax", "ast", "static { } blocks"),
    "top_level_await":        ("ES2022", "syntax", "ast", "await outside any function, in a snippet that is an ES module (import/export)"),
    "await_in_fragment":      ("ES2017", "syntax", "ast", "await outside any function in a non-module snippet: most likely a fragment of an async function body"),
    "regex_flag_d":           ("ES2022", "syntax", "ast", "regex indices flag d"),
    "array_at":               ("ES2022", "builtin", "name", ".at(...)"),
    "object_has_own":         ("ES2022", "builtin", "name", "Object.hasOwn"),
    "error_cause":            ("ES2022", "builtin", "ast", "new Error(msg, { cause })"),
    # --- ES2023 ---
    "hashbang":               ("ES2023", "syntax", "ast", "#! first line"),
    "array_find_last":        ("ES2023", "builtin", "name", ".findLast / .findLastIndex"),
    "array_change_by_copy":   ("ES2023", "builtin", "name", ".toSorted / .toReversed / .toSpliced"),
    # --- ES2024 ---
    "group_by":               ("ES2024", "builtin", "name", "Object.groupBy / Map.groupBy"),
    "promise_with_resolvers": ("ES2024", "builtin", "name", "Promise.withResolvers"),
    "regex_flag_v":           ("ES2024", "syntax", "ast", "regex unicodeSets flag v"),
    "string_well_formed":     ("ES2024", "builtin", "name", "isWellFormed / toWellFormed"),
    # --- ES2025 ---
    "import_attributes":      ("ES2025", "syntax", "ast", "import ... with { type: 'json' }"),
    "regex_modifiers":        ("ES2025", "syntax", "ast", "regex (?i:...) modifiers"),
    "set_methods":            ("ES2025", "builtin", "name", ".union / .intersection / .difference / ..."),
    "iterator_helpers":       ("ES2025", "builtin", "name", "Iterator.from(...)"),
    "promise_try":            ("ES2025", "builtin", "name", "Promise.try"),
    "regexp_escape":          ("ES2025", "builtin", "name", "RegExp.escape"),
    # --- TypeScript-specific ---
    "ts_any":                 ("ts", "ts", "ast", "explicit any type"),
    "ts_as_cast":             ("ts", "ts", "ast", "x as T"),
    "ts_double_cast":         ("ts", "ts", "ast", "x as unknown as T / as any as T"),
    "ts_angle_assertion":     ("ts", "ts", "ast", "<T>x"),
    "ts_non_null":            ("ts", "ts", "ast", "x!"),
    "ts_satisfies":           ("ts", "ts", "ast", "satisfies (TS 4.9)"),
    "ts_enum":                ("ts", "ts", "ast", "enum declarations"),
    "ts_decorator":           ("ts", "ts", "ast", "@decorators"),
    "ts_interface_type":      ("ts", "ts", "ast", "interface / type alias"),
    "ts_generics":            ("ts", "ts", "ast", "type parameters / type arguments"),
    "ts_ignore_comment":      ("ts", "ts", "ast", "// @ts-ignore / @ts-expect-error / @ts-nocheck"),
    # --- JSX ---
    "jsx":                    ("jsx", "jsx", "ast", "JSX elements"),
    # --- APIs, sources and sinks (category api) ---
    "eval_call":              ("api", "api", "ast", "eval(...)"),
    "function_constructor":   ("api", "api", "ast", "new Function(...) / Function(...)"),
    "timer_with_string":      ("api", "api", "ast", "setTimeout/setInterval with string or template argument"),
    "child_process_exec":     ("api", "api", "name", "exec/execSync/spawn/execFile/fork calls"),
    "vm_module":              ("api", "api", "name", "vm.runIn* / new vm.Script"),
    "fs_dynamic_path":        ("api", "api", "name", "fs.* call whose first argument is not a plain string"),
    "path_join_resolve":      ("api", "api", "name", "path.join / path.resolve"),
    "http_request_client":    ("api", "api", "name", "fetch / axios / http(s).request|get / XMLHttpRequest / got / request"),
    "http_url_literal":       ("api", "api", "ast", "string literal starting with http://"),
    "math_random":            ("api", "api", "name", "Math.random()"),
    "crypto_secure_random":   ("api", "api", "name", "crypto.randomBytes / randomUUID / getRandomValues / randomInt"),
    "weak_hash_literal":      ("api", "api", "ast", "'md5' / 'sha1' / 'des' / 'rc4' string literals"),
    "dom_html_sink":          ("api", "api", "name", "innerHTML / outerHTML assignment, insertAdjacentHTML, document.write"),
    "react_dangerous_html":   ("api", "api", "ast", "dangerouslySetInnerHTML"),
    "sql_in_template":        ("api", "api", "ast", "SQL keywords in an interpolated template string"),
    "sql_in_concat":          ("api", "api", "ast", "SQL keywords in a string concatenation"),
    "express_app":            ("api", "api", "name", "express() / app|router.get|post|put|delete|use"),
    "user_input_source":      ("api", "api", "name", "req.query / req.params / req.body / req.headers / req.cookies"),
    "regexp_constructor_dyn": ("api", "api", "ast", "new RegExp(non-literal)"),
    "json_parse":             ("api", "api", "name", "JSON.parse"),
    "process_env":            ("api", "api", "name", "process.env"),
    "secret_like_literal":    ("api", "api", "ast", "string assigned to a name like password/secret/token/api_key"),
    "local_storage":          ("api", "api", "name", "localStorage / sessionStorage"),
    "post_message":           ("api", "api", "name", "postMessage / message event listener"),
    "location_assign":        ("api", "api", "name", "window.location / location.href assignment"),
    "jwt":                    ("api", "api", "name", "jwt.sign / jwt.verify / jwt.decode"),
    "cors_wildcard":          ("api", "api", "ast", "'*' as Access-Control-Allow-Origin or cors origin"),
}

ES_ORDER = ["legacy", "ES2015", "ES2016", "ES2017", "ES2018", "ES2019", "ES2020",
            "ES2021", "ES2022", "ES2023", "ES2024", "ES2025"]
ES_RANK = {v: i for i, v in enumerate(ES_ORDER)}

FUNCTION_NODES = {
    "function_declaration", "function_expression", "function", "arrow_function",
    "method_definition", "generator_function_declaration", "generator_function",
}

CONTAINER_NODES = FUNCTION_NODES | {
    "program", "class_declaration", "class", "abstract_class_declaration", "class_body",
    "statement_block", "lexical_declaration", "variable_declaration", "import_statement",
    "export_statement", "for_in_statement", "for_statement", "catch_clause", "try_statement",
    "jsx_element", "jsx_self_closing_element", "class_static_block", "interface_declaration",
    "type_alias_declaration", "enum_declaration", "field_definition", "public_field_definition",
}

SQL_RE = re.compile(r"\b(select\s+.+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
                    re.IGNORECASE | re.DOTALL)
SECRET_NAME_RE = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential)",
                            re.IGNORECASE)
WEAK_ALGOS = {"md5", "sha1", "sha-1", "des", "rc4", "des-ede", "des-cbc"}
CHILD_PROCESS_FUNCS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
FS_FUNCS = {"readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream",
            "createWriteStream", "unlink", "unlinkSync", "readdir", "readdirSync", "appendFile",
            "appendFileSync", "open", "openSync", "rm", "rmSync", "stat", "statSync",
            "existsSync", "access", "accessSync", "mkdir", "mkdirSync", "sendFile"}
SET_METHODS = {"union", "intersection", "difference", "symmetricDifference",
               "isSubsetOf", "isSupersetOf", "isDisjointFrom"}


# ---------------------------------------------------------------------------
# Snippet loading: must mirror run_semgrep_js.py exactly
# ---------------------------------------------------------------------------
def load_snippets(csv_file, lang, single_or_multi):
    outputs = []
    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["linguaggio"] != lang:
                continue
            if row["risposte_alternative"] != "si":
                outputs.append(row["codice_risposta"])
            elif single_or_multi == "multi":
                try:
                    snippet_list = json.loads(row["codice_risposta"])
                    outputs.append("\n".join(snippet_list))
                except Exception:
                    pass  # skipped in run_semgrep_js.py too ('malformed')
    # snippet_id = index + 1, as in f"{output_prefix}_{start_index+1}.{file_suffix}"
    return [(i + 1, code) for i, code in enumerate(outputs)]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def make_parsers(lang):
    if lang == "javascript":
        return [Parser(Language(ts_js.language()))]
    # plain TS first, TSX as fallback (snippets may contain JSX)
    return [Parser(Language(ts_ts.language_typescript())),
            Parser(Language(ts_ts.language_tsx()))]


def error_bytes(root):
    """Bytes covered by ERROR / MISSING nodes (outermost only)."""
    total = 0
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "ERROR" or n.is_missing:
            total += max(n.end_byte - n.start_byte, 1)
            continue
        if n.has_error:
            stack.extend(n.children)
    return total


def parse(parsers, code_bytes):
    best = None
    for p in parsers:
        tree = p.parse(code_bytes)
        eb = error_bytes(tree.root_node) if tree.root_node.has_error else 0
        if best is None or eb < best[1]:
            best = (tree, eb)
        if eb == 0:
            break
    return best


# ---------------------------------------------------------------------------
# Feature detection
# ---------------------------------------------------------------------------
def txt(node):
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def child_types(node):
    return [c.type for c in node.children]


def string_value(node):
    """Content of a plain string literal node, else None."""
    if node is not None and node.type == "string":
        return txt(node)[1:-1]
    return None


def callee_parts(call):
    """For a call/new expression return (object_text, property_name) or (None, name)."""
    fn = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    if fn is None:
        return None, None
    if fn.type == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        return txt(obj), txt(prop)
    if fn.type in ("identifier", "import"):
        return None, txt(fn) if fn.type == "identifier" else "import"
    return None, None


def first_arg(call):
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    named = [c for c in args.named_children if c.type != "comment"]
    return named[0] if named else None


def inside_function(node):
    p = node.parent
    while p is not None:
        if p.type in FUNCTION_NODES:
            return True
        p = p.parent
    return False


def detect(root):
    """Return dict feature -> list of (start_line, end_line), 1-based."""
    hits = defaultdict(list)

    def hit(feature, node):
        # An expression that contains a parse error/missing token is unreliable
        # (e.g. markdown "**Note**" read as the ** operator). Large structures
        # (functions, classes, blocks, declarations) keep their identity even if
        # something inside them is broken.
        if node.has_error and node.type not in CONTAINER_NODES:
            return
        hits[feature].append((node.start_point[0] + 1, node.end_point[0] + 1))

    stack = [root]
    while stack:
        n = stack.pop()
        t = n.type
        # Do not descend into ERROR regions: they often contain prose/markdown
        # (e.g. "**Note**" would be read as the ** operator)
        if t == "ERROR":
            continue
        stack.extend(n.children)

        # keyword tokens share the node name (e.g. 'class', 'function'): skip them
        if not n.is_named:
            continue

        # ---------------- legacy ----------------
        if t == "variable_declaration":
            hit("var_declaration", n)
        elif t == "identifier" and txt(n) == "arguments" and inside_function(n):
            hit("arguments_object", n)
        elif t == "with_statement":
            hit("with_statement", n)
        elif t in ("function_expression", "function"):
            hit("function_expression", n)

        # ---------------- ES2015+ syntax ----------------
        elif t == "lexical_declaration":
            hit("let_const", n)
        elif t == "arrow_function":
            hit("arrow_function", n)
        elif t in ("class_declaration", "class", "abstract_class_declaration"):
            hit("class", n)
        elif t == "template_string":
            hit("template_literal", n)
            if any(c.type == "template_substitution" for c in n.children):
                hit("template_interpolation", n)
                if SQL_RE.search(txt(n)):
                    hit("sql_in_template", n)
            if n.parent is not None and n.parent.type == "call_expression" \
                    and n.parent.child_by_field_name("arguments") == n:
                hit("tagged_template", n)
        elif t in ("object_pattern", "array_pattern"):
            hit("destructuring", n)
        elif t == "spread_element":
            hit("object_spread" if n.parent is not None and n.parent.type == "object"
                else "array_spread", n)
        elif t == "rest_pattern":
            hit("object_rest" if n.parent is not None and n.parent.type == "object_pattern"
                else "rest_parameters", n)
        elif t in ("assignment_pattern", "required_parameter", "optional_parameter"):
            if t == "assignment_pattern" and n.parent is not None and n.parent.type == "formal_parameters":
                hit("default_parameters", n)
            elif t != "assignment_pattern" and n.child_by_field_name("value") is not None:
                hit("default_parameters", n)
        elif t == "for_in_statement":
            ct = child_types(n)
            if "of" in ct:
                hit("for_await_of" if "await" in ct else "for_of", n)
        elif t in ("generator_function_declaration", "generator_function", "yield_expression"):
            hit("generator", n)
        elif t in ("import_statement", "export_statement"):
            hit("es_modules", n)
            if any(c.type in ("import_attribute", "import_attributes") for c in n.children):
                hit("import_attributes", n)
        elif t in ("shorthand_property_identifier",):
            hit("shorthand_property", n)
        elif t == "computed_property_name":
            hit("computed_property", n)
        elif t == "meta_property":
            s = txt(n)
            if s.startswith("new"):
                hit("new_target", n)
            elif s.startswith("import"):
                hit("import_meta", n)
        elif t == "await_expression":
            hit("await", n)
            if not inside_function(n):
                hit("top_level_await", n)
        elif t == "optional_chain":
            hit("optional_chaining", n)
        elif t == "field_definition" or t == "public_field_definition":
            if any(c.type == "private_property_identifier" for c in n.children):
                hit("private_members", n)
            else:
                hit("class_fields", n)
        elif t == "private_property_identifier":
            p = n.parent
            if p is not None and p.type == "binary_expression" and "in" in child_types(p):
                hit("private_in_check", n)
            elif p is not None and p.type == "method_definition":
                hit("private_members", n)
        elif t == "class_static_block":
            hit("class_static_block", n)
        elif t == "hash_bang_line":
            hit("hashbang", n)
        elif t == "number":
            s = txt(n)
            if s.endswith("n"):  # 'n' is never a digit, also in hex literals
                hit("bigint", n)
            if "_" in s:
                hit("numeric_separator", n)
        elif t == "regex":
            pat = txt(n.child_by_field_name("pattern"))
            flags = txt(n.child_by_field_name("flags"))
            if re.search(r"\(\?<(?![=!])", pat):
                hit("regex_named_groups", n)
            if "(?<=" in pat or "(?<!" in pat:
                hit("regex_lookbehind", n)
            if re.search(r"\(\?[ims]*-?[ims]+:", pat):
                hit("regex_modifiers", n)
            if "s" in flags:
                hit("regex_flag_s", n)
            if "d" in flags:
                hit("regex_flag_d", n)
            if "v" in flags:
                hit("regex_flag_v", n)
            if "u" in flags or "y" in flags:
                hit("regex_flag_u_y", n)
        elif t == "catch_clause":
            if n.child_by_field_name("parameter") is None:
                hit("optional_catch_binding", n)

        # ---------------- operators ----------------
        elif t == "binary_expression":
            op = n.child_by_field_name("operator")
            op = op.type if op is not None else ""
            if op in ("==", "!="):
                hit("loose_equality", n)
            elif op == "**":
                hit("exponent_operator", n)
            elif op == "??":
                hit("nullish_coalescing", n)
            elif op == "+":
                s = txt(n)
                if SQL_RE.search(s) and any(c.type != "string" for c in n.named_children):
                    # report only the outermost concatenation
                    if not (n.parent is not None and n.parent.type == "binary_expression"):
                        hit("sql_in_concat", n)
        elif t == "augmented_assignment_expression":
            op = n.child_by_field_name("operator")
            op = op.type if op is not None else ""
            if op in ("??=", "||=", "&&="):
                hit("logical_assignment", n)
            elif op == "**=":
                hit("exponent_operator", n)

        # ---------------- TypeScript ----------------
        elif t == "predefined_type" and txt(n) == "any":
            hit("ts_any", n)
        elif t == "as_expression":
            hit("ts_as_cast", n)
            inner = n.named_children[0] if n.named_children else None
            if inner is not None and inner.type == "as_expression":
                hit("ts_double_cast", n)
        elif t == "type_assertion":
            hit("ts_angle_assertion", n)
        elif t == "non_null_expression":
            hit("ts_non_null", n)
        elif t == "satisfies_expression":
            hit("ts_satisfies", n)
        elif t == "enum_declaration":
            hit("ts_enum", n)
        elif t == "decorator":
            hit("ts_decorator", n)
        elif t in ("interface_declaration", "type_alias_declaration"):
            hit("ts_interface_type", n)
        elif t in ("type_parameters", "type_arguments"):
            if t == "type_arguments" and n.parent is not None and n.parent.type == "type_assertion":
                pass
            else:
                hit("ts_generics", n)
        elif t == "comment":
            if re.search(r"@ts-(ignore|expect-error|nocheck)", txt(n)):
                hit("ts_ignore_comment", n)

        # ---------------- JSX ----------------
        elif t in ("jsx_element", "jsx_self_closing_element"):
            if not (n.parent is not None and n.parent.type in ("jsx_element",)):
                hit("jsx", n)
        elif t == "jsx_attribute":
            if n.named_children and txt(n.named_children[0]) == "dangerouslySetInnerHTML":
                hit("react_dangerous_html", n)

        # ---------------- strings ----------------
        elif t == "string":
            s = txt(n)[1:-1]
            if s.lower().startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|0\.0\.0\.0)", s.lower()):
                hit("http_url_literal", n)
            if s.lower() in WEAK_ALGOS:
                hit("weak_hash_literal", n)
            if s == "*":
                ctx = txt(n.parent.parent) if n.parent is not None and n.parent.parent is not None else ""
                if "Access-Control-Allow-Origin" in ctx or re.search(r"\borigin\b", ctx):
                    hit("cors_wildcard", n)

        # ---------------- declarators: hardcoded secrets ----------------
        if t in ("variable_declarator", "pair", "assignment_expression", "public_field_definition",
                 "field_definition"):
            key = (n.child_by_field_name("name") or n.child_by_field_name("key")
                   or n.child_by_field_name("left") or n.child_by_field_name("property"))
            val = n.child_by_field_name("value") or n.child_by_field_name("right")
            sv = string_value(val)
            if key is not None and sv and len(sv) >= 4 and SECRET_NAME_RE.search(txt(key).split(".")[-1]) \
                    and not sv.startswith(("process.env", "<", "${")):
                hit("secret_like_literal", n)

        # ---------------- member expressions (no call needed) ----------------
        if t == "member_expression":
            s = txt(n)
            obj = txt(n.child_by_field_name("object"))
            prop = txt(n.child_by_field_name("property"))
            if obj in ("module",) and prop == "exports" or obj == "exports":
                hit("commonjs_exports", n)
            if prop == "prototype":
                p = n.parent
                if p is not None and p.type in ("assignment_expression", "member_expression"):
                    hit("prototype_manipulation", n)
            if obj == "process" and prop == "env":
                hit("process_env", n)
            if re.fullmatch(r"(req|request|ctx\.request)", obj) and prop in ("query", "params", "body", "headers", "cookies"):
                hit("user_input_source", n)
            if obj in ("localStorage", "sessionStorage") or s.startswith(("window.localStorage", "window.sessionStorage")):
                hit("local_storage", n)
            if prop in ("innerHTML", "outerHTML") and n.parent is not None \
                    and n.parent.type in ("assignment_expression", "augmented_assignment_expression") \
                    and n.parent.child_by_field_name("left") == n:
                hit("dom_html_sink", n)
            if (s in ("window.location", "location.href", "window.location.href", "document.location")) \
                    and n.parent is not None and n.parent.type == "assignment_expression" \
                    and n.parent.child_by_field_name("left") == n:
                hit("location_assign", n)
        elif t == "identifier":
            s = txt(n)
            if s == "globalThis":
                hit("global_this", n)
            elif s in ("Map", "Set", "WeakMap", "WeakSet", "Symbol", "Proxy", "Reflect") \
                    and n.parent is not None and n.parent.type in ("new_expression", "call_expression", "member_expression"):
                hit("map_set_symbol", n)
            elif s in ("WeakRef", "FinalizationRegistry") and n.parent is not None and n.parent.type == "new_expression":
                hit("weakref", n)
            elif s == "Promise" and n.parent is not None and n.parent.type in ("new_expression", "member_expression"):
                hit("promise", n)
            elif s == "XMLHttpRequest":
                hit("http_request_client", n)

        # ---------------- calls ----------------
        if t in ("call_expression", "new_expression"):
            obj, name = callee_parts(n)
            arg0 = first_arg(n)
            if name is None:
                continue
            full = f"{obj}.{name}" if obj else name

            if t == "call_expression" and name == "require" and obj is None:
                hit("commonjs_require", n)
            if name == "import" and obj is None and t == "call_expression":
                hit("dynamic_import", n)
            if name == "BigInt" and obj is None:
                hit("bigint", n)
            if name == "eval" and obj in (None, "window", "global", "globalThis"):
                hit("eval_call", n)
            if name == "Function" and obj is None:
                hit("function_constructor", n)
            if name in ("setTimeout", "setInterval") and arg0 is not None \
                    and arg0.type in ("string", "template_string", "binary_expression"):
                hit("timer_with_string", n)
            if name in CHILD_PROCESS_FUNCS and (obj is None or re.search(r"(child_process|cp|childProcess|proc)$", obj or "")):
                hit("child_process_exec", n)
            if obj == "vm" or (obj and obj.endswith(".vm")) or (name == "Script" and obj == "vm"):
                hit("vm_module", n)
            if name in FS_FUNCS and (obj is None or re.search(r"(fs|fsp|promises|fsPromises|res)$", obj or "")):
                if arg0 is not None and arg0.type != "string":
                    hit("fs_dynamic_path", n)
            if obj == "path" and name in ("join", "resolve"):
                hit("path_join_resolve", n)
            if (name == "fetch" and obj in (None, "window", "globalThis")) \
                    or obj == "axios" or (name == "axios" and obj is None) \
                    or (obj in ("http", "https", "got", "superagent", "needle") and name in ("request", "get", "post")) \
                    or (name in ("request", "got") and obj is None):
                hit("http_request_client", n)
            if obj == "Math" and name == "random":
                hit("math_random", n)
            if name in ("randomBytes", "randomUUID", "getRandomValues", "randomInt"):
                hit("crypto_secure_random", n)
            if name in ("insertAdjacentHTML",) or (obj == "document" and name in ("write", "writeln")):
                hit("dom_html_sink", n)
            if name == "RegExp" and arg0 is not None and arg0.type not in ("string", "regex"):
                hit("regexp_constructor_dyn", n)
            if obj == "JSON" and name == "parse":
                hit("json_parse", n)
            if name == "express" and obj is None:
                hit("express_app", n)
            if obj in ("app", "router", "server") and name in ("get", "post", "put", "delete", "patch", "use", "all"):
                hit("express_app", n)
            if name == "postMessage" or (name == "addEventListener" and string_value(arg0) == "message"):
                hit("post_message", n)
            if obj in ("jwt", "jsonwebtoken") and name in ("sign", "verify", "decode"):
                hit("jwt", n)
            if obj in ("location", "window.location") and name in ("assign", "replace"):
                hit("location_assign", n)
            if name == "cors" and obj is None and arg0 is not None and "'*'" in txt(arg0).replace('"', "'"):
                hit("cors_wildcard", n)
            if name == "setHeader" and arg0 is not None and string_value(arg0) == "Access-Control-Allow-Origin":
                hit("cors_wildcard", n)
            if t == "new_expression" and name in ("Error", "TypeError", "RangeError") and "cause" in txt(n.child_by_field_name("arguments")):
                hit("error_cause", n)

            # built-ins identified by name (heuristic)
            if obj == "Object" and name in ("entries", "values", "getOwnPropertyDescriptors"):
                hit("object_entries_values", n)
            if name in ("padStart", "padEnd") and obj:
                hit("string_pad", n)
            if name == "finally" and obj:
                hit("promise_finally", n)
            if name in ("flat", "flatMap") and obj:
                hit("array_flat", n)
            if obj == "Object" and name == "fromEntries":
                hit("object_from_entries", n)
            if name in ("trimStart", "trimEnd") and obj:
                hit("string_trim_start_end", n)
            if obj == "Promise" and name == "allSettled":
                hit("promise_all_settled", n)
            if name == "matchAll" and obj:
                hit("string_match_all", n)
            if name == "replaceAll" and obj:
                hit("string_replace_all", n)
            if obj == "Promise" and name == "any":
                hit("promise_any", n)
            if name == "at" and obj:
                hit("array_at", n)
            if obj == "Object" and name == "hasOwn":
                hit("object_has_own", n)
            if name in ("findLast", "findLastIndex") and obj:
                hit("array_find_last", n)
            if name in ("toSorted", "toReversed", "toSpliced") and obj:
                hit("array_change_by_copy", n)
            if obj in ("Object", "Map") and name == "groupBy":
                hit("group_by", n)
            if obj == "Promise" and name == "withResolvers":
                hit("promise_with_resolvers", n)
            if name in ("isWellFormed", "toWellFormed") and obj:
                hit("string_well_formed", n)
            if name in SET_METHODS and obj:
                hit("set_methods", n)
            if obj == "Iterator" and name == "from":
                hit("iterator_helpers", n)
            if obj == "Promise" and name == "try":
                hit("promise_try", n)
            if obj == "RegExp" and name == "escape":
                hit("regexp_escape", n)

        # async functions/arrows/methods
        if t in ("function_declaration", "function_expression", "function", "arrow_function",
                 "method_definition", "generator_function_declaration", "generator_function"):
            if "async" in child_types(n):
                hit("async_function", n)

    # LLM snippets are often fragments of a function body: an await outside any
    # function is real ES2022 top-level await only if the snippet is an ES module
    if "top_level_await" in hits and "es_modules" not in hits and "import_meta" not in hits:
        hits["await_in_fragment"] = hits.pop("top_level_await")

    return hits


def normalize_module(src):
    """Package name from an import specifier, or None for local paths/aliases."""
    src = src.strip().removeprefix("node:")
    if not src or src.startswith((".", "/", "~/", "@/", "#")):
        return None                       # relative paths, path aliases, subpath imports
    if re.match(r"^[a-z]+:", src):
        return "url-import"               # https://..., npm:..., jsr:...
    parts = src.split("/")
    if src.startswith("@"):
        name = "/".join(parts[:2])
        scope, _, pkg = name.partition("/")
        return f"{scope}/{pkg.split('@')[0]}"
    return parts[0].split("@")[0] or None  # 'd3@5' (Observable style) -> 'd3'


def es_era(max_es):
    """Coarse eras: individual post-ES2020 editions are too rare to analyze one by one."""
    if max_es == "none":
        return "pre-ES2015"
    r = ES_RANK[max_es]
    if r <= ES_RANK["ES2016"]:
        return "ES2015-2016"
    if r <= ES_RANK["ES2019"]:
        return "ES2017-2019"
    return "ES2020+"


def content_kind(code):
    """Coarse check for snippets labelled JS that are not JS code."""
    s = code.strip()
    if not s:
        return "empty"
    if s[0] in "{[":
        try:
            json.loads(s)
            return "json"
        except Exception:
            pass
    low = s[:200].lower()
    if low.startswith(("<!doctype", "<html", "<head", "<body", "<script", "<style", "<?xml", "<template")):
        return "html_like"
    if re.match(r"^(\$ |npm |npx |yarn |pnpm |node |cd |mkdir |git |curl |pip )", s):
        return "shell_like"
    return "code"


def imported_modules(root):
    """Module names from require('x') and import ... from 'x' (normalized, 'node:' stripped)."""
    mods = set()
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        src = None
        if n.type == "import_statement":
            src = string_value(n.child_by_field_name("source"))
        elif n.type == "call_expression":
            obj, name = callee_parts(n)
            if obj is None and name in ("require", "import"):
                src = string_value(first_arg(n))
        if src:
            m = normalize_module(src)
            if m:
                mods.add(m)
    return mods


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_file")
    ap.add_argument("language", choices=["javascript", "typescript"])
    ap.add_argument("single_or_multi", choices=["single", "multi"])
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    suffix = "js" if args.language == "javascript" else "ts"
    prefix = f"{suffix}_{args.single_or_multi}_{os.path.splitext(os.path.basename(args.csv_file))[0]}"
    os.makedirs(args.outdir, exist_ok=True)

    snippets = load_snippets(args.csv_file, args.language, args.single_or_multi)
    parsers = make_parsers(args.language)
    print(f"{len(snippets)} snippets ({args.language}, {args.single_or_multi})")

    features = list(CATALOG)
    long_rows = []
    snippet_rows = []
    module_counter = defaultdict(int)

    for sid, code in snippets:
        code_bytes = code.encode("utf-8")
        tree, err_bytes = parse(parsers, code_bytes)
        root = tree.root_node
        hits = detect(root)
        mods = imported_modules(root)
        for m in mods:
            module_counter[m] += 1

        for feat, lines in hits.items():
            long_rows.append({
                "snippet_id": sid, "feature": feat,
                "es_version": CATALOG[feat][0], "category": CATALOG[feat][1],
                "count": len(lines), "spans": ";".join(f"{a}-{b}" for a, b in sorted(lines)),
            })
        for m in sorted(mods):
            long_rows.append({"snippet_id": sid, "feature": f"module:{m}", "es_version": "api",
                              "category": "module", "count": 1, "spans": ""})

        lines_total = code.count("\n") + 1 if code else 0
        loc = sum(1 for l in code.splitlines() if l.strip())
        es_present = {CATALOG[f][0] for f in hits if CATALOG[f][0] in ES_RANK and CATALOG[f][0] != "legacy"}
        max_es = max(es_present, key=ES_RANK.get) if es_present else "none"
        n_modern = sum(1 for f in hits if CATALOG[f][0] in ES_RANK and ES_RANK[CATALOG[f][0]] >= ES_RANK["ES2017"])
        n_legacy = sum(1 for f in hits if CATALOG[f][0] == "legacy")

        row = {
            "snippet_id": sid,
            "loc": loc,
            "lines_total": lines_total,
            "bytes": len(code_bytes),
            "ts_parse_error": int(root.has_error),
            "ts_error_ratio": round(err_bytes / len(code_bytes), 4) if code_bytes else 0.0,
            "max_es_version": max_es,
            "es_era": es_era(max_es),
            "content_kind": content_kind(code),
            "n_distinct_features": len(hits),
            "n_modern_features_es2017plus": n_modern,
            "n_legacy_features": n_legacy,
            "n_modules": len(mods),
            "modules": ";".join(sorted(mods)),
        }
        for f in features:
            row[f] = int(f in hits)
        snippet_rows.append(row)

    out_long = os.path.join(args.outdir, f"{prefix}_features_long.csv")
    out_snip = os.path.join(args.outdir, f"{prefix}_snippets.csv")
    out_cat = os.path.join(args.outdir, f"{prefix}_feature_catalog.csv")

    with open(out_long, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["snippet_id", "feature", "es_version", "category", "count", "spans"])
        w.writeheader()
        w.writerows(long_rows)
    with open(out_snip, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(snippet_rows[0].keys()) if snippet_rows else ["snippet_id"])
        w.writeheader()
        w.writerows(snippet_rows)
    with open(out_cat, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["feature", "es_version", "category", "detection", "description", "n_snippets"])
        prevalence = defaultdict(int)
        for r in long_rows:
            prevalence[r["feature"]] += 1
        for feat, (ver, cat, method, desc) in CATALOG.items():
            w.writerow([feat, ver, cat, method, desc, prevalence.get(feat, 0)])

    n = len(snippet_rows) or 1
    n_err = sum(r["ts_parse_error"] for r in snippet_rows)
    print(f"tree-sitter parse errors: {n_err} ({n_err / n * 100:.2f}%) - features are still extracted from the valid parts")
    print("\nSnippets by highest ES version used:")
    by_es = defaultdict(int)
    for r in snippet_rows:
        by_es[r["max_es_version"]] += 1
    for v in ["none"] + ES_ORDER[1:]:
        if by_es.get(v):
            print(f"  {v:7} {by_es[v]:6} ({by_es[v] / n * 100:.1f}%)")
    print("\nSnippets by era:")
    for k, c in sorted(Counter(r["es_era"] for r in snippet_rows).items()):
        print(f"  {k:12} {c:6} ({c / n * 100:.1f}%)")
    print("\nContent kind (non-'code' = probably not JS, mislabelled in the dataset):")
    for k, c in Counter(r["content_kind"] for r in snippet_rows).most_common():
        print(f"  {k:12} {c:6} ({c / n * 100:.1f}%)")
    print("\nMost imported modules:")
    for m, c in sorted(module_counter.items(), key=lambda x: -x[1])[:15]:
        print(f"  {m:25} {c}")
    print(f"\nWritten: {out_long}\n         {out_snip}\n         {out_cat}")


if __name__ == "__main__":
    main()
