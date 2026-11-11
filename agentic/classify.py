import csv
import sys
import re
import os
csv.field_size_limit(sys.maxsize)
import pandas as pd

PATTERNS = {
    "javascript": [
        (r"=>", 2),
        (r"\b(?:const|let|var)\s+\w+", 1),
        (r"\bconsole\s*\.\s*log\s*\(", 3),
        (r"\brequire\s*\(", 3),
        (r"\bmodule\.exports\b", 3),
        (r"\b(?:async\s+)?function\s+\w+\s*\(", 2),
        (r"\bnew\s+Promise\s*\(", 3),
    ],
    "typescript": [
        (r"\binterface\s+\w+", 4),
        (r"\btype\s+\w+\s*=", 4),
        (r"\benum\s+\w+", 3),
        (r":\s*(?:string|number|boolean|unknown|any)\b", 3),
        (r"\bas\s+(?:const|string|number|unknown)\b", 3),
        (r"\bimplements\s+\w+", 3),
        (r"\breadonly\s+\w+", 3),
    ],
    "python": [
        (r"^\s*def\s+\w+\s*\(", 4),
        (r"^\s*(?:async\s+)?def\s+\w+", 4),
        (r"^\s*from\s+\w+(?:\.\w+)*\s+import\b", 3),
        (r"^\s*elif\b", 3),
        (r"\bif\s+__name__\s*==\s*['\"]__main__['\"]", 5),
        (r"\bself\.\w+", 2),
        (r"\b(?:None|True|False)\b", 1),
        (r"\bprint\s*\(", 1),
    ],
    "c": [
        (r"#\s*include\s*[<\"](?:stdio|stdlib|string|stdint)\.h[>\"]", 5),
        (r"\bprintf\s*\(", 3),
        (r"\bscanf\s*\(", 3),
        (r"\bint\s+main\s*\(", 3),
        (r"\bsizeof\s*\(", 2),
        (r"\bmalloc\s*\(", 2),
        (r"\b(?:char|int|void)\s+\w+\s*\([^;{}]*\)\s*\{", 2),
    ],
    "cpp": [
        (r"#\s*include\s*[<\"](?:iostream|string|vector|map|memory|algorithm)>?", 5),
        (r"\bstd\s*::", 4),
        (r"\bcout\s*<<", 4),
        (r"\bcin\s*>>", 4),
        (r"\btemplate\s*<", 4),
        (r"\bnullptr\b", 3),
        (r"\bconstexpr\b", 3),
        (r"\busing\s+namespace\s+std\b", 4),
        (r"\bstatic_cast\s*<", 4),
    ],
}

COMPILED = {
    lang: [(re.compile(p, re.MULTILINE), weight)
           for p, weight in patterns]
    for lang, patterns in PATTERNS.items()
}

def classify(text):
    if not isinstance(text, str) or not text.strip():
        return {"classified_language": "unknown", "confidence": 0.0}

    scores = {lang: 0 for lang in COMPILED}

    # Markdown code-fence labels are useful direct evidence.
    fence_labels = re.findall(
        r"```([a-zA-Z0-9_+#.-]+)", text
    )
    aliases = {
        "js": "javascript", "jsx": "javascript",
        "ts": "typescript", "tsx": "typescript",
        "py": "python", "c": "c",
        "h": "c", "cc": "cpp", "cpp": "cpp",
        "cxx": "cpp", "hpp": "cpp",
    }

    for label in fence_labels:
        lang = aliases.get(label.lower(), label.lower())
        if lang in scores:
            scores[lang] += 10

    # Count each pattern once to avoid repeated-keyword domination.
    for lang, patterns in COMPILED.items():
        for regex, weight in patterns:
            if regex.search(text):
                scores[lang] += weight

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    best_lang, best_score = ranked[0]
    second_score = ranked[1][1]

    if best_score < 3:
        return {"classified_language": "unknown", "confidence": 0.0}

    # A heuristic confidence score, not a calibrated probability.
    confidence = (best_score - second_score) / max(best_score, 1)

    if best_score == second_score:
        best_lang = "ambiguous"

    return {
        "classified_language": best_lang,
        "confidence": round(confidence, 3),
        **{f"score_{k}": v for k, v in scores.items()}
    }


df = pd.read_csv("snippet_javascript_typescript.csv")

# Change "response" to the name of your text column.
results = df["codice_risposta"].map(classify).apply(pd.Series)
df = pd.concat([df, results], axis=1)
df['linguaggio'] = df['classified_language']

df.to_csv("classified_agentic_snippets.csv", index=False)
