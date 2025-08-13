
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
spl_regex_portability_audit.py

Scan a text file of SPL queries (one per line), find both `rex` and `regex` commands,
extract their regex patterns, and assess portability vs Java regex and Lucene regex.

This version is robust to doubled quotes in SPL like: rex ""pattern""

Outputs:
- Console summary with totals and per-engine incompatibility counts + examples
- CSV (current working directory): <input>.portability_audit.csv
- JSON (current working directory): <input>.portability_audit.json

Usage:
    python spl_regex_portability_audit.py /path/to/queries.txt
"""

import sys
import re
import csv
import json
from pathlib import Path
from typing import List, Dict, Tuple

# --------------------------------------------------------------------------------------
# Feature detectors (regexes that detect constructs in the pattern strings)
# --------------------------------------------------------------------------------------

DETECTORS = {
    # Common/PCRE-ish constructs
    "lookahead": re.compile(r"\(\?=|\(\?!"),
    "lookbehind": re.compile(r"\(\?<=|\(\?<!"),
    "atomic_group": re.compile(r"\(\?>"),
    "possessive_quantifier": re.compile(r"(?<!\\)(?:\+\+|\*\+|\?\+)"),
    "backtracking_control": re.compile(r"\(\*(?:PRUNE|SKIP|COMMIT|THEN|ACCEPT|FAIL)\)"),
    "branch_reset": re.compile(r"\(\?\|"),
    "recursion": re.compile(r"\(\?R\)|\(\?0\)"),
    "subroutine_number": re.compile(r"\\g(?:\d+|\{\d+\})"),
    "subroutine_name": re.compile(r"\\g(?:['\{][A-Za-z_][A-Za-z0-9_]*['\}])|\(\?&[A-Za-z_][A-Za-z0-9_]*\)"),
    "conditional": re.compile(r"\(\?\([^\)]*\)"),
    "callout": re.compile(r"\(\?C\d*\)"),
    "named_backref_k": re.compile(r"\\k<[^>]+>"),
    # Named capture syntaxes
    "named_capture_angle": re.compile(r"\(\?<[_A-Za-z]\w*>"),
    "named_capture_single": re.compile(r"\(\?'[_A-Za-z]\w*'"),
    # Numbered backreference
    "backref_number": re.compile(r"(?<!\\)\\[1-9]\d*"),
    # Inline mode flags (?i), (?s), (?m), (?x), (?-i), etc.
    "inline_flags": re.compile(r"\(\?[imsUx-]+(?:-[imsUx]+)?\)"),
    # Mode modifiers like (*UTF8) etc.
    "mode_modifier": re.compile(r"\(\*(?:UTF8|UTF|UCP|NO_START_OPT|BSR_[A-Z]+)\)"),
}

# --------------------------------------------------------------------------------------
# Compatibility rules (heuristics)
# --------------------------------------------------------------------------------------
JAVA_INCOMPATIBLE = {
    "backtracking_control",
    "branch_reset",
    "recursion",
    "subroutine_number",
    "subroutine_name",
    "conditional",
    "callout",
    "mode_modifier",
}

LUCENE_INCOMPATIBLE = {
    "lookahead",
    "lookbehind",
    "atomic_group",
    "possessive_quantifier",
    "backtracking_control",
    "branch_reset",
    "recursion",
    "subroutine_number",
    "subroutine_name",
    "conditional",
    "callout",
    "named_backref_k",
    "named_capture_angle",
    "named_capture_single",
    "backref_number",
    "inline_flags",
    "mode_modifier",
}

# --------------------------------------------------------------------------------------
# Helpers to parse quoted strings with support for doubled quotes
# --------------------------------------------------------------------------------------

def _scan_quoted(s: str, i: int) -> Tuple[int, str] or None:
    """
    Scan a quoted string starting at index i.
    Supports:
      - "....."
      - '.....'
      - "".....""  (doubled double-quotes, common in exported SPL)
    Handles backslash escapes within standard quotes.
    Returns (end_index, content) where end_index is the index just after the closing quote(s).
    Returns None if no quoted string starts at i.
    """
    n = len(s)
    if i >= n:
        return None

    ch = s[i]
    if ch not in ("'", '"'):
        return None

    # Doubled double-quotes case
    if ch == '"' and i + 1 < n and s[i+1] == '"':
        # consume opening ""
        i += 2
        start = i
        while i < n - 1:
            # end if we see an unescaped "" pair
            if s[i] == '"' and s[i+1] == '"':
                content = s[start:i]
                return i + 2, content
            i += 1
        return None  # no closing "" found
    else:
        # Standard single quote or double quote
        quote = ch
        i += 1
        start = i
        while i < n:
            if s[i] == '\\':  # skip escaped char
                i += 2
                continue
            if s[i] == quote:
                content = s[start:i]
                return i + 1, content
            i += 1
        return None  # no closing quote found

def _find_all_quoted(s: str) -> List[Tuple[int, int, str]]:
    """Return list of (start, end, content) for all quoted strings, handling doubled quotes."""
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] in ("'", '"'):
            res = _scan_quoted(s, i)
            if res is not None:
                end, content = res
                out.append((i, end, content))
                i = end
                continue
        i += 1
    return out

# --------------------------------------------------------------------------------------
# SPL command extractors
# --------------------------------------------------------------------------------------

WORD_BOUNDARY = re.compile(r"(?<!\w)rex(?!\w)|(?<!\w)regex(?!\w)", re.IGNORECASE)

def _iter_command_tokens(line: str):
    """Yield (cmd, start_index, end_index_of_token) for each 'rex' or 'regex' occurrence."""
    for m in WORD_BOUNDARY.finditer(line):
        cmd = m.group(0).lower()
        yield cmd, m.start(), m.end()

def extract_from_rex(line: str) -> List[Dict]:
    out = []
    for cmd_i, (cmd, s, e) in enumerate(_iter_command_tokens(line), start=1):
        if cmd != "rex":
            continue
        # After 'rex', skip optional args until first quote start
        i = e
        n = len(line)
        # Skip spaces and arg tokens like key=value
        while i < n and line[i].isspace():
            i += 1
        # Consume arg tokens until we hit a quote
        while i < n and line[i] not in ("'", '"'):
            # simple skip of arg chunk until space or quote or pipe
            if line[i] == '|':
                break
            i += 1
        if i >= n or line[i] == '|':
            continue
        # Now expect a quoted pattern (support doubled quotes)
        scanned = _scan_quoted(line, i)
        if scanned is None:
            continue
        end, content = scanned
        out.append({
            "cmd": "rex",
            "cmd_index_on_line": cmd_i,
            "field": "",
            "pattern": content,
            "pattern_index_in_cmd": 1,
        })
    return out

def extract_from_regex(line: str) -> List[Dict]:
    out = []
    cmd_index = 0
    pos = 0
    n = len(line)
    while True:
        m = re.search(r"(?<!\w)regex(?!\w)", line[pos:], flags=re.IGNORECASE)
        if not m:
            break
        s = pos + m.start()
        e = pos + m.end()
        cmd_index += 1

        # Find end of this regex command (next pipe or line end)
        end = line.find("|", e)
        body = line[e:end] if end != -1 else line[e:]
        # Best-effort field extraction in body
        field = ""
        m_field = re.search(r"\bfield\s*=\s*([^\s=|]+)", body, flags=re.IGNORECASE)
        if m_field:
            field = m_field.group(1)
        else:
            lead = re.search(r"(?:^|\s)(?P<name>[\w\.\-]+)\s*=", body)
            if lead and lead.group("name").lower() != "field":
                field = lead.group("name")

        # Find all quoted strings in the body, including doubled quotes
        quotes = _find_all_quoted(body)
        sub_i = 0
        for (qs, qe, content) in quotes:
            sub_i += 1
            out.append({
                "cmd": "regex",
                "cmd_index_on_line": cmd_index,
                "field": field,
                "pattern": content,
                "pattern_index_in_cmd": sub_i,
            })

        pos = e  # continue search after this command token
    return out

# --------------------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------------------

def detect_features(pattern: str) -> List[str]:
    hits = []
    for name, rx in DETECTORS.items():
        if rx.search(pattern):
            hits.append(name)
    return hits

def incompatible_for(engine: str, features: List[str]) -> Tuple[bool, List[str]]:
    if engine == "java":
        bad = sorted(f for f in features if f in JAVA_INCOMPATIBLE)
        return (len(bad) > 0, bad)
    elif engine == "lucene":
        bad = sorted(f for f in features if f in LUCENE_INCOMPATIBLE)
        return (len(bad) > 0, bad)
    else:
        raise ValueError("Unknown engine: " + engine)

def analyze_file(path: Path) -> Tuple[List[Dict], Dict]:
    rows = []
    totals = {
        "lines": 0,
        "rex_commands": 0,
        "regex_commands": 0,
        "total_patterns": 0,
        "java_incompatible_patterns": 0,
        "lucene_incompatible_patterns": 0,
        "java_feature_counts": {},
        "lucene_feature_counts": {},
    }

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            totals["lines"] += 1

            rex_items = extract_from_rex(line)
            regex_items = extract_from_regex(line)

            if rex_items:
                totals["rex_commands"] += len({x['cmd_index_on_line'] for x in rex_items})
            if regex_items:
                totals["regex_commands"] += len({x['cmd_index_on_line'] for x in regex_items})

            for item in rex_items + regex_items:
                totals["total_patterns"] += 1
                feats = detect_features(item["pattern"])

                java_bad, java_feats = incompatible_for("java", feats)
                luc_bad, luc_feats = incompatible_for("lucene", feats)

                if java_bad:
                    totals["java_incompatible_patterns"] += 1
                    for ftr in java_feats:
                        totals["java_feature_counts"][ftr] = totals["java_feature_counts"].get(ftr, 0) + 1
                if luc_bad:
                    totals["lucene_incompatible_patterns"] += 1
                    for ftr in luc_feats:
                        totals["lucene_feature_counts"][ftr] = totals["lucene_feature_counts"].get(ftr, 0) + 1

                rows.append({
                    "line_number": i,
                    "command": item["cmd"],
                    "cmd_index_on_line": item["cmd_index_on_line"],
                    "pattern_index_in_cmd": item.get("pattern_index_in_cmd", 1),
                    "field": item.get("field",""),
                    "pattern": item["pattern"],
                    "features_detected": ",".join(feats),
                    "java_incompatible": java_bad,
                    "java_incompat_features": ",".join(java_feats),
                    "lucene_incompatible": luc_bad,
                    "lucene_incompat_features": ",".join(luc_feats),
                    "line": line,
                })

    return rows, totals

# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------

def write_reports(input_path: Path, rows: List[Dict], totals: Dict) -> Dict[str, Path]:
    cwd = Path.cwd()
    out_csv = cwd / f"{input_path.stem}.portability_audit.csv"
    out_json = cwd / f"{input_path.stem}.portability_audit.json"

    with out_csv.open("w", newline="", encoding="utf-8") as cf:
        w = csv.DictWriter(cf, fieldnames=[
            "line_number","command","cmd_index_on_line","pattern_index_in_cmd","field",
            "pattern","features_detected",
            "java_incompatible","java_incompat_features",
            "lucene_incompatible","lucene_incompat_features",
            "line"
        ])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    with out_json.open("w", encoding="utf-8") as jf:
        json.dump(totals, jf, indent=2)

    return {"csv": out_csv, "json": out_json}

def _truncate(s: str, n: int = 160) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"

def console_summary(input_path: Path, rows: List[Dict], totals: Dict, max_examples: int = 8) -> None:
    print("=== SPL Regex Portability Audit ===")
    print(f"Input file: {input_path}")
    print(f"Total non-empty lines: {totals['lines']}")
    print(f"rex commands found: {totals['rex_commands']}")
    print(f"regex commands found: {totals['regex_commands']}")
    print(f"Total patterns examined: {totals['total_patterns']}")
    print(f"Java-incompatible patterns: {totals['java_incompatible_patterns']}")
    print(f"Lucene-incompatible patterns: {totals['lucene_incompatible_patterns']}")

    def print_feature_counts(title, dct):
        print(f"\n{title}")
        if not dct:
            print("  (none)")
            return
        for k, v in sorted(dct.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  - {k:22s} {v}")

    print_feature_counts("Java incompatibility by feature:", totals["java_feature_counts"])
    print_feature_counts("Lucene incompatibility by feature:", totals["lucene_feature_counts"])

    def examples_for(engine_key_flag, engine_feat_key, title):
        print(f"\nExamples: {title} (up to {max_examples})")
        count = 0
        for r in rows:
            if r[engine_key_flag]:
                print(f"  line {r['line_number']} [{r['command']}] (cmd #{r['cmd_index_on_line']}, pat #{r['pattern_index_in_cmd']})"
                      f"{' field='+r['field'] if r['field'] else ''} -> { _truncate(r['pattern']) }")
                print(f"    features: {r[engine_feat_key]}")
                count += 1
                if count >= max_examples:
                    break
        if count == 0:
            print("  (none)")

    examples_for("java_incompatible", "java_incompat_features", "Java-incompatible patterns")
    examples_for("lucene_incompatible", "lucene_incompat_features", "Lucene-incompatible patterns")

def main():
    if len(sys.argv) != 2:
        print("Usage: python spl_regex_portability_audit.py /path/to/queries.txt", file=sys.stderr)
        sys.exit(2)
    input_path = Path(sys.argv[1]).expanduser()
    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    rows, totals = analyze_file(input_path)
    outputs = write_reports(input_path, rows, totals)

    console_summary(input_path, rows, totals, max_examples=8)

    print("\nReports (written to current working directory):")
    print(f"  CSV : {outputs['csv'].name}")
    print(f"  JSON: {outputs['json'].name}")

if __name__ == "__main__":
    main()
