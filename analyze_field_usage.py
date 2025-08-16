#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_field_usage.py

Analyzes whether rex and regex commands in SPL queries specify fields.
Provides detailed statistics on field usage patterns.
"""

import sys
import re
import json
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

def analyze_rex_field_usage(line: str) -> List[Dict]:
    """Analyze rex commands for field usage."""
    results = []
    
    # Find all rex commands
    rex_pattern = re.compile(r'\brex\b', re.IGNORECASE)
    
    for match in rex_pattern.finditer(line):
        start = match.end()
        
        # Look for field specification after rex
        # Common patterns: field=name, field="name", field='name'
        field_pattern = re.compile(
            r'\s+field\s*=\s*(?:'
            r'([^\s"\']+)|'  # Unquoted field name
            r'"([^"]+)"|'     # Double-quoted field name
            r"'([^']+)')"     # Single-quoted field name
        )
        
        # Search for field within reasonable distance (next 200 chars or until pipe)
        search_end = min(start + 200, len(line))
        next_pipe = line.find('|', start)
        if next_pipe != -1 and next_pipe < search_end:
            search_end = next_pipe
            
        search_text = line[start:search_end]
        field_match = field_pattern.search(search_text)
        
        if field_match:
            field_name = field_match.group(1) or field_match.group(2) or field_match.group(3)
            has_field = True
        else:
            field_name = "_raw"  # Default field for rex without explicit field
            has_field = False
            
        results.append({
            'command': 'rex',
            'has_field': has_field,
            'field_name': field_name,
            'position': match.start()
        })
    
    return results

def analyze_regex_field_usage(line: str) -> List[Dict]:
    """Analyze regex commands for field usage."""
    results = []
    
    # Find all regex commands
    regex_pattern = re.compile(r'\bregex\b', re.IGNORECASE)
    
    for match in regex_pattern.finditer(line):
        start = match.end()
        
        # For regex, the field often comes first or uses field= syntax
        # Pattern 1: regex fieldname=pattern
        # Pattern 2: regex field=fieldname pattern
        
        search_end = min(start + 300, len(line))
        next_pipe = line.find('|', start)
        if next_pipe != -1 and next_pipe < search_end:
            search_end = next_pipe
            
        search_text = line[start:search_end]
        
        # Look for field= pattern
        field_eq_pattern = re.compile(
            r'\s+field\s*=\s*(?:'
            r'([^\s"\']+)|'  # Unquoted field name
            r'"([^"]+)"|'     # Double-quoted field name
            r"'([^']+)')"     # Single-quoted field name
        )
        
        field_match = field_eq_pattern.search(search_text)
        
        if field_match:
            field_name = field_match.group(1) or field_match.group(2) or field_match.group(3)
            has_field = True
        else:
            # Look for pattern like: regex fieldname="pattern" or regex fieldname='pattern'
            direct_field_pattern = re.compile(r'^\s+([a-zA-Z_][\w\.\-]*)\s*[=!]')
            direct_match = direct_field_pattern.search(search_text)
            
            if direct_match and direct_match.group(1).lower() not in ['field', 'mode', 'max_match']:
                field_name = direct_match.group(1)
                has_field = True
            else:
                field_name = "_raw"  # Default field
                has_field = False
        
        results.append({
            'command': 'regex',
            'has_field': has_field,
            'field_name': field_name,
            'position': match.start()
        })
    
    return results

def analyze_file(filepath: Path) -> Dict:
    """Analyze the entire file for rex and regex field usage."""
    
    stats = {
        'total_lines': 0,
        'total_lines_with_commands': 0,
        'rex': {
            'total': 0,
            'without_field': 0,
            'with_field_raw': 0,
            'with_other_field': 0,
            'field_names': Counter(),
            'examples_without_field': [],
            'examples_with_raw': [],
            'examples_with_other': []
        },
        'regex': {
            'total': 0,
            'without_field': 0,
            'with_field_raw': 0,
            'with_other_field': 0,
            'field_names': Counter(),
            'examples_without_field': [],
            'examples_with_raw': [],
            'examples_with_other': []
        }
    }
    
    lines_with_rex = set()
    lines_with_regex = set()
    
    with filepath.open('r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
                
            stats['total_lines'] += 1
            
            # Analyze rex commands
            rex_results = analyze_rex_field_usage(line)
            if rex_results:
                lines_with_rex.add(line_num)
                
            for result in rex_results:
                stats['rex']['total'] += 1
                stats['rex']['field_names'][result['field_name']] += 1
                
                if not result['has_field']:
                    # No field specified - defaults to _raw
                    stats['rex']['without_field'] += 1
                    
                    # Collect examples
                    if len(stats['rex']['examples_without_field']) < 5:
                        start = max(0, result['position'] - 20)
                        end = min(len(line), result['position'] + 150)
                        excerpt = line[start:end]
                        if start > 0:
                            excerpt = "..." + excerpt
                        if end < len(line):
                            excerpt = excerpt + "..."
                        
                        stats['rex']['examples_without_field'].append({
                            'line_num': line_num,
                            'excerpt': excerpt
                        })
                elif result['field_name'] == '_raw':
                    # Explicitly specified _raw
                    stats['rex']['with_field_raw'] += 1
                    
                    # Collect examples
                    if len(stats['rex']['examples_with_raw']) < 5:
                        start = max(0, result['position'] - 20)
                        end = min(len(line), result['position'] + 150)
                        excerpt = line[start:end]
                        if start > 0:
                            excerpt = "..." + excerpt
                        if end < len(line):
                            excerpt = excerpt + "..."
                        
                        stats['rex']['examples_with_raw'].append({
                            'line_num': line_num,
                            'field': result['field_name'],
                            'excerpt': excerpt
                        })
                else:
                    # Other field specified
                    stats['rex']['with_other_field'] += 1
                    
                    # Collect examples
                    if len(stats['rex']['examples_with_other']) < 5:
                        start = max(0, result['position'] - 20)
                        end = min(len(line), result['position'] + 150)
                        excerpt = line[start:end]
                        if start > 0:
                            excerpt = "..." + excerpt
                        if end < len(line):
                            excerpt = excerpt + "..."
                        
                        stats['rex']['examples_with_other'].append({
                            'line_num': line_num,
                            'field': result['field_name'],
                            'excerpt': excerpt
                        })
            
            # Analyze regex commands
            regex_results = analyze_regex_field_usage(line)
            if regex_results:
                lines_with_regex.add(line_num)
                
            for result in regex_results:
                stats['regex']['total'] += 1
                stats['regex']['field_names'][result['field_name']] += 1
                
                if not result['has_field']:
                    # No field specified - defaults to _raw
                    stats['regex']['without_field'] += 1
                    
                    # Collect examples
                    if len(stats['regex']['examples_without_field']) < 5:
                        start = max(0, result['position'] - 20)
                        end = min(len(line), result['position'] + 150)
                        excerpt = line[start:end]
                        if start > 0:
                            excerpt = "..." + excerpt
                        if end < len(line):
                            excerpt = excerpt + "..."
                        
                        stats['regex']['examples_without_field'].append({
                            'line_num': line_num,
                            'excerpt': excerpt
                        })
                elif result['field_name'] == '_raw':
                    # Explicitly specified _raw
                    stats['regex']['with_field_raw'] += 1
                    
                    # Collect examples
                    if len(stats['regex']['examples_with_raw']) < 5:
                        start = max(0, result['position'] - 20)
                        end = min(len(line), result['position'] + 150)
                        excerpt = line[start:end]
                        if start > 0:
                            excerpt = "..." + excerpt
                        if end < len(line):
                            excerpt = excerpt + "..."
                        
                        stats['regex']['examples_with_raw'].append({
                            'line_num': line_num,
                            'field': result['field_name'],
                            'excerpt': excerpt
                        })
                else:
                    # Other field specified
                    stats['regex']['with_other_field'] += 1
                    
                    # Collect examples
                    if len(stats['regex']['examples_with_other']) < 5:
                        start = max(0, result['position'] - 20)
                        end = min(len(line), result['position'] + 150)
                        excerpt = line[start:end]
                        if start > 0:
                            excerpt = "..." + excerpt
                        if end < len(line):
                            excerpt = excerpt + "..."
                        
                        stats['regex']['examples_with_other'].append({
                            'line_num': line_num,
                            'field': result['field_name'],
                            'excerpt': excerpt
                        })
    
    # Count unique lines with commands
    stats['total_lines_with_commands'] = len(lines_with_rex | lines_with_regex)
    
    return stats

def print_report(stats: Dict):
    """Print a formatted report of the analysis."""
    
    print("\n" + "="*70)
    print("SPL REX/REGEX FIELD USAGE ANALYSIS")
    print("="*70)
    
    print(f"\nTotal lines analyzed: {stats['total_lines']:,}")
    print(f"Lines containing rex/regex commands: {stats['total_lines_with_commands']:,}")
    
    # Rex statistics
    print("\n" + "-"*50)
    print("REX COMMAND ANALYSIS")
    print("-"*50)
    
    rex_total = stats['rex']['total']
    rex_without = stats['rex']['without_field']
    rex_with_raw = stats['rex']['with_field_raw']
    rex_with_other = stats['rex']['with_other_field']
    
    print(f"Total rex commands: {rex_total:,}")
    print(f"  Without field specification (implicit _raw): {rex_without:,} ({rex_without/rex_total*100:.1f}%)" if rex_total > 0 else "  Without field: 0")
    print(f"  With field=_raw (explicit): {rex_with_raw:,} ({rex_with_raw/rex_total*100:.1f}%)" if rex_total > 0 else "  With field=_raw: 0")
    print(f"  With other fields: {rex_with_other:,} ({rex_with_other/rex_total*100:.1f}%)" if rex_total > 0 else "  With other fields: 0")
    
    print("\nTop 10 field names in rex:")
    for field, count in stats['rex']['field_names'].most_common(10):
        pct = count / rex_total * 100 if rex_total > 0 else 0
        print(f"  {field:30s} {count:8,} ({pct:5.1f}% of all rex)")
    
    print("\nExamples of rex WITHOUT field specification:")
    for ex in stats['rex']['examples_without_field'][:3]:
        print(f"  Line {ex['line_num']}:")
        print(f"    {ex['excerpt'][:100]}")
    
    print("\nExamples of rex WITH field=_raw:")
    for ex in stats['rex']['examples_with_raw'][:3]:
        print(f"  Line {ex['line_num']}: field={ex['field']}")
        print(f"    {ex['excerpt'][:100]}")
    
    print("\nExamples of rex WITH other fields:")
    for ex in stats['rex']['examples_with_other'][:3]:
        print(f"  Line {ex['line_num']}: field={ex['field']}")
        print(f"    {ex['excerpt'][:100]}")
    
    # Regex statistics
    print("\n" + "-"*50)
    print("REGEX COMMAND ANALYSIS")
    print("-"*50)
    
    regex_total = stats['regex']['total']
    regex_without = stats['regex']['without_field']
    regex_with_raw = stats['regex']['with_field_raw']
    regex_with_other = stats['regex']['with_other_field']
    
    print(f"Total regex commands: {regex_total:,}")
    print(f"  Without field specification (implicit _raw): {regex_without:,} ({regex_without/regex_total*100:.1f}%)" if regex_total > 0 else "  Without field: 0")
    print(f"  With field=_raw (explicit): {regex_with_raw:,} ({regex_with_raw/regex_total*100:.1f}%)" if regex_total > 0 else "  With field=_raw: 0")
    print(f"  With other fields: {regex_with_other:,} ({regex_with_other/regex_total*100:.1f}%)" if regex_total > 0 else "  With other fields: 0")
    
    print("\nTop 10 field names in regex:")
    for field, count in stats['regex']['field_names'].most_common(10):
        pct = count / regex_total * 100 if regex_total > 0 else 0
        print(f"  {field:30s} {count:8,} ({pct:5.1f}% of all regex)")
    
    print("\nExamples of regex WITHOUT field specification:")
    for ex in stats['regex']['examples_without_field'][:3]:
        print(f"  Line {ex['line_num']}:")
        print(f"    {ex['excerpt'][:100]}")
    
    print("\nExamples of regex WITH field=_raw:")
    for ex in stats['regex']['examples_with_raw'][:3]:
        print(f"  Line {ex['line_num']}: field={ex['field']}")
        print(f"    {ex['excerpt'][:100]}")
        
    print("\nExamples of regex WITH other fields:")
    for ex in stats['regex']['examples_with_other'][:3]:
        print(f"  Line {ex['line_num']}: field={ex['field']}")
        print(f"    {ex['excerpt'][:100]}")
    
    # Overall summary
    print("\n" + "="*70)
    print("SUMMARY TABLE")
    print("="*70)
    
    total_commands = rex_total + regex_total
    total_without = rex_without + regex_without
    total_with_raw = rex_with_raw + regex_with_raw
    total_with_other = rex_with_other + regex_with_other
    
    print("\n┌─────────────────────────────┬──────────┬──────────┬──────────┐")
    print("│ Category                    │    Rex   │  Regex   │  Total   │")
    print("├─────────────────────────────┼──────────┼──────────┼──────────┤")
    print(f"│ Total Commands              │ {rex_total:8,} │ {regex_total:8,} │ {total_commands:8,} │")
    print(f"│ Without field (implicit)    │ {rex_without:8,} │ {regex_without:8,} │ {total_without:8,} │")
    print(f"│ With field=_raw (explicit)  │ {rex_with_raw:8,} │ {regex_with_raw:8,} │ {total_with_raw:8,} │")
    print(f"│ With other fields           │ {rex_with_other:8,} │ {regex_with_other:8,} │ {total_with_other:8,} │")
    print("└─────────────────────────────┴──────────┴──────────┴──────────┘")
    
    print("\n┌─────────────────────────────┬──────────┬──────────┬──────────┐")
    print("│ Percentages                 │    Rex   │  Regex   │  Total   │")
    print("├─────────────────────────────┼──────────┼──────────┼──────────┤")
    if rex_total > 0 and regex_total > 0 and total_commands > 0:
        print(f"│ Without field (implicit)    │   {rex_without/rex_total*100:5.1f}% │   {regex_without/regex_total*100:5.1f}% │   {total_without/total_commands*100:5.1f}% │")
        print(f"│ With field=_raw (explicit)  │   {rex_with_raw/rex_total*100:5.1f}% │   {regex_with_raw/regex_total*100:5.1f}% │   {total_with_raw/total_commands*100:5.1f}% │")
        print(f"│ With other fields           │   {rex_with_other/rex_total*100:5.1f}% │   {regex_with_other/regex_total*100:5.1f}% │   {total_with_other/total_commands*100:5.1f}% │")
    print("└─────────────────────────────┴──────────┴──────────┴──────────┘")
    
    print("\nKey Findings:")
    if rex_total > 0:
        total_raw_usage = rex_without + rex_with_raw
        print(f"- Rex: {total_raw_usage:,} commands ({total_raw_usage/rex_total*100:.1f}%) operate on _raw field (implicit or explicit)")
    if regex_total > 0:
        total_raw_usage = regex_without + regex_with_raw
        print(f"- Regex: {total_raw_usage:,} commands ({total_raw_usage/regex_total*100:.1f}%) operate on _raw field (implicit or explicit)")
    
    # Save to JSON
    output_file = Path("field_usage_analysis.json")
    with output_file.open('w') as f:
        # Convert Counter objects to dict for JSON serialization
        json_stats = {
            'total_lines': stats['total_lines'],
            'total_lines_with_commands': stats['total_lines_with_commands'],
            'rex': {
                'total': stats['rex']['total'],
                'without_field': stats['rex']['without_field'],
                'with_field_raw': stats['rex']['with_field_raw'],
                'with_other_field': stats['rex']['with_other_field'],
                'field_names': dict(stats['rex']['field_names'].most_common()),
                'examples_without_field': stats['rex']['examples_without_field'][:3],
                'examples_with_raw': stats['rex']['examples_with_raw'][:3],
                'examples_with_other': stats['rex']['examples_with_other'][:3]
            },
            'regex': {
                'total': stats['regex']['total'],
                'without_field': stats['regex']['without_field'],
                'with_field_raw': stats['regex']['with_field_raw'],
                'with_other_field': stats['regex']['with_other_field'],
                'field_names': dict(stats['regex']['field_names'].most_common()),
                'examples_without_field': stats['regex']['examples_without_field'][:3],
                'examples_with_raw': stats['regex']['examples_with_raw'][:3],
                'examples_with_other': stats['regex']['examples_with_other'][:3]
            }
        }
        json.dump(json_stats, f, indent=2)
    
    print(f"\nDetailed results saved to: {output_file}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_field_usage.py <input_file>")
        sys.exit(1)
    
    input_file = Path(sys.argv[1])
    if not input_file.exists():
        print(f"Error: File not found: {input_file}")
        sys.exit(1)
    
    print(f"Analyzing field usage in: {input_file}")
    stats = analyze_file(input_file)
    print_report(stats)

if __name__ == "__main__":
    main()