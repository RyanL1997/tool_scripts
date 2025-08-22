#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_rex_usage.py

Analyzes rex command usage patterns in SPL queries based on official Splunk documentation.
Identifies usage of different rex functionalities like mode=sed, max_match, offset_field, etc.
"""

import sys
import re
import json
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional

class RexAnalyzer:
    """Analyzes rex command usage patterns."""
    
    def __init__(self):
        self.stats = {
            'total_lines': 0,
            'lines_with_rex': 0,
            'total_rex_commands': 0,
            'field_usage': Counter(),
            'mode_sed_usage': 0,
            'max_match_usage': Counter(),
            'offset_field_usage': 0,
            'extraction_patterns': 0,
            'named_groups': Counter(),
            'field_specified': 0,
            'default_field_raw': 0,
            'sed_operations': {
                'replace': 0,
                'substitute': 0,
                'flags': Counter()
            },
            'examples': {
                'mode_sed': [],
                'max_match': [],
                'offset_field': [],
                'extraction': [],
                'field_specification': []
            },
            'pattern_complexity': {
                'simple': 0,  # Basic patterns with single capture group
                'moderate': 0,  # 2-3 capture groups
                'complex': 0,  # 4+ capture groups or advanced features
            }
        }
    
    def find_rex_commands(self, line: str) -> List[Dict]:
        """Find all rex commands in a line."""
        rex_commands = []
        
        # Pattern to find rex commands (word boundary)
        rex_pattern = re.compile(r'\brex\b', re.IGNORECASE)
        
        for match in rex_pattern.finditer(line):
            start = match.start()
            end = match.end()
            
            # Find the end of this rex command (next pipe or end of line)
            next_pipe = line.find('|', end)
            if next_pipe == -1:
                command_text = line[start:]
            else:
                command_text = line[start:next_pipe]
            
            rex_commands.append({
                'position': start,
                'command': command_text.strip(),
                'full_line': line
            })
        
        return rex_commands
    
    def analyze_rex_command(self, command: str, line_num: int) -> Dict:
        """Analyze a single rex command for its features."""
        analysis = {
            'line_num': line_num,
            'has_field': False,
            'field_name': '_raw',
            'mode_sed': False,
            'sed_type': None,
            'sed_flags': [],
            'max_match': None,
            'offset_field': None,
            'named_groups': [],
            'pattern': None
        }
        
        # Check for field specification
        field_match = re.search(r'field\s*=\s*([^\s]+)', command, re.IGNORECASE)
        if field_match:
            analysis['has_field'] = True
            analysis['field_name'] = field_match.group(1).strip('"\'')
        
        # Check for mode=sed
        sed_match = re.search(r'mode\s*=\s*sed', command, re.IGNORECASE)
        if sed_match:
            analysis['mode_sed'] = True
            
            # Extract sed expression - handle various quote patterns
            # Try different patterns for sed expression
            sed_patterns = [
                r'mode\s*=\s*sed\s+field\s*=\s*\S+\s+""([^"]+)""',  # mode=sed field=X ""expr""
                r'field\s*=\s*\S+\s+mode\s*=\s*sed\s+""([^"]+)""',  # field=X mode=sed ""expr""
                r'mode\s*=\s*sed\s+""([^"]+)""',                     # mode=sed ""expr""
                r'mode\s*=\s*sed\s+["\']([^"\']+)["\']',            # mode=sed "expr" or 'expr'
            ]
            
            sed_expr = None
            for pattern in sed_patterns:
                sed_expr_match = re.search(pattern, command, re.IGNORECASE)
                if sed_expr_match:
                    sed_expr = sed_expr_match.group(1)
                    analysis['pattern'] = sed_expr
                    break
            
            if sed_expr:
                # Determine sed type (s for replace, y for substitute)
                if sed_expr.startswith('s/'):
                    analysis['sed_type'] = 'replace'
                    # Extract flags (g, or number)
                    parts = sed_expr.split('/')
                    if len(parts) >= 4:
                        flags = parts[-1]
                        if flags:
                            analysis['sed_flags'] = list(flags)
                elif sed_expr.startswith('y/'):
                    analysis['sed_type'] = 'substitute'
        
        # Check for max_match
        max_match_match = re.search(r'max_match\s*=\s*(\d+)', command, re.IGNORECASE)
        if max_match_match:
            analysis['max_match'] = int(max_match_match.group(1))
        
        # Check for offset_field
        offset_match = re.search(r'offset_field\s*=\s*([^\s]+)', command, re.IGNORECASE)
        if offset_match:
            analysis['offset_field'] = offset_match.group(1).strip('"\'')
        
        # Extract regex pattern and named groups (if not sed mode)
        if not analysis['mode_sed']:
            # Look for quoted patterns
            pattern_matches = re.findall(r'[""]([^""]+)[""]|["\']([^"\']+)["\']', command)
            if pattern_matches:
                # Get the first non-empty match
                for match in pattern_matches:
                    pattern = match[0] if match[0] else match[1]
                    if pattern and not pattern.startswith('mode=') and not pattern.startswith('field='):
                        analysis['pattern'] = pattern
                        
                        # Extract named groups
                        named_group_pattern = re.compile(r'\(\?<([^>]+)>')
                        named_groups = named_group_pattern.findall(pattern)
                        if named_groups:
                            analysis['named_groups'] = named_groups
                        
                        # Alternative named group syntax
                        named_group_pattern2 = re.compile(r'\(\?\'([^\']+)\'')
                        named_groups2 = named_group_pattern2.findall(pattern)
                        if named_groups2:
                            analysis['named_groups'].extend(named_groups2)
                        break
        
        return analysis
    
    def categorize_pattern_complexity(self, analysis: Dict) -> str:
        """Categorize pattern complexity based on features."""
        if not analysis['pattern']:
            return 'simple'
        
        named_groups_count = len(analysis['named_groups'])
        pattern = analysis['pattern']
        
        # Check for advanced features
        has_lookahead = bool(re.search(r'\(\?[=!]', pattern))
        has_lookbehind = bool(re.search(r'\(\?<[=!]', pattern))
        has_backreference = bool(re.search(r'\\[1-9]', pattern))
        
        if named_groups_count >= 4 or has_lookahead or has_lookbehind or has_backreference:
            return 'complex'
        elif named_groups_count >= 2:
            return 'moderate'
        else:
            return 'simple'
    
    def analyze_file(self, filepath: Path) -> None:
        """Analyze the entire file for rex usage patterns."""
        with filepath.open('r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                self.stats['total_lines'] += 1
                
                # Find rex commands in this line
                rex_commands = self.find_rex_commands(line)
                
                if rex_commands:
                    self.stats['lines_with_rex'] += 1
                
                for rex_cmd in rex_commands:
                    self.stats['total_rex_commands'] += 1
                    
                    # Analyze the command
                    analysis = self.analyze_rex_command(rex_cmd['command'], line_num)
                    
                    # Update statistics
                    if analysis['has_field']:
                        self.stats['field_specified'] += 1
                        self.stats['field_usage'][analysis['field_name']] += 1
                    else:
                        self.stats['default_field_raw'] += 1
                        self.stats['field_usage']['_raw'] += 1
                    
                    if analysis['mode_sed']:
                        self.stats['mode_sed_usage'] += 1
                        if analysis['sed_type']:
                            self.stats['sed_operations'][analysis['sed_type']] += 1
                        for flag in analysis['sed_flags']:
                            self.stats['sed_operations']['flags'][flag] += 1
                        
                        # Collect example
                        if len(self.stats['examples']['mode_sed']) < 5:
                            self.stats['examples']['mode_sed'].append({
                                'line_num': line_num,
                                'command': rex_cmd['command'][:150],
                                'sed_type': analysis['sed_type'],
                                'flags': analysis['sed_flags']
                            })
                    else:
                        self.stats['extraction_patterns'] += 1
                    
                    if analysis['max_match'] is not None:
                        self.stats['max_match_usage'][str(analysis['max_match'])] += 1
                        
                        # Collect example
                        if len(self.stats['examples']['max_match']) < 5:
                            self.stats['examples']['max_match'].append({
                                'line_num': line_num,
                                'command': rex_cmd['command'][:150],
                                'max_match': analysis['max_match']
                            })
                    
                    if analysis['offset_field']:
                        self.stats['offset_field_usage'] += 1
                        
                        # Collect example
                        if len(self.stats['examples']['offset_field']) < 5:
                            self.stats['examples']['offset_field'].append({
                                'line_num': line_num,
                                'command': rex_cmd['command'][:150],
                                'offset_field': analysis['offset_field']
                            })
                    
                    # Track named groups
                    for group in analysis['named_groups']:
                        self.stats['named_groups'][group] += 1
                    
                    # Categorize pattern complexity
                    if analysis['pattern']:
                        complexity = self.categorize_pattern_complexity(analysis)
                        self.stats['pattern_complexity'][complexity] += 1
                        
                        # Collect extraction examples
                        if not analysis['mode_sed'] and len(self.stats['examples']['extraction']) < 5:
                            self.stats['examples']['extraction'].append({
                                'line_num': line_num,
                                'pattern': analysis['pattern'][:100],
                                'named_groups': analysis['named_groups'][:5],
                                'complexity': complexity
                            })
    
    def generate_report(self) -> str:
        """Generate a markdown report of the analysis."""
        report = []
        report.append("# Rex Command Usage Analysis\n")
        report.append("## Executive Summary\n")
        
        total_rex = self.stats['total_rex_commands']
        
        report.append(f"- **Total SPL commands analyzed**: {self.stats['total_lines']:,}")
        report.append(f"- **Commands containing rex**: {self.stats['lines_with_rex']:,} ({self.stats['lines_with_rex']/self.stats['total_lines']*100:.2f}%)")
        report.append(f"- **Total rex command instances**: {total_rex:,}")
        report.append(f"- **Average rex commands per line (when present)**: {total_rex/self.stats['lines_with_rex']:.2f}" if self.stats['lines_with_rex'] > 0 else "")
        
        report.append("\n## Feature Usage Statistics\n")
        report.append("### Primary Functionality\n")
        report.append("| Feature | Count | Percentage |")
        report.append("|---------|-------|------------|")
        report.append(f"| **Field Extraction (default)** | {self.stats['extraction_patterns']:,} | {self.stats['extraction_patterns']/total_rex*100:.2f}% |")
        report.append(f"| **Sed Mode (replace/substitute)** | {self.stats['mode_sed_usage']:,} | {self.stats['mode_sed_usage']/total_rex*100:.2f}% |")
        
        report.append("\n### Optional Parameters\n")
        report.append("| Parameter | Count | Percentage | Description |")
        report.append("|-----------|-------|------------|-------------|")
        report.append(f"| **field=** specified | {self.stats['field_specified']:,} | {self.stats['field_specified']/total_rex*100:.2f}% | Explicit field specification |")
        report.append(f"| **max_match=** | {sum(self.stats['max_match_usage'].values()):,} | {sum(self.stats['max_match_usage'].values())/total_rex*100:.2f}% | Multiple match extraction |")
        report.append(f"| **offset_field=** | {self.stats['offset_field_usage']:,} | {self.stats['offset_field_usage']/total_rex*100:.2f}% | Position tracking |")
        
        report.append("\n### Field Usage Distribution\n")
        report.append("| Field | Count | Percentage |")
        report.append("|-------|-------|------------|")
        for field, count in self.stats['field_usage'].most_common(10):
            pct = count / total_rex * 100
            if field == '_raw':
                report.append(f"| **{field} (default)** | {count:,} | {pct:.2f}% |")
            else:
                report.append(f"| {field} | {count:,} | {pct:.2f}% |")
        
        if self.stats['mode_sed_usage'] > 0:
            report.append("\n### Sed Mode Operations\n")
            report.append("| Operation | Count | Percentage of Sed Commands |")
            report.append("|-----------|-------|----------------------------|")
            sed_total = self.stats['mode_sed_usage']
            report.append(f"| Replace (s///) | {self.stats['sed_operations']['replace']:,} | {self.stats['sed_operations']['replace']/sed_total*100:.2f}% |")
            report.append(f"| Substitute (y///) | {self.stats['sed_operations']['substitute']:,} | {self.stats['sed_operations']['substitute']/sed_total*100:.2f}% |")
            
            if self.stats['sed_operations']['flags']:
                report.append("\n#### Sed Flags Usage")
                report.append("| Flag | Count | Description |")
                report.append("|------|-------|-------------|")
                for flag, count in self.stats['sed_operations']['flags'].most_common():
                    if flag == 'g':
                        desc = "Global replacement"
                    elif flag.isdigit():
                        desc = f"Replace {flag}th occurrence"
                    else:
                        desc = "Other flag"
                    report.append(f"| {flag} | {count:,} | {desc} |")
        
        if sum(self.stats['max_match_usage'].values()) > 0:
            report.append("\n### max_match Values\n")
            report.append("| Value | Count | Description |")
            report.append("|-------|-------|-------------|")
            for value, count in sorted(self.stats['max_match_usage'].items(), key=lambda x: -x[1])[:10]:
                if value == '0':
                    desc = "Unlimited matches"
                elif value == '1':
                    desc = "Single match (default)"
                else:
                    desc = f"Up to {value} matches"
                report.append(f"| {value} | {count:,} | {desc} |")
        
        report.append("\n### Pattern Complexity\n")
        report.append("| Complexity | Count | Percentage | Description |")
        report.append("|------------|-------|------------|-------------|")
        complexity_total = sum(self.stats['pattern_complexity'].values())
        if complexity_total > 0:
            report.append(f"| Simple | {self.stats['pattern_complexity']['simple']:,} | {self.stats['pattern_complexity']['simple']/complexity_total*100:.2f}% | Single capture group or basic pattern |")
            report.append(f"| Moderate | {self.stats['pattern_complexity']['moderate']:,} | {self.stats['pattern_complexity']['moderate']/complexity_total*100:.2f}% | 2-3 capture groups |")
            report.append(f"| Complex | {self.stats['pattern_complexity']['complex']:,} | {self.stats['pattern_complexity']['complex']/complexity_total*100:.2f}% | 4+ groups or advanced features |")
        
        # Top named groups
        if self.stats['named_groups']:
            report.append("\n### Most Common Named Capture Groups\n")
            report.append("| Group Name | Count | Usage |")
            report.append("|------------|-------|-------|")
            for group, count in self.stats['named_groups'].most_common(15):
                report.append(f"| {group} | {count:,} | Field extraction |")
        
        # Examples section
        report.append("\n## Usage Examples\n")
        
        if self.stats['examples']['extraction']:
            report.append("### Field Extraction Examples\n")
            for ex in self.stats['examples']['extraction'][:3]:
                report.append(f"**Line {ex['line_num']}** (Complexity: {ex['complexity']})")
                report.append(f"```spl")
                report.append(f"{ex['pattern']}")
                report.append(f"```")
                if ex['named_groups']:
                    report.append(f"Named groups: {', '.join(ex['named_groups'])}\n")
        
        if self.stats['examples']['mode_sed']:
            report.append("### Sed Mode Examples\n")
            for ex in self.stats['examples']['mode_sed'][:3]:
                report.append(f"**Line {ex['line_num']}** (Type: {ex['sed_type']}, Flags: {ex['flags']})")
                report.append(f"```spl")
                report.append(f"{ex['command']}")
                report.append(f"```\n")
        
        if self.stats['examples']['max_match']:
            report.append("### max_match Examples\n")
            for ex in self.stats['examples']['max_match'][:3]:
                report.append(f"**Line {ex['line_num']}** (max_match={ex['max_match']})")
                report.append(f"```spl")
                report.append(f"{ex['command']}")
                report.append(f"```\n")
        
        if self.stats['examples']['offset_field']:
            report.append("### offset_field Examples\n")
            for ex in self.stats['examples']['offset_field'][:3]:
                report.append(f"**Line {ex['line_num']}** (offset_field={ex['offset_field']})")
                report.append(f"```spl")
                report.append(f"{ex['command']}")
                report.append(f"```\n")
        
        # Key insights
        report.append("\n## Key Insights\n")
        
        insights = []
        
        # Field extraction vs sed mode
        extraction_pct = self.stats['extraction_patterns']/total_rex*100 if total_rex > 0 else 0
        if extraction_pct > 95:
            insights.append(f"- **Primary Use Case**: {extraction_pct:.1f}% of rex commands are used for field extraction (not sed mode)")
        
        # Field specification
        default_raw_pct = self.stats['default_field_raw']/total_rex*100 if total_rex > 0 else 0
        if default_raw_pct > 50:
            insights.append(f"- **Default Field Usage**: {default_raw_pct:.1f}% of commands use the default _raw field")
        
        # Advanced features
        advanced_usage = sum(self.stats['max_match_usage'].values()) + self.stats['offset_field_usage']
        if advanced_usage > 0:
            advanced_pct = advanced_usage/total_rex*100
            insights.append(f"- **Advanced Features**: Only {advanced_pct:.2f}% use max_match or offset_field")
        
        # Sed mode insights
        if self.stats['mode_sed_usage'] > 0:
            sed_pct = self.stats['mode_sed_usage']/total_rex*100
            insights.append(f"- **Sed Mode**: {sed_pct:.2f}% of commands use sed mode for text manipulation")
        
        # Pattern complexity
        if complexity_total > 0:
            complex_pct = self.stats['pattern_complexity']['complex']/complexity_total*100
            if complex_pct > 10:
                insights.append(f"- **Complex Patterns**: {complex_pct:.1f}% of patterns use advanced regex features")
        
        for insight in insights:
            report.append(insight)
        
        report.append("\n## Conclusions\n")
        report.append("Based on the analysis of rex command usage:")
        report.append("1. The vast majority of rex commands are used for simple field extraction")
        report.append("2. Advanced features like max_match and offset_field are rarely used")
        report.append("3. Most patterns operate on the default _raw field")
        report.append("4. Sed mode functionality is underutilized compared to extraction")
        
        report.append("\n---")
        report.append(f"*Analysis based on {self.stats['total_lines']:,} SPL commands*")
        
        return "\n".join(report)
    
    def save_json_stats(self, filepath: Path) -> None:
        """Save detailed statistics to JSON file."""
        json_stats = {
            'total_lines': self.stats['total_lines'],
            'lines_with_rex': self.stats['lines_with_rex'],
            'total_rex_commands': self.stats['total_rex_commands'],
            'field_usage': dict(self.stats['field_usage'].most_common()),
            'mode_sed_usage': self.stats['mode_sed_usage'],
            'max_match_usage': dict(self.stats['max_match_usage']),
            'offset_field_usage': self.stats['offset_field_usage'],
            'extraction_patterns': self.stats['extraction_patterns'],
            'field_specified': self.stats['field_specified'],
            'default_field_raw': self.stats['default_field_raw'],
            'sed_operations': {
                'replace': self.stats['sed_operations']['replace'],
                'substitute': self.stats['sed_operations']['substitute'],
                'flags': dict(self.stats['sed_operations']['flags'])
            },
            'pattern_complexity': self.stats['pattern_complexity'],
            'top_named_groups': dict(self.stats['named_groups'].most_common(50))
        }
        
        with filepath.open('w') as f:
            json.dump(json_stats, f, indent=2)

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_rex_usage.py <input_file>")
        sys.exit(1)
    
    input_file = Path(sys.argv[1])
    if not input_file.exists():
        print(f"Error: File not found: {input_file}")
        sys.exit(1)
    
    print(f"Analyzing rex command usage in: {input_file}")
    
    analyzer = RexAnalyzer()
    analyzer.analyze_file(input_file)
    
    # Generate and save report
    report = analyzer.generate_report()
    
    # Save markdown report
    report_file = Path("rex_usage_analysis.md")
    with report_file.open('w') as f:
        f.write(report)
    print(f"Report saved to: {report_file}")
    
    # Save JSON statistics
    json_file = Path("rex_usage_stats.json")
    analyzer.save_json_stats(json_file)
    print(f"Detailed statistics saved to: {json_file}")
    
    # Print summary
    print("\n=== Summary ===")
    print(f"Total rex commands analyzed: {analyzer.stats['total_rex_commands']:,}")
    print(f"Field extraction: {analyzer.stats['extraction_patterns']:,} ({analyzer.stats['extraction_patterns']/analyzer.stats['total_rex_commands']*100:.1f}%)")
    print(f"Sed mode: {analyzer.stats['mode_sed_usage']:,} ({analyzer.stats['mode_sed_usage']/analyzer.stats['total_rex_commands']*100:.1f}%)")

if __name__ == "__main__":
    main()