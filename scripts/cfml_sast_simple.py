#!/usr/bin/env python3
import re
import sys
import argparse
import json
import shutil
from pathlib import Path

class CFMLSASTScanner:
    def __init__(self):
        # Load ignore patterns
        self.ignore_patterns = self.load_ignore_patterns()
        
        # Pre-compile regex patterns for performance
        self.rules = [
            {
                'id': 'CF-SQLI-001',
                'name': 'SQL Injection',
                'severity': 'HIGH',
                'pattern': re.compile(r'<cfquery[^>]*>.*?#[^#]+#.*?</cfquery>', re.IGNORECASE | re.DOTALL),
                'exclude': re.compile(r'<cfqueryparam', re.IGNORECASE),
                'description': 'Possible SQL Injection (<cfquery> without <cfqueryparam>)'
            },
            {
                'id': 'CF-XSS-001',
                'name': 'XSS',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'#(form|url)\.[^#]+#', re.IGNORECASE),
                'exclude': re.compile(r'EncodeForHTML\(', re.IGNORECASE),
                'description': 'Potential XSS (form/url variable unencoded)'
            },
            {
                'id': 'CF-UPLOAD-001',
                'name': 'Unsafe Upload',
                'severity': 'HIGH',
                'pattern': re.compile(r'<cffile\s+action\s*=\s*["\']upload["\'][^>]*>', re.IGNORECASE),
                'exclude': re.compile(r'accept\s*=|nameconflict\s*=', re.IGNORECASE),
                'description': 'Unsafe file upload without validation'
            },
            {
                'id': 'CF-EXEC-001',
                'name': 'Command Execution',
                'severity': 'HIGH',
                'pattern': re.compile(r'(<cfexecute|Runtime\.exec)', re.IGNORECASE),
                'exclude': None,
                'description': 'Command execution detected'
            },
            {
                'id': 'CF-INCLUDE-001',
                'name': 'Dynamic Include',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'<cfinclude\s+template\s*=\s*["\'][^"\']*#[^#]+#[^"\']*["\']', re.IGNORECASE),
                'exclude': None,
                'description': 'Dynamic include with user input'
            },
            {
                'id': 'CF-CRYPTO-001',
                'name': 'Weak Crypto',
                'severity': 'LOW',
                'pattern': re.compile(r'(MessageDigest|MD5|SHA1)', re.IGNORECASE),
                'exclude': None,
                'description': 'Weak cryptographic algorithm'
            },
            {
                'id': 'CF-EVAL-001',
                'name': 'Eval Abuse',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'evaluate\s*\(', re.IGNORECASE),
                'exclude': None,
                'description': 'Dynamic code evaluation'
            },
            # CFScript patterns
            {
                'id': 'CF-SQLI-002',
                'name': 'CFScript SQL Injection',
                'severity': 'HIGH',
                'pattern': re.compile(r'queryExecute\s*\([^)]*[+&][^)]*\)', re.IGNORECASE),
                'exclude': re.compile(r'queryExecute\s*\([^,]+,\s*\[', re.IGNORECASE),
                'description': 'SQL Injection in queryExecute() without params'
            },
            {
                'id': 'CF-XSS-002',
                'name': 'CFScript XSS',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'writeOutput\s*\(\s*(form|url|arguments)\.', re.IGNORECASE),
                'exclude': re.compile(r'encodeForHTML\(', re.IGNORECASE),
                'description': 'Unencoded output in CFScript'
            },
            {
                'id': 'CF-EXEC-002',
                'name': 'CFScript Command Execution',
                'severity': 'HIGH',
                'pattern': re.compile(r'cfexecute\s*\(', re.IGNORECASE),
                'exclude': None,
                'description': 'Command execution in CFScript'
            },
            {
                'id': 'CF-INCLUDE-002',
                'name': 'CFScript Dynamic Include',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'include\s*\([^)]*[+&].*?\)', re.IGNORECASE),
                'exclude': None,
                'description': 'Dynamic include in CFScript'
            },
            {
                'id': 'CF-EVAL-002',
                'name': 'CFScript Eval',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'evaluate\s*\([^)]*[+&].*?\)', re.IGNORECASE),
                'exclude': None,
                'description': 'Dynamic evaluation in CFScript'
            }
        ]
        self.findings = []
        self.scanned_count = 0
    
    def load_ignore_patterns(self):
        """Load patterns from .sastignore file"""
        ignore_patterns = []
        try:
            ignore_file = Path('.sastignore')
            if ignore_file.exists():
                with open(ignore_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Convert glob patterns to regex
                            pattern = line.replace('*', '.*').replace('?', '.')
                            ignore_patterns.append(re.compile(pattern, re.IGNORECASE))
        except Exception as e:
            print(f"Warning: Error loading .sastignore: {e}", file=sys.stderr)
        return ignore_patterns
    
    def should_ignore_file(self, file_path):
        """Check if file should be ignored based on .sastignore patterns"""
        file_str = str(file_path).replace('\\', '/')
        for pattern in self.ignore_patterns:
            if pattern.search(file_str):
                return True
        return False
    
    def should_ignore_finding(self, finding):
        """Check if finding should be ignored based on patterns"""
        # Check file-level ignores
        if self.should_ignore_file(finding['file']):
            return True
        
        # Check rule-specific ignores (format: rule_id:file_pattern)
        finding_key = f"{finding['rule_id']}:{finding['file']}"
        for pattern in self.ignore_patterns:
            if pattern.search(finding_key):
                return True
        
        return False

    def scan_file(self, file_path):
        try:
            # Validate and resolve path to prevent traversal
            resolved_path = Path(file_path).resolve()
            # Allow files in current directory and subdirectories
            try:
                resolved_path.relative_to(Path.cwd().resolve())
            except ValueError:
                return  # Skip files outside current directory
            
            # Check if file should be ignored
            if self.should_ignore_file(file_path):
                return
            
            # Skip very large files for performance (>5MB)
            if resolved_path.stat().st_size > 5 * 1024 * 1024:
                print(f"Warning: Skipping large file {file_path} (>5MB)", file=sys.stderr)
                return
            
            with open(resolved_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (FileNotFoundError, PermissionError):
            print(f"Warning: Cannot access {file_path}", file=sys.stderr)
            return
        except UnicodeDecodeError:
            print(f"Warning: Cannot decode {file_path} (binary file?)", file=sys.stderr)
            return
        except Exception as e:
            print(f"Error scanning {file_path}: {e}", file=sys.stderr)
            return

        for rule in self.rules:
            try:
                # Use pre-compiled pattern for better performance
                matches = rule['pattern'].finditer(content)
                for match in matches:
                    try:
                        if rule['exclude'] and rule['exclude'].search(match.group()):
                            continue
                        
                        line_num = content[:match.start()].count('\n') + 1
                        finding = {
                            'file': str(file_path),
                            'line': line_num,
                            'rule_id': rule['id'],
                            'severity': rule['severity'],
                            'description': rule['description'],
                            'match': match.group()[:100]
                        }
                        
                        # Check if finding should be ignored
                        if not self.should_ignore_finding(finding):
                            self.findings.append(finding)
                    except Exception as e:
                        print(f"Warning: Error processing match in {file_path}: {e}", file=sys.stderr)
                        continue
            except Exception as e:
                print(f"Warning: Error applying rule {rule['id']} to {file_path}: {e}", file=sys.stderr)
                continue

    def scan_files(self, file_paths):
        cfml_extensions = {'.cfm', '.cfc', '.cfml', '.cfinclude', '.js'}
        self.scanned_count = 0
        
        for file_path in file_paths:
            try:
                path = Path(file_path).resolve()
                # Security: Only scan files within current directory
                try:
                    path.relative_to(Path.cwd().resolve())
                    path_ok = True
                except ValueError:
                    path_ok = False
                
                if (path_ok and path.exists() and path.suffix.lower() in cfml_extensions):
                    self.scan_file(path)
                    self.scanned_count += 1
                elif not path.exists():
                    print(f"Warning: File not found: {file_path}", file=sys.stderr)
                elif path.suffix.lower() not in cfml_extensions:
                    print(f"Warning: Skipping non-CFML file: {file_path}", file=sys.stderr)
            except Exception as e:
                print(f"Error processing {file_path}: {e}", file=sys.stderr)
                continue
        
        if self.scanned_count == 0:
            print("Warning: No valid CFML files were scanned", file=sys.stderr)

    def print_results(self, json_output=False, sarif_output=False):
        try:
            if sarif_output:
                print(json.dumps(self.generate_sarif(), indent=2))
                return False
            
            if json_output:
                print(json.dumps(self.findings, indent=2))
                return False

            high = sum(1 for f in self.findings if f['severity'] == 'HIGH')
            medium = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')
            low = sum(1 for f in self.findings if f['severity'] == 'LOW')

            print("=== CFML SAST (edited files) ===")
            print(f"Files scanned: {self.scanned_count}")
            print(f"Findings: High={high}  Medium={medium}  Low={low}")

            for finding in sorted(self.findings, key=lambda x: (x['severity'], x['file'], x['line'])):
                print(f"- [{finding['severity']}] {finding['rule_id']} :: {finding['file']}:{finding['line']} – {finding['description']}")

            print("Scan complete.")
            return high > 0
        except Exception as e:
            print(f"Error generating results: {e}", file=sys.stderr)
            return False
    
    def generate_sarif(self):
        """Generate SARIF 2.1.0 format output"""
        # Convert findings to SARIF results
        results = []
        for finding in self.findings:
            # Map severity to SARIF levels
            level_map = {'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note'}
            
            result = {
                "ruleId": finding['rule_id'],
                "level": level_map.get(finding['severity'], 'warning'),
                "message": {
                    "text": finding['description']
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding['file'].replace('\\', '/')
                        },
                        "region": {
                            "startLine": finding['line']
                        }
                    }
                }]
            }
            results.append(result)
        
        # Generate SARIF document
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CFML SAST Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/codeventuregit/CF-SAST",
                        "rules": self.generate_sarif_rules()
                    }
                },
                "results": results
            }]
        }
        return sarif
    
    def generate_sarif_rules(self):
        """Generate SARIF rule definitions"""
        rules = []
        for rule in self.rules:
            sarif_rule = {
                "id": rule['id'],
                "name": rule['name'],
                "shortDescription": {
                    "text": rule['description']
                },
                "fullDescription": {
                    "text": rule['description']
                },
                "defaultConfiguration": {
                    "level": "error" if rule['severity'] == 'HIGH' else "warning" if rule['severity'] == 'MEDIUM' else "note"
                },
                "properties": {
                    "security-severity": "9.0" if rule['severity'] == 'HIGH' else "5.0" if rule['severity'] == 'MEDIUM' else "2.0"
                }
            }
            rules.append(sarif_rule)
        return rules
    
    def get_finding_key(self, finding):
        """Generate unique key for finding (file:line:rule_id)"""
        return f"{finding['file']}:{finding['line']}:{finding['rule_id']}"
    
    def load_baseline(self, baseline_file):
        """Load baseline findings from file"""
        try:
            with open(baseline_file, 'r', encoding='utf-8') as f:
                baseline_data = json.load(f)
                return {self.get_finding_key(finding) for finding in baseline_data}
        except FileNotFoundError:
            return set()
        except Exception as e:
            print(f"Warning: Error loading baseline {baseline_file}: {e}", file=sys.stderr)
            return set()
    
    def apply_baseline(self, baseline_file):
        """Filter out findings that exist in baseline"""
        baseline_keys = self.load_baseline(baseline_file)
        if not baseline_keys:
            return
        
        original_count = len(self.findings)
        self.findings = [f for f in self.findings if self.get_finding_key(f) not in baseline_keys]
        suppressed_count = original_count - len(self.findings)
        
        if suppressed_count > 0:
            print(f"Baseline: Suppressed {suppressed_count} existing findings", file=sys.stderr)
    
    def update_baseline(self, baseline_file):
        """Update baseline file with current findings"""
        try:
            baseline_path = Path(baseline_file)
            
            # Create backup if baseline exists
            if baseline_path.exists():
                backup_path = baseline_path.with_suffix(baseline_path.suffix + '.bak')
                shutil.copy2(baseline_path, backup_path)
                print(f"Backup created: {backup_path}", file=sys.stderr)
            
            # Write current findings as new baseline
            with open(baseline_path, 'w', encoding='utf-8') as f:
                json.dump(self.findings, f, indent=2)
            
            print(f"Baseline updated: {len(self.findings)} findings saved to {baseline_file}")
            return 0
        except Exception as e:
            print(f"Error updating baseline: {e}", file=sys.stderr)
            return 1

def main():
    try:
        parser = argparse.ArgumentParser(description='CFML SAST Scanner')
        parser.add_argument('--files', nargs='+', help='Files to scan')
        parser.add_argument('--fail-on-high', action='store_true', help='Exit 1 if high severity issues found')
        parser.add_argument('--json-out', action='store_true', help='Output JSON format')
        parser.add_argument('--sarif', action='store_true', help='Output SARIF 2.1.0 format')
        parser.add_argument('--init-ignore', action='store_true', help='Create default .sastignore file')
        parser.add_argument('--baseline', metavar='FILE', help='Create or use baseline file to suppress existing findings')
        parser.add_argument('--update-baseline', action='store_true', help='Update existing baseline with current findings')
        
        args = parser.parse_args()
        
        # Handle --init-ignore flag
        if args.init_ignore:
            return create_default_sastignore()
        
        # Handle baseline operations
        if args.update_baseline and not args.baseline:
            print("Error: --update-baseline requires --baseline FILE", file=sys.stderr)
            return 1
        
        if not args.files:
            print("Error: No files specified. Use --files *.cfm *.cfc", file=sys.stderr)
            return 1

        scanner = CFMLSASTScanner()
        scanner.scan_files(args.files)
        
        # Handle baseline operations
        if args.baseline:
            if args.update_baseline:
                return scanner.update_baseline(args.baseline)
            else:
                scanner.apply_baseline(args.baseline)
        
        has_high = scanner.print_results(args.json_out, args.sarif)
        
        if args.fail_on_high and has_high:
            return 1
        return 0
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        return 1

def create_default_sastignore():
    """Create a default .sastignore file"""
    ignore_content = '''# CFML SAST Ignore Patterns
# Lines starting with # are comments

# Ignore test files
*test*
*Test*
*/tests/*
*/spec/*

# Ignore third-party libraries
*/lib/*
*/vendor/*
*/node_modules/*
*/external/*

# Ignore generated files
*generated*
*auto*
*.min.cfm
*.min.cfc

# Ignore specific rules in certain files
# CF-XSS-001:*/admin/*
# CF-SQLI-001:*/legacy/*

# Ignore development/debug files
*debug*
*temp*
*tmp*
*.bak

# Ignore documentation
*/docs/*
*.md
*.txt
'''
    
    try:
        if Path('.sastignore').exists():
            print("Warning: .sastignore already exists", file=sys.stderr)
            return 1
        
        with open('.sastignore', 'w', encoding='utf-8') as f:
            f.write(ignore_content)
        
        print("Created .sastignore file with default patterns")
        print("Edit .sastignore to customize ignore patterns for your project")
        return 0
    except Exception as e:
        print(f"Error creating .sastignore: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())