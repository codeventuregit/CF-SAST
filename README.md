# CFML SAST Scanner

🔒 **Lightweight security scanner for ColdFusion applications** - Detects vulnerabilities in changed files only.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

## Features

- **Zero dependencies** - Uses only Python standard library
- **Git-aware** - Scans only changed/modified files
- **CFScript support** - Detects modern CFML syntax vulnerabilities
- **Fast execution** - Pre-compiled patterns, 50-70% performance boost
- **Enterprise ready** - SARIF output, baseline suppression, ignore patterns
- **Pre-push integration** - Secure shell scripts for Git hooks
- **VS Code extension** - Enhanced with baseline and ignore management
- **Multiple output formats** - Console, JSON, and SARIF output

## Security Rules

### Tag-Based Detection
| Rule ID | Severity | Description |
|---------|----------|-------------|
| CF-SQLI-001 | HIGH | SQL Injection in `<cfquery>` without `<cfqueryparam>` |
| CF-XSS-001 | MEDIUM | Unencoded form/url variables (missing `EncodeForHTML()`) |
| CF-UPLOAD-001 | HIGH | Unsafe file uploads without validation |
| CF-EXEC-001 | HIGH | Command execution via `<cfexecute>` or `Runtime.exec` |
| CF-INCLUDE-001 | MEDIUM | Dynamic includes with user input |
| CF-CRYPTO-001 | LOW | Weak cryptographic algorithms (MD5, SHA1) |
| CF-EVAL-001 | MEDIUM | Dynamic code evaluation with `evaluate()` |

### CFScript Detection (NEW)
| Rule ID | Severity | Description |
|---------|----------|-------------|
| CF-SQLI-002 | HIGH | SQL Injection in `queryExecute()` without params |
| CF-XSS-002 | MEDIUM | Unencoded output in `writeOutput()` |
| CF-EXEC-002 | HIGH | Command execution via `cfexecute()` |
| CF-INCLUDE-002 | MEDIUM | Dynamic includes in CFScript |
| CF-EVAL-002 | MEDIUM | Dynamic evaluation in CFScript |

## Installation

### Option 1: One-Click Install (Recommended)
```bash
# Navigate to your ColdFusion project
cd C:\path\to\your-coldfusion-project

# Download and run installer
py -3 -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/codeventuregit/CF-SAST/main/install.py', 'install.py')"
py -3 install.py
```

### Option 2: VS Code Extension
1. Install "CFML SAST Scanner" from VS Code Marketplace
2. Run command: `CFML SAST: Install Git Hooks`
3. Start scanning files!

### Option 3: Manual Installation
```bash
# Create CFSAST folder
mkdir CFSAST

# Download scanner
py -3 -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/codeventuregit/CF-SAST/main/scripts/cfml_sast_simple.py', 'CFSAST/cfml_sast_simple.py')"

# Test installation
py -3 CFSAST/cfml_sast_simple.py --files *.cfm
```

## Usage

### Command Line Scanning

**Basic Scanning:**
```bash
# Scan specific files
py -3 CFSAST/cfml_sast_simple.py --files login.cfm user.cfc

# Scan all CFML files in current directory
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc *.cfml

# Scan specific directories
py -3 CFSAST/cfml_sast_simple.py --files web/*.cfm components/*.cfc
```

**Output Formats:**
```bash
# JSON output
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --json-out

# SARIF output (enterprise integration)
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --sarif

# Save to file
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --sarif > results.sarif
```

**PowerShell (All Files Recursively):**
```powershell
# Scan all CFML files in project
$files = Get-ChildItem -Recurse -Include *.cfm,*.cfc,*.cfml | ForEach-Object {$_.FullName}
py -3 CFSAST/cfml_sast_simple.py --files $files --json-out > full_scan.json
```

**Advanced Options:**
```bash
# Fail CI on high-severity issues
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --fail-on-high

# Create baseline to suppress existing findings
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json --update-baseline

# Scan with baseline (only show NEW findings)
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json

# Create .sastignore file for noise management
py -3 CFSAST/cfml_sast_simple.py --init-ignore
```

### VS Code Extension Usage
- **Right-click scanning**: Right-click any `.cfm`, `.cfc`, or `.cfml` file → "CFML SAST: Scan Current File"
- **Workspace scanning**: Command Palette (`Ctrl+Shift+P`) → "CFML SAST: Scan Changed Files"
- **Baseline management**: "CFML SAST: Create Baseline" to suppress existing findings
- **Ignore patterns**: "CFML SAST: Create .sastignore File" for noise management
- **Visual results**: View findings in formatted webview panel with helpful tips
- **One-click installation**: Run "CFML SAST: Install Git Hooks" command

### Git Integration
The scanner automatically runs on `git push` and scans only changed files:
```bash
git add .
git commit -m "Updated user authentication"
git push  # ← SAST scanner runs here
```

### Sample Output
```
=== CFML SAST (edited files) ===
Files scanned: 3
Findings: High=1  Medium=2  Low=0
- [HIGH] CF-SQLI-001 :: web/user.cfm:42 – Possible SQL Injection (<cfquery> without <cfqueryparam>)
- [MEDIUM] CF-XSS-001 :: web/comment.cfm:17 – Potential XSS (form/url variable unencoded)
- [MEDIUM] CF-INCLUDE-001 :: web/admin.cfm:89 – Dynamic include with user input
✅ Scan complete.
```

## CI/CD Integration (Optional)

**For teams wanting automated security scanning in their pipelines:**

```yaml
# .github/workflows/security-scan.yml
name: CFML Security Scan
on: [push, pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.8'
    - name: Install CFML SAST
      run: |
        python -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/codeventuregit/CF-SAST/main/install.py', 'install.py')"
        python install.py
    - name: Run Security Scan
      run: python CFSAST/cfml_sast_simple.py --files $(git diff --name-only ${{ github.event.before }} ${{ github.sha }}) --fail-on-high
```

## Project Structure After Installation
```
your-coldfusion-project/
├── web/
│   ├── login.cfm
│   └── admin/
├── components/
│   └── User.cfc
├── CFSAST/
│   ├── cfml_sast_simple.py    ← Scanner installed here
│   └── prepush.sh             ← Pre-push script
├── .git/
│   └── hooks/
│       └── pre-push           ← Git hook (optional)
└── install.py                 ← Installer (can be deleted)
```

## Supported File Types
- `.cfm` - ColdFusion Markup (tags + CFScript)
- `.cfc` - ColdFusion Components (tags + CFScript)
- `.cfml` - ColdFusion Markup Language
- `.cfinclude` - ColdFusion Include files
- `.js` - JavaScript (for Runtime.exec detection)

## Noise Management

### .sastignore File
Create a `.sastignore` file to exclude files or directories:
```
# Ignore test files
*test*
*/tests/*

# Ignore third-party libraries
*/vendor/*
*/lib/*

# Ignore specific rules in certain files
CF-XSS-001:*/admin/*
CF-SQLI-001:*/legacy/*

# Ignore generated files
*generated*
*.min.cfm
```

### Baseline Suppression
Suppress existing findings to focus on new issues:
```bash
# Create baseline from current state
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json --update-baseline

# Future scans only show NEW findings
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json
```

## Batch Scripts

**Create `scan_all.bat` for easy scanning:**
```batch
@echo off
echo Scanning all CFML files...
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc *.cfml
pause
```

**Create `scan_sarif.bat` for enterprise output:**
```batch
@echo off
echo Scanning to SARIF file...
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc *.cfml --sarif > scan_results_%date%.sarif
echo SARIF results saved for enterprise tools
pause
```

**Create `setup_baseline.bat` for initial setup:**
```batch
@echo off
echo Creating baseline to suppress existing findings...
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc *.cfml --baseline .sast-baseline.json --update-baseline
echo Baseline created - future scans will only show NEW findings
pause
```

**PowerShell script `comprehensive_scan.ps1`:**
```powershell
# Comprehensive scan with separate file type results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$fileTypes = @("*.cfm", "*.cfc", "*.cfml")

foreach ($type in $fileTypes) {
    $extension = $type.Replace("*.", "")
    $files = Get-ChildItem -Recurse -Filter $type | ForEach-Object {$_.FullName}
    if ($files) {
        py -3 CFSAST/cfml_sast_simple.py --files $files --json-out > "${extension}_scan_$timestamp.json"
        Write-Host "$extension files scanned - results saved"
    }
}
```

## Configuration

**Disable pre-push hook temporarily:**
```bash
git push --no-verify
```

**Create ignore patterns:**
```bash
py -3 CFSAST/cfml_sast_simple.py --init-ignore
```

**Update baseline after security fixes:**
```bash
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json --update-baseline
```

## Troubleshooting

**Python not found?**
```bash
sudo apt install python3  # Ubuntu/Debian
brew install python3      # macOS
```

**Hook not running?**
```bash
chmod +x .git/hooks/pre-push
git config core.hooksPath .git/hooks
```

**No files detected?**
```bash
git branch -vv  # Check upstream branch
git status      # Check staged changes
```

**False positives?**
- Create `.sastignore` file to exclude problematic files
- Use baseline suppression to focus on new findings
- Use `--sarif` output for detailed analysis in enterprise tools

## Enterprise Features

### SARIF Output
Generate SARIF 2.1.0 reports for enterprise security tools:
```bash
# GitHub Advanced Security integration
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --sarif > results.sarif

# Azure DevOps integration
py -3 CFSAST/cfml_sast_simple.py --files $(git diff --name-only) --sarif --fail-on-high
```

### VS Code Configuration
```json
{
  "cfmlSast.outputFormat": "sarif",
  "cfmlSast.useBaseline": true,
  "cfmlSast.showIgnoredFiles": true
}
```

## Performance Optimizations

- **Pre-compiled regex patterns** - 50-70% faster scanning
- **File size limits** - Skips files >5MB automatically
- **Smart filtering** - Only scans CFML files
- **Memory efficient** - Handles large codebases safely

## Requirements

- Python 3.6+
- Git (for changed file detection)
- ColdFusion files (`.cfm`, `.cfc`, `.cfml`)

## What's New

### v1.1.0 - Enhanced Security & Enterprise Features
- ✅ **CFScript Support** - Detects modern CFML syntax vulnerabilities
- ✅ **SARIF Output** - Enterprise security tool integration
- ✅ **Baseline Suppression** - Focus on new findings only
- ✅ **Noise Management** - .sastignore file support
- ✅ **Performance Boost** - 50-70% faster scanning
- ✅ **Security Hardening** - Fixed SSRF, path traversal, and shell injection
- ✅ **VS Code Enhancements** - Baseline and ignore file management

## License

MIT License - See [LICENSE](LICENSE) file.