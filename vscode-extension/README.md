# CFML SAST Scanner - VS Code Extension

Security scanner for ColdFusion files integrated into VS Code.

## Quick Start

1. Install from VS Code Marketplace
2. Right-click any `.cfm`, `.cfc`, or `.cfml` file → "CFML SAST: Scan Current File"
3. Run `CFML SAST: Install Git Hooks` for automatic scanning

## Commands

- `CFML SAST: Scan Current File` - Scan the active file
- `CFML SAST: Scan Changed Files` - Scan Git changed files
- `CFML SAST: Install Git Hooks` - Set up automatic pre-push scanning

## Features

- Right-click scanning from file explorer
- Visual results in webview panel
- One-click Git hook installation
- Detects SQL injection, XSS, unsafe uploads, and more

See main [README](https://github.com/codeventuregit/CF-SAST) for complete documentation.