#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_cmd(cmd_list, cwd=None):
    try:
        # Use list format to prevent injection
        result = subprocess.run(cmd_list, shell=False, cwd=cwd, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def install_cfml_sast():
    print("🔧 Installing CFML SAST Scanner...")
    
    # Create CFSAST directory
    os.makedirs('CFSAST', exist_ok=True)
    print("✅ Created CFSAST folder")
    
    # Create Git hooks directory if Git repo exists
    if Path('.git').exists():
        os.makedirs('.git/hooks', exist_ok=True)
    
    # Download scanner from GitHub
    try:
        import urllib.request
        
        # Download main scanner
        urllib.request.urlretrieve(
            'https://raw.githubusercontent.com/codeventuregit/CF-SAST/main/scripts/cfml_sast_simple.py',
            'CFSAST/cfml_sast_simple.py'
        )
        print("✅ Downloaded CFML SAST scanner to CFSAST/")
        
        # Download secure prepush scripts
        urllib.request.urlretrieve(
            'https://raw.githubusercontent.com/codeventuregit/CF-SAST/main/scripts/sast/prepush.sh',
            'CFSAST/prepush.sh'
        )
        urllib.request.urlretrieve(
            'https://raw.githubusercontent.com/codeventuregit/CF-SAST/main/scripts/sast/prepush.bat',
            'CFSAST/prepush.bat'
        )
        print("✅ Downloaded secure prepush scripts")
        
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return False
    
    # Create secure pre-push hook if Git repo exists
    if Path('.git').exists():
        if os.name == 'nt':  # Windows
            hook_content = '''@echo off
REM CFML SAST Pre-push Hook
cd /d "%~dp0..\.."
call "CFSAST\\prepush.bat"
exit /b %errorlevel%
'''
            hook_file = '.git/hooks/pre-push.bat'
        else:  # Unix/Linux/Mac
            hook_content = '''#!/bin/bash
# CFML SAST Pre-push Hook
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec "./CFSAST/prepush.sh"
'''
            hook_file = '.git/hooks/pre-push'
        
        with open(hook_file, 'w') as f:
            f.write(hook_content)
        
        # Set permissions (Unix/Linux/Mac)
        if os.name != 'nt':
            os.chmod('CFSAST/prepush.sh', 0o755)
            os.chmod(hook_file, 0o755)
        print("✅ Set up secure Git hooks")
    else:
        print("ℹ️ No Git repository found - skipping Git hooks")
    
    # Verify installation
    if Path('CFSAST/cfml_sast_simple.py').exists():
        print("✅ Installation successful!")
        print("\n📋 Usage:")
        print("py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc")
        print("py -3 CFSAST/cfml_sast_simple.py --init-ignore  # Create .sastignore")
        if Path('.git').exists():
            print("\n📋 Git integration:")
            print("git push  # Scanner will run automatically with secure scripts")
        return True
    else:
        print("❌ Installation failed - scanner file not found")
        return False

if __name__ == '__main__':
    install_cfml_sast()