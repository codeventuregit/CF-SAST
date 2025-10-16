const vscode = require('vscode');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

function activate(context) {
    const scanFile = vscode.commands.registerCommand('cfmlSast.scanFile', (uri) => {
        const filePath = uri ? uri.fsPath : vscode.window.activeTextEditor?.document.fileName;
        if (!filePath) return;
        
        runScan([filePath], false);
    });

    const scanWorkspace = vscode.commands.registerCommand('cfmlSast.scanWorkspace', () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) return;
        
        exec('git diff --name-only HEAD~1 HEAD', { cwd: workspaceFolder.uri.fsPath }, (error, stdout) => {
            if (error) {
                // Fallback: scan all CFML files in workspace
                try {
                    // Safe fallback without external dependencies
                    const { readdir } = require('fs').promises;
                    const findCfmlFiles = async (dir, maxFiles = 50) => {
                        const files = [];
                        try {
                            const entries = await readdir(dir, { withFileTypes: true });
                            for (const entry of entries) {
                                if (files.length >= maxFiles) break;
                                if (entry.isFile() && /\.(cfm|cfc|cfml|cfinclude)$/i.test(entry.name)) {
                                    files.push(path.join(dir, entry.name));
                                }
                            }
                        } catch (e) { /* ignore */ }
                        return files;
                    };
                    
                    findCfmlFiles(workspaceFolder.uri.fsPath).then(files => {
                        if (files.length === 0) {
                            vscode.window.showInformationMessage('No CFML files found in workspace');
                            return;
                        }
                        runScan(files, true);
                    });
                } catch (e) {
                    vscode.window.showErrorMessage('Not a git repository and file scanning failed');
                }
                return;
            }
            
            const changedFiles = stdout.trim().split('\n')
                .filter(f => f && f.match(/\.(cfm|cfc|cfml|cfinclude)$/i));
            
            if (changedFiles.length === 0) {
                vscode.window.showInformationMessage('No changed CFML files found');
                return;
            }
            
            runScan(changedFiles, true);
        });
    });

    const createIgnoreFile = vscode.commands.registerCommand('cfmlSast.createIgnoreFile', () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        
        const ignorePath = path.join(workspaceFolder.uri.fsPath, '.sastignore');
        
        if (fs.existsSync(ignorePath)) {
            vscode.window.showWarningMessage('.sastignore already exists');
            return;
        }
        
        const ignoreContent = `# CFML SAST Ignore Patterns
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
`;
        
        try {
            fs.writeFileSync(ignorePath, ignoreContent, 'utf8');
            vscode.window.showInformationMessage('✅ Created .sastignore file with default patterns');
            
            // Open the file for editing
            vscode.workspace.openTextDocument(ignorePath).then(doc => {
                vscode.window.showTextDocument(doc);
            });
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to create .sastignore: ${error.message}`);
        }
    });
    
    const createBaseline = vscode.commands.registerCommand('cfmlSast.createBaseline', () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        
        vscode.window.showInformationMessage('Creating baseline from current findings...');
        
        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        const scannerPath = path.join(workspaceFolder.uri.fsPath, 'CFSAST', 'cfml_sast_simple.py');
        
        if (!fs.existsSync(scannerPath)) {
            vscode.window.showErrorMessage('CFML SAST scanner not found. Install first.');
            return;
        }
        
        // Scan all CFML files to create baseline
        exec('git ls-files "*.cfm" "*.cfc" "*.cfml"', { cwd: workspaceFolder.uri.fsPath }, (error, stdout) => {
            const files = stdout.trim().split('\n').filter(f => f);
            if (files.length === 0) {
                vscode.window.showInformationMessage('No CFML files found in repository');
                return;
            }
            
            const baselinePath = path.join(workspaceFolder.uri.fsPath, '.sast-baseline.json');
            const args = [scannerPath, '--files', ...files, '--baseline', baselinePath, '--update-baseline'];
            
            exec(`"${pythonCmd}" ${args.map(arg => `"${arg}"`).join(' ')}`, { 
                cwd: workspaceFolder.uri.fsPath,
                timeout: 120000
            }, (error, stdout, stderr) => {
                if (error) {
                    vscode.window.showErrorMessage(`Baseline creation failed: ${error.message}`);
                    return;
                }
                
                vscode.window.showInformationMessage('✅ Baseline created successfully! New scans will only show new findings.');
            });
        });
    });
    
    const install = vscode.commands.registerCommand('cfmlSast.install', () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        
        vscode.window.showInformationMessage('Installing CFML SAST Scanner...');
        
        const workspacePath = workspaceFolder.uri.fsPath;
        const targetDir = path.join(workspacePath, 'CFSAST');
        const targetFile = path.join(targetDir, 'cfml_sast_simple.py');
        
        try {
            // Create CFSAST directory
            if (!fs.existsSync(targetDir)) {
                fs.mkdirSync(targetDir, { recursive: true });
            }
            
            const pythonExe = process.platform === 'win32' ? 'py' : 'python3';
            const pythonArgs = process.platform === 'win32' ? ['-3'] : [];
            const script = "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/codeventuregit/CF-SAST/main/scripts/cfml_sast_simple.py', 'CFSAST/cfml_sast_simple.py'); print('Downloaded successfully')";
            
            exec(`"${pythonExe}" ${pythonArgs.join(' ')} -c "${script}"`, { 
                cwd: workspacePath,
                timeout: 60000
            }, (error, stdout, stderr) => {
                if (error) {
                    if (error.code === 'ETIMEDOUT') {
                        vscode.window.showErrorMessage('Installation timeout - check network connection');
                    } else if (error.code === 'ENOENT') {
                        vscode.window.showErrorMessage('Python not found - please install Python 3.6+');
                    } else {
                        vscode.window.showErrorMessage(`Installation failed: ${error.message}`);
                    }
                    return;
                }
                
                if (fs.existsSync(targetFile)) {
                    vscode.window.showInformationMessage('✅ CFML SAST Scanner installed successfully!');
                } else {
                    vscode.window.showErrorMessage('Installation failed - scanner file not created');
                }
            });
        } catch (error) {
            vscode.window.showErrorMessage(`Installation failed: ${error.message}`);
        }
    });

    function runScan(files, isWorkspace) {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) return;
        
        // Convert to absolute paths and validate (prevent path traversal)
        const workspacePath = workspaceFolder.uri.fsPath;
        const absoluteFiles = files.map(f => {
            let resolvedPath;
            if (path.isAbsolute(f)) {
                resolvedPath = path.normalize(f);
            } else {
                resolvedPath = path.resolve(workspacePath, f);
            }
            
            // Prevent path traversal - ensure file is within workspace
            if (!resolvedPath.startsWith(workspacePath)) {
                return null;
            }
            
            return resolvedPath;
        }).filter(f => f && f.match(/\.(cfm|cfc|cfml|cfinclude)$/i) && !shouldIgnoreFile(f, workspacePath));
        
        // Count ignored files for user feedback
        const totalFiles = files.filter(f => f.match(/\.(cfm|cfc|cfml|cfinclude)$/i)).length;
        const ignoredCount = totalFiles - absoluteFiles.length;
        
        if (absoluteFiles.length === 0) {
            if (ignoredCount > 0) {
                vscode.window.showInformationMessage(`No CFML files to scan (${ignoredCount} files ignored by .sastignore)`);
            } else {
                vscode.window.showInformationMessage('No CFML files to scan');
            }
            return;
        }
        
        // Show ignore feedback if enabled
        const config = vscode.workspace.getConfiguration('cfmlSast');
        if (ignoredCount > 0 && config.get('showIgnoredFiles', true)) {
            console.log(`CFML SAST: Ignored ${ignoredCount} files based on .sastignore patterns`);
        }
        
        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        const scannerPath = path.join(workspaceFolder.uri.fsPath, 'CFSAST', 'cfml_sast_simple.py');
        
        // Check if scanner exists
        if (!fs.existsSync(scannerPath)) {
            vscode.window.showErrorMessage('CFML SAST scanner not found. Run "CFML SAST: Install Git Hooks" first.');
            return;
        }
        
        const args = [scannerPath, '--files', ...absoluteFiles, '--json-out'];
        
        // Add SARIF output for enterprise users (optional)
        if (config.get('outputFormat') === 'sarif') {
            args[args.length - 1] = '--sarif';
        }
        
        // Add baseline support if enabled
        const baselinePath = path.join(workspaceFolder.uri.fsPath, '.sast-baseline.json');
        if (config.get('useBaseline', true) && fs.existsSync(baselinePath)) {
            args.push('--baseline', baselinePath);
        }
        
        exec(`"${pythonCmd}" ${args.map(arg => `"${arg}"`).join(' ')}`, { 
            cwd: workspaceFolder.uri.fsPath,
            timeout: 60000
        }, (error, stdout, stderr) => {
            if (error && !stdout) {
                vscode.window.showErrorMessage(`SAST scan failed: ${error.message}`);
                return;
            }
            
            try {
                if (!stdout || stdout.trim().length === 0 || stdout.trim() === '[]') {
                    vscode.window.showInformationMessage('✅ Scan completed with no security issues found');
                    return;
                }
                
                // Safe JSON parsing with size limit
                const output = stdout.trim();
                if (output.length > 1048576) { // 1MB limit
                    // Graceful degradation - show summary instead of failing
                    const lineCount = (output.match(/\n/g) || []).length;
                    vscode.window.showWarningMessage(
                        `⚠️ Large scan results (${Math.round(output.length/1024)}KB, ~${lineCount} findings). ` +
                        'Consider scanning fewer files or use CLI with --json-out for full results.',
                        'View Summary'
                    ).then(selection => {
                        if (selection === 'View Summary') {
                            // Show truncated summary
                            const truncated = output.substring(0, 100000); // First 100KB
                            try {
                                const partial = JSON.parse(truncated + ']'); // Try to close array
                                showResults(partial.slice(0, 100), isWorkspace); // Show first 100 findings
                            } catch {
                                vscode.window.showInformationMessage('Use CLI for full results: py -3 CFSAST/cfml_sast_simple.py --files *.cfm --json-out');
                            }
                        }
                    });
                    return;
                }
                
                const results = JSON.parse(output);
                if (!Array.isArray(results) || results.length > 10000) {
                    throw new Error('Invalid results format');
                }
                
                // Validate result structure
                for (const result of results) {
                    if (typeof result !== 'object' || result === null) {
                        throw new Error('Invalid result object');
                    }
                }
                
                showResults(results, isWorkspace);
            } catch (e) {
                if (stdout && stdout.includes('Scan complete')) {
                    vscode.window.showInformationMessage('✅ Scan completed with no security issues found');
                } else {
                    vscode.window.showErrorMessage(`Failed to parse scan results: ${e.message}`);
                }
            }
        });
    }

    function showResults(findings, isWorkspace) {
        if (findings.length === 0) {
            vscode.window.showInformationMessage('✅ No security issues found');
            return;
        }
        
        const high = findings.filter(f => f.severity === 'HIGH').length;
        const medium = findings.filter(f => f.severity === 'MEDIUM').length;
        const low = findings.filter(f => f.severity === 'LOW').length;
        
        const message = `🔍 CFML SAST Results: High=${high} Medium=${medium} Low=${low}`;
        
        vscode.window.showWarningMessage(message, 'View Details').then(selection => {
            if (selection === 'View Details') {
                const panel = vscode.window.createWebviewPanel(
                    'cfmlSastResults',
                    'CFML SAST Results',
                    vscode.ViewColumn.One,
                    {}
                );
                
                panel.webview.html = generateResultsHtml(findings);
            }
        });
    }

    function generateResultsHtml(findings) {
        // Escape HTML to prevent XSS
        const escapeHtml = (text) => {
            return String(text)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        };
        
        const getSeverityIcon = (severity) => {
            switch(severity) {
                case 'HIGH': return '🔴';
                case 'MEDIUM': return '🟡';
                case 'LOW': return '🔵';
                default: return '⚪';
            }
        };
        
        const cards = findings.map(f => {
            const severity = escapeHtml(f.severity || 'UNKNOWN');
            const ruleId = escapeHtml(f.rule_id || 'N/A');
            const fileName = escapeHtml(f.file ? f.file.split(/[\\\/]/).pop() : 'unknown');
            const line = f.line || '0';
            const description = escapeHtml(f.description || 'No description');
            const icon = getSeverityIcon(severity);
            
            return `
                <div class="finding-card ${severity.toLowerCase()}">
                    <div class="card-header">
                        <span class="severity-badge">${icon} ${severity}</span>
                        <span class="rule-id">${ruleId}</span>
                    </div>
                    <div class="card-body">
                        <div class="description">${description}</div>
                        <div class="location">
                            <span class="file-name">${fileName}</span>
                            <span class="line-number">Line ${line}</span>
                        </div>
                    </div>
                </div>`;
        }).join('');
        
        const high = findings.filter(f => f.severity === 'HIGH').length;
        const medium = findings.filter(f => f.severity === 'MEDIUM').length;
        const low = findings.filter(f => f.severity === 'LOW').length;
        
        return `<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>CFML SAST Results</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: var(--vscode-editor-background);
                    color: var(--vscode-editor-foreground);
                    line-height: 1.5;
                }
                
                .header {
                    margin-bottom: 24px;
                    padding-bottom: 16px;
                    border-bottom: 1px solid var(--vscode-panel-border);
                }
                
                .title {
                    font-size: 24px;
                    font-weight: 600;
                    margin: 0 0 8px 0;
                    color: var(--vscode-editor-foreground);
                }
                
                .summary {
                    display: flex;
                    gap: 16px;
                    margin: 16px 0;
                }
                
                .stat {
                    padding: 8px 12px;
                    border-radius: 6px;
                    font-weight: 500;
                    font-size: 14px;
                }
                
                .stat.high { background: rgba(244, 67, 54, 0.1); color: #f44336; }
                .stat.medium { background: rgba(255, 152, 0, 0.1); color: #ff9800; }
                .stat.low { background: rgba(33, 150, 243, 0.1); color: #2196f3; }
                
                .findings {
                    display: flex;
                    flex-direction: column;
                    gap: 12px;
                }
                
                .finding-card {
                    background: var(--vscode-editor-widget-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 8px;
                    padding: 16px;
                    transition: all 0.2s ease;
                }
                
                .finding-card:hover {
                    border-color: var(--vscode-focusBorder);
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }
                
                .card-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 12px;
                }
                
                .severity-badge {
                    font-weight: 600;
                    font-size: 14px;
                }
                
                .rule-id {
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    background: var(--vscode-badge-background);
                    color: var(--vscode-badge-foreground);
                    padding: 4px 8px;
                    border-radius: 4px;
                }
                
                .description {
                    font-size: 14px;
                    margin-bottom: 8px;
                    color: var(--vscode-editor-foreground);
                }
                
                .location {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    font-size: 12px;
                    color: var(--vscode-descriptionForeground);
                }
                
                .file-name {
                    font-family: 'Courier New', monospace;
                    font-weight: 500;
                }
                
                .line-number {
                    background: var(--vscode-textBlockQuote-background);
                    padding: 2px 6px;
                    border-radius: 3px;
                }
                
                .tip {
                    margin-top: 24px;
                    padding: 12px;
                    background: var(--vscode-textBlockQuote-background);
                    border-left: 4px solid var(--vscode-textLink-foreground);
                    border-radius: 0 4px 4px 0;
                    font-size: 13px;
                    color: var(--vscode-descriptionForeground);
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1 class="title">🔍 CFML Security Scan Results</h1>
                <div class="summary">
                    <div class="stat high">🔴 ${high} High</div>
                    <div class="stat medium">🟡 ${medium} Medium</div>
                    <div class="stat low">🔵 ${low} Low</div>
                </div>
            </div>
            
            <div class="findings">
                ${cards}
            </div>
            
            <div class="tip">
                💡 <strong>Tip:</strong> Use .sastignore file to exclude files or create baseline to suppress existing findings
            </div>
        </body>
        </html>`;
    }

    // Helper function to check .sastignore patterns
    function shouldIgnoreFile(filePath, workspacePath) {
        const ignorePath = path.join(workspacePath, '.sastignore');
        
        if (!fs.existsSync(ignorePath)) {
            return false;
        }
        
        try {
            const ignoreContent = fs.readFileSync(ignorePath, 'utf8');
            const patterns = ignoreContent.split('\n')
                .map(line => line.trim())
                .filter(line => line && !line.startsWith('#'));
            
            const relativePath = path.relative(workspacePath, filePath).replace(/\\/g, '/');
            
            for (const pattern of patterns) {
                // Convert glob pattern to regex
                const regexPattern = pattern
                    .replace(/\./g, '\\.')
                    .replace(/\*/g, '.*')
                    .replace(/\?/g, '.');
                
                const regex = new RegExp(`^${regexPattern}$`, 'i');
                
                if (regex.test(relativePath) || regex.test(path.basename(filePath))) {
                    return true;
                }
            }
        } catch (error) {
            // Ignore errors reading .sastignore
        }
        
        return false;
    }
    
    context.subscriptions.push(scanFile, scanWorkspace, createIgnoreFile, createBaseline, install);
}

function deactivate() {}

module.exports = { activate, deactivate };