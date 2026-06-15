import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

export function activate(context: vscode.ExtensionContext) {
  let disposable = vscode.commands.registerCommand('secure-push.scanWorkspace', () => {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
      vscode.window.showErrorMessage('No workspace folder open');
      return;
    }

    const outputChannel = vscode.window.createOutputChannel('Secure Push');
    outputChannel.show(true);
    outputChannel.appendLine('Scanning workspace for security issues...');

    const securePushPath = getSecurePushPath();
    if (!securePushPath) {
      outputChannel.appendLine('Error: secure-push not found. Please install it first.');
      return;
    }

    const workspacePath = workspaceFolders[0].uri.fsPath;
    const process = cp.execFile(securePushPath, ['scan', workspacePath], { cwd: workspacePath });

    process.stdout?.on('data', (data) => {
      outputChannel.append(data.toString());
    });

    process.stderr?.on('data', (data) => {
      outputChannel.append(data.toString());
    });

    process.on('close', (code) => {
      if (code === 0) {
        outputChannel.appendLine('✓ No security issues found');
      } else {
        outputChannel.appendLine(`\n🚫 Security issues found (exit code: ${code})`);
      }
    });
  });

  context.subscriptions.push(disposable);
}

function getSecurePushPath(): string | undefined {
  return 'secure-push';
}

export function deactivate() {}