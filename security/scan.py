#!/usr/bin/env python3
"""Scan committed/staged data without running application code or exposing secrets."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    result = subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True)
    if result.returncode:
        raise RuntimeError('Could not read the Git data required for the security check')
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--staged', action='store_true')
    modes.add_argument('--range', dest='commit_range')
    modes.add_argument('--tree', action='store_true', help='Scan every tracked file at HEAD')
    args = parser.parse_args()
    binary = os.environ.get('GITLEAKS_BIN') or shutil.which('gitleaks') or str(ROOT / '.security-tools/gitleaks')
    if not Path(binary).is_file():
        parser.error('Install the pinned scanner with: python3 security/install_gitleaks.py')
    base = head = None
    if args.commit_range:
        if not re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', args.commit_range):
            parser.error('--range requires two full hexadecimal commit IDs separated by ..')
        base, head = args.commit_range.split('..')
        names = git('diff', '--name-only', '-z', '--diff-filter=ACMR', base, head)
    elif args.staged:
        names = git('diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR')
    else:
        names = git('ls-tree', '-r', '--name-only', '-z', 'HEAD')
    with tempfile.TemporaryDirectory(prefix='credential-check-') as temp:
        folder = Path(temp)
        files = folder / 'files'
        files.mkdir()
        blocked = []
        for raw in names.split(b'\0'):
            if not raw:
                continue
            name = raw.decode('utf-8', errors='surrogateescape')
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise RuntimeError('Unsafe Git path')
            leaf = path.name.lower()
            env_template = leaf in ('.env.example', '.env.sample', '.env.template', '.env.dist')
            if (leaf == '.env' or leaf.startswith('.env.')) and not env_template:
                blocked.append((name, 'environment file'))
            if leaf in ('id_rsa', 'id_ed25519', 'id_ecdsa', 'wp-config.php') or leaf.endswith(('.p12', '.pfx', '.pyc')):
                blocked.append((name, 'credential/runtime file'))
            spec = ':' + name if args.staged else (head or 'HEAD') + ':' + name
            data = git('show', spec)
            if leaf.endswith('.json'):
                try:
                    document = json.loads(data)
                    if isinstance(document, dict) and document.get('type') == 'service_account' and document.get('private_key'):
                        blocked.append((name, 'service-account private key'))
                except (ValueError, UnicodeError):
                    pass
            destination = files.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        for name, reason in blocked:
            print(f'BLOCKED {name}: {reason}', file=sys.stderr)
        common = ['--config', str(ROOT / 'security/gitleaks.toml'), '--redact=100', '--no-banner', '--no-color',
                  '--ignore-gitleaks-allow', '--gitleaks-ignore-path', str(folder), '--log-level=error', '--report-format=json']
        commands = [('files', [binary, 'dir', str(files), '--max-archive-depth=3'])]
        if args.commit_range:
            # Also detect secrets added and removed within the same push/PR.
            commands.append(('commits', [binary, 'git', str(ROOT), '--log-opts=' + args.commit_range + ' --full-history -m']))
        failed = bool(blocked)
        for label, command in commands:
            report = folder / (label + '.json')
            environment = dict(os.environ)
            if sys.platform == 'darwin':
                environment['PATH'] = '/opt/homebrew/bin:/usr/bin:/bin:' + environment.get('PATH', '')
            result = subprocess.run(command + common + ['--report-path', str(report)], capture_output=True, env=environment)
            if result.returncode not in (0, 1) or not report.exists() or b'ERR' in result.stderr or b'FTL' in result.stderr:
                print(f'Security scan could not complete ({label}); refusing to pass.', file=sys.stderr)
                return 2
            findings = json.loads(report.read_text())
            failed |= bool(findings)
            for finding in findings:
                name = str(finding.get('File', '')).replace(str(files) + '/', '')
                print(f'BLOCKED {name}:{finding.get("StartLine")}: {finding.get("RuleID")}', file=sys.stderr)
        if failed:
            print('Remove credentials and use environment variables or a secret store. Revoke any exposed value.', file=sys.stderr)
            return 1
    print('Credential check passed for the selected Git data.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f'Security check failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(2)
