#!/usr/bin/env python3
"""Install a checksum-pinned Gitleaks binary locally, without modifying PATH."""
import hashlib
import io
from pathlib import Path
import platform
import subprocess
import tarfile

VERSION = '8.30.1'
CHECKSUMS = {
    'darwin_arm64': 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5',
    'darwin_x64': 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709',
    'linux_arm64': 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080',
    'linux_x64': '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
}
system = platform.system().lower()
machine = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'x64', 'amd64': 'x64'}.get(platform.machine().lower())
target = f'{system}_{machine}'
if target not in CHECKSUMS:
    raise SystemExit('Unsupported platform: install Gitleaks 8.30.1 and set GITLEAKS_BIN.')
url = f'https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_{target}.tar.gz'
archive = subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https', '--tlsv1.2', '--max-time', '120', url], capture_output=True)
if archive.returncode or hashlib.sha256(archive.stdout).hexdigest() != CHECKSUMS[target]:
    raise SystemExit('Scanner download or checksum verification failed.')
with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode='r:gz') as stream:
    member = stream.getmember('gitleaks')
    if not member.isfile():
        raise SystemExit('Invalid scanner archive.')
    binary = stream.extractfile(member).read()
folder = Path(__file__).resolve().parents[1] / '.security-tools'
folder.mkdir(mode=0o700, exist_ok=True)
destination = folder / 'gitleaks'
if destination.is_symlink():
    raise SystemExit('Refusing to replace a symbolic link.')
destination.write_bytes(binary)
destination.chmod(0o700)
print(f'Installed checksum-verified Gitleaks {VERSION}.')
