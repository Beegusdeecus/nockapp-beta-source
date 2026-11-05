"""Fresh Ubuntu 24.04 Chrome installation; never replaces an existing setup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

NATIVE = '9cc8a9986ee0c9a0f40fde21e87f767cedf2286f304b1d09bc6e60593741e4c7'
EXTENSION = 'e4446b339c9e608cb1b5ad3d3b38496104ffbf3d59ae08adf099ff937d3511be'
BWRAP = 'e318903862396f96de3df57264e0158682b952fd3fb53ac23d876413e7b30f71'
TEMPLATE = '837e3ea0d515c42620d02d6dfd4db585ab29f5cc9e50e2376adf69d975c967cc'
APPARMOR = '11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sandbox_ready(*, binary=Path('/usr/bin/bwrap'), profile=Path('/etc/apparmor.d/bwrap-userns-restrict'),
                  restriction=Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')):
    require(binary.is_file() and sha(binary) == BWRAP,
            'The installed bubblewrap differs from this reviewed build. See PREREQUISITES.txt; do not bypass the check.')
    require(profile.is_file() and sha(profile) == APPARMOR,
            'The reviewed Ubuntu AppArmor profile is missing or changed. Complete PREREQUISITES.txt before setup.')
    require(restriction.is_file() and restriction.read_text().strip() == '1',
            'Ubuntu global user-namespace protection must remain enabled. Do not disable it to install NockApp.')
    checked = subprocess.run([str(binary), '--unshare-all', '--new-session', '--die-with-parent',
        '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
        '--proc', '/proc', '--dev', '/dev', '--', '/usr/bin/true'],
        capture_output=True, timeout=20, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(checked.returncode == 0 and not checked.stderr,
            'The reviewed sandbox cannot start. See PREREQUISITES.txt; no NockApp state was created.')


def main(extension_id):
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    require(sha(root / 'public-configuration.template.json') == TEMPLATE,
            'The deployment settings do not match this reviewed kit.')
    require(platform.machine() == 'x86_64', 'This kit requires an x86-64 computer.')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04',
            'This kit targets Ubuntu 24.04. Other systems need a reviewed sandbox build.')
    require(os.geteuid() != 0, 'Run setup as your normal desktop user, without sudo.')
    sandbox_ready()  # Must pass before any extension/configuration/data writes.
    home = Path.home()
    registrations = home / '.config/google-chrome/NativeMessagingHosts'
    require(not any((registrations / name).exists() for name in
                    ('com.nockapp.zkid.public.json', 'com.nockapp.zkid.json')),
            'An installed NockApp helper already exists. This fresh-install kit will not replace it.')
    require(extension_id is None or re.fullmatch('[a-p]{32}', extension_id) is not None,
            'Copy the 32-letter NockApp extension ID from chrome://extensions.')
    native = root / 'native'
    require(sha(native / 'manifest.json') == NATIVE, 'The native package manifest does not match this kit.')
    checked = subprocess.run([sys.executable, '-I', '-B', str(native / 'manage.py'), 'verify', '--manifest-sha256', NATIVE],
                             capture_output=True, timeout=60)
    require(checked.returncode == 0, 'The native package integrity check failed; keep this kit for diagnosis.')
    sys.path.insert(0, str(root))
    import extension_release
    extension_release.require(sha(root / 'extension-release.json') == EXTENSION)
    extension_release.verify(root / 'extension', json.loads((root / 'extension-release.json').read_bytes()))
    destination = home / '.local/lib/nockapp-beta/extension'
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if destination.exists():
        extension_release.installed(destination, EXTENSION)
    else:
        extension_release.install(root, destination)
    if extension_id is None:
        print('In Chrome, open chrome://extensions and enable Developer mode.')
        print('Choose Load unpacked, then select: ' + str(destination))
        print('Copy NockApp\'s extension ID, then run: python3 SETUP.py --extension-id YOUR_EXTENSION_ID')
        return
    template = root / 'public-configuration.template.json'
    config = json.loads(template.read_bytes())
    require(config['installation']['legacy_wallets'] == [], 'Fresh setup must not adopt another installation.')
    state = home / '.local/share/nockapp-public-beta'
    require(not state.exists(), 'NockApp data already exists. Keep it; use the recovery or migration procedure.')
    admission = {'kind': 'chrome', 'origin': 'chrome-extension://' + extension_id + '/'}
    config['browser'] = admission
    config['installation']['browser'] = admission
    config['installation']['data_directory'] = str(state)
    configuration = destination.parent / 'public-configuration.json'
    with configuration.open('x') as stream:
        json.dump(config, stream, sort_keys=True, separators=(',', ':'))
    installed = subprocess.run([sys.executable, '-I', '-B', str(native / 'manage.py'), 'install-public',
        '--manifest-sha256', NATIVE, '--configuration', str(configuration), '--extension-id', extension_id,
        '--home', str(home), '--browser', 'google-chrome'], capture_output=True, timeout=180)
    require(installed.returncode == 0, 'Installation did not complete. Keep this kit and saved files; report the failure before retrying.')
    print('NockApp is installed. Open its Chrome sidebar to browse or publish.')
    print('Twitter and wallet badges are optional. Do not repeat an uncertain payment.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--extension-id')
    try:
        main(parser.parse_args().extension_id)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if type(error) is ValueError else 'Setup could not complete. Existing identities were not replaced.', file=sys.stderr)
        raise SystemExit(1)
