#!/usr/bin/env python3
"""Install a private, frozen stage-1 native helper for one Ubuntu browser add-on."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/"research/nock-mpc/source-auth"
NAME = "com.nockapp.helper"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def install(extension_id, *, home=None, browser="google-chrome", name=NAME):
    firefox = browser == "firefox"
    if firefox and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}@[a-z0-9][a-z0-9.-]{0,100}", extension_id) is None:
        raise ValueError("Expected the exact Firefox add-on ID from the manifest")
    if not firefox and re.fullmatch(r"[a-p]{32}", extension_id) is None:
        raise ValueError("Expected the 32-letter extension ID from chrome://extensions")
    if browser not in {"google-chrome", "google-chrome-for-testing", "chromium", "firefox"}:
        raise ValueError("Unsupported Linux browser configuration")
    if re.fullmatch(r"com\.nockapp\.(helper|test_[a-z0-9_]+)", name) is None:
        raise ValueError("Unsupported helper name")
    home = Path.home() if home is None else Path(home)
    registration = (home/".mozilla/native-messaging-hosts"/(name + ".json") if firefox
                    else home/".config"/browser/"NativeMessagingHosts"/(name + ".json"))
    if registration.exists() or registration.is_symlink():
        raise ValueError("Native host already registered; remove or deliberately update that registration first")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = home/".local/lib/nockapp-helper"/(stamp + "-" + name)
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    for filename in ("x_native_host.py", "x_probe.py"):
        shutil.copy2(SOURCE/filename, directory/filename)
        (directory/filename).chmod(0o600)
    config = {"files_sha256": {p: digest(directory/p) for p in ("x_native_host.py", "x_probe.py")}}
    if firefox:
        config.update(allowed_firefox_id=extension_id, registration_path=str(registration))
    else:
        config["allowed_origin"] = "chrome-extension://" + extension_id + "/"
    (directory/"host-config.json").write_text(json.dumps(config, sort_keys=True))
    (directory/"host-config.json").chmod(0o600)
    launcher = directory/"run"
    launcher.write_text("#!/bin/sh\nexec /usr/bin/python3 -I \"$(dirname -- \"$0\")/bootstrap.py\" \"$@\"\n")
    launcher.chmod(0o700)
    # Isolated Python ignores Python startup/import environment. Only the
    # installed frozen helper directory is then added explicitly.
    (directory/"bootstrap.py").write_text(
        "from pathlib import Path\nimport runpy,sys\n"
        "root=Path(__file__).resolve().parent\nsys.path.insert(0,str(root))\n"
        "runpy.run_path(str(root/'x_native_host.py'),run_name='__main__')\n")
    manifest = {"name": name, "description": "NockApp private source feasibility helper (no passports yet)",
                "path": str(launcher), "type": "stdio"}
    manifest.update({"allowed_extensions": [extension_id]} if firefox else {"allowed_origins": [config["allowed_origin"]]})
    registration.parent.mkdir(parents=True, exist_ok=True)
    if registration.exists() or registration.is_symlink():
        raise ValueError("Native host already registered; remove or deliberately update that registration first")
    with registration.open("x") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    registration.chmod(0o600)
    result = {"registration": str(registration), "directory": str(directory), "browser": browser,
              "stage": "source-feasibility",
              "verified_passport_available": False, "files_sha256": config["files_sha256"]}
    result.update({"extension_id": extension_id} if firefox else {"extension_origin": config["allowed_origin"]})
    (directory/"installation.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension-id", required=True)
    parser.add_argument("--browser", choices=["google-chrome", "google-chrome-for-testing", "chromium", "firefox"], default="google-chrome")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        raise SystemExit("Install as your regular Ubuntu user; no sudo is needed")
    try:
        print(json.dumps(install(args.extension_id, browser=args.browser), indent=2))
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from None
