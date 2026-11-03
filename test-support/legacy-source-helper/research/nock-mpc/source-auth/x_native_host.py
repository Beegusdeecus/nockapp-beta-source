#!/usr/bin/env python3
"""Stage-1 browser Native Messaging host: bounded source feasibility only.

No proving, passports, key generation, network listener or caller-selected
commands/paths/trust. The installer freezes this file and x_probe.py together.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from x_probe import probe, unique_object, ProbeRejected, PROFILE

MAX_MESSAGE = 64 * 1024
MAX_MESSAGES = 4
HOST_NAME = "com.nockapp.helper"


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def receive(stream):
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise EOFError
    length, = struct.unpack("=I", header)
    if not 1 <= length <= MAX_MESSAGE:
        raise ValueError("message-size")
    data = read_exact(stream, length)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("message-json")))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("message-json") from None


def send(stream, value):
    data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
    if len(data) > MAX_MESSAGE:
        raise ValueError("output-size")
    stream.write(struct.pack("=I", len(data)) + data)
    stream.flush()


def authorize(origin, directory):
    if not isinstance(origin, str) or re.fullmatch(r"chrome-extension://[a-p]{32}/", origin) is None:
        return False
    config_file = directory/"host-config.json"
    if config_file.is_symlink() or config_file.stat().st_size > 8192:
        return False
    config = json.loads(config_file.read_bytes(), object_pairs_hook=unique_object)
    if set(config) != {"allowed_origin", "files_sha256"} or origin != config["allowed_origin"]:
        return False
    if set(config["files_sha256"]) != {"x_native_host.py", "x_probe.py"}:
        return False
    for name, expected in config["files_sha256"].items():
        path = directory/name
        if path.is_symlink() or not path.is_file():
            return False
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                return False
    return True


def authorize_firefox(manifest_path, extension_id, directory):
    """Authorize only the installed registration and its one approved Firefox ID."""
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}@[a-z0-9][a-z0-9.-]{0,100}", extension_id) is None:
        return False
    config_file = directory/"host-config.json"
    if config_file.is_symlink() or config_file.stat().st_size > 8192:
        return False
    config = json.loads(config_file.read_bytes(), object_pairs_hook=unique_object)
    if (set(config) != {"allowed_firefox_id", "registration_path", "files_sha256"}
            or extension_id != config["allowed_firefox_id"]
            or manifest_path != config["registration_path"]):
        return False
    # Read only our configured registration, never an arbitrary argv path.
    registration = Path(config["registration_path"])
    if (not registration.is_absolute() or registration.is_symlink()
            or registration.stat().st_size > 8192):
        return False
    manifest = json.loads(registration.read_bytes(), object_pairs_hook=unique_object)
    if (set(manifest) != {"name", "description", "path", "type", "allowed_extensions"}
            or not isinstance(manifest["name"], str)
            or re.fullmatch(r"com\.nockapp\.(helper|test_[a-z0-9_]+)", manifest["name"]) is None
            or manifest["path"] != str(directory/"run") or manifest["type"] != "stdio"
            or manifest["allowed_extensions"] != [extension_id]):
        return False
    if set(config["files_sha256"]) != {"x_native_host.py", "x_probe.py"}:
        return False
    for name, expected in config["files_sha256"].items():
        path = directory/name
        if path.is_symlink() or not path.is_file():
            return False
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                return False
    return True


def serve(incoming, outgoing):
    used_probe = False
    for _ in range(MAX_MESSAGES):
        message = receive(incoming)
        if message is None:
            return
        if (type(message) is not dict or type(message.get("id")) is not str
                or re.fullmatch(r"[a-f0-9]{32}", message["id"]) is None):
            raise ValueError("message-schema")
        base = {"id": message["id"], "verified": False, "passport_issuance_allowed": False}
        if message.get("op") == "capabilities" and set(message) == {"id", "op"}:
            send(outgoing, {**base, "status": "ready", "stage": "source-feasibility",
                            "source_probe_available": True, "proving_available": False,
                            "passport_available": False, "protocol": 1, "source_profile": PROFILE})
        elif (message.get("op") == "probe_x" and not used_probe
              and set(message) == {"id", "op", "endpoint", "context"}):
            used_probe = True
            result = probe(message["endpoint"], message["context"])
            # Request context is held only for this operation; it is never
            # saved, logged, included in a result or sent to a notary/backend.
            message.clear()
            send(outgoing, {**result, **base})
            return
        else:
            send(outgoing, {**base, "status": "rejected", "code": "message-schema"})
            return


def main():
    # Chrome supplies one caller origin; Firefox supplies the registration path
    # and add-on ID. Both must match installation metadata exactly.
    directory = Path(__file__).resolve().parent
    allowed = ((len(sys.argv) == 2 and authorize(sys.argv[1], directory))
               or (len(sys.argv) == 3 and authorize_firefox(sys.argv[1], sys.argv[2], directory)))
    if not allowed:
        return 1
    try:
        serve(sys.stdin.buffer, sys.stdout.buffer)
    except (ValueError, OSError, EOFError, ProbeRejected, RecursionError):
        # Fixed error only; never include arbitrary input or exception text.
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, ProbeRejected, KeyError, TypeError):
        raise SystemExit(1) from None
