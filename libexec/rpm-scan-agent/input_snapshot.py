"""Bind the event's expected digest to the private file used by the scanner."""

import hashlib
import os
from pathlib import Path
import re
import stat


def copy_input(rpm_name, expected_sha256, directory, cancelled):
    if not rpm_name.endswith(".rpm") or "/" in rpm_name:
        raise ValueError("RPM_NAME must be a file name ending with .rpm")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("CURRENT_RPM_SHA256 must contain the expected lowercase SHA256")

    source_path = Path("/scan-input") / rpm_name
    snapshot = Path(directory) / rpm_name
    digest = hashlib.sha256()
    size = 0
    # Open once: rename cannot redirect the copy to a different inode. Reject
    # symlinks and special files; NONBLOCK prevents a FIFO from blocking open().
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(source_path, flags), "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("RPM input must be a regular file")
        with snapshot.open("xb") as target:
            while True:
                if cancelled():
                    raise InterruptedError("RPM input preparation cancelled")
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                target.write(chunk)
                digest.update(chunk)
                size += len(chunk)

    if not size:
        raise ValueError("RPM input must not be empty")
    if digest.hexdigest() != expected_sha256:
        raise ValueError("RPM input SHA256 does not match the scan event; input may have changed")
    # Independent bytes, not a hard link. The private directory and read-only
    # file avoid accidental edits; this is not a sandbox against the same UID.
    snapshot.chmod(0o400)
    return snapshot, expected_sha256, size
