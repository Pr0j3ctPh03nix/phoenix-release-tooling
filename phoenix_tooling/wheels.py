#!/usr/bin/env python3
"""Prove `wheels/` holds the bytes it claims to hold.

`wheels/` is installed from with `pip install --no-index --find-links`, in the job that holds the
release signing key — so the wheels ARE the code the key is handed to, and this repo is the only
thing standing between them and that job. See wheels/README.md.

    python phx.py wheels check   # offline: the .whl files against wheels/SHA256SUMS
    python phx.py wheels write   # cross-check every file against PyPI, THEN write SHA256SUMS

TWO COMMANDS, AND THE SPLIT IS THE POINT. `check` never reaches the network, so it is runnable in a
producer's CI at the pinned SHA, offline, for the same reason the install itself is. `write` reaches
PyPI on purpose: a `pip download` proves only that some index answered on the day it ran, and the
hash a vendored wheel is later checked against must come from the index's OWN published digest, not
from the file that arrived. `write` therefore refuses to record a hash it could not confirm — there
is deliberately no offline way to bless a file, because a SHA256SUMS written from whatever landed in
the directory is a record of nothing.

The listing covers `*.whl` only; README.md and SHA256SUMS itself live in the same directory and are
not install inputs. `sha256sum` layout ("<hex>  <name>", LF), sorted by name.

Stdlib only, like everything else here that is not the signer.
"""
import hashlib
import json
import os
import sys
import urllib.request

from ._paths import ROOT

WHEELS = os.path.join(ROOT, "wheels")
SUMS = os.path.join(WHEELS, "SHA256SUMS")
PYPI = "https://pypi.org/pypi/{}/{}/json"


def wheel_files():
    """-> sorted .whl names in wheels/, or exit if there are none.

    An empty directory must not be a quietly passing `check`: "every listed file matches" is
    vacuously true of a listing of nothing, and the answer a reader wants is "the install set is
    there and intact"."""
    if not os.path.isdir(WHEELS):
        sys.exit("wheels_check: no such directory: {}".format(WHEELS))
    names = sorted(n for n in os.listdir(WHEELS) if n.endswith(".whl"))
    if not names:
        sys.exit("wheels_check: {} holds no wheels".format(WHEELS))
    return names


def sha256(name):
    h = hashlib.sha256()
    with open(os.path.join(WHEELS, name), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read_sums():
    if not os.path.isfile(SUMS):
        sys.exit("wheels_check: no {} — run `wheels_check.py write`".format(SUMS))
    out = {}
    with open(SUMS, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            digest, _, name = line.partition("  ")
            if len(digest) != 64 or not name:
                sys.exit("wheels_check: {}:{}: not a '<sha256>  <name>' line".format(SUMS, n))
            out[name] = digest
    return out


def project_version(name):
    """(project, version) from a wheel filename. PEP 427: name-version[-build]-py-abi-plat.whl, and
    the first two fields never contain '-' (they are escaped to '_' when a wheel is built)."""
    project, version = name.split("-")[:2]
    return project.replace("_", "-"), version


def pypi_files(project, version, cache):
    key = (project, version)
    if key not in cache:
        url = PYPI.format(project, version)
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                data = json.load(r)
        except Exception as e:                          # noqa: BLE001 — any failure is "unconfirmed"
            sys.exit("wheels_check: cannot read {}: {}".format(url, e))
        cache[key] = {u["filename"]: (u["digests"]["sha256"], u["size"]) for u in data["urls"]}
    return cache[key]


def check():
    """Every wheel matches SHA256SUMS, and the two name the same set. -> failure count."""
    listed, present = read_sums(), wheel_files()
    bad = 0
    for name in sorted(set(listed) | set(present)):
        if name not in listed:
            print("  FAIL {}\n         in wheels/ but not in SHA256SUMS".format(name))
        elif name not in present:
            print("  FAIL {}\n         in SHA256SUMS but not in wheels/".format(name))
        else:
            got = sha256(name)
            if got == listed[name]:
                print("  ok   {}".format(name))
                continue
            print("  FAIL {}\n         recorded {}\n         on disk  {}".format(
                name, listed[name], got))
        bad += 1
    print("wheels_check: {} wheels, all match SHA256SUMS".format(len(present)) if not bad
          else "wheels_check: {} of {} FAILED".format(bad, len(set(listed) | set(present))))
    return bad


def write():
    """Confirm every wheel against PyPI's published digest, then record it. -> failure count.

    Size as well as sha256: a file that matches neither is a different artifact, and saying which of
    the two disagrees is the difference between "the index changed under us" and "the download was
    truncated"."""
    names, cache, bad, rows = wheel_files(), {}, 0, []
    for name in names:
        project, version = project_version(name)
        published = pypi_files(project, version, cache)
        if name not in published:
            print("  FAIL {}\n         PyPI's {} {} publishes no such file".format(
                name, project, version))
            bad += 1
            continue
        want, want_size = published[name]
        got, got_size = sha256(name), os.path.getsize(os.path.join(WHEELS, name))
        if got != want or got_size != want_size:
            print("  FAIL {}\n         PyPI     {} ({} bytes)\n         on disk  {} ({} bytes)"
                  .format(name, want, want_size, got, got_size))
            bad += 1
            continue
        print("  ok   {}  {}".format(name, got))
        rows.append((name, got))
    if bad:
        print("wheels_check: {} of {} unconfirmed — SHA256SUMS NOT written".format(bad, len(names)))
        return bad
    with open(SUMS, "w", encoding="utf-8", newline="\n") as fh:
        for name, digest in rows:
            fh.write("{}  {}\n".format(digest, name))
    print("wheels_check: {} wheels confirmed against PyPI -> {}".format(len(rows), SUMS))
    return 0


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    argv = sys.argv[1:] if argv is None else list(argv)
    cmds = {"check": check, "write": write}
    if len(argv) == 1 and argv[0] in cmds:
        sys.exit(1 if cmds[argv[0]]() else 0)
    sys.exit("usage: phx wheels {check|write}")


if __name__ == "__main__":
    main()
