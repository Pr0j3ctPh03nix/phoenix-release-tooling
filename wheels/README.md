# wheels/ — the offline install set for this repo's two non-stdlib dependencies

`cryptography` (imported by `phoenix_tooling/minisign.py`) and `zstandard` (imported by
`phoenix_tooling/phxb.py`), plus the closure `cryptography` pulls in (`cffi` → `pycparser`),
vendored as wheels so a producer installs them with

    python -m pip install --disable-pip-version-check --no-index --find-links <checkout>/wheels cryptography [zstandard]

and reaches no index at all. Every producer already checks this repo out at a pinned commit SHA to
seal with, so the wheels arrive by the same pin as the signer they feed.

WHY, in one line: the job doing that install is the job that holds `PHOENIX_SIGNING_KEY`, and these
wheels are the code the key is handed to. The argument is written out on the install step of each
producer's workflow — `client-dist-staging` and `phoenix-launcher`'s `.github/workflows/release.yml`,
`phoenix-mirror-registry`'s `.github/workflows/publish.yml` — and not restated here. What this
directory buys is that after that step, the key-holding job's inputs are two git checkouts at pinned
commit SHAs and nothing else.

`pip --find-links` does not recurse, so this directory is FLAT: one set for both runner platforms,
with the wheel tags doing the selecting.

## What is here, and for which interpreter

Every wheel is for **CPython 3.12, x86_64** — what both runner images ship as `python`, since no
producer uses `actions/setup-python`:

| label | image | Python |
|---|---|---|
| `ubuntu-latest` | ubuntu-24.04 | 3.12.3 |
| `windows-latest` | windows-2025 | 3.12.10 |

Wheels only, never an sdist: a source build would compile Rust and C inside the signing job instead
of failing fast, which is the opposite of what this directory is for.

An image that moves to another Python leaves pip with no compatible wheel and the step fails —
loudly, and before the key is read — rather than installing something unvendored. That failure is
the signal to re-run the recipe below for the new version, and it is the same property the
hash-pinned requirements file this replaced had.

## Regenerating

Once per platform, into this directory, then confirm and record:

    pip download --only-binary=:all: --implementation cp --python-version 3.12 \
        --platform win_amd64 \
        -d wheels cryptography==<version> zstandard==<version>

    pip download --only-binary=:all: --implementation cp --python-version 3.12 \
        --platform manylinux_2_34_x86_64 --platform manylinux_2_28_x86_64 \
        --platform manylinux_2_17_x86_64 --platform manylinux2014_x86_64 \
        -d wheels cryptography==<version> zstandard==<version>

    python phx.py wheels write        # cross-checks PyPI, then writes SHA256SUMS
    python phx.py minisign selftest   # the signer, against what was just vendored

Delete the superseded files first — nothing prunes them, and a stale wheel left beside a new one is
a version pip is free to pick.

**No file is committed here whose sha256 was not cross-checked against
`https://pypi.org/pypi/<package>/<version>/json`.** A local `pip download` proves only that some
index answered on the day it ran. `phx.py wheels write` performs that cross-check and refuses
to record a digest it could not confirm; `phx.py wheels check` re-proves the directory
against `SHA256SUMS` offline, at any pinned SHA.
