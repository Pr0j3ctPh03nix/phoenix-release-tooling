"""The `.phxb` bundle format — the one implementation both producers write through.

A bundle is CONTAINERLESS: `zstd(member₀ ‖ member₁ ‖ …)` with no header, no member table and no
padding. Everything needed to take it apart lives in the manifest (each member's `sha256`, `size`
and ORDER), which is what lets a reader verify `psha256`, decode once, and split the stream by
counting bytes -- see phoenix_tooling/manifest_schema.py and phoenix_tooling/build_manifest.py for
the producer side of that; the reader side lived in docs/manifest-reader-contract.md before that
directory was deleted alongside the validator it supported (see git history).

WHY THIS FILE EXISTS. The mod producer (`dist/tools/gen_manifest.py`) and the base-game producer
(`tools/build_game_bundles.py`) both emit this format, and used to carry byte-identical copies of
the settings and the writer below, kept in step by a comment asking that they be "kept deliberately
IDENTICAL". Nothing enforced it. The three settings are not tuning knobs — they are wire-format
commitments (see each) — so a divergence would not fail a test, it would ship bundles a reader
refuses or a build that is no longer reproducible.

The old justification for copying was that this file "cannot be imported from dist". That was never
the rule: `sync.py` copies dev-side tools into `dist/tools/` precisely for tools CI has to RUN, and
the rule it enforces is about UNRUNNABLE DEPENDENCIES — a module that reaches for `../research/src`
cannot live on a CI box. This one reaches for nothing: stdlib plus `zstandard`, no path assumptions.
So it ships through `sync.py`'s `DEV_TOOLS`, like the signer, and hand-edits to the dist copy are
reverted by the next sync like every other mirrored file.
"""
import hashlib
import os
import sys

import zstandard as zstd

from . import build_manifest

# Capped at 27 by the spec: that is the reference decoder's default ZSTD_d_windowLogMax, so a bundle
# never requires a reader to raise its window limit. Above it, correct readers refuse our bundles.
# Used to be a second, hand-duplicated copy of this exact commitment -- precisely the drift this
# docstring warns about -- so it is imported from manifest_schema.py, the one place the wire format
# is declared, rather than restated here.
from .manifest_schema import ZSTD_WLOG

# --- wire-format settings: NOT tuning knobs ------------------------------------------------------
ZSTD_LEVEL = 19
# Single-threaded per compressor, and not for want of cores. libzstd derives its job size from the
# window log, so at windowLog 27 anything under ~512 MiB is smaller than ONE job and exactly one
# worker engages whatever `threads` says — the flag buys nothing here. What it COSTS is determinism:
# zstd's job splitting depends on the worker count, so the same logical bundle would compress to
# different bytes on a machine with a different core count, and the bundle's name is its content
# hash. Producers that want parallelism run several compressors at once instead.
ZSTD_THREADS = 0
CHUNK = 1 << 20


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def extclass(dest):
    """The extension a dest is grouped by when ordering members — '' for an extensionless file.

    Splits on the BASENAME so a dot in a directory name is not mistaken for an extension."""
    return dest.rsplit(".", 1)[-1].lower() if "." in dest.rsplit("/", 1)[-1] else ""


class HashingWriter:
    """Hashes the compressed frame as it is written, so the packed sha256 costs no second read of
    the finished asset — with several of these running at once that re-read was pure contention."""

    def __init__(self, fh):
        self.fh, self.h, self.n = fh, hashlib.sha256(), 0

    def write(self, b):
        self.h.update(b)
        self.n += len(b)
        return self.fh.write(b)

    def flush(self):
        self.fh.flush()


def build_bundle(members, staging, label, path_of, tmp_name="bundle.tmp"):
    """Compress `members` into one solid frame under `staging`; return the manifest's Bundle.

    The order IS the format: a reader splits the decoded stream by counting each member's declared
    `size`, so nothing may be reordered after this runs.

    The returned `name` is PURELY content-addressed — label plus a prefix of the packed hash, with
    nothing positional in it. Identical bytes must always produce an identical name, or an
    incremental publish cannot tell "already uploaded" from "changed". (Uniqueness across a release
    is enforced separately: phoenix_tooling/build_manifest.py refuses two bundles sharing one
    asset name, B8, when the manifest is assembled.)
    """
    members = list(members)
    usize = sum(m.size for m in members)
    tmp = os.path.join(staging, tmp_name)
    params = zstd.ZstdCompressionParameters.from_level(
        ZSTD_LEVEL, window_log=ZSTD_WLOG, threads=ZSTD_THREADS)
    cctx = zstd.ZstdCompressor(compression_params=params)
    with open(tmp, "wb") as raw_out:
        hw = HashingWriter(raw_out)
        # closefd=False: the frame is flushed when this context exits, but the file must stay open
        # until then — and hw.n is only final after that flush.
        with cctx.stream_writer(hw, size=usize, closefd=False) as w:
            for m in members:
                with open(path_of(m), "rb") as fh:
                    for chunk in iter(lambda: fh.read(CHUNK), b""):
                        w.write(chunk)
        psha, psize = hw.h.hexdigest(), hw.n
    name = "{}-{}.phxb".format(label, psha[:12])
    os.replace(tmp, os.path.join(staging, name))
    return build_manifest.Bundle(name, "zstd", psize, psha, entries=members)


def _selftest():
    import tempfile

    results = []

    def ok(name, fn):
        try:
            fn()
        except Exception as e:
            results.append((False, name, f"{type(e).__name__}: {e}"))
        else:
            results.append((True, name, ""))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    blobs = {"game/dota/scripts/npc/npc_units.txt": b"npc_units\n" * 700,
             "game/dota/pak01_000.vpk": bytes(range(256)) * 64}
    root = tempfile.mkdtemp()
    staging = os.path.join(root, "staging")
    os.makedirs(staging)
    paths = {}
    for dest, data in blobs.items():
        p = os.path.join(root, "src", dest.replace("/", os.sep))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
        paths[dest] = p
    entries = [build_manifest.entry(dest, hashlib.sha256(data).hexdigest(), len(data))
               for dest, data in blobs.items()]
    bundle = build_bundle(entries, staging, "mod", lambda e: paths[e.dest])
    packed = os.path.join(staging, bundle.name)

    def the_members_it_was_given_in_order():
        assert_([id(e) for e in bundle.entries] == [id(e) for e in entries],
                "the Bundle does not hold the member objects it was given, in order")
        assert_(bundle.codec == "zstd", f"codec: {bundle.codec}")
        assert_(bundle.name == f"mod-{bundle.psha256[:12]}.phxb", f"name: {bundle.name}")

    def the_packed_bytes_are_what_it_declares():
        assert_(sha256(packed) == bundle.psha256, "psha256 is not the hash of the written file")
        assert_(os.path.getsize(packed) == bundle.psize, "psize is not the size of the written file")
        with open(packed, "rb") as fh:
            decoded = zstd.ZstdDecompressor().decompress(fh.read())
        assert_(decoded == b"".join(blobs.values()),
                "the frame does not decode to the members concatenated in the order given")

    def size_and_members_derive_through_build():
        doc = build_manifest.build("mod", "1.0.0", 1, entries, bundles=[bundle])
        assert_(doc["bundles"] == [{
            "name": bundle.name, "codec": "zstd", "psize": bundle.psize, "psha256": bundle.psha256,
            "size": sum(len(d) for d in blobs.values()),
            "members": [hashlib.sha256(d).hexdigest() for d in blobs.values()]}],
            f"bundles: {doc['bundles']}")

    ok("a two-member pack returns a Bundle holding those two objects, in stream order",
       the_members_it_was_given_in_order)
    ok("the packed file is exactly the psize/psha256 the Bundle declares, and decodes in order",
       the_packed_bytes_are_what_it_declares)
    ok("the manifest's bundle size/members derive from that Bundle through build()",
       size_and_members_derive_through_build)

    for good, name, detail in results:
        print(f"  {'ok  ' if good else 'FAIL'} {name}" + (f"\n         {detail}" if detail else ""))
    bad = sum(not good for good, _, _ in results)
    print(f"selftest: {len(results)} checks, all pass" if not bad
          else f"selftest: {bad} of {len(results)} checks FAILED")
    return bad


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    argv = sys.argv[1:] if argv is None else list(argv)
    if len(argv) == 1 and argv[0] == "selftest":
        sys.exit(1 if _selftest() else 0)
    sys.exit("usage: phx phxb selftest    (the bundle writer is a library; this is its own check)")


if __name__ == "__main__":
    main()
