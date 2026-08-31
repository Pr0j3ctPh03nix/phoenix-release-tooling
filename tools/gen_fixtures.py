#!/usr/bin/env python3
"""Generate the manifest CONFORMANCE FIXTURES — the test suite for anything that reads a manifest.

The producers only ever emit a correct, current manifest; that is their job. But the interesting
half of the compatibility contract is what a reader does with input it was NOT built for: a
manifest from the future, one from before a field existed, one carrying keys the reader has never
heard of, one with a `dest` that escapes the game root, and — since schema 3 — one whose bundle
bookkeeping is internally inconsistent. None of those can come out of a producer, so they are
constructed here.

The version these fixtures are written against is the FORMAT version (manifest_schema.py), not any
producer's emit-version. Both producers emit 3 today, but every mod release published BEFORE the
payload became a single bundle is schema 2 and stays readable forever — which is what the
schema-2 fixture pins. A producer's number moving must not drag the fixtures with it either way.

Each fixture is a byte-valid manifest with no annotations inside it — a reader is fed the file
verbatim. What each one asserts lives beside them in index.json, so a reader's test suite can walk
the index and needs no knowledge of this script.

The fixtures are COMMITTED. Regenerate and commit whenever FORMAT_SCHEMA or the emitted shape
changes; `--check` fails if what is on disk no longer matches, so drift is caught rather than
discovered.

Signatures get their own subdirectory and their own index, because validating a document you cannot
attribute is the smaller half of the job — see signature_files() for why those cases regenerate on
different terms from the rest.

    python tools/gen_fixtures.py [--out docs/manifest-fixtures] [--check | --selftest]

stdlib only, EXCEPT when the signature cases have to be MINTED or self-tested — that reaches
tools/phoenix_minisign.py and so `cryptography`. Deterministic: same inputs produce byte-identical
output, so a no-op run leaves the tree clean.
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from manifest_schema import FORMAT_SCHEMA, PAYLOAD_IDS  # noqa: E402  the one source of both

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join("docs", "manifest-fixtures")

FUTURE = FORMAT_SCHEMA + 1   # a version no reader built against FORMAT_SCHEMA can know
UNKNOWN_KIND = "sequence"    # an option kind that does not exist, and deliberately never will
UNKNOWN_CODEC = "brotli"     # a codec this format does not define
UNKNOWN_PAYLOAD = "skins"    # a payload id nothing produces and no reader can dispatch
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# Frozen, not time.time(): a fixture that changed every run would make --check useless. The value
# is also the point of the advisory-signed-at case — it is years stale and must still be accepted.
SIGNED_AT = 1767225600       # 2026-01-01T00:00:00Z

SIG_DIR = "signatures"       # the signature cases, with an index of their own
SIGNED_DOC = "current.json"  # the document those cases are signatures OF
GENERATED_EXT = (".json", ".minisig", ".pub")


def fake_sha(label):
    """A stable, well-formed sha256 for a fixture asset. Fixtures are never downloaded, so the
    digest only has to be the right SHAPE (64 lowercase hex) and stable across runs."""
    return hashlib.sha256(label.encode()).hexdigest()


def fake_size(label):
    return 1024 + (int(fake_sha(label)[:4], 16) % 9000)


def entry(label, dest, bundled=False, size=None):
    """One file-bearing entry. `bundled` drops `name`: its bytes come from a bundle instead."""
    e = {"dest": dest, "sha256": fake_sha(label), "size": fake_size(label) if size is None else size}
    if not bundled:
        e = {"name": label, **e}
    return e


def bundle(name, members, codec="zstd", size=None):
    """A bundle over `members` (entries). `size` defaults to the sum the spec requires (B2)."""
    total = sum(m["size"] for m in members) if size is None else size
    packed = max(1, total // 3)
    return {
        "name": name, "codec": codec,
        "psize": packed, "psha256": fake_sha(name + ":packed"),
        "size": total,
        "members": [m["sha256"] for m in members],
    }


# --- the current shape -------------------------------------------------------------------------

def current():
    """Every feature of the current schema at once — the shape a reader must fully support.

    Deliberately exercises all three ways an entry resolves to bytes (raw asset / bundle member /
    zero-byte materialized), both bundle arities (multi-member and one-member), a bundled
    OPTION VARIANT — the case that forces membership to be keyed by content hash, since choice
    variants share one dest and live outside files[] — and the signing envelope every current
    document carries. It is also the document the signatures/ cases are signatures of."""
    raw = entry("pak01_000.vpk", "game/dota/pak01_000.vpk")
    small_a = entry("npc_units.txt", "game/dota/scripts/npc/npc_units.txt", bundled=True)
    small_b = entry("hero_ids.txt", "game/dota/scripts/npc/hero_ids.txt", bundled=True)
    solo = entry("client.dll", "game/dota/bin/win64/client.dll", bundled=True, size=104857600)
    zero = {"dest": "game/dota/empty.marker", "sha256": EMPTY_SHA256, "size": 0}

    var_bundled = {"id": "mod", "label": {"en": "New lighting", "ru": "Новое освещение"},
                   "sha256": fake_sha("opt__lighting__mod.vpk"),
                   "size": fake_size("opt__lighting__mod.vpk")}
    var_raw = {"id": "original", "label": {"en": "Original lighting", "ru": "Оригинальное освещение"},
               "name": "opt__lighting__original.vpk",
               "sha256": fake_sha("opt__lighting__original.vpk"),
               "size": fake_size("opt__lighting__original.vpk")}
    toggle_file = entry("opt__terrain__pak01_dir.vpk", "game/dota_phoenix/pak01_dir.vpk", bundled=True)

    tail = bundle("b000-txt-4f3a91c2e5d8.phxb", [small_a, small_b, var_bundled, toggle_file])
    pack = bundle("b001-pack-9c2e7ab04d13.phxb", [solo])

    return {
        "schema": FORMAT_SCHEMA,
        "payload_id": "mod",
        "serial": 42,
        "signed_at": SIGNED_AT,
        "version": "1.0.0",
        "notes": "### Added\n- Something a player can see.",
        "bundles": [tail, pack],
        "files": [raw, small_a, small_b, solo, zero],
        "remove": [{"dest": "game/dota/scripts/regions.txt"}],
        # PRESENTATIONAL display hierarchy: labeled nodes, dest refs into files[], one UNLABELED
        # node (content splices inline), and "Hero Demo Plus" as a heading holding always-installed
        # files — the tree is not an options tree. A reader may ignore all of it.
        "tree": [
            {"label": {"en": "Phoenix Core", "ru": "Ядро Phoenix"},
             "files": ["game/dota/pak01_000.vpk", "game/dota/empty.marker"],
             "groups": [
                 {"label": {"en": "Hero Demo Plus"},
                  "files": ["game/dota/scripts/npc/npc_units.txt",
                            "game/dota/scripts/npc/hero_ids.txt"]}]},
            {"files": ["game/dota/bin/win64/client.dll"]},
        ],
        "options": [
            {"id": "lighting", "kind": "choice",
             "label": {"en": "Lighting", "ru": "Освещение"},
             "default": "original", "dest": "game/dota_phoenix/maps/dota.vpk",
             "variants": [var_bundled, var_raw]},
            {"id": "terrain", "kind": "toggle",
             "label": {"en": "Less acidic Radiant terrain", "ru": "Менее кислотная трава"},
             "default": False, "files": [toggle_file]},
        ],
    }


def schema2_options():
    """The shape gen_manifest.py emitted BEFORE the mod payload became one bundle: schema 2,
    options, every entry named, no bundles. A schema-3 reader must keep reading it verbatim,
    because every mod release published up to that cutover is this shape and stays installable."""
    variants = []
    for vid, label in (("mod", {"en": "New lighting", "ru": "Новое освещение"}),
                       ("original", {"en": "Original lighting", "ru": "Оригинальное освещение"})):
        name = "opt__lighting__{}.vpk".format(vid)
        variants.append({"name": name, "sha256": fake_sha(name), "size": fake_size(name),
                         "id": vid, "label": label})
    tname = "opt__terrain__pak01_dir.vpk"
    return {
        "schema": 2,
        "payload_id": "mod",
        "serial": 41,
        "signed_at": SIGNED_AT,
        "version": "1.0.0",
        "notes": "### Added\n- Something a player can see.",
        "files": [entry("winmm.dll", "game/bin/win64/winmm.dll"),
                  entry("events.lua", "game/dota_addons_phoenix/hero_demo/scripts/vscripts/"
                                      "events.lua"),
                  entry("regions.txt", "game/dota_phoenix/scripts/regions.txt")],
        "remove": [{"dest": "game/dota/scripts/regions.txt"}],
        "tree": [
            {"label": {"en": "Phoenix Core", "ru": "Ядро Phoenix"},
             "files": ["game/bin/win64/winmm.dll", "game/dota_phoenix/scripts/regions.txt"],
             "groups": [
                 {"label": {"en": "Hero Demo Plus"},
                  "files": ["game/dota_addons_phoenix/hero_demo/scripts/vscripts/events.lua"]}]},
        ],
        "options": [
            {"id": "lighting", "kind": "choice", "label": {"en": "Lighting", "ru": "Освещение"},
             "default": "original", "dest": "game/dota_phoenix/maps/dota.vpk",
             "variants": variants},
            {"id": "terrain", "kind": "toggle",
             "label": {"en": "Less acidic Radiant terrain", "ru": "Менее кислотная трава"},
             "default": False,
             "files": [{"name": tname, "dest": "game/dota_phoenix/pak01_dir.vpk",
                        "sha256": fake_sha(tname), "size": fake_size(tname)}]},
        ],
    }


# --- the matrix --------------------------------------------------------------------------------

def build():
    """[(filename, manifest, expect, why)] — the whole matrix."""
    out = []

    out.append(("current.json", current(), "accept",
                "The current schema with every feature present: a raw entry, a multi-member "
                "bundle, a one-member bundle, a zero-byte entry and a BUNDLED OPTION VARIANT. A "
                "reader that rejects this is broken outright."))

    out.append(("schema2-options.json", schema2_options(), "accept",
                "The shape the mod producer emitted before its payload became a single bundle — "
                "schema 2, every entry named, no bundles. Every mod release published up to that "
                "cutover is this shape and must stay installable, so a schema-3 reader that only "
                "handles bundled documents would break on every release already in the wild."))

    no_bundles = current()
    no_bundles.pop("bundles")
    no_bundles["files"] = [entry("pak01_000.vpk", "game/dota/pak01_000.vpk"),
                           {"dest": "game/dota/empty.marker", "sha256": EMPTY_SHA256, "size": 0}]
    no_bundles["options"] = []
    out.append(("schema3-no-bundles.json", no_bundles, "accept",
                "Schema 3 with no `bundles` key at all. Absent MUST mean none — a schema-3 "
                "document that bundles nothing is exactly a schema-2 document."))

    legacy = {"payload_id": "mod", "serial": 1, "signed_at": SIGNED_AT,
              "version": "0.0.1",
              "files": [entry("winmm.dll", "game/bin/win64/winmm.dll")],
              "remove": []}
    out.append(("legacy-no-schema.json", legacy, "accept",
                "Schema 1 predates the `schema` key, so an ABSENT key means 1 — not 'unknown'. "
                "A reader that requires the key rejects every manifest ever published before it. "
                "It still carries the signing envelope: signatures are verified before a document "
                "is parsed, so the only documents that reach these checks come from a producer "
                "that signs — the absent-`schema` rule is orthogonal to that."))

    fut = current()
    fut["schema"] = FUTURE
    out.append(("future-schema.json", fut, "refuse:schema",
                "A manifest newer than the reader. Must fail with 'update the app', citing the "
                "schema — never a parse or validation error."))

    fut_kind = current()
    fut_kind["schema"] = FUTURE
    fut_kind["options"] = [
        {"id": "combo", "kind": UNKNOWN_KIND, "label": {"en": "Something new"},
         "default": None, "steps": [entry("a.bin", "game/dota_phoenix/a.bin")]}]
    out.append(("future-unknown-option-kind.json", fut_kind, "refuse:schema",
                "THE ORDERING TEST. Carries an option kind that does not exist, so a reader that "
                "parses the document before checking `schema` dies on the unknown kind and reports "
                "a parse failure. Correct behaviour is the SAME clean schema refusal as "
                "future-schema.json: read `schema` first, decide, only then parse."))

    dangling = current()
    dangling["tree"] = dangling["tree"] + [
        {"label": {"en": "Ghost"}, "files": ["game/dota/not-shipped.bin"]}]
    out.append(("tree-dangling-ref.json", dangling, "accept",
                "A `tree` node referencing a dest that files[] does not carry. The tree is "
                "PRESENTATIONAL, so this must not be fatal — skip the reference and install exactly "
                "as declared. A reader that refuses here turns a display slip into a client that "
                "cannot update at all."))

    additive = current()
    additive["some_future_top_level_key"] = {"anything": [1, 2, 3]}
    additive["files"][0]["some_future_entry_key"] = "ignore me"
    additive["bundles"][0]["some_future_bundle_key"] = "ignore me too"
    additive["options"][0]["description"] = {"en": "A longer explanation."}
    out.append(("additive-unknown-keys.json", additive, "accept",
                "Same schema, unknown keys added at the top level, inside a file entry, inside a "
                "BUNDLE and inside an option. The producers treat additive keys as "
                "backward-compatible and do NOT bump `schema` for them, so a reader MUST ignore "
                "what it does not recognise. A reader that errors on unknown fields forces a "
                "needless bump for every addition."))

    # --- the signing envelope: who the document is for, and where it sits in that payload's order --

    m = current()
    m["signed_at"] = SIGNED_AT - 3 * 365 * 24 * 3600
    out.append(("advisory-signed-at.json", m, "accept",
                "`signed_at` years in the past, and still accepted. It is ADVISORY — display it, "
                "sort by it, never decide with it. A reader that ages a manifest out hands anyone "
                "with a wrong clock (or a release cut from an old branch) a client that can no "
                "longer update, and buys nothing: `serial` is the ordering authority and it is "
                "signed."))

    m = current()
    m.pop("payload_id")
    out.append(("missing-payload-id.json", m, "refuse:invalid",
                "No `payload_id`. A signature proves who wrote a document, not what it is FOR, so "
                "the payload has to be stated inside the signed bytes and checked against what the "
                "client came for — otherwise a validly signed launcher manifest can be served as "
                "the mod manifest and installed as one. Missing means the check cannot be made."))

    m = current()
    m["payload_id"] = UNKNOWN_PAYLOAD
    out.append(("unknown-payload-id.json", m, "refuse:invalid",
                "A `payload_id` outside the closed set. NOT 'update the app': the reader is not "
                "missing a feature, it has been handed a document it cannot dispatch, which means "
                "the release was mis-served or rewritten. Guessing from the contents is exactly "
                "the mistake signing exists to prevent."))

    m = current()
    m.pop("serial")
    out.append(("missing-serial.json", m, "refuse:invalid",
                "No `serial`. Version strings are for humans and are not ordered (`1.10.0` vs "
                "`1.9.0`), so without a serial a mirror can replay a stale but perfectly signed "
                "manifest forever and no client can tell."))

    m = current()
    m["serial"] = True
    out.append(("serial-is-bool.json", m, "refuse:invalid",
                "`serial` is JSON `true`. In several languages that IS an integer 1 — Python's "
                "isinstance(True, int) is true — so a reader that only checks 'is a whole number' "
                "silently orders releases by a boolean. The same trap `schema` already carries."))

    m = current()
    m["serial"] = -1
    out.append(("serial-negative.json", m, "refuse:invalid",
                "A negative `serial`. Nothing legitimately produces one, and a reader storing "
                "'the highest serial installed' can be pushed below its own floor by a document "
                "claiming one."))

    # --- B1-B8: well-formed schema-3 documents whose bundle bookkeeping is inconsistent ---

    m = current()
    m["bundles"][0]["size"] += 4096
    out.append(("invalid-bundle-size-sum.json", m, "refuse:invalid",
                "B2: the members' sizes no longer sum to the bundle's `size`. The reader splits a "
                "solid stream by counting bytes, so a wrong total silently misaligns every member "
                "after the error — it must be caught up front, not discovered as a hash mismatch."))

    m = current()
    m["bundles"][0]["members"].append(fake_sha("a-hash-no-entry-claims"))
    out.append(("invalid-orphan-member.json", m, "refuse:invalid",
                "B1: a member hash matching no entry in the document. Its size is therefore "
                "unknowable and the stream cannot be split at all."))

    m = current()
    m["bundles"][0]["members"] = [h for h in m["bundles"][0]["members"]
                                  if h != m["files"][1]["sha256"]]
    m["bundles"][0]["size"] -= m["files"][1]["size"]
    out.append(("invalid-unbundled-entry.json", m, "refuse:invalid",
                "B3: an entry with no `name`, a non-zero size, and its hash in no bundle. Nothing "
                "in the document says where its bytes come from."))

    m = current()
    m["bundles"][1]["members"] = m["bundles"][1]["members"] + m["bundles"][0]["members"][:1]
    m["bundles"][1]["size"] += m["files"][1]["size"]
    out.append(("invalid-duplicate-member.json", m, "refuse:invalid",
                "B5: one hash carried by two bundles. The reader would fetch and decode the same "
                "content twice, and 'the bundle holding X' stops being well defined."))

    m = current()
    m["bundles"][1]["members"] = []
    m["bundles"][1]["size"] = 0
    out.append(("invalid-empty-bundle.json", m, "refuse:invalid",
                "B7: a bundle with no members — an asset that costs a download and yields "
                "nothing."))

    m = current()
    m["bundles"][0]["codec"] = UNKNOWN_CODEC
    out.append(("unknown-codec.json", m, "refuse:codec",
                "A codec this build cannot decode, under a schema it CAN read. Adding a codec is "
                "supposed to bump `schema`, so this is a producer that broke that rule — but the "
                "user-facing answer is still 'update the app', never 'your download is corrupt'. "
                "Must be caught at parse time (R9), not deferred to when the bundle is needed."))

    m = current()
    m["files"][0] = dict(m["files"][0], dest="../../../Windows/System32/winmm.dll")
    out.append(("invalid-dest-traversal.json", m, "refuse:invalid",
                "A `dest` with `..` components that escapes the game root. dest is the one field that "
                "turns a compromised manifest into an arbitrary file write, so a reader must REFUSE it "
                "rather than trust the producer — a supported schema, but not safely installable."))

    return out


# --- the signature cases -------------------------------------------------------------------------

FIXTURE_KEY = SIG_DIR + "/fixture.pub"
STRANGER_KEY = SIG_DIR + "/stranger.pub"
SIG_TRUSTED = "phoenix mod payload, serial 42"
SIG_REWRITTEN = "phoenix mod payload, serial 9999"

SIG_CASES = [
    {"sig": SIG_DIR + "/good.minisig", "doc": SIGNED_DOC, "keys": [FIXTURE_KEY],
     "expect": "accept",
     "why": "The baseline: a signature by a trusted key over the document it was made for. A "
            "verifier that cannot accept this one proves nothing by refusing the rest — most "
            "likely it disagrees about the framing (the exact four lines, the algorithm bytes, or "
            "what the global signature covers) rather than about the cryptography."},
    {"sig": SIG_DIR + "/good.minisig", "doc": SIGNED_DOC, "keys": [STRANGER_KEY, FIXTURE_KEY],
     "expect": "accept",
     "why": "The same signature against a key RING, with the signing key second. The key_id picks "
            "the key; a verifier that only tries the first entry breaks the moment a key is "
            "rotated, which is the one time a ring exists."},
    {"sig": SIG_DIR + "/good.minisig", "doc": SIG_DIR + "/tampered.json", "keys": [FIXTURE_KEY],
     "expect": "refuse:signature",
     "why": "The signed document with ONE hex digit of ONE sha256 changed — still valid JSON, "
            "still a valid manifest, and it redirects a file to bytes of the attacker's choosing. "
            "This is the entire reason the signature exists, and nothing but the signature can "
            "catch it."},
    {"sig": SIG_DIR + "/stranger.minisig", "doc": SIGNED_DOC, "keys": [FIXTURE_KEY],
     "expect": "refuse:signature",
     "why": "A perfectly valid signature over the identical bytes, by a key the reader does not "
            "trust. Anyone can sign anything; the trust root is what makes a signature mean "
            "something."},
    {"sig": SIG_DIR + "/stranger.minisig", "doc": SIGNED_DOC, "keys": [STRANGER_KEY],
     "expect": "accept",
     "why": "The control for the case above: the same file verifies under its own key. Without "
            "this pair, a verifier that refuses everything would pass the whole suite."},
    {"sig": SIG_DIR + "/truncated.minisig", "doc": SIGNED_DOC, "keys": [FIXTURE_KEY],
     "expect": "refuse:signature",
     "why": "A .minisig missing its fourth line — what an interrupted download leaves behind. It "
            "must fail as a refusal, not as a crash and not as 'no global signature to check, so "
            "nothing to disagree with'."},
    {"sig": SIG_DIR + "/hashed-algo.minisig", "doc": SIGNED_DOC, "keys": [FIXTURE_KEY],
     "expect": "refuse:signature",
     "why": "The one substitution that survives every other check: a genuine, verifying "
            "pure-Ed25519 signature by the trusted key, relabelled 'ED' (Blake2b-prehashed). A "
            "verifier that reads the algorithm and ignores it accepts this, and has silently "
            "acquired a second algorithm it never implemented."},
    {"sig": SIG_DIR + "/rewritten-comment.minisig", "doc": SIGNED_DOC, "keys": [FIXTURE_KEY],
     "expect": "refuse:signature",
     "why": "The primary signature is untouched and verifies; only the trusted comment was edited, "
            "to claim a newer serial. It fails ONLY if the global signature is actually checked — "
            "which is the whole reason a comment inside a signature can be quoted at all."},
]

# Everything a mint produces, derived from the matrix so a rename cannot leave an orphan behind.
KEY_BEARING = sorted({c["sig"] for c in SIG_CASES} | {k for c in SIG_CASES for k in c["keys"]})


def _mint(doc_text):
    """A fresh keypair and every key-bearing signature case over `doc_text`."""
    from phoenix_minisign import (ALGO_HASHED, format_signature, generate_keypair,  # noqa: E402
                                  parse_signature, sign)
    comment = "phoenix manifest fixtures"
    pub, sec = generate_keypair(comment)
    stranger_pub, stranger_sec = generate_keypair(comment + ", an untrusted key")
    data = doc_text.encode("utf-8")
    good = sign(data, sec, comment, SIG_TRUSTED)
    parsed = parse_signature(good)
    return {
        FIXTURE_KEY: pub,
        STRANGER_KEY: stranger_pub,
        SIG_DIR + "/good.minisig": good,
        SIG_DIR + "/stranger.minisig": sign(data, stranger_sec, comment, SIG_TRUSTED),
        SIG_DIR + "/truncated.minisig": "\n".join(good.split("\n")[:3]) + "\n",
        SIG_DIR + "/hashed-algo.minisig": format_signature(parsed._replace(algo=ALGO_HASHED)),
        SIG_DIR + "/rewritten-comment.minisig": format_signature(
            parsed._replace(trusted_comment=SIG_REWRITTEN)),
    }


def _committed(out_dir, signed_sha):
    """The committed key-bearing files, if they are all present, still cover `signed_sha`, and are
    still written in the format this build produces.

    The format check is not redundant with the document hash: a change to the .minisig FRAMING —
    the comment prefixes, the algorithm label, the line count — leaves the signed document
    untouched, so the hash alone would hand back files that no longer parse. That is not
    hypothetical; the trusted-comment prefix was wrong once, and the stale set sailed through
    --check while --selftest failed three cases. Round-tripping one committed file through the
    parser costs nothing and closes the gap: whatever this build cannot read, it re-mints."""
    try:
        with open(os.path.join(out_dir, SIG_DIR, "index.json"), encoding="utf-8", newline="") as f:
            if json.load(f).get("signed_sha256") != signed_sha:
                return None
        out = {}
        for name in KEY_BEARING:
            with open(os.path.join(out_dir, name), encoding="utf-8", newline="") as f:
                out[name] = f.read()
        from phoenix_minisign import MinisignError, parse_signature
        try:
            parse_signature(out[SIG_DIR + "/good.minisig"])
        except MinisignError:
            return None
        return out
    except (OSError, ValueError):
        return None


def _tampered(doc_text, doc):
    """The signed document with ONE hex digit of ONE sha256 flipped. Done on the TEXT, not by
    re-rendering a mutated dict, so the two files differ in exactly one byte and the case cannot
    quietly become 'a different document that also fails'."""
    sha = doc["files"][0]["sha256"]
    out = doc_text.replace(sha, ("1" if sha[0] == "0" else "0") + sha[1:])
    if out == doc_text:
        sys.exit("gen_fixtures: the tamper target is no longer in " + SIGNED_DOC)
    return out


def signature_files(doc_text, doc, out_dir):
    """{path relative to the fixtures root: exact file text} for the signature cases.

    These regenerate on different terms from every other fixture, because THE KEY THAT SIGNS THEM IS
    DISCARDED the moment they are minted: committing it would put a private key in the repo, and
    Ed25519 reproduces a signature only for a key you still hold. So while the committed set still
    covers the current document (index.json records its sha256) it is returned verbatim, and a run
    that finds it stale mints a new keypair — changing every file here, fixture.pub included, at
    once.

    The division of labour that follows is worth knowing: `--check` pins these bytes against the
    document they cover, and only `--selftest` proves they still verify."""
    signed_sha = hashlib.sha256(doc_text.encode("utf-8")).hexdigest()
    files = dict(_committed(out_dir, signed_sha) or _mint(doc_text))
    files[SIG_DIR + "/tampered.json"] = _tampered(doc_text, doc)
    files[SIG_DIR + "/index.json"] = json.dumps({
        "_note": "Signature conformance cases for manifest readers, generated by "
                 "tools/gen_fixtures.py. Verify `sig` over the bytes of `doc` against the keys in "
                 "`keys`, and assert `expect`. Paths are relative to the fixtures root. Read `doc` "
                 "as BYTES: a signature covers bytes, and a text-mode read that rewrites line "
                 "endings verifies a file nobody sent. Do not edit by hand.",
        "format": "minisign, algorithm 'Ed' (pure Ed25519). The four-line format, and the ways it "
                  "is narrower than upstream minisign, are documented in tools/phoenix_minisign.py.",
        "signed_document": SIGNED_DOC,
        "signed_sha256": signed_sha,
        "expectations": {
            "accept": "Both the signature and the global signature verify under one of `keys`.",
            "refuse:signature": "The document is not authenticated. ONE outcome on purpose, "
                                "covering the file's structure, its algorithm, its key, its "
                                "signature and its global signature alike — a reader that "
                                "distinguishes them ends up treating one of them as benign.",
        },
        "cases": SIG_CASES,
    }, indent=2, ensure_ascii=False) + "\n"
    return files


# --- rendering ---------------------------------------------------------------------------------

def render(fixtures, out_dir):
    """{relative path: exact file text} for the whole output directory."""
    files = {name: json.dumps(m, indent=2, ensure_ascii=False) + "\n" for name, m, _, _ in fixtures}
    index = {
        "_note": "Conformance fixtures for manifest readers, generated by tools/gen_fixtures.py. "
                 "Feed each `file` to the reader and assert `expect`. Do not edit by hand.",
        "schema": FORMAT_SCHEMA,
        "future_schema": FUTURE,
        "payload_ids": sorted(PAYLOAD_IDS),
        "signatures": SIG_DIR + "/index.json",
        "expectations": {
            "accept": "The reader parses the manifest and proceeds normally.",
            "refuse:schema": "Rejected specifically because the schema is unsupported, with a "
                             "message telling the user to update. NOT a parse error.",
            "refuse:invalid": "The schema is supported but the document cannot be safely acted on "
                              "— a missing or unusable signing envelope (`payload_id`, `serial`), "
                              "an unsafe `dest` (escapes the game root), or a violated bundle "
                              "guarantee (the B1-B8 invariants in tools/validate_manifest.py). A broken release — "
                              "NOT an 'update the app' message, and not a schema refusal.",
            "refuse:codec": "The schema is supported but a bundle names a codec the reader cannot "
                            "decode. Same user-facing outcome as refuse:schema (tell the user to "
                            "update); different detection point.",
        },
        "cases": [{"file": name, "expect": exp, "why": why} for name, _, exp, why in fixtures],
    }
    files["index.json"] = json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    doc = next(m for name, m, _, _ in fixtures if name == SIGNED_DOC)
    files.update(signature_files(files[SIGNED_DOC], doc, out_dir))
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT, help="output dir (default: " + DEFAULT_OUT + ")")
    ap.add_argument("--check", action="store_true",
                    help="report drift, write nothing, exit 1 if any")
    ap.add_argument("--selftest", action="store_true",
                    help="assert every fixture produces the outcome index.json claims")
    a = ap.parse_args()

    out_dir = a.out if os.path.isabs(a.out) else os.path.join(REPO, a.out)
    fixtures = build()
    files = render(fixtures, out_dir)

    if a.selftest:
        # The matrix is only worth anything if each case still fails the way it says it does — a
        # fixture that quietly drifted into passing (or into failing for a DIFFERENT reason) would
        # keep the suite green while testing nothing. Checked against the reference validator, so
        # this catches drift in the fixtures AND in the rules they encode.
        from validate_manifest import PAYLOAD_IDS as READER_PAYLOADS, validate, verify_signature
        bad = 0
        for name, manifest, expect, _why in fixtures:
            got, detail = validate(manifest)
            ok = got == expect
            bad += not ok
            print(f"  {'ok  ' if ok else 'FAIL'} {name:<34} expect {expect:<15} got {got:<15}"
                  f"{detail}")
        # The reference validator keeps its own copy of the payload set so it stays one portable
        # file; if the two ever disagree, the fixtures test a rule no reader ports.
        if READER_PAYLOADS != PAYLOAD_IDS:
            bad += 1
            print(f"  FAIL validate_manifest.PAYLOAD_IDS {sorted(READER_PAYLOADS)} has drifted "
                  f"from manifest_schema {sorted(PAYLOAD_IDS)}")
        for c in SIG_CASES:
            got, detail = verify_signature(files[c["doc"]].encode("utf-8"), files[c["sig"]],
                                           [files[k] for k in c["keys"]])
            ok = got == c["expect"]
            bad += not ok
            label = (f"{c['sig'].rsplit('/', 1)[-1]} over {c['doc'].rsplit('/', 1)[-1]} "
                     f"[{', '.join(k.rsplit('/', 1)[-1] for k in c['keys'])}]")
            print(f"  {'ok  ' if ok else 'FAIL'} {label:<64} expect {c['expect']:<17} "
                  f"got {got:<17}{detail}")
        print("selftest: all fixtures behave as claimed" if not bad
              else f"selftest: {bad} fixture(s) do NOT match index.json")
        sys.exit(1 if bad else 0)

    drift = []
    for name, text in sorted(files.items()):
        path = os.path.join(out_dir, name)
        old = None
        if os.path.exists(path):
            # newline="": a fixture a text-mode copy has turned into CRLF is a DIFFERENT file, and
            # for a .minisig it is a broken one — universal newlines would hide exactly that.
            with open(path, encoding="utf-8", newline="") as fh:
                old = fh.read()
        if old == text:
            continue
        drift.append(name)
        if not a.check:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)

    # A fixture removed from the matrix must not linger on disk as a case nobody generates.
    stale = []
    if os.path.isdir(out_dir):
        for dirpath, _dirs, names in os.walk(out_dir):
            for n in names:
                rel = os.path.relpath(os.path.join(dirpath, n), out_dir).replace(os.sep, "/")
                if rel not in files and n.endswith(GENERATED_EXT):
                    stale.append(rel)
        for n in sorted(stale):
            if not a.check:
                os.remove(os.path.join(out_dir, n))

    for n in drift:
        print(("DRIFT  " if a.check else "write  ") + n)
    for n in sorted(stale):
        print(("DRIFT  " if a.check else "remove ") + n + "  (no longer in the matrix)")
    if not drift and not stale:
        print("gen_fixtures: up to date ({} manifests, {} signature cases, format schema {})".format(
            len(fixtures), len(SIG_CASES), FORMAT_SCHEMA))
    elif a.check:
        sys.exit(1)


if __name__ == "__main__":
    main()
