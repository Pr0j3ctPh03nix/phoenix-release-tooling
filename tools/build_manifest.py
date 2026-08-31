#!/usr/bin/env python3
"""Build a manifest document by walking manifest_schema.MANIFEST -- the one producer path.

Replaces "build a dict by hand, then run tools/validate_manifest.py over it afterwards" (deleted
alongside this). That split let the two drift: a producer bug and a validator bug could agree with
each other and nothing would notice. Here there is only one path to a document -- `build()` -- and
it cannot return one that violates the format, because most of what the old validator checked is no
longer expressible as an input in the first place; the rest is checked once, at construction, before
a single key is written.

THE DEFINING DESIGN RULE: the input language never refers to anything by string. Wherever the wire
document carries a `sha256` or a `dest` that has to match something else in the SAME document (a
bundle's members, a tree node's files, a choice's default), the caller passes the OBJECT that field
belongs to -- an Entry, a Variant -- and manifest_schema.Ref pulls the string out on the way to the
wire. A hand-typed hash or path can never end up pointing at nothing, because nothing is ever
hand-typed there.

    entries = [pak := entry("game/dota/pak01_000.vpk", sha1, size1, name="pak01_000.vpk"),
               npc := entry("game/dota/scripts/npc/npc_units.txt", sha2, size2)]   # bundled: no name
    bundle = Bundle("b000-txt-4f3a91c2.phxb", "zstd", psize, psha, entries=[npc])
    doc = build("mod", "1.0.0", 2_000_007, entries, bundles=[bundle])

Structural consequences worth spelling out, because each one replaces a rule
tools/validate_manifest.py used to check AFTER the fact:

  * `Bundle(...)` refuses to construct empty (B7), with a zero-size member (B6), with the same
    OBJECT already in another bundle, or with a member that is also a named/loose entry -- an entry
    is one or the other, never both, and Bundle is the only thing that ever sets that.
  * `bundles[].size`/`.members` are Derived (manifest_schema.py) from the entries a Bundle actually
    holds, so they can never disagree with what is really inside it (B2, and half of B1).
  * `Choice(...)` refuses a `default` that is not one of its own `variants` (structural, not a typo
    waiting to happen).
  * `build()` itself closes the gaps no single object's constructor can see, because they are
    properties of the WHOLE document assembled together: every entry with a positive size is either
    named or its `sha256` is claimed by a bundle (B3, checked by HASH -- see `_check_unbundled` --
    which is what lets two different dests legally share one bundled hash, the shape the base-game
    producer's content-keyed bundling always relied on); every bundle's members are all reachable
    from `files[]` or an option (the rest of B1); no two bundles share a name (B8); no sha256 is
    claimed by two bundle slots even via two DIFFERENT objects that happen to carry the same hash
    (the rest of B5 -- Bundle's own check is by object identity and cannot see that case); and every
    tree reference resolves to one of the manifest's own top-level entries.
  * `schema` is Derived: 3 the instant any bundle exists, 2 otherwise. No caller ever sets it.

B4 -- "nothing between members, nothing after the last" -- has no producer-side equivalent; it is a
property of the DECODED bundle stream, checkable only by something that decodes one, which nothing
here does. It was absent from tools/validate_manifest.py for the identical reason.

    python tools/build_manifest.py selftest
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import manifest_schema as schema  # noqa: E402


# --- input objects: what a caller actually constructs ---------------------------------------------

class Asset:
    """A file-bearing thing: either a LOOSE release asset (carries `name`) or a bundle member --
    never neither (unless `size` is 0, which resolves by being materialized empty and needs neither),
    never both. `_bundle` is set exactly once, by Bundle(), which is what makes "in two bundles at
    once" and "a named entry inside a bundle" impossible to construct rather than merely wrong."""
    def __init__(self, sha256, size, name=None):
        self.sha256, self.size, self.name = sha256, size, name
        self._bundle = None


class Entry(Asset):
    """One `files[]` entry, or one file inside a toggle option -- the same shape either way."""
    def __init__(self, dest, sha256, size, name=None):
        super().__init__(sha256, size, name)
        self.dest = dest


def entry(dest, sha256, size, name=None):
    return Entry(dest, sha256, size, name)


class Variant(Asset):
    """One variant of a choice option. Shares its option's `dest`, so it does not carry one."""
    def __init__(self, id, label, sha256, size, name=None):
        super().__init__(sha256, size, name)
        self.id, self.label = id, label


class Bundle:
    """One `.phxb` asset. `psize`/`psha256`/`codec` describe the packed bytes (produced by
    tools/phxb.py, elsewhere -- this module never compresses anything); `entries` are the Asset
    objects it packs, in the order the stream was written. `size` and `members` on the wire are
    DERIVED from `entries` -- see manifest_schema.BUNDLE -- so this constructor is the only place
    B5/B6/B7 can be violated, and it refuses all three outright."""
    def __init__(self, name, codec, psize, psha256, entries):
        entries = list(entries)
        if not entries:
            raise ValueError(f"bundle {name!r}: no entries (B7 -- an asset that decodes to nothing)")
        for e in entries:
            if e.size == 0:
                raise ValueError(f"bundle {name!r}: a zero-size entry cannot be a member (B6)")
            if e.name is not None:
                raise ValueError(f"bundle {name!r}: {e.name!r} carries its own `name` -- a loose "
                                 "entry and a bundle member are mutually exclusive")
            if e._bundle is not None:
                raise ValueError(f"bundle {name!r}: sha256 {e.sha256[:12]} is already in bundle "
                                 f"{e._bundle.name!r} (B5 -- one hash, one bundle)")
        self.name, self.codec, self.psize, self.psha256 = name, codec, psize, psha256
        self.entries = entries
        for e in entries:
            e._bundle = self


class Choice:
    """An option offering exactly one of several Variant objects. `default` MUST be one of
    `variants` -- checked here, at construction, so a default naming no variant cannot exist."""
    kind = "choice"

    def __init__(self, id, label, default, dest, variants):
        variants = list(variants)
        if default not in variants:
            raise ValueError(f"option {id!r}: default is not one of its own variants")
        self.id, self.label, self.default, self.dest = id, label, default, dest
        self.variants = variants


class Toggle:
    """An option installing a `files[]` set when enabled."""
    kind = "toggle"

    def __init__(self, id, label, default, files):
        self.id, self.label, self.default = id, label, default
        self.files = list(files)


class Node:
    """One node of the presentational display tree. `files` are Entry objects that must also be
    among the manifest's own top-level entries -- build() checks this, since no single Node knows
    the full entry list at construction time."""
    def __init__(self, label=None, files=(), groups=()):
        self.label = label
        self.files = list(files) or None
        self.groups = list(groups) or None


# --- the generic walk: manifest_schema.MANIFEST in, a wire dict out -------------------------------

def _value(field, raw):
    if isinstance(field, schema.Derived):
        return field.fn(raw)                          # may itself return schema.ABSENT
    if isinstance(field, schema.Ref):
        return getattr(raw, field.attr)
    if isinstance(field, schema.Opt):
        return schema.ABSENT if raw is None else _value(field.inner, raw)
    if isinstance(field, schema.List):
        return [_value(field.inner, item) for item in raw]
    if isinstance(field, schema.Obj):
        return _render_obj(field, raw)
    if isinstance(field, dict):                       # OPTION: a kind-dispatched union
        return _render_obj(field[raw.kind], raw)
    return field.render(raw)                          # Const / Enum / Int / Str / Hex64 / Dest / Label


def _render_obj(obj, owner):
    """{wire key: value} for one Obj, walking `obj.fields` -- and ONLY `obj.fields` -- in order.
    No key name from any wire shape appears anywhere in this function; every one comes from the
    schema module, which is the single edit adding a field requires."""
    out = {}
    for key, field in obj.fields.items():
        raw = owner if isinstance(field, schema.Derived) else getattr(owner, key, None)
        value = _value(field, raw)
        if value is not schema.ABSENT:
            out[key] = value
    return out


# --- cross-object checks: properties of the WHOLE document, not of any one field ------------------

def _asset_pool(entries, options):
    """Every Asset the document could legally bundle: top-level entries, plus every choice's
    variants and every toggle's files. Mirrors tools/validate_manifest.py's old `entries()`."""
    pool = list(entries)
    for o in options:
        pool += o.variants if isinstance(o, Choice) else o.files
    return pool


def _check_unbundled(entries, options, bundled_hashes):
    """B3: a positive-size asset with no `name` and whose sha256 is in no bundle has no route to
    bytes at all.

    Checked by HASH (`bundled_hashes`, every sha256 that survived `_check_bundles` below), not by
    "is this exact object inside some Bundle". The reader resolves an entry to bytes by hash -- see
    docs/manifest-reader-contract.md's entry -> bytes order, back when docs/ existed: `size` 0 ->
    empty; else `name` present -> that release asset; else -> the one bundle whose `members`
    contains the entry's `sha256` -- and content-keyed producers (the base-game bundler among them)
    legitimately point two different Entry objects at two different `dest`s with ONE shared hash,
    stored once, inside a single bundle. Checking by object identity refused that legal shape;
    checking by hash accepts it, while B5 below still refuses the same hash claimed by two bundles."""
    for a in _asset_pool(entries, options):
        if a.size > 0 and a.name is None and a.sha256 not in bundled_hashes:
            where = getattr(a, "dest", None) or getattr(a, "id", "<entry>")
            raise ValueError(f"{where!r} has positive size, no `name`, and is in no bundle (B3)")


def _check_bundles(entries, bundles, options):
    """B8 (no two bundles share a name), the other half of B1 (a bundle can only pack an asset that
    is actually reachable from `files[]` or an option -- otherwise its dest is unrecoverable, even
    though manifest_schema.BUNDLE guarantees its `members` entry is never a stray hash), and B5.
    Returns the set of every sha256 that legally belongs to exactly one bundle, for `_check_unbundled`
    (B3) to resolve entries against -- so B3 can never accept a hash this function would have refused.

    B5 is checked by HASH here, not left to Bundle.__init__'s per-OBJECT `_bundle` tracking, because
    that tracking alone misses two shapes: the identical Entry object listed twice in one bundle's
    own `entries` (each check in that loop runs before either assignment lands), and two DISTINCT
    Entry/Variant objects that legitimately carry the same sha256 -- identical bytes at two
    different dests, or a variant and a raw file sharing content -- placed in two DIFFERENT bundles
    (the bytes would ship twice, and the reader's "the one bundle whose members contains this hash"
    rule becomes ambiguous). Both produce a document with one hash claimed by two bundle slots,
    which is exactly what B5 forbids; only a scan over every member's sha256, once every bundle is
    known, catches both. The SAME hash reused between a bundle and a LOOSE entry is not this case at
    all -- see `_check_unbundled` -- and the same hash reused across several UNBUNDLED loose entries
    was never restricted either."""
    pool = _asset_pool(entries, options)
    names = set()
    seen_hashes = set()
    for b in bundles:
        if b.name in names:
            raise ValueError(f"duplicate bundle asset name {b.name!r} (B8)")
        names.add(b.name)
        for e in b.entries:
            if e not in pool:
                raise ValueError(f"bundle {b.name!r} packs an entry absent from files[] and every "
                                 "option -- its dest would be unrecoverable (B1)")
            if e.sha256 in seen_hashes:
                raise ValueError(f"sha256 {e.sha256[:12]} claimed by more than one bundle slot, "
                                 f"via bundle {b.name!r} (B5 -- one hash, one bundle)")
            seen_hashes.add(e.sha256)
    return seen_hashes


def _check_tree(tree, entries):
    """A tree reference must resolve to one of the manifest's OWN top-level entries. (Stricter than
    a reader has to be -- docs/manifest-reader-contract.md required a reader to treat a dangling ref
    as non-fatal, because a reader can be handed a manifest from an old or buggy producer. A
    producer has no such excuse: it wrote the entries itself, so here a dangling ref is refused.)"""
    for n in tree:
        for e in (n.files or ()):
            if e not in entries:
                raise ValueError(f"tree references dest {e.dest!r}, which is not in files[]")
        _check_tree(n.groups or (), entries)


# --- the public API ---------------------------------------------------------------------------

def build(payload_id, version, serial, entries, bundles=(), options=(), tree=None, notes=None,
          signed_at=None):
    """-> a manifest dict.

    `entries` become `files[]`. `bundles`/`options`/`tree` are omitted from the document entirely
    when empty -- the shape every existing producer already used for "this release has none".

    `signed_at` defaults to None, which manifest_schema.MANIFEST's Derived reads as "omit the key"
    -- so a plain build() call is a pure function of its arguments and never touches the clock.
    write() below is the only caller that passes a real timestamp; nothing stops another caller
    doing the same, but nothing needs to."""
    entries = list(entries)
    bundles = list(bundles)
    options = list(options)
    tree = list(tree) if tree else []

    # _check_bundles first: it both validates the bundles themselves (B1/B5/B8) and returns the
    # hash set _check_unbundled (B3) resolves entries against -- so B3 can only ever accept a hash
    # that has already been proven to belong to exactly one bundle.
    bundled_hashes = _check_bundles(entries, bundles, options)
    _check_unbundled(entries, options, bundled_hashes)
    _check_tree(tree, entries)

    class _Doc:
        pass
    doc = _Doc()
    doc.payload_id, doc.version, doc.serial, doc.notes = payload_id, version, serial, notes
    doc.bundles = bundles or None
    doc.files = entries
    doc.tree = tree or None
    doc.options = options or None
    doc.signed_at = signed_at

    return _render_obj(schema.MANIFEST, doc)


def write(path, payload_id, version, serial, entries, bundles=(), options=(), tree=None, notes=None):
    """build() with the wall clock filled in for `signed_at`, then write the result to `path`.

    `signed_at` is ADVISORY (docs/manifest-reader-contract.md, back when docs/ existed) and is the
    one field genuinely tied to the moment of writing rather than to the release's content -- which
    is why the timestamp is taken here and not inside a plain build() call."""
    doc = build(payload_id, version, serial, entries, bundles, options, tree, notes,
               signed_at=int(time.time()))

    out_dir = os.path.dirname(os.path.abspath(path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return doc


# --- selftest -----------------------------------------------------------------------------------

def _selftest():
    results = []

    def ok(name, fn):
        try:
            fn()
        except Exception as e:                       # noqa: BLE001 -- any escape is the failure
            results.append((False, name, f"{type(e).__name__}: {e}"))
        else:
            results.append((True, name, ""))

    def refused(name, fn):
        try:
            fn()
        except (ValueError, TypeError) as e:
            results.append((True, name, str(e)))
        except Exception as e:                        # noqa: BLE001
            results.append((False, name, f"raised {type(e).__name__}, not ValueError/TypeError: {e}"))
        else:
            results.append((False, name, "ACCEPTED -- the check does not exist"))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    def sha(label):
        import hashlib
        return hashlib.sha256(label.encode()).hexdigest()

    # --- 1. full shape, matched against docs/manifest-fixtures/current.json (captured before that
    # directory was deleted -- see git history for the original file). ---------------------------

    def full_shape():
        pak = entry("game/dota/pak01_000.vpk",
                    "7b4c2d7516f75dbac823ecb59828a8d2a42589cb96f4bcd4d49926971fa1e932", 5588,
                    name="pak01_000.vpk")
        npc = entry("game/dota/scripts/npc/npc_units.txt",
                    "37552e086665ccac8a7ad7fa0ebe1a608c2cbd83e8a1cac7e324884aafffff6e", 6189)
        hero = entry("game/dota/scripts/npc/hero_ids.txt",
                     "be41f7e8050257dd8851c9384fd16b4063b4d70384f80d1dbba14df482cab5e5", 4729)
        client = entry("game/dota/bin/win64/client.dll",
                       "71000e2e30bf6fae705511f8e1ea3ecca8ce18fc678e248b35b2662a6d6d0996", 104857600)
        empty = entry("game/dota/empty.marker",
                      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0)

        var_mod = Variant("mod", {"en": "New lighting", "ru": "Новое освещение"},
                          "ffe9dacff9bbaa5d508a84be9a1a20869eaaf5324de853c067ca6d3a57270f80", 3537)
        var_original = Variant("original",
                               {"en": "Original lighting", "ru": "Оригинальное освещение"},
                               "37b5d4462d71d85f4eee306a80c93c4827c6e8bb42df31dc8635ab201618df6e",
                               6285, name="opt__lighting__original.vpk")
        terrain_file = entry("game/dota_phoenix/pak01_dir.vpk",
                             "634c0f4d9c199e010a28c8e2aaf48b86c005ffa33c6458936d2cb2b788c4d2c4", 8444)

        b000 = Bundle("b000-txt-4f3a91c2e5d8.phxb", "zstd", 7633,
                      "7fd8bc307e43703a1df170724b5facda3cebaeaff5e1783fc824bdcf81c82b3c",
                      entries=[npc, hero, var_mod, terrain_file])
        b001 = Bundle("b001-pack-9c2e7ab04d13.phxb", "zstd", 34952533,
                      "45e116fe6bb47162f76f8cfa1947e46066fc1d9cc3e321cd3e035909db66235b",
                      entries=[client])

        tree = [
            Node(label={"en": "Phoenix Core", "ru": "Ядро Phoenix"}, files=[pak, empty],
                 groups=[Node(label={"en": "Hero Demo Plus"}, files=[npc, hero])]),
            Node(files=[client]),
        ]
        options = [
            Choice("lighting", {"en": "Lighting", "ru": "Освещение"}, var_original,
                  "game/dota_phoenix/maps/dota.vpk", [var_mod, var_original]),
            Toggle("terrain", {"en": "Less acidic Radiant terrain", "ru": "Менее кислотная трава"},
                  False, [terrain_file]),
        ]

        # current.json's own fixture serial (42) predates SERIAL_FLOOR -- it is a READER conformance
        # fixture, not a document any current producer could emit. Everything else about it (every
        # dest, hash, size, label and the nesting they sit in) is reproduced exactly.
        serial = schema.SERIAL_FLOOR + 42
        doc = build("mod", "1.0.0", serial, [pak, npc, hero, client, empty], bundles=[b000, b001],
                    options=options, tree=tree,
                    notes="### Added\n- Something a player can see.")

        assert_(doc["schema"] == 3, "schema")
        assert_(doc["payload_id"] == "mod", "payload_id")
        assert_(doc["serial"] == serial, "serial")
        assert_(doc["version"] == "1.0.0", "version")
        assert_(doc["notes"] == "### Added\n- Something a player can see.", "notes")
        assert_("signed_at" not in doc, "build() must not set signed_at -- write() does")
        assert_(doc["remove"] == [], "remove")

        expect_files = [
            {"name": "pak01_000.vpk", "dest": "game/dota/pak01_000.vpk",
             "sha256": "7b4c2d7516f75dbac823ecb59828a8d2a42589cb96f4bcd4d49926971fa1e932", "size": 5588},
            {"dest": "game/dota/scripts/npc/npc_units.txt",
             "sha256": "37552e086665ccac8a7ad7fa0ebe1a608c2cbd83e8a1cac7e324884aafffff6e", "size": 6189},
            {"dest": "game/dota/scripts/npc/hero_ids.txt",
             "sha256": "be41f7e8050257dd8851c9384fd16b4063b4d70384f80d1dbba14df482cab5e5", "size": 4729},
            {"dest": "game/dota/bin/win64/client.dll",
             "sha256": "71000e2e30bf6fae705511f8e1ea3ecca8ce18fc678e248b35b2662a6d6d0996",
             "size": 104857600},
            {"dest": "game/dota/empty.marker",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        ]
        assert_(doc["files"] == expect_files, f"files: {doc['files']}")

        expect_bundles = [
            {"name": "b000-txt-4f3a91c2e5d8.phxb", "codec": "zstd", "psize": 7633,
             "psha256": "7fd8bc307e43703a1df170724b5facda3cebaeaff5e1783fc824bdcf81c82b3c",
             "size": 22899,
             "members": [
                 "37552e086665ccac8a7ad7fa0ebe1a608c2cbd83e8a1cac7e324884aafffff6e",
                 "be41f7e8050257dd8851c9384fd16b4063b4d70384f80d1dbba14df482cab5e5",
                 "ffe9dacff9bbaa5d508a84be9a1a20869eaaf5324de853c067ca6d3a57270f80",
                 "634c0f4d9c199e010a28c8e2aaf48b86c005ffa33c6458936d2cb2b788c4d2c4"]},
            {"name": "b001-pack-9c2e7ab04d13.phxb", "codec": "zstd", "psize": 34952533,
             "psha256": "45e116fe6bb47162f76f8cfa1947e46066fc1d9cc3e321cd3e035909db66235b",
             "size": 104857600,
             "members": ["71000e2e30bf6fae705511f8e1ea3ecca8ce18fc678e248b35b2662a6d6d0996"]},
        ]
        assert_(doc["bundles"] == expect_bundles, f"bundles: {doc['bundles']}")

        expect_tree = [
            {"label": {"en": "Phoenix Core", "ru": "Ядро Phoenix"},
             "files": ["game/dota/pak01_000.vpk", "game/dota/empty.marker"],
             "groups": [{"label": {"en": "Hero Demo Plus"},
                        "files": ["game/dota/scripts/npc/npc_units.txt",
                                  "game/dota/scripts/npc/hero_ids.txt"]}]},
            {"files": ["game/dota/bin/win64/client.dll"]},
        ]
        assert_(doc["tree"] == expect_tree, f"tree: {doc['tree']}")

        expect_options = [
            {"id": "lighting", "kind": "choice", "label": {"en": "Lighting", "ru": "Освещение"},
             "default": "original", "dest": "game/dota_phoenix/maps/dota.vpk",
             "variants": [
                 {"id": "mod", "label": {"en": "New lighting", "ru": "Новое освещение"},
                  "sha256": "ffe9dacff9bbaa5d508a84be9a1a20869eaaf5324de853c067ca6d3a57270f80",
                  "size": 3537},
                 {"id": "original",
                  "label": {"en": "Original lighting", "ru": "Оригинальное освещение"},
                  "name": "opt__lighting__original.vpk",
                  "sha256": "37b5d4462d71d85f4eee306a80c93c4827c6e8bb42df31dc8635ab201618df6e",
                  "size": 6285}]},
            {"id": "terrain", "kind": "toggle",
             "label": {"en": "Less acidic Radiant terrain", "ru": "Менее кислотная трава"},
             "default": False,
             "files": [{"dest": "game/dota_phoenix/pak01_dir.vpk",
                       "sha256": "634c0f4d9c199e010a28c8e2aaf48b86c005ffa33c6458936d2cb2b788c4d2c4",
                       "size": 8444}]},
        ]
        assert_(doc["options"] == expect_options, f"options: {doc['options']}")

    ok("full-shape document (bundles, options, tree) matches current.json key-for-key", full_shape)

    # --- 2. schema derives from bundle presence alone ------------------------------------------

    def schema_with_bundles():
        e = entry("game/dota/a.bin", sha("a"), 10)
        b = Bundle("b-x.phxb", "zstd", 5, sha("packed"), entries=[e])
        doc = build("mod", "1.0.0", schema.SERIAL_FLOOR, [e], bundles=[b])
        assert_(doc["schema"] == 3, f"expected schema 3, got {doc['schema']}")

    def schema_without_bundles():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        doc = build("mod", "1.0.0", schema.SERIAL_FLOOR, [e])
        assert_(doc["schema"] == 2, f"expected schema 2, got {doc['schema']}")

    ok("schema derives to 3 with a bundle present", schema_with_bundles)
    ok("schema derives to 2 with no bundles", schema_without_bundles)

    # --- 3. a traversing dest is refused -------------------------------------------------------

    def with_dest(d):
        e = entry(d, sha("x"), 10, name="x.bin")
        build("mod", "1.0.0", schema.SERIAL_FLOOR, [e])

    refused("dest '..' escapes the game root", lambda: with_dest("game/../../evil.dll"))
    refused("dest with a leading '/' is absolute", lambda: with_dest("/game/evil.dll"))
    refused("dest with a backslash", lambda: with_dest("game\\evil.dll"))
    refused("dest with a drive/ADS colon", lambda: with_dest("game/evil.dll:hidden"))
    refused("dest with an empty path component (doubled '/')",
            lambda: with_dest("game/dota//evil.dll"))
    refused("dest with a trailing '/'", lambda: with_dest("game/dota/evil.dll/"))

    # --- 4. bad sha256 / payload_id / codec / serial floor are each refused --------------------

    def bad_sha():
        e = entry("game/dota/a.bin", "not-a-sha256", 10, name="a.bin")
        build("mod", "1.0.0", schema.SERIAL_FLOOR, [e])

    def bad_payload_id():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        build("skins", "1.0.0", schema.SERIAL_FLOOR, [e])

    def bad_codec():
        e = entry("game/dota/a.bin", sha("a"), 10)
        b = Bundle("b-x.phxb", "brotli", 5, sha("packed"), entries=[e])
        build("mod", "1.0.0", schema.SERIAL_FLOOR, [e], bundles=[b])

    def serial_below_floor():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        build("mod", "1.0.0", schema.SERIAL_FLOOR - 1, [e])

    def serial_is_bool():
        # Python's bool is an int subclass (True == 1), so a floor/type check that only compares
        # VALUE would silently accept this -- the same trap tools/validate_manifest.py named
        # explicitly for `schema`/`serial`. Int.render() checks isinstance(..., bool) first.
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        build("mod", "1.0.0", True, [e])

    refused("a malformed sha256", bad_sha)
    refused("a payload_id outside the closed set", bad_payload_id)
    refused("a codec this format does not define", bad_codec)
    refused("a serial below SERIAL_FLOOR", serial_below_floor)
    refused("a serial that is `True` rather than an int", serial_is_bool)

    # --- 5. bundle membership is single, and a bundle cannot be empty --------------------------

    def entry_in_two_bundles():
        e = entry("game/dota/a.bin", sha("a"), 10)
        Bundle("b-1.phxb", "zstd", 5, sha("p1"), entries=[e])
        Bundle("b-2.phxb", "zstd", 5, sha("p2"), entries=[e])

    def empty_bundle():
        Bundle("b-empty.phxb", "zstd", 0, sha("p"), entries=[])

    def entry_twice_in_one_bundle():
        # Bundle.__init__'s per-object `_bundle` check cannot see this: both occurrences are
        # inspected before either assignment lands. Only build()'s hash scan catches it.
        e = entry("game/dota/a.bin", sha("a"), 10)
        b = Bundle("b-dup.phxb", "zstd", 5, sha("p"), entries=[e, e])
        build("mod", "1.0.0", schema.SERIAL_FLOOR, [e], bundles=[b])

    def duplicate_hash_across_bundles():
        # Two DISTINCT objects -- identical content at two different dests is legal -- each placed
        # in a different bundle. Bundle.__init__ tracks membership by object identity and cannot see
        # that these are the same hash; only build()'s hash scan does.
        e1 = entry("game/dota/a.bin", sha("dup"), 10)
        e2 = entry("game/dota/b.bin", sha("dup"), 10)
        b1 = Bundle("b-1.phxb", "zstd", 5, sha("p1"), entries=[e1])
        b2 = Bundle("b-2.phxb", "zstd", 5, sha("p2"), entries=[e2])
        build("mod", "1.0.0", schema.SERIAL_FLOOR, [e1, e2], bundles=[b1, b2])

    refused("the same entry placed in two bundles", entry_in_two_bundles)
    refused("a bundle with no entries", empty_bundle)
    refused("the same entry object listed twice in one bundle's own entries", entry_twice_in_one_bundle)
    refused("two different entries sharing one sha256, in two different bundles",
            duplicate_hash_across_bundles)

    # --- 6. a one-entry launcher-shaped document builds, and derives schema 2 ------------------

    def launcher_shaped():
        e = entry("phoenix-launcher.exe", sha("exe"), 12345678, name="phoenix-launcher.exe")
        doc = build("launcher", "1.5.2", schema.SERIAL_FLOOR + 42, [e])
        assert_(doc["schema"] == 2, "schema")
        assert_("bundles" not in doc, "bundles must be omitted, not empty")
        assert_("tree" not in doc, "tree must be omitted, not empty")
        assert_("options" not in doc, "options must be omitted, not empty")
        assert_(doc["files"] == [{"name": "phoenix-launcher.exe", "dest": "phoenix-launcher.exe",
                                  "sha256": sha("exe"), "size": 12345678}], "files")

    ok("a one-entry launcher-shaped document builds and derives schema 2", launcher_shaped)

    # --- 7. write() threads signed_at through the SAME schema-driven walk as every other field --
    # (proves the fix for the one wire key that used to be set by a hardcoded `doc["signed_at"] = `
    # in write() itself, bypassing the walker -- see manifest_schema.MANIFEST's `signed_at` field.)

    def write_stamps_signed_at():
        import tempfile
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        tmp_dir = tempfile.mkdtemp()
        path = os.path.join(tmp_dir, "manifest.json")
        before = int(time.time())
        doc = write(path, "mod", "1.0.0", schema.SERIAL_FLOOR, [e])
        after = int(time.time())
        assert_("signed_at" in doc, "write() must set signed_at")
        assert_(isinstance(doc["signed_at"], int) and not isinstance(doc["signed_at"], bool),
                "signed_at must be a plain int")
        assert_(before <= doc["signed_at"] <= after, "signed_at must be roughly now")
        with open(path, encoding="utf-8") as fh:
            on_disk = json.load(fh)
        assert_(on_disk == doc, "the written file must match what write() returned")
        assert_(list(on_disk.keys())[:4] == ["schema", "payload_id", "serial", "signed_at"],
                f"signed_at should land in its schema-declared position, got {list(on_disk.keys())}")

    ok("write() stamps signed_at through the schema, not by hardcoding the key", write_stamps_signed_at)

    # --- extra: the other structural rules the deleted validator also carried ------------------

    def unbundled_entry():
        e = entry("game/dota/a.bin", sha("a"), 10)   # no name, never bundled
        build("mod", "1.0.0", schema.SERIAL_FLOOR, [e])

    def duplicate_bundle_name():
        e1 = entry("game/dota/a.bin", sha("a"), 10)
        e2 = entry("game/dota/b.bin", sha("b"), 10)
        b1 = Bundle("same.phxb", "zstd", 5, sha("p1"), entries=[e1])
        b2 = Bundle("same.phxb", "zstd", 5, sha("p2"), entries=[e2])
        build("mod", "1.0.0", schema.SERIAL_FLOOR, [e1, e2], bundles=[b1, b2])

    def dangling_tree_ref():
        shown = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        ghost = entry("game/dota/ghost.bin", sha("ghost"), 10, name="ghost.bin")
        build("mod", "1.0.0", schema.SERIAL_FLOOR, [shown], tree=[Node(files=[ghost])])

    def default_not_a_variant():
        v1 = Variant("a", "A", sha("a"), 10, name="a.bin")
        v2 = Variant("b", "B", sha("b"), 10, name="b.bin")
        stray = Variant("c", "C", sha("c"), 10, name="c.bin")
        Choice("opt", "Opt", stray, "game/dota/opt.bin", [v1, v2])

    def zero_size_bundle_member():
        e = entry("game/dota/empty.marker", sha("empty"), 0)
        Bundle("b-x.phxb", "zstd", 0, sha("p"), entries=[e])

    def named_entry_bundled():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        Bundle("b-x.phxb", "zstd", 5, sha("p"), entries=[e])

    refused("an entry with positive size, no name, in no bundle (B3)", unbundled_entry)
    refused("two bundles sharing one asset name (B8)", duplicate_bundle_name)
    refused("a tree node referencing an entry outside files[]", dangling_tree_ref)
    refused("a choice default that names none of its own variants", default_not_a_variant)
    refused("a zero-size entry as a bundle member (B6)", zero_size_bundle_member)
    refused("a named (loose) entry placed in a bundle", named_entry_bundled)

    # --- content-keyed sharing: one sha256, two dests. B3 resolves by HASH (see
    # _check_unbundled), not by "is this exact object inside some Bundle" -- three shapes that
    # must NOT be conflated, reproducing the base-game producer's legitimate use and the two ways
    # sharing a hash still goes wrong. --------------------------------------------------------

    def shared_hash_one_bundled_one_loose():
        # a's bytes are stored once, inside `bun`; b names no bundle of its own but carries the
        # SAME sha256, so the reader resolves it through that one bundle -- exactly the shape
        # base-game bundling relies on (content-keyed: one hash, several dests). Must ACCEPT.
        h = sha("shared")
        a = Entry(dest="game/dota/x.txt", sha256=h, size=10)
        b = Entry(dest="game/dota/copy/x.txt", sha256=h, size=10)
        bun = Bundle(name="b000.phxb", codec="zstd", psize=5, psha256=sha("packed"), entries=[a])
        doc = build(payload_id="game", version="1805", serial=schema.SERIAL_FLOOR + 1,
                   entries=[a, b], bundles=[bun])
        assert_(doc["bundles"][0]["members"] == [h], "the bundle carries the hash once, not twice")
        b_out = next(f for f in doc["files"] if f["dest"] == "game/dota/copy/x.txt")
        assert_("name" not in b_out, "b resolves through the shared hash, not a release asset")

    def shared_hash_two_different_bundles():
        # The SAME hash claimed by two SEPARATE bundles -- the bytes would ship twice, and "the
        # one bundle whose members contains this hash" stops being well defined. Must REFUSE (B5).
        h = sha("shared")
        a = Entry(dest="game/dota/x.txt", sha256=h, size=10)
        b = Entry(dest="game/dota/copy/x.txt", sha256=h, size=10)
        bun1 = Bundle(name="b000.phxb", codec="zstd", psize=5, psha256=sha("p1"), entries=[a])
        bun2 = Bundle(name="b001.phxb", codec="zstd", psize=5, psha256=sha("p2"), entries=[b])
        build(payload_id="game", version="1805", serial=schema.SERIAL_FLOOR + 1,
              entries=[a, b], bundles=[bun1, bun2])

    def shared_hash_same_object_twice_one_bundle():
        # The identical OBJECT listed twice inside one bundle's own entries -- still refused, same
        # as before this fix; make sure resolving B3 by hash did not accidentally loosen B5 too.
        h = sha("shared")
        a = Entry(dest="game/dota/x.txt", sha256=h, size=10)
        bun = Bundle(name="b000.phxb", codec="zstd", psize=5, psha256=sha("p"), entries=[a, a])
        build(payload_id="game", version="1805", serial=schema.SERIAL_FLOOR + 1,
              entries=[a], bundles=[bun])

    ok("one sha256, one bundled entry and one loose entry sharing it -- resolves, ACCEPT",
       shared_hash_one_bundled_one_loose)
    refused("one sha256 claimed by two DIFFERENT bundles -- still B5, REFUSE",
            shared_hash_two_different_bundles)
    refused("the same entry object listed twice in one bundle, via the game producer's shape "
            "-- still B5, REFUSE", shared_hash_same_object_twice_one_bundle)

    for good, name, detail in results:
        print(f"  {'ok  ' if good else 'FAIL'} {name}" + (f"\n         {detail}" if detail else ""))
    bad = sum(not good for good, _, _ in results)
    print(f"selftest: {len(results)} checks, all pass" if not bad
          else f"selftest: {bad} of {len(results)} checks FAILED")
    return bad


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) == 2 and sys.argv[1] == "selftest":
        sys.exit(1 if _selftest() else 0)
    sys.exit("usage: python tools/build_manifest.py selftest")


if __name__ == "__main__":
    main()
