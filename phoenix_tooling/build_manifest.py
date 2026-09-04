#!/usr/bin/env python3
"""Build a manifest document by walking manifest_schema.MANIFEST -- the one producer path.

Replaces "build a dict by hand, then run validate_manifest.py over it afterwards" (deleted
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
    doc = build("mod", "1.0.0", entries=entries, bundles=[bundle])   # serial 0: a SEAL REQUEST

Structural consequences worth spelling out, because each one replaces a rule
validate_manifest.py used to check AFTER the fact:

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
    from `files[]` or an option (the rest of B1); no sha256 is claimed by two bundle slots even via
    two DIFFERENT objects that happen to carry the same hash (the rest of B5 -- Bundle's own check
    is by object identity and cannot see that case); every tree reference resolves to one of the
    manifest's own top-level entries; and the document's two NAMESPACES each hold one thing per
    slot -- no two entries install to one `dest` (`_check_dests`), and no two release assets, bundle
    or loose, answer to one `name` (`_check_names`, which is B8 widened to the namespace a bundle
    name really shares).
  * `schema` is Derived: 3 the instant any bundle exists, 2 otherwise. No caller ever sets it.

B4 -- "nothing between members, nothing after the last" -- has no producer-side equivalent; it is a
property of the DECODED bundle stream, checkable only by something that decodes one, which nothing
here does. It was absent from validate_manifest.py for the identical reason.

    python phx.py manifest selftest
"""
import json
import os
import sys
import time

from . import manifest_schema as schema


# --- input objects: what a caller actually constructs ---------------------------------------------

class Asset:
    """A file-bearing thing: either a LOOSE release asset (carries `name`) or a bundle member --
    never neither (unless `size` is 0, which resolves by being materialized empty and needs neither),
    never both. `_bundle` is set exactly once, by Bundle(), which is what makes "in two bundles at
    once" and "a named entry inside a bundle" impossible to construct rather than merely wrong.

    `size` and `sha256` are the one PAIR of wire fields whose values constrain each other, and this
    is the only place both arrive together -- no single field type can see the other. Zero bytes
    hash to exactly one value (manifest_schema.EMPTY_SHA256) and nothing else does, so the two say
    the same thing twice and a reader that reads only one of them still has to be right: `size` 0
    short-circuits to "materialize an empty file" without ever fetching the bytes the hash names,
    while a hash-keyed cache (the launcher stores by sha256) would hand the empty file's slot to a
    108 MB entry. Both directions, or the disagreement just moves."""
    def __init__(self, sha256, size, name=None):
        if size == 0 and sha256 != schema.EMPTY_SHA256:
            raise ValueError(f"a zero-size entry must carry the sha256 of zero bytes, not "
                             f"{sha256[:12] if isinstance(sha256, str) else sha256!r}")
        if size != 0 and sha256 == schema.EMPTY_SHA256:
            raise ValueError(f"size {size} with the sha256 of zero bytes -- one of the two is wrong")
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
    phoenix_tooling/phxb.py, elsewhere -- this module never compresses anything); `entries` are
    the Asset objects it packs, in the order the stream was written. `size` and `members` on the
    wire are DERIVED from `entries` -- see manifest_schema.BUNDLE -- so this constructor is the
    only place B5/B6/B7 can be violated, and it refuses all three outright."""
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
    `variants` -- checked here, at construction, so a default naming no variant cannot exist.

    `assets`/`dests` are the two questions build() asks of every option, answered by the class next
    to the `kind` that renders it rather than by anything dispatching on type -- see
    _option_assets(). Whichever variant wins installs to the option's ONE `dest`, so a choice claims
    exactly one install path however many variants it offers."""
    kind = "choice"

    def __init__(self, id, label, default, dest, variants):
        variants = list(variants)
        if default not in variants:
            raise ValueError(f"option {id!r}: default is not one of its own variants")
        self.id, self.label, self.default, self.dest = id, label, default, dest
        self.variants = variants

    @property
    def assets(self):
        return self.variants

    @property
    def dests(self):
        return [self.dest]


class Toggle:
    """An option installing a `files[]` set when enabled. Its files ARE its assets, and each one
    carries its own dest (see Choice for why both properties exist)."""
    kind = "toggle"

    def __init__(self, id, label, default, files):
        self.id, self.label, self.default = id, label, default
        self.files = list(files)

    @property
    def assets(self):
        return self.files

    @property
    def dests(self):
        return [f.dest for f in self.files]


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
        if len(raw) < field.min:
            raise ValueError(f"a list of {len(raw)} where the format requires at least {field.min}")
        return [_value(field.inner, item) for item in raw]
    if isinstance(field, schema.Obj):
        return _render_obj(field, raw)
    if isinstance(field, dict):                       # OPTION: a kind-dispatched union
        # `raw.kind` keys this union AND selects the assets the option owns -- one dispatch, in
        # _option_assets(), which build() runs over every option before a key is rendered. So a kind
        # outside the union has already been refused by name and cannot arrive here as a KeyError.
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

def _option_assets(option):
    """The Assets one option owns, and the ONE place an option's `kind` meets the closed union.

    The union used to be dispatched two ways: the walk picked the wire shape by `raw.kind`
    (manifest_schema.OPTION), this picked the asset list by `isinstance(o, Choice)`. Anything the
    two disagreed about -- a Choice subclass overriding `kind`, a caller's own option class -- was
    rendered as one shape while B1/B3 inspected the other's assets, or died on `.files` with an
    AttributeError. Now `kind` alone decides, and the list comes off the object (Choice.assets /
    Toggle.assets), declared beside the `kind` it belongs to. build() calls this over every option
    before rendering starts, which is also what makes an unknown kind a refusal here instead of a
    KeyError inside the walk."""
    if option.kind not in schema.OPTION:
        raise ValueError(f"option {getattr(option, 'id', '?')!r}: unknown kind {option.kind!r} "
                         f"(the format defines {tuple(schema.OPTION)})")
    return option.assets


def _asset_pool(entries, options):
    """Every Asset the document could legally bundle: top-level entries, plus every choice's
    variants and every toggle's files. Mirrors validate_manifest.py's old `entries()`.

    Built ONCE per build() and passed down, together with the id() index below: it used to be
    rebuilt for each of the two checks that need it, and `e not in pool` scanned it per bundle
    member. Measured on the base game's shape -- 4,272 members over a 4,635-entry pool, several
    million identity comparisons -- the whole build went 0.072s -> 0.027s."""
    pool = list(entries)
    for o in options:
        pool += _option_assets(o)
    return pool


def _id_index(pool):
    """id() -> membership for `pool`. These objects define no __eq__/__hash__, so `in` compares them
    by identity anyway and a set is the same answer without the scan -- keyed on id() because they
    are not hashable by value. The CALLER must hold `pool` alive for as long as the index is used:
    CPython recycles the id of a freed object, and a recycled id is a false positive."""
    return {id(a) for a in pool}


def _check_dests(entries, options):
    """No two things in one document may install to the same path.

    The pool is the READER's: top-level files[], each toggle's files, and each choice's own dest --
    a choice's variants are mutually exclusive and SHARE that one dest, so they must not each count.
    A duplicate is not a resolvable conflict, it is two entries silently overwriting each other in
    whatever order the installer happens to run, and the loser's bytes are downloaded for nothing.

    Compared case-folded, because the only filesystem this installs onto is case-insensitive:
    `game/dota/A.txt` and `game/dota/a.txt` are two legal entries -- both pass every field rule and
    the reader's own checks -- naming ONE file. `lower()`, not `casefold()`: casefold folds 'ss' out
    of 'ß', and those genuinely are two different files on Windows. Only the comparison folds; what
    goes on the wire is the dest exactly as the caller wrote it."""
    seen = {}
    for d in [e.dest for e in entries] + [d for o in options for d in o.dests]:
        first = seen.get(d.lower())
        if first is not None:
            how = "" if first == d else f" (one file with {first!r} on a case-insensitive filesystem)"
            raise ValueError(f"two entries install to {d!r}{how}")
        seen[d.lower()] = d


def _check_names(pool, bundles):
    """Bundle names and loose entry/variant names share ONE namespace, so they are checked in one
    pass (B8, widened).

    Every `name` in the document -- a bundle's or a loose asset's -- is the filename of a file
    uploaded to the SAME GitHub release, and an entry resolves to bytes by looking that name up.
    Two assets cannot hold one name there, so the second upload either fails the publish or answers
    for both entries. B8 only ever compared bundle names against EACH OTHER, and a loose `name` was
    never uniqueness-checked at all, which left a bundle colliding with a raw asset invisible --
    tools/build_game_bundles.py carries its own `taken` set and a hand-rolled "B8 violated" exit for
    exactly that case, over names it minted itself. It is a property of the whole document, so it
    belongs here, where the whole document is."""
    seen = set()
    for a in list(pool) + list(bundles):
        if a.name is None:
            continue
        if a.name in seen:
            raise ValueError(f"release asset name {a.name!r} is claimed twice (B8)")
        seen.add(a.name)


def _check_unbundled(pool, bundled_hashes):
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
    for a in pool:
        if a.size > 0 and a.name is None and a.sha256 not in bundled_hashes:
            where = getattr(a, "dest", None) or getattr(a, "id", "<entry>")
            raise ValueError(f"{where!r} has positive size, no `name`, and is in no bundle (B3)")


def _check_bundles(bundles, pool_ids):
    """The other half of B1 (a bundle can only pack an asset that is actually reachable from
    `files[]` or an option -- otherwise its dest is unrecoverable, even though
    manifest_schema.BUNDLE guarantees its `members` entry is never a stray hash), and B5.
    Returns the set of every sha256 that legally belongs to exactly one bundle, for `_check_unbundled`
    (B3) to resolve entries against -- so B3 can never accept a hash this function would have refused.
    (B8 used to be here as "no two BUNDLES share a name"; it moved to `_check_names`, which checks
    the one namespace a bundle name actually lives in.)

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
    seen_hashes = set()
    for b in bundles:
        for e in b.entries:
            if id(e) not in pool_ids:
                raise ValueError(f"bundle {b.name!r} packs an entry absent from files[] and every "
                                 "option -- its dest would be unrecoverable (B1)")
            if e.sha256 in seen_hashes:
                raise ValueError(f"sha256 {e.sha256[:12]} claimed by more than one bundle slot, "
                                 f"via bundle {b.name!r} (B5 -- one hash, one bundle)")
            seen_hashes.add(e.sha256)
    return seen_hashes


def _check_tree(tree, entry_ids):
    """A tree reference must resolve to one of the manifest's OWN top-level entries. (Stricter than
    a reader has to be -- docs/manifest-reader-contract.md required a reader to treat a dangling ref
    as non-fatal, because a reader can be handed a manifest from an old or buggy producer. A
    producer has no such excuse: it wrote the entries itself, so here a dangling ref is refused.)"""
    for n in tree:
        for e in (n.files or ()):
            if id(e) not in entry_ids:
                raise ValueError(f"tree references dest {e.dest!r}, which is not in files[]")
        _check_tree(n.groups or (), entry_ids)


# --- the public API ---------------------------------------------------------------------------

def build(payload_id, version, serial=0, entries=(), bundles=(), options=(), tree=None, notes=None,
          signed_at=None):
    """-> a manifest dict.

    `serial` defaults to 0, which is a SEAL REQUEST: the document names no release, and the signing
    authority assigns the real number (see `assign`). A producer that fills one in itself is a
    producer that has to know the ledger -- which is the whole thing that moved.

    `entries` carries a default only so that `serial` can: the three producers pass both
    positionally, so moving `entries` ahead of `serial` would be a breaking change in three
    repositories to save this line. An empty files[] is refused by the format a few lines below,
    which is where it should be refused anyway.

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

    # The pool and its index are built ONCE here and handed down; every check below is a question
    # about the same set of objects, and this local is what keeps them alive for as long as the
    # index's id()s stand for them (see _id_index). Building the pool is also what refuses an
    # option whose `kind` is outside the union, before anything renders.
    pool = _asset_pool(entries, options)
    pool_ids = _id_index(pool)

    # _check_bundles first: it both validates the bundles themselves (B1/B5) and returns the
    # hash set _check_unbundled (B3) resolves entries against -- so B3 can only ever accept a hash
    # that has already been proven to belong to exactly one bundle.
    bundled_hashes = _check_bundles(bundles, pool_ids)
    _check_unbundled(pool, bundled_hashes)
    _check_names(pool, bundles)
    _check_dests(entries, options)
    _check_tree(tree, _id_index(entries))

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


def render(doc):
    """A manifest dict -> the document's exact bytes. THE canonical serialization, and the only one.

    A signature covers bytes, so this has to be a single definition: the authority signs
    `render(assign(request, serial))` and the producer proves the document it got back is that same
    thing by rendering it again itself. Two spellings of "the same JSON" would make that comparison
    a coin toss, and the disagreement would only ever surface as a signature nobody can verify."""
    return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"


def write(path, payload_id, version, serial=0, entries=(), bundles=(), options=(), tree=None,
          notes=None):
    """build() with the wall clock filled in for `signed_at`, then write the result to `path`.

    `serial` defaults to 0 for the reason build() does: what this writes is a SEAL REQUEST unless
    the caller is the authority itself.

    `signed_at` is ADVISORY (docs/manifest-reader-contract.md, back when docs/ existed) and is the
    one field genuinely tied to the moment of writing rather than to the release's content -- which
    is why the timestamp is taken here and not inside a plain build() call."""
    doc = build(payload_id, version, serial, entries, bundles, options, tree, notes,
               signed_at=int(time.time()))

    out_dir = os.path.dirname(os.path.abspath(path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(render(doc))
    return doc


# --- reading a document back: the check the SIGNING AUTHORITY makes -------------------------------
#
# Sealing used to need no validate step, and the reason was structural: the job that signed a
# manifest was the job that BUILT it, three lines earlier, through build() -- which cannot return a
# document violating the format (see this module's docstring, and seal.py's). That argument holds
# only while those are one job. They are not any more: the release key has left every payload repo's
# CI, and the signing authority is handed BYTES by a requester it did not run (see
# .github/workflows/seal.yml). Without a check on this side, that authority is an oracle that signs
# whatever it is sent, with the one key every payload -- and the mirror list -- is trusted under.
#
# So the check is back, and it is deliberately NOT a second implementation of the format. The
# deleted validate_manifest.py was a hand-written copy of the rules, free to drift from the
# producer's (manifest_schema.py's own docstring records the pair of PAYLOAD_IDS sets that did
# exactly that). This instead REBUILDS: load the objects the document says it was built from, run
# the one builder over them, and require the result to equal the document. Every rule is then
# enforced by the code that already owns it -- field types, the cross-object checks, and every
# Derived field (`schema`, a bundle's `size`/`members`, `remove`) recomputed from the contents
# rather than believed. There is nothing here for a rule to drift FROM.


def parse(raw):
    """Manifest BYTES -> a document, strictly. Refuses what a lenient parser would accept.

    DUPLICATE KEYS are the reason this is not a bare json.loads. A signature covers bytes, and two
    parsers are free to disagree about which value `{"serial": 1, "serial": 9}` has -- Python and
    serde_json both keep the last, but nothing makes them; a document whose meaning depends on the
    reader is one nobody should sign. json's own decoder is silent about it, so the pairs hook is
    what makes it an error. UTF-8 with no BOM, and a JSON object at the root: everything else is a
    file that merely resembles a manifest."""
    def no_duplicates(pairs):
        seen = set()
        for k, _ in pairs:
            if k in seen:
                raise ValueError(f"duplicate key {k!r} -- two readers may disagree about its value")
            seen.add(k)
        return dict(pairs)

    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("parse() takes the document's exact bytes")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"not UTF-8: {e}") from None
    doc = json.loads(text, object_pairs_hook=no_duplicates)
    if not isinstance(doc, dict):
        raise ValueError("not a manifest: the document's root is not a JSON object")
    return doc


def _get(obj, key, what):
    if not isinstance(obj, dict):
        raise ValueError(f"{what} is not a JSON object")
    if key not in obj:
        raise ValueError(f"{what} carries no {key!r}")
    return obj[key]


def _load_asset(cls, raw, what, **extra):
    """One FILE- or VARIANT-shaped object -> an Entry/Variant. Keys the wire shape does not define
    are not rejected here -- they simply do not survive the rebuild, and the comparison in
    validate() names them."""
    return cls(sha256=_get(raw, "sha256", what), size=_get(raw, "size", what),
               name=raw.get("name"), **extra)


def _load_option(raw, what):
    kind = _get(raw, "kind", what)
    if kind == "choice":
        variants = [_load_asset(Variant, v, f"{what}.variants[{i}]",
                                id=_get(v, "id", f"{what}.variants[{i}]"),
                                label=_get(v, "label", f"{what}.variants[{i}]"))
                    for i, v in enumerate(_get(raw, "variants", what))]
        wanted = _get(raw, "default", what)
        default = next((v for v in variants if v.id == wanted), None)
        if default is None:
            raise ValueError(f"{what}: default {wanted!r} names none of its own variants")
        return Choice(_get(raw, "id", what), _get(raw, "label", what), default,
                      _get(raw, "dest", what), variants)
    if kind == "toggle":
        files = [_load_asset(Entry, f, f"{what}.files[{i}]", dest=_get(f, "dest", f"{what}.files[{i}]"))
                 for i, f in enumerate(_get(raw, "files", what))]
        return Toggle(_get(raw, "id", what), _get(raw, "label", what),
                      _get(raw, "default", what), files)
    raise ValueError(f"{what}: unknown kind {kind!r} (the format defines {tuple(schema.OPTION)})")


def _load_bundles(raw_bundles, entries, options):
    """Bundles, packing the SAME objects the entries/options above produced.

    A bundle's `members` are hashes, so this is where the wire's one indirection is resolved back
    into objects -- by the reader's own rule (entry -> bytes: `name` first, else the bundle whose
    members carry its sha256), which is why a NAMED asset is never a candidate. Where two unbundled
    entries share one hash -- legal, and what content-keyed bundling relies on -- either object
    stands for the pair, so the first is taken: they agree on the only field a bundle derives from
    a member, its size, or the rebuilt `size` will not match and validate() refuses the document."""
    by_hash = {}
    for a in list(entries) + [a for o in options for a in o.assets]:
        if a.name is None:
            by_hash.setdefault(a.sha256, a)
    out = []
    for i, b in enumerate(raw_bundles):
        what = f"bundles[{i}]"
        packed = []
        for h in _get(b, "members", what):
            a = by_hash.get(h) if isinstance(h, str) else None
            if a is None:
                raise ValueError(f"{what}: member {h!r} is carried by no bundleable entry -- its "
                                 "bytes would decode to a file with no dest")
            packed.append(a)
        out.append(Bundle(_get(b, "name", what), _get(b, "codec", what), _get(b, "psize", what),
                          _get(b, "psha256", what), packed))
    return out


def _load_tree(raw_nodes, by_dest, what):
    out = []
    for i, n in enumerate(raw_nodes):
        here = f"{what}[{i}]"
        if not isinstance(n, dict):
            raise ValueError(f"{here} is not a JSON object")
        files = []
        for d in n.get("files") or []:
            e = by_dest.get(d) if isinstance(d, str) else None
            if e is None:
                raise ValueError(f"{here}: references dest {d!r}, which is not in files[]")
            files.append(e)
        out.append(Node(label=n.get("label"), files=files,
                        groups=_load_tree(n.get("groups") or [], by_dest, f"{here}.groups")))
    return out


def load(doc):
    """A wire document -> the build() arguments it says it was built from.

    Nothing here decides whether the document is LEGAL -- build() does, over the objects this
    returns. This only has to resolve the two things the wire states by reference (a bundle's
    members, a tree's dests) back into the objects the input language uses, and to say plainly when
    a reference names nothing."""
    entries = [_load_asset(Entry, f, f"files[{i}]", dest=_get(f, "dest", f"files[{i}]"))
               for i, f in enumerate(_get(doc, "files", "the manifest"))]
    options = [_load_option(o, f"options[{i}]") for i, o in enumerate(doc.get("options") or [])]
    return dict(
        payload_id=_get(doc, "payload_id", "the manifest"),
        version=_get(doc, "version", "the manifest"),
        serial=_get(doc, "serial", "the manifest"),
        entries=entries,
        options=options,
        bundles=_load_bundles(doc.get("bundles") or [], entries, options),
        tree=_load_tree(doc.get("tree") or [], {e.dest: e for e in entries}, "tree"),
        notes=doc.get("notes"),
        signed_at=doc.get("signed_at"),
    )


def _short(value, limit=120):
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _difference(want, got, path="manifest"):
    """The FIRST place a rebuilt document and the original disagree, named by its wire path. A bare
    "these differ" over a document with hundreds of entries is a refusal nobody can act on."""
    if isinstance(want, dict) and isinstance(got, dict):
        for k in want:
            if k not in got:
                return f"{path}.{k} is missing"
        for k in got:
            if k not in want:
                return f"{path}.{k} is not a key this format writes here"
        for k in want:
            if want[k] != got[k]:
                return _difference(want[k], got[k], f"{path}.{k}")
    if isinstance(want, list) and isinstance(got, list):
        if len(want) != len(got):
            return f"{path}: {len(got)} items where this builder writes {len(want)}"
        for i, (a, b) in enumerate(zip(want, got)):
            if a != b:
                return _difference(a, b, f"{path}[{i}]")
    return f"{path}: {_short(got)} where this builder writes {_short(want)}"


def validate(doc):
    """-> the document, proven to be exactly what build() produces from its own contents.

    Raises ValueError/TypeError -- the same two a bad input to build() raises -- and a caller must
    treat EITHER as "do not sign this". What it proves is narrow and worth stating: the document is
    a legal manifest that a builder could have written, its derived fields really follow from its
    contents, and it carries nothing else. It says nothing about whether the hashes name real
    bytes, nor about which serial the document ought to carry -- that second question is the
    ledger's (see phoenix_tooling/ping.py's ledger_high) and is answered by the authority, in
    `assign` below, after this has passed."""
    rebuilt = build(**load(doc))
    # `signed_at` is the ONE field a rebuild cannot re-derive: manifest_schema declares it Derived
    # from an attribute the builder is handed (the clock is not this format's to read), so whatever
    # the document carries is echoed back and compares equal to itself. Checked here against the
    # format's own u64 field type rather than against a rule invented in this function.
    if "signed_at" in doc:
        try:
            schema.Int(min=0).render(doc["signed_at"])
        except (TypeError, ValueError) as e:
            raise ValueError(f"signed_at: {e}") from None
    if rebuilt != doc:
        raise ValueError("this builder does not produce this document from its own contents -- "
                         + _difference(rebuilt, doc))
    return rebuilt


def assign(doc, serial):
    """A seal request (serial 0) + the serial the authority picked -> the document to sign.

    THE ONE PLACE A SERIAL IS WRITTEN INTO A DOCUMENT that was not built with one, and it runs on
    BOTH sides of the boundary: the authority renders this and signs it, the producer renders it
    again and requires the bytes it fetched back to be identical. That is what proves the signature
    covers the document this producer built, rather than an earlier attempt's under the same tag --
    a comparison, not a judgement, which is why there must be exactly one function doing it.

    The result goes through validate(), so it is a document this builder produces from its own
    contents; and being validate()'s own rebuild, it comes back in the format's key order whatever
    order the request arrived in.

    `serial` is checked by ping.check_serial -- >= 1, within the u64, never a bool -- because that
    is already the rule the ping and the ledger enforce, and a second one here would eventually
    disagree with it."""
    from . import ping     # local: this module is the format, and the format does not need a ping

    current = _get(doc, "serial", "the manifest")
    if isinstance(current, bool) or current != 0:
        raise ValueError(f"the authority assigns serials; a request carries serial 0, and this "
                         f"document carries {current!r}")
    try:
        assigned = int(ping.check_serial(serial))
    except ping.PingError as e:
        raise ValueError(f"{e} -- a seal assigns the serial a release is published at") from None
    return validate(dict(doc, serial=assigned))


# --- selftest -----------------------------------------------------------------------------------

# A serial for every case where the NUMBER itself is beside the point. The format's only rule about
# one is Int(min=0); which value a real release carries is the signing authority's decision, made
# from the ledger at the moment it seals. Shaped like a real one so a failure message reads like a
# real document rather than a toy.
_TEST_SERIAL = 2_000_001


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

        # current.json's own fixture serial. It used to be unreachable here -- 42 sat below the
        # SERIAL_FLOOR the format then imposed, so this case had to carry a stand-in; with the floor
        # gone (Int(min=0) is the whole rule now), the fixture's own number is expressible again and
        # this reproduces it exactly, as it already does every dest, hash, size, label and the
        # nesting they sit in.
        serial = 42
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
        doc = build("mod", "1.0.0", _TEST_SERIAL, [e], bundles=[b])
        assert_(doc["schema"] == 3, f"expected schema 3, got {doc['schema']}")

    def schema_without_bundles():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        doc = build("mod", "1.0.0", _TEST_SERIAL, [e])
        assert_(doc["schema"] == 2, f"expected schema 2, got {doc['schema']}")

    ok("schema derives to 3 with a bundle present", schema_with_bundles)
    ok("schema derives to 2 with no bundles", schema_without_bundles)

    # --- 3. a traversing dest is refused -------------------------------------------------------

    def with_dest(d):
        e = entry(d, sha("x"), 10, name="x.bin")
        build("mod", "1.0.0", _TEST_SERIAL, [e])

    refused("dest '..' escapes the game root", lambda: with_dest("game/../../evil.dll"))
    refused("dest with a leading '/' is absolute", lambda: with_dest("/game/evil.dll"))
    refused("dest with a backslash", lambda: with_dest("game\\evil.dll"))
    refused("dest with a drive/ADS colon", lambda: with_dest("game/evil.dll:hidden"))
    refused("dest with an empty path component (doubled '/')",
            lambda: with_dest("game/dota//evil.dll"))
    refused("dest with a trailing '/'", lambda: with_dest("game/dota/evil.dll/"))

    # --- 4. bad sha256 / payload_id / codec / serial are each refused --------------------------

    def bad_sha():
        e = entry("game/dota/a.bin", "not-a-sha256", 10, name="a.bin")
        build("mod", "1.0.0", _TEST_SERIAL, [e])

    def bad_payload_id():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        build("skins", "1.0.0", _TEST_SERIAL, [e])

    def bad_codec():
        e = entry("game/dota/a.bin", sha("a"), 10)
        b = Bundle("b-x.phxb", "brotli", 5, sha("packed"), entries=[e])
        build("mod", "1.0.0", _TEST_SERIAL, [e], bundles=[b])

    def serial_negative():
        # The one thing Int(min=0) still guarantees about a serial now that SERIAL_FLOOR is gone:
        # the wire type is a u64, so a negative number never came from a publisher counting -- it
        # came from arithmetic that underflowed on the way here.
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        build("mod", "1.0.0", -1, [e])

    def serial_is_bool():
        # Python's bool is an int subclass (True == 1), so a check comparing only VALUE would let
        # this through the minimum (`True >= 0`) -- the same trap validate_manifest.py named
        # explicitly for `schema`/`serial`. Int.render() checks isinstance(..., bool) first.
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        build("mod", "1.0.0", True, [e])

    refused("a malformed sha256", bad_sha)
    refused("a payload_id outside the closed set", bad_payload_id)
    refused("a codec this format does not define", bad_codec)
    refused("a negative serial", serial_negative)
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
        build("mod", "1.0.0", _TEST_SERIAL, [e], bundles=[b])

    def duplicate_hash_across_bundles():
        # Two DISTINCT objects -- identical content at two different dests is legal -- each placed
        # in a different bundle. Bundle.__init__ tracks membership by object identity and cannot see
        # that these are the same hash; only build()'s hash scan does.
        e1 = entry("game/dota/a.bin", sha("dup"), 10)
        e2 = entry("game/dota/b.bin", sha("dup"), 10)
        b1 = Bundle("b-1.phxb", "zstd", 5, sha("p1"), entries=[e1])
        b2 = Bundle("b-2.phxb", "zstd", 5, sha("p2"), entries=[e2])
        build("mod", "1.0.0", _TEST_SERIAL, [e1, e2], bundles=[b1, b2])

    refused("the same entry placed in two bundles", entry_in_two_bundles)
    refused("a bundle with no entries", empty_bundle)
    refused("the same entry object listed twice in one bundle's own entries", entry_twice_in_one_bundle)
    refused("two different entries sharing one sha256, in two different bundles",
            duplicate_hash_across_bundles)

    # --- 6. a one-entry launcher-shaped document builds, and derives schema 2 ------------------

    def launcher_shaped():
        e = entry("phoenix-launcher.exe", sha("exe"), 12345678, name="phoenix-launcher.exe")
        doc = build("launcher", "1.5.2", _TEST_SERIAL, [e])
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
        doc = write(path, "mod", "1.0.0", _TEST_SERIAL, [e])
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
        build("mod", "1.0.0", _TEST_SERIAL, [e])

    def duplicate_bundle_name():
        e1 = entry("game/dota/a.bin", sha("a"), 10)
        e2 = entry("game/dota/b.bin", sha("b"), 10)
        b1 = Bundle("same.phxb", "zstd", 5, sha("p1"), entries=[e1])
        b2 = Bundle("same.phxb", "zstd", 5, sha("p2"), entries=[e2])
        build("mod", "1.0.0", _TEST_SERIAL, [e1, e2], bundles=[b1, b2])

    def dangling_tree_ref():
        shown = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        ghost = entry("game/dota/ghost.bin", sha("ghost"), 10, name="ghost.bin")
        build("mod", "1.0.0", _TEST_SERIAL, [shown], tree=[Node(files=[ghost])])

    def default_not_a_variant():
        v1 = Variant("a", "A", sha("a"), 10, name="a.bin")
        v2 = Variant("b", "B", sha("b"), 10, name="b.bin")
        stray = Variant("c", "C", sha("c"), 10, name="c.bin")
        Choice("opt", "Opt", stray, "game/dota/opt.bin", [v1, v2])

    def zero_size_bundle_member():
        # The real empty hash, not a stand-in: Asset now refuses size 0 with any other hash, and a
        # stand-in would make this case fail for THAT reason and stop exercising B6 at all.
        e = entry("game/dota/empty.marker", schema.EMPTY_SHA256, 0)
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
        doc = build(payload_id="game", version="1805", serial=_TEST_SERIAL,
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
        build(payload_id="game", version="1805", serial=_TEST_SERIAL,
              entries=[a, b], bundles=[bun1, bun2])

    def shared_hash_same_object_twice_one_bundle():
        # The identical OBJECT listed twice inside one bundle's own entries -- still refused, same
        # as before this fix; make sure resolving B3 by hash did not accidentally loosen B5 too.
        h = sha("shared")
        a = Entry(dest="game/dota/x.txt", sha256=h, size=10)
        bun = Bundle(name="b000.phxb", codec="zstd", psize=5, psha256=sha("p"), entries=[a, a])
        build(payload_id="game", version="1805", serial=_TEST_SERIAL,
              entries=[a], bundles=[bun])

    ok("one sha256, one bundled entry and one loose entry sharing it -- resolves, ACCEPT",
       shared_hash_one_bundled_one_loose)
    refused("one sha256 claimed by two DIFFERENT bundles -- still B5, REFUSE",
            shared_hash_two_different_bundles)
    refused("the same entry object listed twice in one bundle, via the game producer's shape "
            "-- still B5, REFUSE", shared_hash_same_object_twice_one_bundle)

    # --- the dest namespace: one installed file per path ------------------------------------

    def duplicate_dest():
        a = entry("game/dota/a.txt", sha("a"), 10, name="a.txt")
        b = entry("game/dota/a.txt", sha("b"), 20, name="b.txt")
        build("mod", "1.0.0", _TEST_SERIAL, [a, b])

    def case_only_dest_collision():
        # Two entries that pass every field rule AND the reader's own check_dest, naming one file
        # on the only filesystem this installs onto -- whichever lands last wins, and the other's
        # bytes were downloaded to be overwritten.
        a = entry("game/dota/A.txt", sha("a"), 10, name="a.txt")
        b = entry("game/dota/a.txt", sha("b"), 20, name="b.txt")
        build("mod", "1.0.0", _TEST_SERIAL, [a, b])

    def option_dest_collides_with_a_file():
        e = entry("game/dota_phoenix/maps/dota.vpk", sha("core"), 10, name="core.vpk")
        v = Variant("mod", "Mod", sha("v"), 10, name="v.vpk")
        opt = Choice("lighting", "Lighting", v, "game/dota_phoenix/maps/dota.vpk", [v])
        build("mod", "1.0.0", _TEST_SERIAL, [e], options=[opt])

    def variants_share_their_option_dest():
        # The ACCEPTING direction, and the reason the dest pool takes a choice's own dest rather
        # than one per variant: variants are mutually exclusive, so counting each as a claim on
        # that dest would refuse every choice ever shipped.
        v1 = Variant("mod", "Mod", sha("v1"), 10, name="v1.vpk")
        v2 = Variant("original", "Original", sha("v2"), 20, name="v2.vpk")
        e = entry("game/dota/a.txt", sha("a"), 10, name="a.txt")
        opt = Choice("lighting", "Lighting", v2, "game/dota_phoenix/maps/dota.vpk", [v1, v2])
        doc = build("mod", "1.0.0", _TEST_SERIAL, [e], options=[opt])
        assert_(doc["options"][0]["dest"] == "game/dota_phoenix/maps/dota.vpk", "the option's dest")

    def dests_differing_by_one_legal_character():
        # Only CASE folds. '-' and '_' are different characters and different files, so a fold any
        # wider than the filesystem's own would refuse a legal pair like this one.
        a = entry("game/dota/a-b.txt", sha("a"), 10, name="a-b.txt")
        b = entry("game/dota/a_b.txt", sha("b"), 20, name="a_b.txt")
        doc = build("mod", "1.0.0", _TEST_SERIAL, [a, b])
        assert_(len(doc["files"]) == 2, "both entries survive")

    refused("two entries installing to the same dest", duplicate_dest)
    refused("two dests differing only in case -- one file on Windows", case_only_dest_collision)
    refused("a choice's dest colliding with a top-level entry's", option_dest_collides_with_a_file)
    ok("a choice's variants sharing their option's one dest -- ACCEPT",
       variants_share_their_option_dest)
    ok("two dests differing by a legal character ('-' vs '_') -- ACCEPT",
       dests_differing_by_one_legal_character)

    # --- the release-asset namespace: bundle names and loose names are ONE set --------------

    def bundle_name_collides_with_a_loose_asset():
        # The hole tools/build_game_bundles.py patches with its own `taken` set: B8 compared bundle
        # names only against each other, and a loose `name` was never uniqueness-checked at all.
        loose = entry("game/dota/a.txt", sha("a"), 10, name="mod-4f3a91c2e5d8.phxb")
        packed = entry("game/dota/b.txt", sha("b"), 20)
        bun = Bundle("mod-4f3a91c2e5d8.phxb", "zstd", 5, sha("p"), entries=[packed])
        build("mod", "1.0.0", _TEST_SERIAL, [loose, packed], bundles=[bun])

    def two_loose_entries_sharing_one_name():
        a = entry("game/dota/a.txt", sha("a"), 10, name="same.vpk")
        b = entry("game/dota/b.txt", sha("b"), 20, name="same.vpk")
        build("mod", "1.0.0", _TEST_SERIAL, [a, b])

    refused("a bundle name colliding with a loose entry's name (B8, widened)",
            bundle_name_collides_with_a_loose_asset)
    refused("two loose entries claiming one release asset name", two_loose_entries_sharing_one_name)

    # --- a name GitHub would rewrite is not a name --------------------------------------

    def with_name(n):
        e = entry("game/dota/a.bin", sha("a"), 10, name=n)
        build("mod", "1.0.0", _TEST_SERIAL, [e])

    def the_names_producers_actually_mint():
        # Both shapes in one document, because refusing either would break a shipping producer:
        # build_game_bundles.asset_name() ('/' -> '__', everything else outside [A-Za-z0-9._-] -> '_')
        # and phxb.build_bundle's content-addressed `<label>-<psha[:12]>.phxb`.
        loose = entry("game/dota/scripts/npc/npc_units.txt", sha("npc"), 10,
                      name="game__dota__scripts__npc__npc_units.txt")
        packed = entry("game/dota/b.txt", sha("b"), 20)
        bun = Bundle("b000-txt-4f3a91c2e5d8.phxb", "zstd", 5, sha("p"), entries=[packed])
        doc = build("game", "1805", _TEST_SERIAL, [loose, packed], bundles=[bun])
        assert_(doc["files"][0]["name"] == "game__dota__scripts__npc__npc_units.txt", "loose name")
        assert_(doc["bundles"][0]["name"] == "b000-txt-4f3a91c2e5d8.phxb", "bundle name")

    refused("an asset name with a space", lambda: with_name("hero demo.vpk"))
    refused("a non-ASCII asset name", lambda: with_name("оружие.vpk"))
    ok("the names both producers really mint (asset_name()'s and phxb's) -- ACCEPT",
       the_names_producers_actually_mint)

    # --- dests Win32 does not resolve to what they say -------------------------------------

    def dest_merely_containing_a_device_name():
        # The ACCEPTING direction: the device is the whole stem, never a prefix of one, so these
        # three ordinary files must still build.
        for d in ("game/dota/console.log", "game/dota/nulls.txt", "game/dota/aux_scripts/x.txt"):
            build("mod", "1.0.0", _TEST_SERIAL, [entry(d, sha(d), 10, name="x.bin")])

    refused("a dest component ending in a dot", lambda: with_dest("game/dota/a.txt."))
    refused("a dest component ending in a space", lambda: with_dest("game/dota/a.txt "))
    refused("a '.' dest component", lambda: with_dest("game/./a.txt"))
    refused("a reserved device name as a dest component", lambda: with_dest("game/dota/NUL"))
    refused("a reserved device name wearing an extension", lambda: with_dest("game/dota/COM1.cfg"))
    ok("dests that merely contain a device name ('console.log', 'nulls.txt') -- ACCEPT",
       dest_merely_containing_a_device_name)

    # --- size and sha256 state the same fact, and must agree -------------------------------

    def zero_size_with_a_content_hash():
        entry("game/dota/empty.marker", sha("something"), 0)

    def positive_size_with_the_empty_hash():
        entry("game/dota/a.bin", schema.EMPTY_SHA256, 10, name="a.bin")

    def the_empty_entry_agreeing():
        e = entry("game/dota/empty.marker", schema.EMPTY_SHA256, 0)
        doc = build("mod", "1.0.0", _TEST_SERIAL, [e])
        assert_(doc["files"] == [{"dest": "game/dota/empty.marker",
                                  "sha256": schema.EMPTY_SHA256, "size": 0}], "the empty entry")

    refused("a zero-size entry carrying a content hash", zero_size_with_a_content_hash)
    refused("a positive-size entry carrying the hash of zero bytes", positive_size_with_the_empty_hash)
    ok("size 0 with the hash of zero bytes -- the one agreeing pair, ACCEPT", the_empty_entry_agreeing)

    # --- the wire's own limits: a u64 ceiling, and a files[] with something in it ---------------

    def serial_above_u64():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        build("mod", "1.0.0", schema.U64_MAX + 1, [e])

    def size_above_u64():
        e = entry("game/dota/a.bin", sha("a"), schema.U64_MAX + 1, name="a.bin")
        build("mod", "1.0.0", _TEST_SERIAL, [e])

    def serial_at_the_ceiling():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        doc = build("mod", "1.0.0", schema.U64_MAX, [e])
        assert_(doc["serial"] == schema.U64_MAX, "the ceiling itself is a legal serial")

    def no_files_at_all():
        # What a glob that matched nothing produces: a document that signs, publishes and installs
        # nothing, while every client that fetches it reports itself up to date. (The accepting
        # direction is every other case here -- `launcher_shaped` is a files[] of exactly one.)
        build("mod", "1.0.0", _TEST_SERIAL, [])

    refused("a serial above the u64 the wire carries", serial_above_u64)
    refused("a size above the u64 the wire carries", size_above_u64)
    ok("a serial of exactly u64 max -- the boundary is legal, ACCEPT", serial_at_the_ceiling)
    refused("a manifest with an empty files[]", no_files_at_all)

    # --- the option union is closed, and dispatched once -----------------------------------------

    def an_option_kind_outside_the_union():
        # Refused BY NAME, where the asset pool is built -- this used to reach the walk's
        # `OPTION[kind]` and come out as a KeyError, which is not a format complaint at all.
        class Skin:
            kind, id = "skin", "skin"
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        build("mod", "1.0.0", _TEST_SERIAL, [e], options=[Skin()])

    refused("an option whose kind is outside the format's union", an_option_kind_outside_the_union)

    # --- reading a document back: what the SIGNING AUTHORITY refuses to put a key to ------------
    # Every case here is a document that PARSES as JSON and could be handed to seal.py, which signs
    # bytes and reads nothing. validate() is the only thing between such bytes and the release key.

    def sample():
        """A document with every optional part present, built the only way one can be."""
        pak = entry("game/dota/pak01_000.vpk", sha("pak"), 5588, name="pak01_000.vpk")
        npc = entry("game/dota/scripts/npc/npc_units.txt", sha("npc"), 6189)
        v_mod = Variant("mod", "New lighting", sha("vmod"), 3537)
        v_org = Variant("original", "Original lighting", sha("vorg"), 6285, name="orig.vpk")
        bun = Bundle("b000-txt-4f3a91c2e5d8.phxb", "zstd", 7633, sha("packed"),
                     entries=[npc, v_mod])
        opt = Choice("lighting", "Lighting", v_org, "game/dota_phoenix/maps/dota.vpk",
                     [v_mod, v_org])
        return build("mod", "1.0.0", _TEST_SERIAL, [pak, npc], bundles=[bun], options=[opt],
                     tree=[Node(label="Phoenix Core", files=[pak, npc])], notes="what changed")

    def as_sent(**tweaks):
        """The bytes a producer uploads and this authority is asked to sign, read back."""
        doc = sample()
        doc.update(tweaks)
        return validate(parse(render(doc)))

    ok("a full document round-trips: parse -> validate returns it unchanged",
       lambda: assert_(as_sent() == sample(), "the rebuilt document differs from the original"))

    def a_written_manifest_validates():
        import tempfile
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        path = os.path.join(tempfile.mkdtemp(), "manifest.json")
        doc = write(path, "mod", "1.0.0", _TEST_SERIAL, [e])
        with open(path, "rb") as fh:
            raw = fh.read()
        assert_(validate(parse(raw)) == doc, "write()'s own output did not validate")

    ok("what write() puts on disk -- signed_at and all -- validates from its bytes",
       a_written_manifest_validates)

    refused("a top-level key this format does not write", lambda: as_sent(mirrors=["http://x"]))
    refused("a rewritten bundle size (the sum is DERIVED from the members)",
            lambda: as_sent(bundles=[dict(sample()["bundles"][0], size=1)]))
    refused("a bundle member no entry carries",
            lambda: as_sent(bundles=[dict(sample()["bundles"][0], members=[sha("ghost")])]))
    refused("a `schema` that disagrees with the document's own shape", lambda: as_sent(schema=2))
    refused("a non-empty `remove` (the format writes it empty, always)",
            lambda: as_sent(remove=["game/dota/old.txt"]))
    refused("a payload_id outside the closed set, on the wire", lambda: as_sent(payload_id="skins"))
    refused("a serial that is not a whole number, on the wire", lambda: as_sent(serial="2000001"))

    # The mirror list is sealed by the same authority (.github/workflows/seal.yml) and is NOT a
    # manifest: it is checked by its own narrow rules and its signature is named after its own
    # document. Both directions of that line are asserted here, where the closed set lives -- a
    # manifest cannot claim to be a mirror list, and a mirror list cannot validate as a manifest.
    ok("'mirrors' is not one of this format's payload ids",
       lambda: assert_("mirrors" not in schema.PAYLOAD_IDS, f"PAYLOAD_IDS: {schema.PAYLOAD_IDS}"))
    refused("a manifest claiming payload_id 'mirrors'", lambda: as_sent(payload_id="mirrors"))
    refused("a mirror list offered to the manifest builder",
            lambda: validate(parse(json.dumps(
                {"format": 1, "payload_id": "mirrors", "serial": 2,
                 "mirrors": []}).encode("utf-8"))))

    def traversing_dest_on_the_wire():
        # Rewritten in BOTH places the wire names it, so the refusal is the dest rule rather than
        # a tree reference that stopped resolving.
        doc = sample()
        doc["files"][0]["dest"] = "../evil.dll"
        doc["tree"][0]["files"][0] = "../evil.dll"
        validate(parse(render(doc)))

    def an_entry_carrying_its_own_key():
        doc = sample()
        doc["files"][0]["url"] = "http://mirror.example/pak01_000.vpk"
        validate(parse(render(doc)))

    refused("a traversing dest, on the wire", traversing_dest_on_the_wire)
    refused("a tree node pointing at a dest that is not in files[]",
            lambda: as_sent(tree=[{"label": "x", "files": ["game/dota/ghost.txt"]}]))
    refused("a signed_at that is not a timestamp", lambda: as_sent(signed_at="yesterday"))
    ok("a signed_at that IS one", lambda: as_sent(signed_at=1758000000))
    refused("an entry carrying a key of its own", an_entry_carrying_its_own_key)
    refused("a manifest with no files[] at all",
            lambda: validate(parse(b'{"schema":2,"payload_id":"mod","serial":1,"version":"1.0.0"}')))

    refused("a document whose duplicate key means two things to two parsers",
            lambda: parse(b'{"payload_id":"mod","serial":1,"serial":9}'))
    refused("a root that is not an object", lambda: parse(b'["mod", 1]'))
    refused("bytes that are not UTF-8", lambda: parse(b'{"version":"\xff\xfe"}'))
    refused("JSON with something appended after it",
            lambda: parse(render(sample()) + b'{"serial":9}'))
    refused("bytes that are not JSON at all", lambda: parse(b"winmm.dll"))

    # --- the seal request: ONE serialization, and ONE place a serial is written ------------------
    # Both sides of the signing boundary run this code over the same request, so every case here is
    # really about whether they can disagree.

    def request():
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        return build("mod", "1.0.0", entries=[e])

    def build_defaults_to_a_request():
        assert_(request()["serial"] == 0, "build() must default to a seal request")

    def write_renders():
        import tempfile
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        path = os.path.join(tempfile.mkdtemp(), "manifest.json")
        doc = write(path, "mod", "1.0.0", entries=[e])
        with open(path, "rb") as fh:
            on_disk = fh.read()
        assert_(on_disk == render(doc), "write() puts something other than render() on disk")
        assert_(doc["serial"] == 0, "write() must default to a seal request too")

    def assign_writes_the_serial_and_nothing_else():
        req = request()
        sealed = assign(req, 2_000_042)
        assert_(sealed["serial"] == 2_000_042, f"serial is {sealed['serial']}")
        assert_(validate(sealed) == sealed, "the assigned document does not validate")
        assert_(dict(sealed, serial=0) == req, "assign() changed something other than the serial")
        # The bytes are what is signed, so the byte-level statement is the one worth making.
        assert_(render(sealed) != render(req), "the rendered bytes did not change at all")

    def a_serial_as_text_assigns_the_same_document():
        # ping.check_serial takes both, deliberately: the authority reads its number out of an env
        # var and a caller in Python has an int. They must land on one document.
        assert_(assign(request(), "2000042") == assign(request(), 2_000_042), "text and int differ")

    ok("build() with no serial is a seal request", build_defaults_to_a_request)
    ok("write() puts exactly render()'s bytes on disk", write_renders)
    ok("assign() sets the serial and leaves every other byte alone",
       assign_writes_the_serial_and_nothing_else)
    ok("a serial given as decimal text assigns the same document as the int",
       a_serial_as_text_assigns_the_same_document)

    def assign_cli_rewrites_the_file_in_place():
        import subprocess
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "manifest.json")
        e = entry("game/dota/a.bin", sha("a"), 10, name="a.bin")
        req = write(path, "mod", "1.0.0", entries=[e])
        cli = [sys.executable, os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "phx.py"), "manifest", "assign", "--serial"]
        p = subprocess.run([*cli, "2000042", path], capture_output=True)
        assert_(p.returncode == 0, f"exit {p.returncode}: {p.stdout + p.stderr!r}")
        with open(path, "rb") as fh:
            on_disk = fh.read()
        # Byte-exact: what lands on disk is what the authority would have signed for this request.
        assert_(on_disk == render(assign(req, 2_000_042)),
                "the file was not rewritten as the request at the assigned serial")
        assert_(subprocess.run([*cli, "7", path], capture_output=True).returncode != 0,
                "a document that already names a release was assigned again")

    ok("`phx manifest assign` numbers a request in place, once",
       assign_cli_rewrites_the_file_in_place)

    refused("assigning to a document that already names a release",
            lambda: assign(assign(request(), 7), 8))
    refused("a document with no serial at all", lambda: assign({"payload_id": "mod"}, 7))
    refused("serial 0 as the assignment -- it names no release", lambda: assign(request(), 0))
    refused("a negative serial as the assignment", lambda: assign(request(), -1))
    refused("a serial above the u64 as the assignment",
            lambda: assign(request(), schema.U64_MAX + 1))
    refused("`True` as the assignment", lambda: assign(request(), True))
    refused("assigning to a document this builder would not build",
            lambda: assign(dict(request(), remove=["game/dota/old.txt"]), 7))

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
    # `validate` is a CLI because two callers outside this module want it: the sealing workflow,
    # which refuses a dispatched document before the key is read, and a producer, which can ask the
    # same question of its own manifest before dispatching anything.
    if len(argv) == 2 and argv[0] == "validate":
        with open(argv[1], "rb") as fh:
            raw = fh.read()
        try:
            doc = validate(parse(raw))
        except (ValueError, TypeError) as e:
            sys.exit(f"REFUSED {argv[1]}\n  {e}")
        # A document at serial 0 is not half-written: it is what a producer sends the authority, and
        # saying so here is what stops "serial 0" reading as a bug at the one moment it is checked.
        serial = ("serial 0 (a seal request)" if doc["serial"] == 0
                  else f"serial {doc['serial']}")
        print(f"ok {argv[1]} — schema {doc['schema']}, payload {doc['payload_id']}, "
              f"{serial}, {len(doc['files'])} file(s)")
        return
    # `assign` is a CLI for the one release that cannot ask the authority to number it: a RECOVERY
    # release, sealed by hand under the recovery key (client-dist-staging/docs/release-keys.md).
    # Rewrites the file in place with exactly the bytes the authority would have signed.
    if len(argv) == 4 and argv[0] == "assign" and argv[1] == "--serial":
        with open(argv[3], "rb") as fh:
            raw = fh.read()
        try:
            doc = assign(parse(raw), argv[2])
        except (ValueError, TypeError) as e:
            sys.exit(f"REFUSED {argv[3]}\n  {e}")
        with open(argv[3], "wb") as fh:
            fh.write(render(doc))
        print(f"ok {argv[3]} — assigned serial {doc['serial']}")
        return
    sys.exit("usage: phx manifest selftest | validate <manifest.json> | "
             "assign --serial <N> <request.json>")


if __name__ == "__main__":
    main()
