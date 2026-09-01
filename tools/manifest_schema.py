"""The manifest FORMAT, declared as DATA.

Nothing here builds a document -- see build_manifest.py for that. This module answers only "what
does the wire format look like and what does each field mean", as a small vocabulary of field types
(Const, Enum, Int, Str, Hex64, Dest, Label, Opt, List, Obj, Derived, Ref) composed into the five
named shapes below (FILE, BUNDLE, NODE, OPTION, MANIFEST). Adding or changing a wire field is meant
to be a ONE-FILE edit here; build_manifest.py's builder walks whatever this module declares and
hardcodes no key name of its own.

Two kinds of field carry no input from a caller at all:

  * Derived(fn) -- fn(owner) computes the value from data already on the object (bundle `size` from
    its own entries' sizes, `schema` from whether any bundle exists, `remove` as the permanent empty
    list -- see build_manifest.py's module docstring for why it stays empty). These are pure: no
    randomness, no clock, no bytes read from disk, which is also why they can live here. `fn` may
    return `ABSENT` (below) to say the key does not belong on the wire at all this time -- the walk
    then omits it, exactly like an absent Opt.
  * Ref(attr) -- a cross-reference to another object's OWN field, e.g. a tree node's `files` are
    Entry objects and the wire value is each one's `.dest`; a choice's `default` is one of its own
    Variant objects and the wire value is that variant's `.id`. The caller never types the string
    that ends up on the wire -- see build_manifest.py's docstring for why that is the whole point.

`signed_at` needs the wall clock, and this module does no I/O, no timekeeping and no hashing -- so
it cannot compute the value itself. It is still an ordinary Derived field, not a special case the
walker has to know the name of: its `fn` reads `owner.signed_at`, a plain attribute build() always
sets (to `None` by default) and that write() overwrites with the real timestamp just before
rendering. `fn` returns `ABSENT` while that attribute is `None`, so build() alone -- never told a
time -- omits the key, and stays a pure function of its inputs; two builds of "the same" release
never differ. The KEY NAME "signed_at" appears exactly once outside this module: as build()'s
keyword-only parameter of the same name, which is a naming convention (like `payload_id` or
`version`), not the walker special-casing a string.
"""

SCHEMA = 3

# Deliberately WITHOUT "mirrors": nothing in this codebase emits one or reads one. Adding it back
# is an ADDITIVE change to this tuple alone, made the day something actually produces it -- not
# reserved speculatively, which is exactly how the previous four-entry set went stale (see git
# history: validate_manifest.py carried a second, hand-duplicated copy of this same set, and the
# two were free to drift apart with nothing to notice).
PAYLOAD_IDS = ("mod", "launcher", "game")

CODECS = ("zstd",)

# The reference zstd decoder's default ZSTD_d_windowLogMax -- a bundle built at a higher window log
# would need a reader to raise its own limit, so this is a wire-format ceiling, not a tuning knob.
ZSTD_WLOG = 27


# --- the field vocabulary -------------------------------------------------------------------------
# Each of these answers exactly one question -- given a RAW value, what belongs on the wire, or why
# not -- and nothing else. build_manifest.py is the only code that calls render(); a field that
# raises makes the document it would have poisoned impossible to produce, rather than merely flagged
# after the fact.

# The one value that means "this key does not appear on the wire this time" -- what an absent Opt
# already meant, and what a Derived(fn) may now also return. A plain `object()`: nothing about it is
# I/O, the clock or a hash, so it costs this module nothing to own it.
ABSENT = object()

class Const:
    """A key whose value never varies and is never supplied by a caller."""
    def __init__(self, value):
        self.value = value

    def render(self, _raw):
        return self.value


class Enum:
    """One of a fixed, closed set of values -- matched by VALUE AND TYPE.

    Python's `bool` is a subtype of `int` (`True == 1`), so a same-value check alone would let a
    boolean slip through an int enum and vice versa -- the identical trap `schema`/`serial` guard
    against elsewhere in this format (see tools/manifest_schema.py's old validator, now folded into
    Int below). Matching type as well is what lets this ALSO serve as the boolean field type: a
    toggle's `default` is `Enum(True, False)`, and nothing else is needed for it."""
    def __init__(self, *values):
        self.values = values

    def render(self, value):
        if not any(type(value) is type(v) and value == v for v in self.values):
            raise ValueError(f"{value!r} is not one of {self.values!r}")
        return value


class Int:
    """A whole number, optionally floored. Rejects `bool` explicitly for the reason above."""
    def __init__(self, min=None):
        self.min = min

    def render(self, value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{value!r} is not a whole number")
        if self.min is not None and value < self.min:
            raise ValueError(f"{value} is below the minimum {self.min}")
        return value


class Str:
    """A non-empty string -- used for ids, names, versions and free text alike."""
    def render(self, value):
        if not isinstance(value, str) or not value:
            raise TypeError(f"{value!r} is not a non-empty string")
        return value


class Hex64:
    """A lowercase 64-hex sha256 digest -- the ONLY form this format ever carries one in."""
    _DIGITS = frozenset("0123456789abcdef")

    def render(self, value):
        if not isinstance(value, str) or len(value) != 64 or any(c not in self._DIGITS for c in value):
            raise ValueError(f"{value!r} is not a lowercase 64-hex sha256")
        return value


class Dest:
    """An install path: relative to the game root, always forward-slashed, never escaping it.

    Ports every rule tools/validate_manifest.py's `unsafe_dest` used to check -- empty/non-string,
    backslash, absolute (leading `/`), `..` traversal -- as something a caller CANNOT construct
    rather than something caught afterwards. Two rules are WIDER than that ported original:

      * the old check only refused a colon at index 1 (`C:...`, the drive-letter form); this refuses
        a colon ANYWHERE, because on Windows -- the only platform anything here installs onto -- a
        colon after the first path segment names an NTFS alternate data stream (`file.txt:evil`),
        which is exactly the same "write somewhere the author didn't intend" hazard traversal is;
      * an empty path component (`game/dota//x.txt`, or a trailing `/`) was not checked by
        `unsafe_dest` either, but the READER's own `check_dest` refuses it -- so a producer built
        against `unsafe_dest` alone could emit a manifest the launcher then rejects at install time.
        Refusing it here closes that gap now that this is the one definition of a legal dest.

    Losing no rule from the port does not mean adding no rule to it."""
    def render(self, value):
        if not isinstance(value, str) or not value:
            raise ValueError("dest must be a non-empty string")
        if "\\" in value:
            raise ValueError(f"{value!r}: backslash (dest must be forward-slashed)")
        if ":" in value:
            raise ValueError(f"{value!r}: ':' (a drive letter or an NTFS alternate data stream)")
        if value.startswith("/"):
            raise ValueError(f"{value!r}: absolute path")
        parts = value.split("/")
        if "" in parts:
            raise ValueError(f"{value!r}: empty path component (a doubled or trailing '/')")
        if ".." in parts:
            raise ValueError(f"{value!r}: '..' escapes the game root")
        return value


class Label:
    """A display string, or a `{lang: text}` map (fallback `en` -> any is the READER's job, not
    this format's -- see docs/manifest-reader-contract.md, back when docs/ existed)."""
    def render(self, value):
        if isinstance(value, str) and value:
            return value
        if isinstance(value, dict) and value and all(
                isinstance(k, str) and isinstance(v, str) and v for k, v in value.items()):
            return dict(value)
        raise TypeError(f"{value!r} is not a label string or a non-empty {{lang: text}} map")


class Opt:
    """The wrapped field may be absent: a raw value of None omits the key entirely rather than
    writing `null`, which is the shape every existing producer already used."""
    def __init__(self, inner):
        self.inner = inner


class List:
    """Zero or more of `inner`, in order. Order is meaningful for bundle-derived fields (a bundle
    splits its decoded stream by counting bytes against its members IN ORDER) and cosmetic
    everywhere else."""
    def __init__(self, inner):
        self.inner = inner


class Obj:
    """A nested JSON object: an ORDERED {wire key: field} vocabulary. `fields` is a plain dict --
    declared as data, walked by build_manifest.py, never referenced by key name outside this file
    (`NODE.fields["groups"]` below is the one necessary exception, for self-reference)."""
    def __init__(self, **fields):
        self.fields = fields


class Derived:
    """A field the BUILDER computes -- `fn(owner) -> value`, where `owner` is the object the field
    belongs to (a Bundle for `size`/`members`, the document itself for `schema`/`remove`/
    `signed_at`). `fn` may return `ABSENT` to omit the key entirely -- see `signed_at` below, the
    one field this module cannot compute a value for itself (it needs the wall clock), but can still
    declare structurally: its `fn` just reads whatever build_manifest.py put on `owner.signed_at`."""
    def __init__(self, fn):
        self.fn = fn


class Ref:
    """A cross-reference to another object's OWN field: the raw value is that object, `attr` names
    which of ITS fields ends up on the wire. This is what makes "the input language never refers to
    anything by string" hold structurally -- a tree node's `files` are Entry objects (Ref("dest")),
    a choice's `default` is one of its own Variant objects (Ref("id")); there is no string a caller
    could mistype into a dangling reference."""
    def __init__(self, attr):
        self.attr = attr


# --- the wire shapes ---------------------------------------------------------------------------

# One file-bearing entry as it appears in `files[]`, or in a toggle option's `files[]`. `name` is
# present only for a LOOSE entry (its own release asset); absent, it is a bundle member instead --
# build_manifest.py's Entry/Bundle enforce that this is the only two states an entry can be in.
FILE = Obj(
    name=Opt(Str()),
    dest=Dest(),
    sha256=Hex64(),
    size=Int(min=0),
)

# A choice option's one variant. Shares its option's `dest` (there is no `dest` field here); is
# otherwise exactly a FILE plus a stable `id` and its own `label`.
VARIANT = Obj(
    id=Str(),
    label=Label(),
    name=Opt(Str()),
    sha256=Hex64(),
    size=Int(min=0),
)

# A `.phxb` bundle. `size` and `members` are DERIVED from the entries the bundle actually packs --
# see build_manifest.Bundle -- so a size-sum mismatch or an orphan member cannot be expressed; there
# is no field here a caller can set directly for either.
BUNDLE = Obj(
    name=Str(),
    codec=Enum(*CODECS),
    psize=Int(min=0),
    psha256=Hex64(),
    size=Derived(lambda b: sum(e.size for e in b.entries)),
    members=Derived(lambda b: [e.sha256 for e in b.entries]),
)

# The presentational display tree: `{label?, files?, groups?}`, unbounded depth, a node without a
# `label` splices into its parent. `files` are Ref("dest") -- Entry objects whose dest ends up on
# the wire -- so a tree can only ever point at an entry that genuinely exists (build_manifest.py
# additionally requires it be one of the manifest's own top-level entries, matching what
# docs/manifest-reader-contract.md said tree may reference).
NODE = Obj(
    label=Opt(Label()),
    files=Opt(List(Ref("dest"))),
)
NODE.fields["groups"] = Opt(List(NODE))   # self-reference; must come after NODE exists

# A choice shares one `dest` among mutually-exclusive `variants`; `default` is Ref("id") -- one of
# those SAME Variant objects, never a typed string -- so a default that names no variant cannot be
# expressed (build_manifest.Choice checks `default in variants` at construction).
_OPTION_CHOICE = Obj(
    id=Str(),
    kind=Const("choice"),
    label=Label(),
    default=Ref("id"),
    dest=Dest(),
    variants=List(VARIANT),
)

# A toggle is a `files[]` set, installed when enabled. `default` is Enum(True, False) -- see Enum's
# docstring for why that alone is a sound boolean field.
_OPTION_TOGGLE = Obj(
    id=Str(),
    kind=Const("toggle"),
    label=Label(),
    default=Enum(True, False),
    files=List(FILE),
)

# The choice/toggle union: a plain dict keyed by `kind`, not a new vocabulary primitive -- one
# option shape or the other is picked by the INPUT object's own `.kind`, which build_manifest.py's
# walker dispatches on wherever it meets a dict instead of an Obj.
OPTION = {"choice": _OPTION_CHOICE, "toggle": _OPTION_TOGGLE}

# The document itself. `signed_at` and `remove` are commented individually below; everything else
# either comes straight from a builder argument (same key name -- see build_manifest.build) or is
# Derived from the objects the caller passed in.
MANIFEST = Obj(
    # 3 exactly when a bundle exists, else 2 -- "the widest compatibility the honest number
    # allows". No producer keeps its own SCHEMA constant any more; this is the one place that
    # decides, and it decides from the DOCUMENT's own shape, never from a caller's say-so.
    schema=Derived(lambda m: SCHEMA if m.bundles else 2),
    payload_id=Enum(*PAYLOAD_IDS),
    # The SOLE ordering authority within one payload line -- `version` is display text and is never
    # compared -- and what a client ratchets against: a manifest below the serial it already holds
    # is refused. Int(min=0) is the whole of what the FORMAT can say about it. WHICH number comes
    # next is the publisher's business, and tools/next_serial.py answers it by reading the last
    # PUBLISHED manifest and adding one. A SERIAL_FLOOR (2_000_000) used to sit here instead,
    # encoding one producer's `2000000 + github.run_number` convention into the format: it caught
    # nothing real -- a run counter reset by a renamed workflow yields 2000001, which clears the
    # floor and still lands below every installed client's ratchet, so the release is invisible to
    # everyone who already has one -- while making this module know a thing about a producer's CI.
    serial=Int(min=0),
    # Reads whatever build_manifest.py put on `owner.signed_at` -- None by default (build() alone
    # never touches the clock), the real timestamp once write() supplies one. ABSENT while it is
    # None, so the key is simply missing from a plain build() result, never `null`.
    signed_at=Derived(lambda m: ABSENT if m.signed_at is None else m.signed_at),
    version=Str(),
    notes=Opt(Str()),
    bundles=Opt(List(BUNDLE)),
    files=List(FILE),
    # A known, permanent gap (see the old docs/manifest-reader-contract.md, and every producer that
    # ever existed): nothing here can populate a removal, so a retired file's old dest is orphaned
    # forever. Encoding that honestly -- always empty, never a caller argument -- beats silently
    # "fixing" it in a rewrite nobody asked to change the format's actual behaviour.
    remove=Derived(lambda m: []),
    tree=Opt(List(NODE)),
    options=Opt(List(OPTION)),
)
