# manifest.json — the reader's contract

The `manifest.json` in every release is the only contract between this repo and whatever installs
from it. **The format itself is not described here — it is executable.** Three committed artifacts are
the authority; port or consult them, don't reimplement from prose:

- **`tools/validate_manifest.py`** — the reference reader-side validator: the schema gate, the
  signing envelope, the `dest`-traversal refusal, the codec gate, and the **document** half of the
  B1–B8 bundle invariants. B4 is not among them by nature, not by omission: "nothing between
  members, nothing after the last" is a property of the DECODED stream, so only a reader that
  decodes can enforce it (it is the third bullet under Bundles below).
  Porting it gives you schema-first parsing, absent-`schema`==1, unknown-key tolerance, and
  unsupported-schema refusal for free.
- **`docs/manifest-fixtures/`** (`index.json`) — example manifests, each with an expected outcome;
  the conformance suite. `current.json` is the full shape at once; what every other fixture is FOR is
  stated in its own `index.json` entry, which is the authority — restating it here only rots.
  `signatures/index.json` is the same idea for signature verification,
  including the failures a correct verifier is the only thing that catches.
- **`tools/phoenix_minisign.py`** — the signature format, and the ways it is deliberately narrower
  than upstream minisign. Also a working signer/verifier and its own `selftest`.

This document holds only what those cannot: **document semantics that surface at install time** (no
validator ever touches a byte), a few **reader semantics** a document-checker has no reason to know,
and the **boundary rule**. The reader is developed independently and must not read the *producer* to
learn the format.

**Scope, and it is a hard line.** This repo defines the FORMAT and seals it. What a reader must do
for the format's own guarantees to hold — verify before it commits, refuse what it cannot verify,
resolve an entry to bytes by the one defined route — is in scope. HOW a reader installs — how it
schedules, resumes, retries, persists a selection, or words a refusal to a user — is not, and is
deliberately absent. Prose here that describes a reader's implementation cannot be checked by
anything in this repo, so it would only rot.

## The boundary

The manifest **declares the format it is written in** (`schema`); deciding whether it can be read is
the reader's job — the producer never names a reader version. So: support a **range** of schemas,
refuse one outside it as an unsupported-VERSION refusal and never as a parse error — a manifest from
the future is not malformed — and raise your ceiling in the same change that teaches you the new
format. How that refusal reads to a user is the reader's own business. Absent `schema` means 1;
1, 2 and 3 are defined today.

## Signatures — before anything else

Every manifest ships beside a `manifest.json.minisig`: minisign's four-line format, algorithm **`Ed`**
(pure Ed25519). TLS proves a server answered; once releases come from mirrors that is all it proves.
Obligations no fixture can hold:

- **Verify the bytes that arrived, then parse them.** A signature covers a FILE. Re-encoding a
  document you already parsed and verifying that says nothing about what was delivered. Until it
  verifies, a manifest has no author and nothing in it is worth reading — not even its `schema`.
- **Check both signatures.** The second covers the trusted comment, which is the only reason a
  comment carried inside a signature can be quoted at all. Neither signature makes it
  AUTHORITATIVE: everything you act on comes from the signed document, never from parsing that line.
- **Refuse any algorithm but `Ed`.** `ED` is the Blake2b-prehashed variant, which we do not use. A
  relabelled `Ed` signature verifies perfectly, so a verifier that reads the field and ignores it has
  silently acquired an algorithm it never implemented.
- **The trust root is yours.** `key_id` selects among keys that shipped WITH you; it never introduces
  one. A key fetched from where the manifest came from is not a trust root. Support a ring, or the
  first key rotation needs an update that cannot be delivered because the key rotated.
- **`payload_id` must equal what you came for.** A signature says who wrote a document, not what it
  is for. Without this, a validly signed `launcher` manifest can be served as the `mod` one and
  installed as one. `mod` / `launcher` / `game` / `mirrors`; anything else is a broken release.
- **`serial` must not go backwards.** It is the SOLE ordering authority — version strings are for
  humans and do not order (`1.10.0` vs `1.9.0`). Keep the highest serial installed per payload and
  refuse anything below it; equal is the ordinary case, since that is what every poll of an
  unchanged release looks like. Without it a mirror replays a stale, validly signed manifest forever.
- **`signed_at` decides nothing.** Display it, sort by it, never gate on it. Refusing a manifest for
  its timestamp hands anyone with a wrong clock a client that can no longer update, and buys nothing
  that `serial` does not already cover.

## Document semantics that only bite at install time

No validator can hold these: they are properties of the DOCUMENT that come into play only once
something resolves it to bytes. How a reader schedules, resumes, retries or reports that work is the
reader's own business and is deliberately not specified here.

- **Verify before you write.** Check an asset's `sha256`/`psha256` **before** decoding or installing
  it, and never commit a partially-verified file. This is the hash chain, not hygiene: the signature
  covers the manifest and the manifest's hashes cover the assets, so "what was installed is what was
  signed" holds only if verification precedes commit.
- **Entry → bytes** resolves by exactly one route, in order: `size` 0 → materialize an empty file;
  else `name` present → the release asset of that name; else → the one bundle whose `members` contains
  the entry's `sha256`.
- **Bundles are containerless.** A bundle asset is `codec(member₀ ‖ member₁ ‖ …)` — no
  tar/zip/header/member-table; the manifest carries every member's `sha256`, `size` and order. So:
  verify `psha256` before decoding; split the decoded stream by counting bytes against the members'
  `size`s; verify **each member's own `sha256`** before committing it (a torn or interrupted decode is
  then safe — nothing unverified is committed, nothing committed is lost); the decoded stream is
  exactly the members concatenated, with no padding or trailing bytes. A member mismatch **after** a
  clean `psha256` is deterministic — a producer defect, not a transport failure.
- **`psize` vs `size` are different numbers** — `psize` is the packed asset on the wire (progress,
  ETA, scratch space); `size` is the decoded footprint on disk. Never interchange them.
- **Codec** is `"zstd"`, window log capped at **27** (the reference decoder's default — no decoder
  configuration needed). An unrecognised codec is an unsupported-format refusal, not corruption.

## Reader semantics a validator has no reason to know

- **`dest`** is relative to the game root — the directory *containing* `game/` — always
  forward-slashed, never absolute, never `..`-escaping. It's the one field that turns a compromised
  manifest into an arbitrary file write, so **reject a traversing `dest`** (`validate_manifest.py`
  enforces it; you must on your side too). This applies to bundled entries identically.
- **`options[]`** — each has a stable unique `id` and a `label`. A **`choice`** shares one `dest` and
  installs exactly one `variants[]` entry; a **`toggle`** is a `files[]` set, present when enabled and
  absent when disabled. `default` is a variant-id **string** for `choice`, a **boolean** for `toggle`.
  A `label`/`description` is a string or a `{"en":…,"ru":…}` map (fall back `en` → any). **Deselecting
  an installed option removes its files.**
- **`tree` is PRESENTATIONAL and optional.** A nested display hierarchy for the always-installed
  content: nodes are `{label?, files?, groups?}`, where `files` lists `dest`s from `files[]`, depth
  is unbounded, and a node without a `label` just splices its content into its parent. It is **not an
  options tree** — a heading may hold only always-installed files (that is how "Hero Demo Plus"
  appears: a group with no checkbox). A `label` is a string or an `{"en":…,"ru":…}` map, like any
  other label. **Ignoring `tree` wholesale is conforming** — a flat list is plainer, not wrong, which
  is why it carries no schema number. For the same reason a ref to a `dest` that `files[]` does not
  carry **must not be fatal**: skip it, never refuse a release over presentation.
- **Assets are a flat namespace** — `name` is an OPAQUE handle unique within one release, while
  `dest` keeps the real install path. **Do not assume `name` is `dest`'s basename** (two game dirs
  can hold the same filename — every Dota addon has an `addon_game_mode.lua`) or that it follows any
  naming scheme. Match an asset by `name` **within the release you already fetched**. There is
  deliberately **no URL** (a private repo needs an authenticated API request).

## Versioning, the bump rule, and known gaps

The three version numbers — the FORMAT version, each PRODUCER's emit-version, and the READER's
supported range — are documented in `tools/manifest_schema.py`; don't collapse them. The producer
bumps `schema` only on a **breaking** change (a new option `kind` or enum value; a new required field;
a retype/rename/removal of a field readers declare; a change to what a field *means*); additive keys
never bump it. The signing envelope is the worked exception to "a new required field": a current
reader refuses without it, yet no schema number could compel that check — a stripped `payload_id` is
indistinguishable from a producer that predates signing, so the requirement lives in the reader
(`manifest_schema.py` spells out the argument).

Two known gaps, real and unsolved:
- **`remove[]` is always emitted empty** — implement it fully anyway; a file whose `dest` changes is
  otherwise orphaned on every install.
- **Nothing records or checks the target game build** (every shim RVA targets build **1805**). The
  field must not return without the reader-side check.
