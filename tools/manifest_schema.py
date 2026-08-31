"""The manifest FORMAT version — shared by every producer and the fixture generator.

This is the highest schema the format defines (see docs/manifest-reader-contract.md), NOT what
any one producer emits. The distinction matters:

  * the format version moves ONLY when a change would force a producer to bump — that is, one a
    reader cannot safely ignore. It moves together with the reader's supported ceiling and the
    conformance fixtures. A purely ADDITIVE capability (a new top-level key, a new field older
    readers can skip) is specified and fixture-covered at the CURRENT format version instead:
    nothing about it requires a reader to be newer, so giving it a number would only invite a
    producer to claim one and lock out readers that would have coped. Option categories
    (`groups` / `group`) are the worked example — a reader that ignores both renders one flat
    list, which is plainer, not wrong;
  * a PRODUCER declares the format it actually wrote in, and bumps only when it uses a feature
    of the newer schema. Each keeps its OWN `SCHEMA` constant, and that constant is the only thing
    that can be right about it — read the number off the producer. Listing them here instead re-rots
    every time one is added or moves, which is exactly what happened: this said "both producers"
    while there were three, one of them emitting a different number. A producer that emitted
    `FORMAT_SCHEMA` directly would collapse these two numbers back together, and a spec-side bump
    here — a new fixture, a rule no reader has learned yet — would silently raise the number in
    every manifest it writes.

Bumping a producer ahead of the reader hard-fails every client at once, which is why these are
separate numbers rather than one.
"""

FORMAT_SCHEMA = 3

# --- the signing envelope ----------------------------------------------------------------------
# Signing (docs/manifest-reader-contract.md) adds three top-level keys. They do NOT move
# FORMAT_SCHEMA, even though a current reader REFUSES a document missing two of them, because that
# requirement is reader POLICY and not document format:
#
#   * to a reader that does not verify signatures the keys are inert — it installs exactly what it
#     installed before — so nothing about them needs a NEWER reader, which is the only thing a
#     schema bump buys. Bumping would instead hard-fail every shipped client at once to deliver a
#     capability those clients still would not have;
#   * "refuse what I cannot verify" cannot be encoded in the document at all: a stripped
#     `payload_id` is indistinguishable from a producer that predates signing, so no field value
#     could ever compel the check. Whether the keys are required is therefore a build-time property
#     of the reader, exactly like validate_manifest.MAX_SCHEMA — not a property of the format.
PAYLOAD_ID = "payload_id"   # which payload the document describes; one of PAYLOAD_IDS
SERIAL = "serial"           # non-negative int, monotonic per payload — the SOLE ordering authority
SIGNED_AT = "signed_at"     # unix seconds, ADVISORY: nothing may fail on it, clocks and CI lie

# Closed set. Each id names a payload with its own release source, its own key and its own install
# action, so a reader can only act on ids it was built to know; an unrecognised one is a document
# it cannot dispatch, not a document from the future. Adding one is an additive change HERE,
# shipped together with the reader that handles it.
PAYLOAD_IDS = {"mod", "launcher", "game", "mirrors"}
