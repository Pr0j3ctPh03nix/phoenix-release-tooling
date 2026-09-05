#!/usr/bin/env python3
"""The mirror ping — a SIGNED, serial-bound "payload X is at serial N" that anyone may deliver.

    python phx.py ping sign   --payload mod --serial 2000042 --out ping.json
    python phx.py ping verify ping.json --pub keys/phoenix-active.pub
    python phx.py ping ledger --payload mod --sealed <a checkout of the `sealed` branch>
    python phx.py ping selftest

WHY IT IS SIGNED. phoenix_tooling/notify.py used to POST an empty body to an unauthenticated
endpoint, and that was sound while the ping SAID nothing: the worst a forgery bought was a sync the
forger could have asked for himself. The ping now carries a SERIAL, and a mirror uses that number
to decide whether it is behind. An unsigned number is a claim a mirror acts on -- one forged
"serial 99999999" tells every mirror it is permanently stale, and a forged low one tells a mirror
it is current when it is not. The signature binds the PAIR to the release key, which is also what
lets the ping be delivered by anybody at all: the deliverer is no longer trusted for anything, so
the three producers, a bystander, or a mirror relaying to another mirror are all the same courier.

THE MESSAGE IS A WIRE CONTRACT, re-derived byte for byte by the mirror app (phoenix-mirror's
`mirror.ts`) before it checks the signature. It is declared as data below and must not be "tidied":

    MAGIC + b"\\n" + payload + b"\\n" + serial      ->   b"phoenix-ping\\nmod\\n2000042"

  * `payload` is `[a-z]+`. Deliberately NOT manifest_schema.PAYLOAD_IDS: which payload lines exist
    is a publishing fact (seal.yml's authorization map decides it, per requesting repo), and a new
    line must not need a release of this repo before a mirror can be told about it. The character
    class is what the format owes the mirror -- it is a path segment in the sync route. `mirrors`
    is exactly that case made real: the mirror list seals under its own ledger payload, and is NOT
    a manifest payload_id (manifest_schema.PAYLOAD_IDS still, deliberately, omits it).
  * `serial` is plain decimal: no sign, no leading zero, no exponent, no separators. There is
    exactly ONE spelling of a number, so "is this the same serial" is the same question whether a
    reader compares the strings or the integers.

NOT A .minisig, and not a second signing format either. A .minisig signs a FILE's exact bytes and
carries a trusted comment (see minisign.py); here the signed thing is not a file at all --
it is two short fields the reader RE-DERIVES from JSON it parsed, so there are no framing bytes to
agree on. What is shared with .minisig is everything that matters: the same pure-Ed25519 primitive
and the same release key. `verify` refuses a .minisig envelope offered as a `sig` (it is not 64
raw bytes), so the two can never be confused for one another.

THE SERIAL IS A STRING in the JSON. A serial is a u64 and the mirror app is TypeScript, where
`JSON.parse` yields a double and silently rounds above 2**53. A decimal string crosses every JSON
reader unharmed, and the signed message is built from that same text.

STDLIB ONLY UNLESS IT SIGNS. `cryptography` is imported inside `sign`/`verify`, never at module
scope, because `ledger` runs in the signing authority's job BEFORE the signing wheel is installed
-- assigning the next serial is a gate, and a request refused at a gate installs nothing. See
`ledger_high`.
"""
import argparse
import base64
import json
import os
import re
import sys
from typing import NoReturn

from . import manifest_schema as schema   # for U64_MAX only; this module imports nothing

# --- the wire contract: the signed message ---------------------------------------------------------

MAGIC = b"phoenix-ping"
SEP = b"\n"
PAYLOAD_RE = re.compile(r"\A[a-z]+\Z")
# No sign, no leading zero, no '.', no exponent -- and no zero: an empty ledger reads as 0 and the
# authority assigns one above it, so 0 is a number no payload is ever sealed at. That is exactly
# what makes it usable as the "no release yet" marker a seal request carries. (The FORMAT allows it
# -- manifest_schema's `serial` is Int(min=0) -- because that is the widest honest statement about a
# u64; refusing it here is what a ping means, not what the format says.)
SERIAL_RE = re.compile(r"\A[1-9][0-9]*\Z")

# The ping document. Exactly these four keys, no more: a reader that ignores unknown keys cannot
# tell a future field from one an attacker stripped, and nothing here is signed except payload and
# serial. Adding a field is a deliberate change to this tuple AND to mirror.ts, together.
FIELDS = ("payload", "serial", "key_id", "sig")

SIG_LEN = 64                  # a raw Ed25519 signature
KEY_ID_LEN = 8                # minisign's key id, hex-encoded in the document

# --- the ledger: where a sealed payload's serial is recorded ---------------------------------------

# The sealing workflow commits `<LEDGER_DIR>/<owner>/<name>/<tag>/{<document>,<document>.minisig,
# ping.json}` to the branch `sealed`, where <document> is the file that was sealed -- see
# `document_name` below. The document itself is there because the authority is what WRITES the
# serial into it: the bytes that were signed are the answer, not merely a signature over bytes the
# producer already had. These names are part of what the producers fetch, so they live here rather
# than in the workflow that writes them; and because the signature is named after the DOCUMENT,
# what a ledger entry can be checked for is the SUFFIX, never one filename.
LEDGER_DIR = "sealed"
PING_NAME = "ping.json"
SIG_SUFFIX = ".minisig"

# The one document kind that is not a payload manifest: the mirror registry's list. It is not a
# manifest_schema.PAYLOAD_ID and never will be (see the docstring), so the name it seals under is
# the only thing that has to be agreed on, and it is agreed on HERE -- the authority writes the
# entry (.github/workflows/seal.yml) and the producer reads it back (phoenix_tooling/dispatch.py),
# and a name each side spelled for itself would be a ledger entry only one of them could find.
MIRRORS = "mirrors"
MANIFEST_DOCUMENT = "manifest.json"
DOCUMENTS = {MIRRORS: "mirrors.json"}


def document_name(payload_id):
    """-> the filename this payload's sealed document is filed under, in the ledger and on the
    release. Everything but the mirror list is a payload manifest."""
    return DOCUMENTS.get(payload_id, MANIFEST_DOCUMENT)


class PingError(Exception):
    """Every way a ping can fail to be produced, read or believed -- one type, for the reason
    minisign.MinisignError is one type: a caller that catches "malformed" separately from
    "did not verify" eventually treats one of them as benign."""


def die(msg) -> NoReturn:
    sys.exit("ping: " + msg)


# --- the message ----------------------------------------------------------------------------------

def check_payload(value):
    """-> the payload id, or PingError. The same rule the sync route needs (see notify)."""
    if not isinstance(value, str) or not PAYLOAD_RE.match(value):
        raise PingError(f"payload {value!r} is not [a-z]+")
    return value


def check_serial(value):
    """-> the serial as its ONE canonical decimal spelling, from an int or that same text.

    An int is accepted because the caller that signs has one (it came out of a manifest); a string
    is accepted because that is what crosses the wire. Both land on the same text, so the signed
    bytes cannot depend on which side of the boundary the number came from."""
    if isinstance(value, bool):                       # bool is an int subclass; True is not a serial
        raise PingError(f"serial {value!r} is a boolean, not a number")
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        raise PingError(f"serial {value!r} is neither an integer nor decimal text")
    if not SERIAL_RE.match(text):
        raise PingError(f"serial {text!r} is not plain decimal (no sign, no leading zero, "
                        "no '.', and never 0)")
    if int(text) > schema.U64_MAX:
        raise PingError(f"serial {text} is above the u64 the format carries")
    return text


def message(payload, serial):
    """The exact bytes a ping's signature covers. THE wire contract -- mirror.ts rebuilds this."""
    return MAGIC + SEP + check_payload(payload).encode("ascii") + SEP + \
        check_serial(serial).encode("ascii")


# --- the document ---------------------------------------------------------------------------------

def check_doc(doc):
    """Structure only -- no signature. -> (payload, serial text), or PingError.

    Split out from `verify` because two callers need the fields WITHOUT the key: notify,
    which only has to know which mirrors a ping is for, and the ledger below, which runs in a
    producer's CI where `cryptography` is not installed."""
    if not isinstance(doc, dict):
        raise PingError("not a ping: the document is not a JSON object")
    keys = tuple(sorted(doc))
    if keys != tuple(sorted(FIELDS)):
        raise PingError(f"not a ping: keys {keys}, expected exactly {tuple(sorted(FIELDS))}")
    for k in FIELDS:
        if not isinstance(doc[k], str):
            raise PingError(f"{k} is {doc[k]!r}, and every field of a ping is a string")
    return check_payload(doc["payload"]), check_serial(doc["serial"])


def sign(payload, serial, secret_key):
    """-> the ping document, signed by `secret_key` (the .key file's text)."""
    from . import minisign as pm                      # lazy: see the module docstring

    p, s = check_payload(payload), check_serial(serial)
    try:
        sk = pm.parse_secret_key(secret_key)
    except pm.MinisignError as e:
        raise PingError(f"the signing key is unreadable: {e}") from None
    sig = sk.key.sign(message(p, s))
    return {"payload": p, "serial": s, "key_id": sk.key_id.hex(),
            "sig": base64.b64encode(sig).decode("ascii")}


def verify(doc, public_keys):
    """-> (payload, serial as int), or PingError. `public_keys` is the trust root: .pub file texts.

    Like minisign.verify, the key_id only SELECTS among the ring -- it is a hint, not a
    credential."""
    from . import minisign as pm                      # lazy: see the module docstring
    from cryptography.exceptions import InvalidSignature

    payload, serial = check_doc(doc)
    try:
        key_id = bytes.fromhex(doc["key_id"])
    except ValueError:
        raise PingError(f"key_id {doc['key_id']!r} is not hex") from None
    if len(key_id) != KEY_ID_LEN:
        raise PingError(f"key_id is {len(key_id)} bytes, expected {KEY_ID_LEN}")
    try:
        raw = base64.b64decode(doc["sig"], validate=True)
    except Exception as e:                            # noqa: BLE001 -- binascii raises its own type
        raise PingError(f"sig: not valid base64 ({e})") from None
    # This is also what refuses a .minisig envelope pasted in as a `sig`: a signature line decodes
    # to 2 + 8 + 64 bytes, and the four-line file is not base64 at all.
    if len(raw) != SIG_LEN:
        raise PingError(f"sig: {len(raw)} bytes, expected a raw {SIG_LEN}-byte Ed25519 signature")

    try:
        ring = [pm.parse_public_key(k) if isinstance(k, str) else k for k in public_keys]
    except pm.MinisignError as e:
        raise PingError(f"the trust root is unreadable: {e}") from None
    if not ring:
        raise PingError("no public keys given; a signature with no trust root proves nothing")
    candidates = [k for k in ring if k.key_id == key_id]
    if not candidates:
        raise PingError(f"signed by key {key_id.hex()}, which is not in the trust root "
                        f"({', '.join(k.key_id.hex() for k in ring)})")
    msg = message(payload, serial)
    for k in candidates:
        try:
            k.key.verify(raw, msg)
        except InvalidSignature:
            continue
        return payload, int(serial)
    raise PingError(f"the signature by key {key_id.hex()} does not cover {msg!r}")


def read_file(path):
    """-> (document, its exact bytes). notify POSTS those bytes, so it must not
    re-serialise what it read: the file a mirror receives is the file that was committed."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise PingError(f"{path}: not readable as a ping: {e}") from None
    check_doc(doc)
    return doc, raw


# --- the ledger -----------------------------------------------------------------------------------

def ledger_root(path):
    """-> the directory holding `<owner>/<name>/<tag>/`.

    Accepts either a checkout of the `sealed` branch (which carries a top-level `sealed/`) or that
    directory itself, because both are what a caller naturally has: the sealing workflow clones the
    branch, a producer fetches it into an existing checkout and points at the extracted tree."""
    if not os.path.isdir(path):
        raise PingError(f"{path}: no such directory -- fetch the `{LEDGER_DIR}` branch first")
    nested = os.path.join(path, LEDGER_DIR)
    return nested if os.path.isdir(nested) else path


def ledger_entries(root):
    """-> [(<owner>/<name>/<tag>, document)] for every sealed entry, in path order.

    Exactly three levels deep, and nothing else is looked at: the branch may carry a README at its
    root without becoming unreadable. Within a tag directory, an entry is `ping.json` plus at least
    one `*.minisig` -- the signature is named after the DOCUMENT it covers, which differs by kind
    (see SIG_SUFFIX), so the rule cannot be one filename without the ledger refusing every entry
    whose document is not a manifest. Either half missing is a PingError rather than a skip -- see
    ledger_high.

    The DOCUMENT is not required, though every seal now writes one: entries sealed before it was
    part of an answer carry only these two files, and they are perfectly good ledger lines -- the
    serial in them was spent. What the missing document costs them is only the authority's
    idempotency check, which then reads such an entry as "not sealed the way I would seal it"."""
    out = []
    for owner in sorted(_subdirs(root)):
        for name in sorted(_subdirs(os.path.join(root, owner))):
            for tag in sorted(_subdirs(os.path.join(root, owner, name))):
                rel = "/".join((owner, name, tag))
                entry = os.path.join(root, owner, name, tag)
                files = _files(entry)
                if PING_NAME not in files:
                    raise PingError(f"{rel}: no {PING_NAME} -- a sealed entry carries both it and "
                                    f"the sealed document's *{SIG_SUFFIX}, written in one commit")
                if not any(f.endswith(SIG_SUFFIX) for f in files):
                    raise PingError(f"{rel}: no *{SIG_SUFFIX} -- a sealed entry carries both "
                                    f"{PING_NAME} and the signature it was written beside")
                doc, _ = read_file(os.path.join(entry, PING_NAME))
                out.append((rel, doc))
    return out


def _subdirs(path):
    try:
        return [e.name for e in os.scandir(path) if e.is_dir() and e.name != ".git"]
    except OSError as e:
        raise PingError(f"{path}: unreadable ({e})") from None


def _files(path):
    try:
        return [e.name for e in os.scandir(path) if e.is_file()]
    except OSError as e:
        raise PingError(f"{path}: unreadable ({e})") from None


def ledger_high(path, payload):
    """-> the highest serial ever sealed for `payload`, or 0 if none ever was.

    THE SIGNING AUTHORITY READS THIS, and it is the only thing that does so to decide a number:
    the serial it assigns is `this + 1` (.github/workflows/seal.yml), so one payload line can never
    be sealed at a number it already used -- including on a rebuild of a tag that was already
    sealed, and including a number that was sealed but never published. A producer used to compute
    the same thing for itself and no longer does: it sends a document at serial 0 and is handed
    back the one it was sealed at.

    Nothing else reads it to decide anything. A person reads it (`phx ping ledger`) to see where a
    line stands; the mirror app never sees the ledger at all -- what it acts on is the signed ping.
    It must still not need `cryptography`: it runs in the authority's job BEFORE the signing wheel
    is installed, which is deliberate (a request refused at the gates installs nothing), and the
    rehearsal drives that same step with nothing installed at all.

    A malformed entry is REFUSED, never skipped, because this number is the whole counter: the one
    thing an unreadable entry could be hiding is a serial higher than the one we would otherwise
    return, and skipping it silently lowers the high-water mark. What the ledger is NOT is
    self-authenticating -- nothing here checks the ping signatures it reads (that would need the
    signer, and this must stay stdlib-only). Its integrity is a property of who may push to the
    `sealed` branch; see docs/publishing.md."""
    check_payload(payload)
    high = 0
    for rel, doc in ledger_entries(ledger_root(path)):
        if doc["payload"] != payload:
            continue
        high = max(high, int(doc["serial"]))
    return high


# --- selftest -------------------------------------------------------------------------------------

def _selftest():
    """Keys are minted here and thrown away -- a fixed test key in the repo is a private key in the
    repo (the rule minisign's selftest states)."""
    import tempfile

    from . import minisign as pm

    results = []

    def ok(name, fn):
        try:
            fn()
        except Exception as e:                        # noqa: BLE001 -- any escape is the failure
            results.append((False, name, f"{type(e).__name__}: {e}"))
        else:
            results.append((True, name, ""))

    def refused(name, fn):
        try:
            fn()
        except PingError as e:
            results.append((True, name, str(e)))
        except Exception as e:                        # noqa: BLE001
            results.append((False, name, f"raised {type(e).__name__}, not PingError: {e}"))
        else:
            results.append((False, name, "ACCEPTED -- the check does not exist"))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    pub_text, sec_text = pm.generate_keypair("phoenix ping selftest")
    other_pub, other_sec = pm.generate_keypair("phoenix ping selftest, an unrelated key")
    key_id = pm.parse_public_key(pub_text).key_id
    doc = sign("mod", 2_000_042, sec_text)

    # --- the message is the contract ---------------------------------------------------------
    ok("the signed message is exactly MAGIC/payload/serial, LF-separated",
       lambda: assert_(message("mod", 2_000_042) == b"phoenix-ping\nmod\n2000042",
                       f"message is {message('mod', 2_000_042)!r}"))
    ok("an int serial and its decimal text sign the same bytes",
       lambda: assert_(message("mod", 7) == message("mod", "7"), "int and text disagree"))

    # --- sign -> verify ------------------------------------------------------------------------
    ok("sign -> verify, and verify returns the pair that was signed",
       lambda: assert_(verify(doc, [pub_text]) == ("mod", 2_000_042), "wrong pair returned"))
    ok("the document names the signing key",
       lambda: assert_(doc["key_id"] == key_id.hex(), "key_id"))
    ok("the serial is carried as a STRING, so no JSON reader rounds it",
       lambda: assert_(doc["serial"] == "2000042" and isinstance(doc["serial"], str), "serial"))
    ok("a serial above 2**53 survives the round trip exactly",
       lambda: assert_(verify(sign("mod", 2**60 + 1, sec_text), [pub_text])[1] == 2**60 + 1,
                       "precision lost"))
    ok("a key ring: the key_id selects, order does not",
       lambda: assert_(verify(doc, [other_pub, pub_text]) == ("mod", 2_000_042), "not selected"))

    refused("a tampered payload", lambda: verify(dict(doc, payload="launcher"), [pub_text]))
    refused("a tampered serial", lambda: verify(dict(doc, serial="2000043"), [pub_text]))
    raw_sig = base64.b64decode(doc["sig"])
    refused("a tampered signature",
            lambda: verify(dict(doc, sig=base64.b64encode(
                bytes([raw_sig[0] ^ 1]) + raw_sig[1:]).decode()), [pub_text]))
    refused("a real ping by a key the trust root does not hold",
            lambda: verify(sign("mod", 2_000_042, other_sec), [pub_text]))
    refused("an empty trust root", lambda: verify(doc, []))
    refused("a ping for one payload replayed as another",
            lambda: verify(dict(sign("launcher", 2_000_042, sec_text), payload="mod"), [pub_text]))

    # --- the serial's ONE spelling --------------------------------------------------------------
    for bad in ("0", "-1", "01", "1.0", "1e3", " 7", "7 ", "+7", "2_000_042", "0x10", "seven", ""):
        refused(f"serial {bad!r} is not a plain decimal serial",
                lambda bad=bad: verify(dict(doc, serial=bad), [pub_text]))
    refused("serial 0 cannot be signed either", lambda: sign("mod", 0, sec_text))
    refused("a negative serial cannot be signed", lambda: sign("mod", -1, sec_text))
    refused("a boolean serial", lambda: sign("mod", True, sec_text))
    refused("a serial above the u64 the format carries",
            lambda: sign("mod", schema.U64_MAX + 1, sec_text))
    ok("the u64 ceiling itself is a legal serial",
       lambda: assert_(verify(sign("mod", schema.U64_MAX, sec_text), [pub_text])[1]
                       == schema.U64_MAX, "the ceiling was refused"))

    # --- the payload is a path segment, so its character set is closed --------------------------
    for bad in ("Mod", "mod-1", "mod/../x", "mod ", "", "mod2", "mód"):
        refused(f"payload {bad!r} is not [a-z]+",
                lambda bad=bad: verify(dict(doc, payload=bad), [pub_text]))

    # --- a ping is not a .minisig, and a .minisig is not a ping ---------------------------------
    minisig = pm.sign(b"a manifest", sec_text, "selftest", "phoenix mod v1.0.0")
    refused("a whole .minisig offered as a ping signature",
            lambda: verify(dict(doc, sig=base64.b64encode(minisig.encode()).decode()), [pub_text]))
    refused("a .minisig's own signature line offered as a ping signature",
            lambda: verify(dict(doc, sig=minisig.split("\n")[1]), [pub_text]))

    # --- document shape ------------------------------------------------------------------------
    refused("a ping with an extra field",
            lambda: verify(dict(doc, note="hello"), [pub_text]))
    refused("a ping missing a field",
            lambda: verify({k: v for k, v in doc.items() if k != "key_id"}, [pub_text]))
    refused("a ping whose serial is a JSON number rather than a string",
            lambda: verify(dict(doc, serial=2_000_042), [pub_text]))
    refused("a ping that is not an object at all", lambda: verify([doc], [pub_text]))
    refused("a key_id that is not hex", lambda: verify(dict(doc, key_id="zz"), [pub_text]))
    refused("a key_id of the wrong length",
            lambda: verify(dict(doc, key_id="aabb"), [pub_text]))
    refused("a sig that is not base64", lambda: verify(dict(doc, sig="@@@"), [pub_text]))

    # --- the ledger ------------------------------------------------------------------------------
    # The two document names the sealing authority writes -- see SIG_SUFFIX. The ledger must read
    # both, which is why its rule is the suffix rather than either of these strings.
    ok("every payload line but the mirror list seals a manifest",
       lambda: assert_({document_name(p) for p in ("mod", "launcher", "game", "mirrorapp")}
                       == {MANIFEST_DOCUMENT}, "a payload line seals something else"))
    ok("the mirror list seals under its own name",
       lambda: assert_(document_name(MIRRORS) == "mirrors.json", document_name(MIRRORS)))
    manifest_sig = document_name("mod") + SIG_SUFFIX
    mirrors_sig = document_name(MIRRORS) + SIG_SUFFIX

    with tempfile.TemporaryDirectory() as tmp:
        def write_entry(repo, tag, payload, serial, body=None, sig_name=manifest_sig):
            d = os.path.join(tmp, LEDGER_DIR, *repo.split("/"), tag)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, PING_NAME), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(body if body is not None
                                    else sign(payload, serial, sec_text)))
            with open(os.path.join(d, sig_name), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(minisig)
            return d

        empty = os.path.join(tmp, "empty")
        os.makedirs(os.path.join(empty, LEDGER_DIR))
        ok("an empty ledger reads 0 -- no payload has ever been sealed",
           lambda: assert_(ledger_high(empty, "mod") == 0, "not 0"))
        ok("a checkout with no sealed/ directory at all also reads 0",
           lambda: assert_(ledger_high(os.path.join(empty, LEDGER_DIR), "mod") == 0, "not 0"))
        refused("a --sealed path that does not exist",
                lambda: ledger_high(os.path.join(tmp, "nope"), "mod"))

        write_entry("Pr0j3ctPh03nix/client-dist-staging", "v1.0.0", "mod", 2_000_041)
        write_entry("Pr0j3ctPh03nix/client-dist-staging", "v1.1.0", "mod", 2_000_043)
        write_entry("Pr0j3ctPh03nix/client-dist-staging", "v1.0.1", "mod", 2_000_042)
        write_entry("Pr0j3ctPh03nix/phoenix-launcher", "v1.5.2", "launcher", 3_000_009)
        # The mirror registry seals a document that is not a manifest, so its entry's signature is
        # named mirrors.json.minisig. It is a sealed entry like any other and the ledger must read
        # it -- the number the authority counts that line from is this one.
        write_entry("Pr0j3ctPh03nix/phoenix-mirror-registry", "v2", "mirrors", 2,
                    sig_name=mirrors_sig)
        with open(os.path.join(tmp, LEDGER_DIR, "README.md"), "w", encoding="utf-8") as fh:
            fh.write("the ledger\n")

        ok("several tags: the HIGHEST serial wins, not the last one written",
           lambda: assert_(ledger_high(tmp, "mod") == 2_000_043, "wrong high-water mark"))
        ok("one payload's entries do not count towards another's",
           lambda: assert_(ledger_high(tmp, "launcher") == 3_000_009, "launcher"))
        ok("a payload nobody has sealed reads 0",
           lambda: assert_(ledger_high(tmp, "game") == 0, "game"))
        ok("an entry whose signature is named for another document (mirrors.json.minisig) reads",
           lambda: assert_(ledger_high(tmp, "mirrors") == 2, "the mirror list's own ledger line"))
        ok("a checkout ROOT and its sealed/ directory read the same",
           lambda: assert_(ledger_high(os.path.join(tmp, LEDGER_DIR), "mod")
                           == ledger_high(tmp, "mod"), "the two roots disagree"))
        ok("serials are compared as integers, not as text",
           lambda: (write_entry("Pr0j3ctPh03nix/client-dist-staging", "v2.0.0", "mod", 10_000_000),
                    assert_(ledger_high(tmp, "mod") == 10_000_000, "9 > 10 by string order")))

        write_entry("Pr0j3ctPh03nix/client-dist", "v9.9.9", "mod", 1, body={"serial": "1"})
        refused("a malformed entry is REFUSED, never skipped -- it could be hiding a higher serial",
                lambda: ledger_high(tmp, "mod"))
        half = os.path.join(tmp, LEDGER_DIR, "Pr0j3ctPh03nix", "client-dist", "v9.9.9")
        os.remove(os.path.join(half, PING_NAME))
        refused("a tag directory with a signature and no ping -- half of what a seal writes",
                lambda: ledger_high(tmp, "mod"))
        # The other half, and the case the suffix rule exists for: a directory carrying a ping and
        # NO signature at all is as incomplete as the one above, whatever the document was called.
        write_entry("Pr0j3ctPh03nix/client-dist", "v9.9.9", "mod", 1)
        os.remove(os.path.join(half, manifest_sig))
        refused("a tag directory with a ping and no signature -- the other half",
                lambda: ledger_high(tmp, "mod"))

    for good, name, detail in results:
        print(f"  {'ok  ' if good else 'FAIL'} {name}" + (f"\n         {detail}" if detail else ""))
    bad = sum(not good for good, _, _ in results)
    print(f"selftest: {len(results)} checks, all pass" if not bad
          else f"selftest: {bad} of {len(results)} checks FAILED")
    return bad


# --- CLI --------------------------------------------------------------------------------------------

def _read_text(path):
    with open(path, encoding="utf-8", newline="") as fh:   # newline="": CRLF must not be hidden
        return fh.read()


def main(argv=None):
    # newline="\n" on STDOUT, for the two things that go there: `ledger`'s bare number, which a
    # workflow captures with $(...) -- Windows text mode would leave the CR on the end of it, since
    # command substitution strips only the LF -- and `sign` without --out, whose bytes are a ping
    # document that must be the same on every platform. stderr is read by people.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(prog="phx ping", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sign", help="sign a (payload, serial) ping with the release key")
    s.add_argument("--payload", required=True, help="the payload id, e.g. mod")
    s.add_argument("--serial", required=True, help="the serial from the SEALED manifest's bytes")
    s.add_argument("--sec", help="secret key FILE (by-hand builds; prefer --key-env in CI)")
    s.add_argument("--key-env", default="PHOENIX_SIGNING_KEY",
                   help="env var holding the secret key text (default: %(default)s)")
    s.add_argument("--out", help="write the ping document here (default: stdout)")

    v = sub.add_parser("verify", help="check a ping against a trust root")
    v.add_argument("file")
    v.add_argument("--pub", required=True, action="append", metavar="PATH",
                   help="a trusted public key; repeat for a key ring")

    lg = sub.add_parser("ledger", help="the highest serial ever sealed for a payload")
    lg.add_argument("--payload", required=True)
    lg.add_argument("--sealed", required=True, metavar="PATH",
                    help="a checkout of the `sealed` branch (or its sealed/ directory)")

    sub.add_parser("selftest", help="check the ping rules and the ledger against each other")
    a = ap.parse_args(argv)

    if a.cmd == "selftest":
        sys.exit(1 if _selftest() else 0)

    try:
        if a.cmd == "sign":
            if a.sec:
                if not os.path.isfile(a.sec):
                    die(f"no such secret key file: {a.sec}")
                secret = _read_text(a.sec)
            else:
                secret = os.environ.get(a.key_env)
                if not secret:
                    die(f"{a.key_env} is not set and no --sec was given -- refusing to emit an "
                        "unsigned ping. A mirror obeys nothing it cannot verify.")
            doc = sign(a.payload, a.serial, secret)
            text = json.dumps(doc, indent=2) + "\n"
            if a.out:
                with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
                print(f"ping: {doc['payload']} serial {doc['serial']} -> {a.out}", file=sys.stderr)
            else:
                sys.stdout.write(text)
            return

        if a.cmd == "verify":
            doc, _ = read_file(a.file)
            payload, serial = verify(doc, [_read_text(p) for p in a.pub])
            print(f"ok {a.file} -- {payload} serial {serial}, signed by key {doc['key_id']}")
            return

        # `ledger`: the number ALONE on stdout, so a workflow can read it with $(...). Everything
        # else this command has to say goes to stderr.
        high = ledger_high(a.sealed, a.payload)
        print(f"ping: {a.payload} highest sealed serial {high}"
              + ("  (nothing sealed yet)" if not high else ""), file=sys.stderr)
        print(high)
    except PingError as e:
        die(str(e))


if __name__ == "__main__":
    main()
