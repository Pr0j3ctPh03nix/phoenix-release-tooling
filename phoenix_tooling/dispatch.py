#!/usr/bin/env python3
"""The producer's half of the signing authority: ask for a seal, then fetch and PROVE the answer.

    python phx.py dispatch send  --repo Pr0j3ctPh03nix/client-dist-staging --tag v1.2.3 \\
        --document staging/manifest.json --trusted-comment "phoenix mod v1.2.3"
    python phx.py dispatch await --repo Pr0j3ctPh03nix/client-dist-staging --tag v1.2.3 \\
        --document staging/manifest.json --out staging
    python phx.py dispatch selftest

A PRODUCER KNOWS NOTHING ABOUT SERIALS. It builds a document at serial 0 -- which names no release,
because nothing anywhere accepts one at 0 -- and sends it. The authority
(.github/workflows/seal.yml) assigns the number one above its ledger, writes it into the document,
signs THOSE bytes, and commits document + signature + ping to branch `sealed`. `await` fetches all
three, prints the assigned serial as a BARE number on stdout, and publishes the document that came
back, not the one it sent. Every producer used to run the same `max(ledger, published) + 1` rule for
itself; three copies of an arithmetic whose only correct answer lives in one place is three chances
to be wrong about it.

WHAT `await` PROVES, in this order, all against THIS CHECKOUT's own keys/phoenix-active.pub -- the
same public half every client pins, and whichever reference of this repo the producer reached:

  (a) the signature covers the document's exact bytes;
  (b) the ping is signed by that same key;
  (c) the ping names the payload the document does -- neither half is usable for the other line;
  (d) THE DOCUMENT IS THIS REQUEST, at the serial the ping names: the request rendered again
      through build_manifest.assign must equal the fetched bytes, byte for byte.

(d) is the one that cannot be skipped. A tag directory is a PATH, and a re-dispatched or rebuilt tag
can leave an earlier attempt's entry sitting exactly where this run looks; (a) to (c) all pass over
it, because it was genuinely sealed by the real key. Only rebuilding the answer from the request in
hand distinguishes "sealed" from "sealed for me".

NO `gh`, ON PURPOSE. The dispatch is a plain urllib POST because the CLI cost two releases' worth of
traps: a *Windows* runner's `shell: bash` is MSYS, which rewrites an argument that looks like an
absolute Unix path, so the endpoint `/repos/...` reached gh as `C:/Program Files/Git/repos/...` and
was refused AFTER the draft release was up; and `-f manifest=...` puts a base64 blob in argv, which
a Windows command line caps at about 32,000 characters -- a document well inside GitHub's own limit
then fails to be sent at all. urllib has neither, on any runner.

STDLIB, PLUS `cryptography` FOR THE PROOF ONLY. `send` runs before anything is installed and needs
nothing; `await` verifies signatures, so it imports phoenix_tooling/minisign.py where it verifies,
never at module scope. (This module's SELFTEST needs `cryptography` outright -- it mints a throwaway
keypair and seals a fixture ledger with it, which is the only honest way to test a verifier.)
"""
import argparse
import base64
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import NoReturn

from . import build_manifest, ping
from ._paths import ROOT

# The one repository that holds the key. A producer overrides this only in a rehearsal.
AUTHORITY = "Pr0j3ctPh03nix/phoenix-release-tooling"
API = "https://api.github.com/repos/{}"
CLONE = "https://github.com/{}"
DISPATCH_PATH = "/actions/workflows/seal.yml/dispatches"

# `ref` is part of the request, and the authority refuses to sign on anything else: a dispatch names
# the ref it runs, and an older branch is an older set of the rules that guard the key.
REF = "main"

# GitHub caps a whole workflow_dispatch `inputs` object at 65,535 characters. Refused HERE, before
# the POST, because the alternative is a 422 arriving after the draft release is already up.
MAX_ENCODED = 65_535

# The branch the answer is published on. It and the directory it carries (ping.LEDGER_DIR) are both
# called `sealed`; named apart here because they are two different things that happen to agree.
LEDGER_BRANCH = "sealed"

TOKEN_ENV = "PHOENIX_TOOLING_DISPATCH"
PUB = os.path.join(ROOT, "keys", "phoenix-active.pub")
API_VERSION = "2022-11-28"
UA = "phoenix-dispatch"
NET_TIMEOUT = 30.0
WAIT = 600
INTERVAL = 10


class DispatchError(Exception):
    """Every way asking for a seal, or believing the answer, can fail. One type: a caller that told
    "the ledger has not answered yet" apart from "the answer does not verify" would eventually
    publish on the wrong one."""


def die(msg) -> NoReturn:
    sys.exit("dispatch: " + msg)


def _base(authority, template):
    """-> the URL to talk to. `--authority` is `<owner>/<name>` in every real run; a full URL is
    taken verbatim, which is what lets the selftest point both halves at a local fixture without a
    second flag that nothing else ever passes."""
    return authority.rstrip("/") if "://" in authority else template.format(authority)


# --- the request ----------------------------------------------------------------------------------

def read_request(path):
    """A document on disk -> (its exact bytes, the parsed document, its payload id).

    Both subcommands start here, and both refuse the same three things: bytes that are not one
    unambiguous document, a manifest this repo's own builder would not have produced, and a serial
    that is not 0. The middle check is the authority's own (build_manifest.validate) run early: a
    document it would refuse is better refused before a draft release exists than after. The mirror
    list has no builder to be rebuilt by -- that is what makes it a separate kind -- so it is only
    parsed, exactly as the authority parses it."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        raise DispatchError(f"{path}: {e}") from None
    try:
        doc = build_manifest.parse(raw)
    except (ValueError, TypeError) as e:
        raise DispatchError(f"{path}: not a document this repo will read: {e}") from None
    payload = doc.get("payload_id")
    if payload != ping.MIRRORS:
        try:
            build_manifest.validate(doc)
        except (ValueError, TypeError) as e:
            raise DispatchError(f"{path}: the authority would refuse this document: {e}") from None
    serial = doc.get("serial")
    if isinstance(serial, bool) or serial != 0:
        raise DispatchError(f"{path} carries serial {serial!r}, and a seal request carries 0. The "
                            "authority assigns serials from its ledger -- see docs/publishing.md.")
    return raw, doc, payload


def sealed_document(request, payload, serial):
    """The document's exact bytes as the authority seals them at `serial`.

    THE SAME THREE LINES RUN IN .github/workflows/seal.yml's `Assign the serial` step (its `sealed`
    helper); change one and change both. Duplicated rather than shared because the authority must
    not import a producer's module to decide what it signs -- and if the two ever disagree, this
    side's check (d) refuses the answer and nothing is published, which is the direction the
    duplication is allowed to fail in."""
    if payload == ping.MIRRORS:
        return build_manifest.render(dict(request, serial=int(ping.check_serial(serial))))
    return build_manifest.render(build_manifest.assign(request, serial))


def send(repo, tag, raw, trusted_comment, token, authority=AUTHORITY, dry_run=False):
    """POST the dispatch. -> (the URL, the request body's size in bytes)."""
    # mtime=0: the encoded input is then a pure function of the document, so two dispatches of one
    # request are the same string and a log can be compared with a log.
    encoded = base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii")
    if len(encoded) > MAX_ENCODED:
        raise DispatchError(
            f"the encoded document is {len(encoded)} chars and GitHub caps a whole "
            f"workflow_dispatch `inputs` object at {MAX_ENCODED}, which the other three fields "
            f"share. Nothing was sent. The document is {len(raw)} bytes; a payload this large has "
            f"to reach the authority some other way, and that is a change to both sides.")
    body = json.dumps({"ref": REF, "inputs": {
        "repo": repo, "tag": tag, "manifest": encoded,
        "trusted_comment": trusted_comment}}).encode("utf-8")
    url = _base(authority, API) + DISPATCH_PATH
    if dry_run:
        return url, len(body)

    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "Content-Type": "application/json",
        "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=NET_TIMEOUT) as r:
            # 204 is the endpoint's whole answer: the run is queued, and its name is not returned.
            # Anything else means something answered that is not this endpoint.
            if r.status != 204:
                raise DispatchError(f"{url} answered HTTP {r.status}, and the workflow-dispatch "
                                    f"endpoint answers 204. Nothing can be assumed to be queued.")
    except urllib.error.HTTPError as e:
        detail = e.read()[:400].decode("utf-8", "replace").strip()
        raise DispatchError(f"{url}: HTTP {e.code} {e.reason}\n  {detail}\n"
                            "  403/404 here is usually the token: it must be fine-grained, scoped "
                            "to the authority repo, with Actions: write.") from None
    except (urllib.error.URLError, OSError) as e:
        raise DispatchError(f"{url}: {getattr(e, 'reason', e)}") from None
    return url, len(body)


# --- the answer -----------------------------------------------------------------------------------

def _git(args, cwd=None):
    """-> (exit code, stdout as BYTES). stdout is a blob's exact content, so it is never decoded
    and never passed through a shell."""
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    return p.returncode, p.stdout


def entry_files(payload):
    """The three files one ledger entry holds, in the order the checks below want them."""
    name = ping.document_name(payload)
    return (name, name + ping.SIG_SUFFIX, ping.PING_NAME)


def fetch_entry(repo, tag, payload, authority=AUTHORITY, wait=WAIT, interval=INTERVAL,
                log=None):
    """Poll branch `sealed` until this tag's entry is there. -> {filename: bytes}.

    `git init` + `git fetch --depth 1` rather than a clone: a branch that does not exist yet is a
    legitimate state -- exactly once, before anything was ever sealed, and every time while a seal
    is still running -- and a failed fetch is then "not yet" without having to tell it apart from a
    failed clone. Blobs are read with `cat-file`, which is the only way to get a file's bytes with
    no filter, no eol conversion and no working tree to be dirty."""
    url = _base(authority, CLONE)
    names = entry_files(payload)
    path = "/".join((ping.LEDGER_DIR, repo, tag))
    work = tempfile.mkdtemp(prefix="phx-ledger-")
    code, _ = _git(["init", "--quiet", work])
    if code:
        raise DispatchError(f"cannot create a scratch repository in {work}")
    _git(["remote", "add", "origin", url], cwd=work)

    try:
        deadline = time.monotonic() + wait
        while True:
            code, _ = _git(["fetch", "--quiet", "--depth", "1", "origin", LEDGER_BRANCH], cwd=work)
            got, missing = {}, None
            if code:
                missing = f"branch `{LEDGER_BRANCH}` cannot be fetched from {url} yet"
            else:
                for name in names:
                    rc, blob = _git(["cat-file", "blob", f"FETCH_HEAD:{path}/{name}"], cwd=work)
                    if rc:
                        missing = f"{path}/{name} is not there yet"
                        break
                    got[name] = blob
            if missing is None:
                return got
            if log:
                log(missing)
            left = deadline - time.monotonic()
            if left <= 0:
                raise DispatchError(
                    f"timed out after {wait}s waiting for {path}/ on `{LEDGER_BRANCH}` "
                    f"({missing}).\n"
                    "  A refused request leaves the ledger untouched: read the seal run's log. The "
                    "draft release is still a draft, so nothing a client can see was published.")
            time.sleep(min(interval, left))
    finally:
        # The whole answer is in memory by now, and this is a scratch clone of a public branch.
        shutil.rmtree(work, ignore_errors=True)


def verify_answer(request, payload, files, public_keys):
    """-> the serial the authority assigned, or a DispatchError naming the check that failed.

    See the module docstring for what each of (a)..(d) is worth. The order matters: nothing about
    the document's CONTENT is worth asking until it is known to be signed by the key clients pin."""
    from . import minisign                              # lazy: `send` needs no signature code

    name, sig_name, ping_name = entry_files(payload)
    document = files[name]

    try:
        minisign.verify(document, files[sig_name].decode("utf-8"), public_keys)
    except (minisign.MinisignError, UnicodeDecodeError) as e:
        raise DispatchError(
            f"(a) {sig_name} does not verify over {name}: {e}\n"
            "  Either these are not the bytes that were signed, or the signing key and the public "
            "half in this checkout disagree -- in which case every client would refuse the release "
            "too, and the only symptom would be that no update ever appears.") from None

    try:
        pinged, serial = ping.verify(json.loads(files[ping_name].decode("utf-8")), public_keys)
    except (ping.PingError, ValueError, UnicodeDecodeError) as e:
        raise DispatchError(f"(b) {ping_name} is not a ping this key signed: {e}") from None

    try:
        sealed = build_manifest.parse(document)
    except (ValueError, TypeError) as e:
        raise DispatchError(f"(c) the sealed {name} is not readable: {e}") from None
    if pinged != sealed.get("payload_id"):
        raise DispatchError(f"(c) the ping announces payload {pinged!r} and the document it was "
                            f"written beside is {sealed.get('payload_id')!r}. One of them belongs "
                            f"to another release.")

    if document != sealed_document(request, payload, serial):
        raise DispatchError(
            f"(d) the sealed {name} is not this request at serial {serial}.\n"
            "  It is signed, and by the right key -- so what is in the ledger under this tag is "
            "some OTHER document: an earlier attempt at the same tag, most likely. Nothing here "
            "may be published. Dispatch again (the authority will seal the current request at a "
            "fresh serial) or take the tag that entry belongs to.")
    return serial


def write_answer(files, out_dir):
    """The three files, as fetched, into `out_dir`. Exactly the bytes that were verified: a
    re-serialisation of the document would be a file the signature does not cover."""
    os.makedirs(out_dir, exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)


# --- selftest -------------------------------------------------------------------------------------

def _fixture_server():
    """A stand-in for the dispatch endpoint: /ok answers 204 as GitHub does, /bad answers 422 as it
    does for a workflow that will not run."""
    import http.server
    import threading

    class Fixture(http.server.HTTPServer):
        seen: list

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.server.seen.append((self.path, dict(self.headers), body))
            code = 204 if self.path.startswith("/ok/") else 422
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_POST

        def log_message(self, format, *args):
            pass

    srv = Fixture(("127.0.0.1", 0), Handler)
    srv.seen = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _selftest():
    """A real git repository served over file://, and a keypair minted and thrown away.

    `await` is exercised through the REAL CLI in a subprocess, like notify's selftest: its exit
    status and its one line of stdout are the contract a release workflow reads, and an in-process
    call would prove only that the helpers here agree with each other."""
    import pathlib
    import threading

    from . import minisign

    results = []

    def ok(name, fn):
        try:
            fn()
        except Exception as e:                        # noqa: BLE001 -- any escape is the failure
            results.append((False, name, f"{type(e).__name__}: {e}"))
        else:
            results.append((True, name, ""))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    pub_text, sec_text = minisign.generate_keypair("phoenix dispatch selftest")
    other_pub, other_sec = minisign.generate_keypair("phoenix dispatch selftest, an unrelated key")

    tmp = tempfile.mkdtemp(prefix="phx-dispatch-selftest-")
    srv = _fixture_server()
    base = f"http://127.0.0.1:{srv.server_port}"
    cli = [sys.executable, os.path.join(ROOT, "phx.py"), "dispatch"]
    REPO, TAG = "Pr0j3ctPh03nix/client-dist-staging", "v1.2.3"

    def request_file(name, payload_id="mod", serial=0, version="1.0.0"):
        e = build_manifest.entry("game/dota/a.bin", "a" * 64, 10, name="a.bin")
        path = os.path.join(tmp, name)
        build_manifest.write(path, payload_id, version, serial, [e])
        return path

    def raw(path):
        with open(path, "rb") as fh:
            return fh.read()

    def ledger_repo(name):
        """A git repository whose `sealed` branch is still unborn -- what a producer's fetch loop
        meets before the first seal, and what it has to read as "not yet" rather than as an error."""
        path = os.path.join(tmp, name)
        _git(["init", "--quiet", "--initial-branch", LEDGER_BRANCH, path])
        return path

    def commit(repo_path, files, repo=REPO, tag=TAG):
        d = os.path.join(repo_path, ping.LEDGER_DIR, *repo.split("/"), tag)
        os.makedirs(d, exist_ok=True)
        for fname, data in files.items():
            with open(os.path.join(d, fname), "wb") as fh:
                fh.write(data)
        _git(["add", "-A"], cwd=repo_path)
        code, _ = _git(["-c", "user.name=selftest", "-c", "user.email=selftest@example",
                        "commit", "--quiet", "-m", f"seal: {repo} {tag}"], cwd=repo_path)
        assert_(code == 0, "the fixture ledger could not be committed")
        return repo_path

    def answer(request_path, serial, payload="mod", document=None, sign_over=None,
               ping_payload=None, sec=None):
        """The three files one seal writes. Every argument that is not None is a way for the
        answer to be genuinely signed and still not be this producer's."""
        name, sig_name, ping_name = entry_files(payload)
        doc = document if document is not None else sealed_document(
            build_manifest.parse(raw(request_path)), payload, serial)
        sig = minisign.sign(doc if sign_over is None else sign_over, sec or sec_text,
                            trusted_comment="phoenix selftest")
        pdoc = ping.sign(ping_payload or payload, serial, sec or sec_text)
        return {name: doc, sig_name: sig.encode("utf-8"),
                ping_name: (json.dumps(pdoc, indent=2) + "\n").encode("utf-8")}

    def url_of(path):
        return pathlib.Path(path).as_uri()

    def run(*args, env=None):
        p = subprocess.run([*cli, *args], capture_output=True,
                           env=None if env is None else {**os.environ, **env})
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")

    pub_path = os.path.join(tmp, "phoenix-active.pub")
    with open(pub_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(pub_text)
    other_pub_path = os.path.join(tmp, "other.pub")
    with open(other_pub_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(other_pub)

    try:
        # --- send: what it refuses before anything is sent --------------------------------------
        req = request_file("manifest.json")
        token = {TOKEN_ENV: "not-a-real-token"}

        def sent(*args, env=token, **kw):
            return run("send", "--repo", REPO, "--tag", TAG, "--document", req,
                       "--trusted-comment", "phoenix selftest v1.2.3", *args, env=env, **kw)

        before = len(srv.seen)
        named = request_file("named.json", serial=2_000_042)
        ok("a document that already names a release is refused, and nothing is sent",
           lambda: assert_(run("send", "--repo", REPO, "--tag", TAG, "--document", named,
                               "--trusted-comment", "x", "--dry-run")[0] != 0
                           and len(srv.seen) == before, "a request naming a serial was sent"))

        broken = os.path.join(tmp, "broken.json")
        with open(broken, "wb") as fh:
            fh.write(b'{"schema":3,"payload_id":"mod","serial":0}')
        ok("a document this repo's builder would not produce is refused here, not at the authority",
           lambda: assert_(run("send", "--repo", REPO, "--tag", TAG, "--document", broken,
                               "--trusted-comment", "x", "--dry-run")[0] != 0, "accepted"))
        ok("a --document that does not exist is refused",
           lambda: assert_(run("send", "--repo", REPO, "--tag", TAG,
                               "--document", os.path.join(tmp, "nope.json"),
                               "--trusted-comment", "x", "--dry-run")[0] != 0, "accepted"))

        # Enough entries that the encoded input passes GitHub's cap. Real sha256s, not a counter
        # padded with zeros: the limit is on the COMPRESSED input, and a document made of runs of
        # zeros would gzip to nothing and never reach it. The refusal has to happen HERE -- at the
        # authority it is a 422 that arrives after the draft release is already up.
        import hashlib
        big = os.path.join(tmp, "big.json")
        entries = [build_manifest.entry(
            f"game/dota/f{i:05d}.bin", hashlib.sha256(str(i).encode()).hexdigest(), 10 + i,
            name=f"f{i:05d}.bin") for i in range(3000)]
        build_manifest.write(big, "mod", "1.0.0", 0, entries)
        ok("a document too large for a dispatch is refused before the POST",
           lambda: assert_(run("send", "--repo", REPO, "--tag", TAG, "--document", big,
                               "--trusted-comment", "x", "--dry-run")[0] != 0,
                           "an oversized document was accepted"))

        # --- send: the dispatch itself ------------------------------------------------------
        code, out, err = sent("--authority", base + "/ok", "--dry-run")
        ok("--dry-run reports the body it would send, and sends nothing",
           lambda: assert_(code == 0 and "would send" in (out + err) and len(srv.seen) == before,
                           f"exit {code}: {out}{err}"))
        ok("...and it needs no token at all -- there is nothing to authenticate",
           lambda: assert_(sent("--authority", base + "/ok", "--dry-run",
                                env={TOKEN_ENV: ""})[0] == 0, "a dry run demanded a token"))

        code, out, err = sent("--authority", base + "/ok")
        ok("a 204 from the dispatch endpoint is the whole answer, and the run exits 0",
           lambda: assert_(code == 0, f"exit {code}: {out}{err}"))
        ok("...POSTed to <authority>/actions/workflows/seal.yml/dispatches, with the PAT as Bearer",
           lambda: assert_(srv.seen[-1][0] == "/ok" + DISPATCH_PATH
                           and srv.seen[-1][1].get("Authorization") == "Bearer not-a-real-token",
                           f"the fixture saw {srv.seen[-1][0]}"))

        def round_trip():
            body = json.loads(srv.seen[-1][2])
            assert_(body["ref"] == REF, f"ref is {body['ref']!r}")
            assert_(tuple(sorted(body["inputs"])) ==
                    ("manifest", "repo", "tag", "trusted_comment"), "the input set is not closed")
            back = gzip.decompress(base64.b64decode(body["inputs"]["manifest"]))
            assert_(back == raw(req), "the document did not survive base64(gzip(...))")

        ok("...carrying the document's exact bytes as base64(gzip(...)), and nothing else",
           round_trip)
        ok("a token that is not set at all is refused before the POST",
           lambda: assert_(sent("--authority", base + "/ok", env={TOKEN_ENV: ""})[0] != 0,
                           "an unauthenticated dispatch was attempted"))
        ok("anything but a 204 is a failed run",
           lambda: assert_(sent("--authority", base + "/bad")[0] != 0, "a 422 exited 0"))

        # --- await: the ledger has not answered yet -----------------------------------------
        empty = ledger_repo("empty-ledger")

        def waited(*args, document=None, out_name="out", pub=None):
            out_dir = os.path.join(tmp, out_name)
            return run("await", "--repo", REPO, "--tag", TAG,
                       "--document", document or req, "--out", out_dir,
                       "--pub", pub or pub_path, *args), out_dir

        (code, out, err), _ = waited("--authority", url_of(empty), "--timeout", "0")
        ok("a `sealed` branch that does not exist yet is waited for, then times out",
           lambda: assert_(code != 0 and "timed out" in err,
                           f"exit {code}: {out}{err}"))

        other_tag = commit(ledger_repo("other-tag"), answer(req, 7), tag="v9.9.9")
        (code, out, err), _ = waited("--authority", url_of(other_tag), "--timeout", "0")
        ok("a ledger that holds some other tag is also just 'not yet'",
           lambda: assert_(code != 0 and "timed out" in err, f"exit {code}: {out}{err}"))

        # --- await: the answer arrives ------------------------------------------------------
        good = commit(ledger_repo("good"), answer(req, 2_000_043))
        (code, out, err), out_dir = waited("--authority", url_of(good), "--timeout", "0")
        ok("a sealed entry passes every check, and stdout is the bare serial and nothing else",
           lambda: assert_(code == 0 and out.strip() == "2000043",
                           f"exit {code}, stdout {out!r}, stderr {err}"))
        ok("...and the three files are written as fetched, byte for byte",
           lambda: assert_(all(raw(os.path.join(out_dir, n)) == b
                               for n, b in answer(req, 2_000_043).items()),
                           "the answer was rewritten on the way to disk"))
        ok("...including the document, which is the request at the serial the ping names",
           lambda: assert_(raw(os.path.join(out_dir, "manifest.json"))
                           == sealed_document(build_manifest.parse(raw(req)), "mod", 2_000_043),
                           "the published document is not the sealed one"))

        # An entry that arrives WHILE the loop is waiting -- the case the whole poll exists for.
        late = ledger_repo("late")
        appears = threading.Timer(1.5, lambda: commit(late, answer(req, 5)))
        appears.start()
        try:
            (code, out, err), _ = waited("--authority", url_of(late), "--timeout", "60",
                                         "--interval", "1", out_name="out-late")
        finally:
            appears.cancel()
        ok("an entry committed while the loop is waiting is picked up by a later poll",
           lambda: assert_(code == 0 and out.strip() == "5",
                           f"exit {code}, stdout {out!r}, stderr {err}"))

        # --- await: answers that are genuinely signed and still not ours ---------------------
        forged = commit(ledger_repo("forged"), answer(req, 9, sign_over=b"some other bytes"))
        (code, out, err), _ = waited("--authority", url_of(forged), "--timeout", "0",
                                     out_name="out-forged")
        ok("a signature that does not cover the document fails check (a)",
           lambda: assert_(code != 0 and "(a)" in err, f"exit {code}: {out}{err}"))

        wrong_key = commit(ledger_repo("wrong-key"), answer(req, 9))
        (code, out, err), _ = waited("--authority", url_of(wrong_key), "--timeout", "0",
                                     pub=other_pub_path, out_name="out-wrongkey")
        ok("a signature by a key this checkout does not pin fails check (a) too",
           lambda: assert_(code != 0 and "(a)" in err, f"exit {code}: {out}{err}"))

        unsigned_ping = answer(req, 9)
        unsigned_ping[ping.PING_NAME] = (json.dumps(ping.sign("mod", 9, other_sec)) + "\n").encode()
        bad_ping = commit(ledger_repo("bad-ping"), unsigned_ping)
        (code, out, err), _ = waited("--authority", url_of(bad_ping), "--timeout", "0",
                                     out_name="out-badping")
        ok("a ping signed by another key fails check (b)",
           lambda: assert_(code != 0 and "(b)" in err, f"exit {code}: {out}{err}"))

        mismatched = commit(ledger_repo("mismatched"),
                            answer(req, 9, ping_payload="launcher"))
        (code, out, err), _ = waited("--authority", url_of(mismatched), "--timeout", "0",
                                     out_name="out-mismatched")
        ok("a ping announcing another payload line fails check (c)",
           lambda: assert_(code != 0 and "(c)" in err, f"exit {code}: {out}{err}"))

        # The case (d) exists for: a tag directory is a path, and an EARLIER attempt at this tag was
        # sealed by the real key over a real document -- just not this one.
        earlier = request_file("earlier.json", version="0.9.0")
        stale = commit(ledger_repo("stale"),
                       answer(req, 9, document=sealed_document(
                           build_manifest.parse(raw(earlier)), "mod", 9)))
        (code, out, err), _ = waited("--authority", url_of(stale), "--timeout", "0",
                                     out_name="out-stale")
        ok("an earlier attempt's document, correctly sealed under the same tag, fails check (d)",
           lambda: assert_(code != 0 and "(d)" in err, f"exit {code}: {out}{err}"))

        # ...and the same answer at a serial nobody assigned it: the ping and the document are each
        # signed, and only re-rendering the request catches that they do not agree.
        renumbered = answer(req, 9)
        renumbered[ping.PING_NAME] = (json.dumps(ping.sign("mod", 10, sec_text)) + "\n").encode()
        moved = commit(ledger_repo("renumbered"), renumbered)
        (code, out, err), _ = waited("--authority", url_of(moved), "--timeout", "0",
                                     out_name="out-renumbered")
        ok("a document sealed at one serial beside a ping naming another fails check (d)",
           lambda: assert_(code != 0 and "(d)" in err, f"exit {code}: {out}{err}"))

        # --- await: the mirror list, the kind with no builder --------------------------------
        mirrors_doc = {"format": 1, "payload_id": ping.MIRRORS, "serial": 0,
                       "mirrors": [{"base_url": "https://mirror.example", "name": "phx-fi-1",
                                    "country": "FI", "payloads": ["mod"]}]}
        mirrors_req = os.path.join(tmp, "mirrors.json")
        with open(mirrors_req, "wb") as fh:
            fh.write(build_manifest.render(mirrors_doc))
        registry = "Pr0j3ctPh03nix/phoenix-mirror-registry"
        mirrors_led = commit(ledger_repo("mirrors"),
                             answer(mirrors_req, 3, payload=ping.MIRRORS), repo=registry, tag="v3")
        code, out, err = run("await", "--repo", registry, "--tag", "v3",
                             "--document", mirrors_req, "--out", os.path.join(tmp, "out-mirrors"),
                             "--pub", pub_path, "--authority", url_of(mirrors_led), "--timeout", "0")
        ok("a mirror list is fetched and proven under its own document name",
           lambda: assert_(code == 0 and out.strip() == "3"
                           and os.path.isfile(os.path.join(tmp, "out-mirrors", "mirrors.json")),
                           f"exit {code}, stdout {out!r}, stderr {err}"))
    finally:
        srv.shutdown()
        srv.server_close()
        shutil.rmtree(tmp, ignore_errors=True)

    for good_, name, detail in results:
        print(f"  {'ok  ' if good_ else 'FAIL'} {name}" + (f"\n         {detail}" if detail else ""))
    bad = sum(not g for g, _, _ in results)
    print(f"selftest: {len(results)} checks, all pass" if not bad
          else f"selftest: {bad} of {len(results)} checks FAILED")
    return bad


# --- CLI --------------------------------------------------------------------------------------------

def _read_text(path):
    with open(path, encoding="utf-8", newline="") as fh:   # newline="": CRLF must not be hidden
        return fh.read()


def main(argv=None):
    # Everything this says goes to stderr except `await`'s last line; both streams carry a tag and a
    # repo name on a box whose default encoding is not UTF-8.
    #
    # newline="\n" on STDOUT only, and it is not cosmetic: Windows text mode writes CRLF, `$(...)`
    # strips the trailing LF and leaves the CR, and the serial a workflow captured is then a number
    # with an invisible character on the end of it. stderr is read by people, where CRLF is fine.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(prog="phx dispatch", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("send", help="ask the signing authority to seal a document")
    s.add_argument("--repo", required=True, metavar="OWNER/NAME",
                   help="the repository asking; it may seal one payload line and no other")
    s.add_argument("--tag", required=True, help="the release tag this seal is filed under")
    s.add_argument("--document", required=True, metavar="PATH",
                   help="the document to seal, carrying serial 0")
    # Required, with no default: it is SIGNED and therefore quotable, so what it says is a decision
    # about a release rather than a field this repo can fill in on a producer's behalf.
    s.add_argument("--trusted-comment", required=True,
                   help="signed and therefore quotable, e.g. 'phoenix mod v1.2.3'")
    s.add_argument("--token-env", default=TOKEN_ENV,
                   help="env var holding the dispatch PAT (default: %(default)s)")
    s.add_argument("--authority", default=AUTHORITY,
                   help="owner/name of the signing authority (default: %(default)s)")
    s.add_argument("--dry-run", action="store_true",
                   help="check the document and build the request, but send nothing")

    w = sub.add_parser("await", help="fetch this tag's seal from the ledger and prove it")
    w.add_argument("--repo", required=True, metavar="OWNER/NAME")
    w.add_argument("--tag", required=True)
    w.add_argument("--document", required=True, metavar="PATH",
                   help="the request that was sent; the answer is proven against it")
    w.add_argument("--out", required=True, metavar="DIR",
                   help="where the sealed document, its signature and the ping are written")
    w.add_argument("--authority", default=AUTHORITY)
    w.add_argument("--timeout", type=float, default=WAIT,
                   help="seconds to wait for the entry (default: %(default)s)")
    w.add_argument("--interval", type=float, default=INTERVAL,
                   help="seconds between polls (default: %(default)s)")
    w.add_argument("--pub", action="append", metavar="PATH",
                   help=f"a trusted public key; repeat for a ring (default: {PUB})")

    sub.add_parser("selftest", help="check both halves against a local ledger and a throwaway key")
    a = ap.parse_args(argv)

    if a.cmd == "selftest":
        sys.exit(1 if _selftest() else 0)

    try:
        raw, doc, payload = read_request(a.document)

        if a.cmd == "send":
            token = ""
            if not a.dry_run:
                token = os.environ.get(a.token_env) or ""
                if not token:
                    die(f"{a.token_env} is not set. The dispatch needs a fine-grained PAT scoped "
                        f"to {a.authority} with Actions: write, and nothing else.")
            url, size = send(a.repo, a.tag, raw, a.trusted_comment, token, a.authority, a.dry_run)
            print(f"dispatch: {'would send' if a.dry_run else 'sent'} {size} bytes to {url}\n"
                  f"  {a.repo} {a.tag}, payload {payload}, a seal request of {len(raw)} bytes",
                  file=sys.stderr)
            return

        if a.interval <= 0:
            die("--interval must be positive")
        pub = [_read_text(p) for p in (a.pub or [PUB])]
        print(f"dispatch: waiting for {ping.LEDGER_DIR}/{a.repo}/{a.tag}/ on {a.authority}",
              file=sys.stderr)
        files = fetch_entry(a.repo, a.tag, payload, a.authority, a.timeout, a.interval,
                            log=lambda m: print(f"  {m}", file=sys.stderr))
        serial = verify_answer(doc, payload, files, pub)
        write_answer(files, a.out)
        print(f"dispatch: {a.repo} {a.tag} is sealed at serial {serial}; "
              f"{', '.join(sorted(files))} -> {a.out}", file=sys.stderr)
        # The one line on stdout, last, and BARE: a workflow captures it whole
        # (`SERIAL=$(phx dispatch await ...)`), exactly as it captures `phx ping ledger`. A prefix
        # here would be a word every caller has to cut off again, and one of them would forget.
        print(serial)
    except (DispatchError, OSError) as e:
        die(str(e))


if __name__ == "__main__":
    main()
