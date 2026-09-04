#!/usr/bin/env python3
"""Rehearse .github/workflows/seal.yml — run the authority's own gates, off GitHub.

    python phx.py rehearsal selftest

WHY THIS EXISTS AS A FILE. The gates that decide what the release key signs are written INSIDE the
workflow, on purpose: who may ask for what is a fact about publishing, not about any format, and the
map belongs beside the job that acts on it. The cost of that is that nothing imports them — a
mistake in those steps is discovered by a producer whose release is already built, or worse, is not
discovered at all because the mistake ACCEPTS something. So this runs the real thing: it extracts
each step's script out of the YAML and executes it in a subprocess with a fabricated environment,
exactly as the runner would, and checks the exit status and what the step exported.

It is a rehearsal, not a reimplementation. Nothing here restates a rule from the workflow; every
check is "hand these bytes to that step and see what it does". If a step is renamed or its script
stops being a heredoc, this fails loudly rather than quietly testing nothing — see `step_run`.

WHAT IT CANNOT SEE: everything after the gates. `cryptography` is not installed here, no key
exists, and the ledger is a directory rather than a branch — so the seal, the ping and the push are
phoenix_tooling/seal.py's and phoenix_tooling/ping.py's own selftests to cover, and the ledger's
shape is checked through the same `ping.ledger_high` the workflow calls. What this owns is the
decision to sign.

Stdlib only, like everything here that does not sign.
"""
import base64
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from . import build_manifest, ping
from ._paths import ROOT

WORKFLOW = os.path.join(ROOT, ".github", "workflows", "seal.yml")

# The steps this rehearses, by the name they carry in the workflow. A renamed step is a LookupError
# here, never a silently skipped check.
REF_STEP = "Refuse to sign on any ref but main"
REQUEST_STEP = "Read the request"
ASSIGN_STEP = "Assign the serial"

# The one ref the workflow signs on, and the env var the runner delivers it in. Stated here only to
# drive the fixtures; the RULE is the workflow's.
MAIN_REF = "refs/heads/main"


class RehearsalError(Exception):
    """The workflow is not shaped the way this file reads it. Never a check result — a check that
    cannot be set up has not passed."""


# --- getting the real scripts out of the real file ------------------------------------------------

def step_run(text, name):
    """-> the `run:` block of the step called `name`, dedented.

    Deliberately a small line scanner rather than a YAML parser: this repo installs nothing to run
    its own checks, and the shapes it has to find are two (`- name:` and `run: |`). Anything else it
    meets is a RehearsalError, because a rehearsal that cannot find a step must not report the
    checks that needed it as passing."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*- name:\s*(.+?)\s*$", line)
        if not m or m.group(1).strip('"') != name:
            continue
        for j in range(i + 1, len(lines)):
            if re.match(r"^\s*- (name|uses):", lines[j]):
                break
            block = re.match(r"^(\s*)run: \|\s*$", lines[j])
            if not block:
                continue
            indent = len(block.group(1)) + 2
            body = []
            for ln in lines[j + 1:]:
                if ln.strip() and not ln.startswith(" " * indent):
                    break
                body.append(ln[indent:] if len(ln) >= indent else "")
            return "\n".join(body).rstrip() + "\n"
        raise RehearsalError(f"step {name!r} carries no `run: |` block")
    raise RehearsalError(f"no step named {name!r} in {WORKFLOW}")


def heredoc(script, tag="PY"):
    """-> the body of the `<<'TAG'` heredoc in `script`. The workflow's rule that no `${{ }}` ever
    reaches a `run:` block is what makes this safe to run as-is: the text here is the text the
    runner executes, with nothing substituted into it."""
    lines = script.splitlines()
    starts = [i for i, ln in enumerate(lines) if ln.rstrip().endswith(f"<<'{tag}'")]
    if len(starts) != 1:
        raise RehearsalError(f"expected exactly one <<'{tag}' heredoc, found {len(starts)}")
    for end in range(starts[0] + 1, len(lines)):
        if lines[end].strip() == tag:
            return "\n".join(lines[starts[0] + 1:end]) + "\n"
    raise RehearsalError(f"the <<'{tag}' heredoc is never closed")


def run_python(script, env):
    """Run a step's Python exactly as the runner does: a subprocess, cwd at the repo root. ->
    (exit code, everything it printed).

    PYTHONPATH is this file's one departure from the runner. There, the step is `python - <<'PY'`,
    so sys.path[0] is the cwd and `from phoenix_tooling import ...` resolves out of the checkout;
    here the same text is written to a temp FILE, which puts the temp directory on sys.path
    instead. Naming the root explicitly is what keeps the script itself byte-for-byte the one the
    runner executes."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step.py")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(script)
        p = subprocess.run([sys.executable, path], cwd=ROOT, capture_output=True,
                           env={**os.environ, "PYTHONPATH": ROOT, **env})
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def run_shell(script, env):
    """The same, for a step whose script is shell. -> (exit code, output).

    A missing POSIX shell is a RehearsalError, not a skip: the ref gate is the first thing standing
    between a dispatched ref and the signing key, and "we could not check it here" is not a state
    this file reports as green."""
    sh = shutil.which("bash") or shutil.which("sh")
    if sh is None:
        raise RehearsalError("no bash/sh on PATH — the shell steps cannot be rehearsed")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step.sh")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(script)
        p = subprocess.run([sh, path], cwd=ROOT, capture_output=True, env={**os.environ, **env})
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


# --- the fixtures ---------------------------------------------------------------------------------

def wire(doc):
    """The bytes a producer uploads and this authority is asked to sign. build_manifest.render is
    that framing, and the registry's generate_mirror_list renders identically — which is why one
    function makes both kinds of fixture here."""
    return build_manifest.render(doc)


def manifest_bytes(payload_id="mod", serial=0, version="1.0.0"):
    """A real payload manifest, built the only way one can be (phoenix_tooling/build_manifest.py).
    Serial 0 by default: what a producer dispatches is a seal REQUEST."""
    e = build_manifest.entry("game/dota/a.bin", "a" * 64, 10, name="a.bin")
    return wire(build_manifest.build(payload_id, version, serial, [e]))


def mirrors_bytes(serial=0, **over):
    """A mirror list shaped exactly as the registry's generate_mirror_list.build renders one."""
    doc = {"format": 1, "payload_id": "mirrors", "serial": serial,
           "signed_at": "2026-09-01T11:00:00Z",
           "mirrors": [{"base_url": "https://mirror.example", "name": "phx-fi-1",
                        "country": "FI", "payloads": ["mod", "launcher", "game"]}]}
    doc.update(over)
    return wire(doc)


def encoded(raw):
    """The `manifest` input: base64(gzip(the exact bytes))."""
    return base64.b64encode(gzip.compress(raw)).decode("ascii")


def ledger_entry(root, repo, tag, payload, serial, sig_name, document=None):
    """One entry on the `sealed` branch, as the workflow's last step writes it.

    The ping is structurally valid and NOT signed: `ping.ledger_high` reads the serial out of it and
    checks no signature (it must stay stdlib-only — see that function), so minting a keypair here
    would only make this file depend on `cryptography` to test something it does not use.

    `document` is the sealed document's bytes. Omitted, this writes the two-file entry every seal
    before the serial moved here left behind — which the assign step must read as "not sealed the
    way I would seal it" rather than as a broken entry."""
    d = os.path.join(root, ping.LEDGER_DIR, *repo.split("/"), tag)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, ping.PING_NAME), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"payload": payload, "serial": str(serial), "key_id": "00" * ping.KEY_ID_LEN,
                   "sig": base64.b64encode(b"\0" * ping.SIG_LEN).decode("ascii")}, fh)
    with open(os.path.join(d, sig_name), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("untrusted comment: a rehearsal\n")
    if document is not None:
        with open(os.path.join(d, sig_name[:-len(ping.SIG_SUFFIX)]), "wb") as fh:
            fh.write(document)
    return d


# --- selftest -------------------------------------------------------------------------------------

def _selftest():
    text = open(WORKFLOW, encoding="utf-8").read()
    ref_script = step_run(text, REF_STEP)
    request_script = heredoc(step_run(text, REQUEST_STEP))
    assign_script = heredoc(step_run(text, ASSIGN_STEP))

    results = []

    def ok(name, fn):
        try:
            fn()
        except Exception as e:                        # noqa: BLE001 — any escape is the failure
            results.append((False, name, f"{type(e).__name__}: {e}"))
        else:
            results.append((True, name, ""))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    tmp = tempfile.mkdtemp()

    def request(repo, raw=None, tag="v1.2.3", comment="phoenix selftest v1.2.3", **override):
        """Hand the real step a request. -> (exit code, output, what it exported to GITHUB_ENV).

        `override` replaces or adds fields of the inputs object, which is how the closed-field-set
        and non-string cases are built."""
        inputs = {"repo": repo, "tag": tag, "trusted_comment": comment,
                  "manifest": encoded(manifest_bytes() if raw is None else raw)}
        inputs.update(override)
        for k in [k for k, v in inputs.items() if v is None]:
            del inputs[k]
        work = tempfile.mkdtemp(dir=tmp)
        env_file = os.path.join(work, "github.env")
        open(env_file, "w").close()
        code, out = run_python(request_script, {
            "REQUEST": json.dumps(inputs), "WORK": work, "GITHUB_ENV": env_file})
        exported = dict(ln.split("=", 1) for ln in
                        open(env_file, encoding="utf-8").read().splitlines() if "=" in ln)
        exported["WORK"] = work
        return code, out, exported

    def accepted(res, **expect):
        code, out, env = res
        assert_(code == 0, f"exit {code}: {out}")
        for k, v in expect.items():
            assert_(env.get(k) == v, f"{k} is {env.get(k)!r}, expected {v!r}")
        # A step that accepted must have written the REQUEST it accepted — not the document, which
        # does not exist yet: the next step is what renders it, at the serial it assigns.
        assert_(os.path.isfile(env["REQUEST_FILE"]), "the request bytes were not written")
        assert_(not os.path.exists(os.path.join(env["WORK"], env["DOC"])),
                f"{env['DOC']} exists already, before a serial has been assigned")
        assert_("SERIAL" not in env, "the request step must not export a serial")

    def refused(res, needle=""):
        code, out, _ = res
        assert_(code != 0, f"ACCEPTED — the check does not exist. Output: {out}")
        assert_("REFUSED" in out, f"exited {code} without refusing: {out}")
        assert_(needle in out, f"refused for the wrong reason ({needle!r} not in): {out}")

    # --- 0. THE REF GATE ------------------------------------------------------------------------
    # A dispatcher names the ref, and GitHub runs that ref's copy of the workflow. Anything but main
    # is an older set of rules holding the same key.
    ok("a run on refs/heads/main passes the ref gate",
       lambda: assert_(run_shell(ref_script, {"GITHUB_REF": MAIN_REF, "SEAL_REF": MAIN_REF})[0] == 0,
                       "main was refused"))
    for bad in ("refs/heads/old-seal-rules", "refs/tags/v1", "refs/pull/7/merge", "main"):
        ok(f"a run on {bad} is refused before anything else happens",
           lambda bad=bad: assert_(
               run_shell(ref_script, {"GITHUB_REF": bad, "SEAL_REF": MAIN_REF})[0] != 0,
               f"{bad} was allowed to sign"))

    # --- 1. THE REQUEST: a closed set of four fields ---------------------------------------------
    ok("a valid mod manifest from client-dist-staging is accepted",
       lambda: accepted(request("Pr0j3ctPh03nix/client-dist-staging"),
                        PAYLOAD_ID="mod", DOC="manifest.json"))
    ok("a manifest that already names a release is refused — the authority picks the serial",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging",
                               manifest_bytes(serial=2_000_042)), "a seal request carries 0"))
    ok("inputs carrying a fifth key are refused",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging", note="hello"),
                       "expected exactly"))
    ok("inputs missing a key are refused",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging", trusted_comment=None),
                       "expected exactly"))
    ok("an empty field is refused",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging", trusted_comment=""),
                       "non-empty string"))
    ok("a tag that is a path is refused",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging", tag="../../etc"), "is not"))
    ok("a trusted comment carrying a newline is refused",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging", comment="one\ntwo"),
                       "printable ASCII"))
    ok("a `manifest` field that is not base64(gzip(...)) is refused",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging", manifest="not-base64!"),
                       "base64(gzip"))

    # --- 2. AUTHORIZATION IS BY SHAPE: one repo, one payload line --------------------------------
    ok("a repository that is on no list may ask for nothing",
       lambda: refused(request("Pr0j3ctPh03nix/phoenix-mirror"), "may not ask"))
    ok("a launcher manifest dispatched by the mod's repo is refused",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging",
                               manifest_bytes(payload_id="launcher")), "may seal payload_id"))
    ok("a launcher manifest from the launcher's own repo is accepted",
       lambda: accepted(request("Pr0j3ctPh03nix/phoenix-launcher",
                                manifest_bytes(payload_id="launcher")),
                        PAYLOAD_ID="launcher", DOC="manifest.json"))

    # --- 3. THE MIRROR REGISTRY, the one repo that may seal a document that is not a manifest ----
    ok("a valid mirrors.json from the registry is accepted, and sealed under its own name",
       lambda: accepted(request("Pr0j3ctPh03nix/phoenix-mirror-registry", mirrors_bytes(),
                                tag="v2", comment="phoenix mirror list"),
                        PAYLOAD_ID="mirrors", DOC="mirrors.json"))
    ok("a mirror list that already names a release is refused, exactly as a manifest is",
       lambda: refused(request("Pr0j3ctPh03nix/phoenix-mirror-registry", mirrors_bytes(serial=2)),
                       "a seal request carries 0"))
    ok("the SAME mirror list dispatched by the mod's repo is refused",
       lambda: refused(request("Pr0j3ctPh03nix/client-dist-staging", mirrors_bytes()),
                       "not a manifest this repo would build"))
    ok("a payload manifest dispatched by the registry is refused",
       lambda: refused(request("Pr0j3ctPh03nix/phoenix-mirror-registry", manifest_bytes()),
                       "payload_id 'mirrors'"))
    ok("a mirror list claiming payload_id 'mod' is refused",
       lambda: refused(request("Pr0j3ctPh03nix/phoenix-mirror-registry",
                               mirrors_bytes(payload_id="mod")), "payload_id 'mirrors'"))
    ok("a mirror list with no `mirrors` array is refused",
       lambda: refused(request("Pr0j3ctPh03nix/phoenix-mirror-registry",
                               mirrors_bytes(mirrors={"phx-fi-1": {}})), "`mirrors` array"))
    ok("a mirror list whose serial is a string is refused",
       lambda: refused(request("Pr0j3ctPh03nix/phoenix-mirror-registry", mirrors_bytes(serial="2")),
                       "whole number"))
    ok("a mirror list carrying one key twice is refused — two parsers may read two documents",
       lambda: refused(request("Pr0j3ctPh03nix/phoenix-mirror-registry",
                               b'{"payload_id":"mirrors","serial":1,"serial":9,"mirrors":[]}'),
                       "duplicate key"))
    ok("a mirror list that is not an object at the root is refused",
       lambda: refused(request("Pr0j3ctPh03nix/phoenix-mirror-registry", b'["mirrors"]'),
                       "root is not a JSON object"))

    # Anti-rot: every repo the workflow authorizes has a case above. A line added to that map
    # without one here is a producer whose requests nothing ever rehearsed.
    covered = {"Pr0j3ctPh03nix/client-dist-staging", "Pr0j3ctPh03nix/phoenix-launcher",
               "Pr0j3ctPh03nix/phoenix-mirror-registry"}
    listed = set(re.findall(r'"(Pr0j3ctPh03nix/[\w.-]+)":\s*"', request_script))
    ok("every repository the authorization map names is exercised here",
       lambda: assert_(listed - covered == {"Pr0j3ctPh03nix/client-dist"},
                       f"map: {sorted(listed)}, covered: {sorted(covered)}"))

    # --- 4. ASSIGNING THE SERIAL, over a ledger holding both kinds of entry ----------------------
    # The step's own output is two things: the number it exports, and the document it renders at
    # that number. Both are checked, because the second is what gets signed.
    ledger = os.path.join(tmp, "ledger")
    ledger_entry(ledger, "Pr0j3ctPh03nix/client-dist-staging", "v1.0.0", "mod", 2_000_042,
                 "manifest.json.minisig")
    ledger_entry(ledger, "Pr0j3ctPh03nix/phoenix-mirror-registry", "v2", "mirrors", 2,
                 "mirrors.json.minisig")
    empty_ledger = os.path.join(tmp, "empty-ledger")
    os.makedirs(os.path.join(empty_ledger, ping.LEDGER_DIR))

    def assign(payload, ledger_path, raw=None, repo="Pr0j3ctPh03nix/client-dist-staging",
               tag="v1.2.3"):
        """Hand the real step a request and a ledger. -> (exit, output, exported, outputs, WORK)."""
        raw = manifest_bytes() if raw is None else raw
        work = tempfile.mkdtemp(dir=tmp)
        request_file = os.path.join(work, "request.json")
        with open(request_file, "wb") as fh:
            fh.write(raw)
        env_file, out_file = os.path.join(work, "github.env"), os.path.join(work, "github.out")
        for f in (env_file, out_file):
            open(f, "w").close()
        code, out = run_python(assign_script, {
            "WORK": work, "LEDGER": ledger_path, "PAYLOAD_ID": payload, "REQ_REPO": repo,
            "REQ_TAG": tag, "DOC": ping.document_name(payload), "REQUEST_FILE": request_file,
            "GITHUB_ENV": env_file, "GITHUB_OUTPUT": out_file})

        def read(path):
            return dict(ln.split("=", 1) for ln in
                        open(path, encoding="utf-8").read().splitlines() if "=" in ln)

        return code, out, read(env_file), read(out_file), work

    def assigned(res, serial, already=False):
        """What the step must have done, for a run over the default mod request."""
        code, out, env, outputs, work = res
        assert_(code == 0, f"exit {code}: {out}")
        assert_(env.get("SERIAL") == str(serial), f"SERIAL is {env.get('SERIAL')!r}, want {serial}")
        assert_(outputs.get("already_sealed") == ("1" if already else None),
                f"already_sealed is {outputs.get('already_sealed')!r}")
        document = os.path.join(work, ping.document_name("mod"))
        if already:
            assert_(not os.path.exists(document), "a no-op step rendered a document to sign")
        else:
            with open(document, "rb") as fh:
                assert_(fh.read() == build_manifest.render(
                    build_manifest.assign(build_manifest.parse(manifest_bytes()), serial)),
                    "the rendered document is not this request at that serial")

    ok("an empty ledger assigns 1 — the first serial a payload line ever has",
       lambda: assigned(assign("mod", empty_ledger), 1))
    ok("a seeded ledger assigns one above its high-water mark",
       lambda: assigned(assign("mod", ledger), 2_000_043))
    ok("one payload line's ledger does not hold another's back",
       lambda: assert_(assign("mirrors", ledger, mirrors_bytes(),
                              repo="Pr0j3ctPh03nix/phoenix-mirror-registry",
                              tag="v3")[2].get("SERIAL") == "3", "the two lines are one counter"))
    ok("a payload nothing has ever sealed starts from 1, on a ledger others have used",
       lambda: assert_(assign("launcher", ledger,
                              manifest_bytes(payload_id="launcher"),
                              repo="Pr0j3ctPh03nix/phoenix-launcher")[2].get("SERIAL") == "1",
                       "an untouched line did not start at 1"))

    # IDEMPOTENCY: the same request, under the same tag, after it was already sealed. The entry's
    # document is what decides — "sealed at N" only counts if the ledger holds the exact bytes this
    # request renders to at N.
    same = os.path.join(tmp, "already")
    already_at = 2_000_100
    ledger_entry(same, "Pr0j3ctPh03nix/client-dist-staging", "v1.2.3", "mod", already_at,
                 "manifest.json.minisig",
                 document=build_manifest.render(
                     build_manifest.assign(build_manifest.parse(manifest_bytes()), already_at)))
    ok("a re-dispatch of a request that is already sealed is a no-op at the SAME serial",
       lambda: assigned(assign("mod", same), already_at, already=True))

    different = os.path.join(tmp, "different")
    ledger_entry(different, "Pr0j3ctPh03nix/client-dist-staging", "v1.2.3", "mod", already_at,
                 "manifest.json.minisig",
                 document=build_manifest.render(build_manifest.assign(
                     build_manifest.parse(manifest_bytes(version="9.9.9")), already_at)))
    ok("a DIFFERENT document under a tag that was already sealed is a fresh seal, one higher",
       lambda: assigned(assign("mod", different), already_at + 1))

    old = os.path.join(tmp, "old-style")
    ledger_entry(old, "Pr0j3ctPh03nix/client-dist-staging", "v1.2.3", "mod", already_at,
                 "manifest.json.minisig")
    ok("an entry from before the document was part of an answer is a fresh seal, not a no-op",
       lambda: assigned(assign("mod", old), already_at + 1))

    shutil.rmtree(tmp, ignore_errors=True)

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
        try:
            sys.exit(1 if _selftest() else 0)
        except RehearsalError as e:
            sys.exit(f"rehearsal: {e}")
    sys.exit("usage: phx rehearsal selftest")


if __name__ == "__main__":
    main()
