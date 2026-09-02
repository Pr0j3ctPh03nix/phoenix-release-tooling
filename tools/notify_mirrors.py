#!/usr/bin/env python3
"""Ping every published mirror so it syncs the release that was just published.

    python tools/notify_mirrors.py notify                       # the published registry list
    python tools/notify_mirrors.py notify --list mirrors.json --strict
    python tools/notify_mirrors.py selftest

ONE copy, because there are three producers and a mirror must not hear about a release three
different ways: the mod in dist's CI, the launcher in its own, the base game by hand. Each already
checks this repo out at a pinned commit SHA to seal with, so the ping arrives by the same pin as the
seal — and the one thing every producer does after publishing is written once, here.

Mirrors pull from GitHub on a timer; this only says "now". `<base_url>/sync` is unauthenticated and
rate-limited on the mirror's side, so nothing here carries a credential and a mirror is free to
ignore it. The list of mirrors is the registry's latest release asset `mirrors.json`
(Pr0j3ctPh03nix/phoenix-mirror-registry — public, hence no token), whose format is that repo's
generate_mirror_list.py.

THE EXIT STATUS IS THE CONTRACT, and it is the reason this is a script rather than a curl loop in
each of the three workflows:

  0          the list was obtained and every mirror was attempted — however many refused, failed or
             were unreachable. The release is already published by the time this runs, so a mirror
             being down must never turn a shipped release into a red run: nobody can fix it from
             here, and a red run beside a green release is a light everyone learns to ignore.
  non-zero   the list itself could not be fetched or parsed, or an argument was bad. That is a fact
             about this repo's tooling — no mirror was pinged at all — and it is worth waking up to.
  --strict   also non-zero if any mirror failed. For the by-hand game release, where a person is
             watching and can retry a single host.

THE LIST IS NOT VERIFIED, deliberately, though it ships with a `.minisig` beside it. Every other
document this project reads is signed because obeying it grants something: a manifest names bytes to
install, the mirror list names hosts to download releases from. A ping grants nothing — the worst a
forged entry buys is an unauthenticated POST that the forger could have sent themselves. What IS
enforced is that the entry is an HTTP URL at all: a `base_url` whose scheme is not http:// or
https:// is refused WITHOUT a request, and a redirect is never followed. So no line in a downloaded
document can make a release runner open anything but an HTTP request to the host it named.

Stdlib only, like everything here that is not the signer: this runs in release CI right after the
sealed release is published, and a `pip install` is an input that pipeline does not need.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import namedtuple
from typing import NoReturn

REGISTRY = "Pr0j3ctPh03nix/phoenix-mirror-registry"
LATEST = "https://api.github.com/repos/{}/releases/latest"
LIST_ASSET = "mirrors.json"

# The mirror's sync endpoint, appended to a registered `base_url`. Part of the mirror app's
# contract, not a local naming choice.
SYNC_PATH = "/sync"

# The only two schemes a list entry may name. See the header: this is the one rule that keeps a
# published document from choosing what a key-holding runner connects to.
SCHEMES = ("http", "https")

UA = "phoenix-notify-mirrors"
TIMEOUT = 10.0
BACKOFF = 1.0                 # seconds, times the attempt number: 1s, 2s, ...

Result = namedtuple("Result", "name url ok detail")


class NotifyError(Exception):
    """The list could not be obtained or is not a mirror list. The ONLY failure that is this
    script's own — everything a mirror does is a reported result, never an exception."""


def die(msg) -> NoReturn:
    sys.exit("notify-mirrors: " + msg)


# --- the list -------------------------------------------------------------------------------------

def _get(url, timeout, token=None):
    """One GET, or a NotifyError naming the URL. Nothing here retries: a registry that cannot be
    read is reported, not worked around, because the run is over either way."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except (urllib.error.URLError, OSError) as e:      # URLError is an OSError; HTTPError is both
        raise NotifyError("cannot read {}: {}".format(url, e)) from None


def fetch_list(registry, timeout, token=None):
    """The mirror list from `registry`'s latest release."""
    api = LATEST.format(registry)
    try:
        release = json.loads(_get(api, timeout, token))
    except ValueError as e:
        raise NotifyError("{} did not answer with JSON: {}".format(api, e)) from None
    assets = release.get("assets") if isinstance(release, dict) else None
    url = next((a.get("browser_download_url") for a in assets or []
                if isinstance(a, dict) and a.get("name") == LIST_ASSET), None)
    if not url:
        raise NotifyError(
            "the latest release of {} carries no {}\n"
            "  Its publish workflow uploads that asset; a release without one is a publish that "
            "did not finish.".format(registry, LIST_ASSET))
    # NO Authorization on this one, even when the caller supplied a token: browser_download_url
    # redirects to a storage host whose signed URL carries its own credentials, and a second
    # mechanism arriving in a header is refused there. The registry is public, so none is needed.
    try:
        return json.loads(_get(url, timeout))
    except ValueError as e:
        raise NotifyError("{} is not JSON: {}".format(url, e)) from None


def load_list(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        raise NotifyError("{}: not readable as a mirror list: {}".format(path, e)) from None


def mirror_entries(doc):
    """-> [(name, base_url)] in the document's own order, which the registry has already sorted.

    A document that is not shaped like a mirror list is a NotifyError — "I could not read the list"
    — while an entry that merely names something unpingable is a reported failure below. The two
    must not collapse: the first means no mirror was reached, the second means one was skipped.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("mirrors"), list):
        raise NotifyError("not a mirror list: no `mirrors` array")
    out = []
    for i, e in enumerate(doc["mirrors"]):
        if not isinstance(e, dict) or not isinstance(e.get("base_url"), str):
            raise NotifyError("mirrors[{}] carries no string base_url".format(i))
        name = e.get("name")
        out.append((name if isinstance(name, str) and name else e["base_url"], e["base_url"]))
    return out


# --- the ping -------------------------------------------------------------------------------------

def sync_url(base_url):
    """`<base_url>/sync`, or None if base_url is not an http(s) URL.

    The trailing slash is stripped for the same reason the registry refuses one: the launcher's
    canonical form has none, and `//sync` is a different path on plenty of servers."""
    url = base_url.strip()
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in SCHEMES or not parts.netloc:
        return None
    return url.rstrip("/") + SYNC_PATH


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow a redirect: returning None makes urllib raise the 3xx as an HTTPError.

    Following one would hand the choice of what to connect to back to the mirror — urllib carries
    headers across hosts, downgrades the POST to a GET, and its default opener will happily follow
    a redirect to ftp://. That is exactly the scheme rule above, undone one hop later."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def ping(url, retries, timeout, opener):
    """POST it. -> (ok, detail). Retries connection failures and 5xx, nothing else.

    ANY 2xx is success and urllib enforces that by itself: urlopen returns only for 200..299 and
    raises HTTPError for everything else. A 4xx is the mirror's considered answer — retrying it
    would just be the same answer, three times."""
    req = urllib.request.Request(url, data=b"", method="POST", headers={"User-Agent": UA})
    detail = ""
    for attempt in range(1, retries + 1):
        try:
            with opener.open(req, timeout=timeout) as r:
                return True, "HTTP {}".format(r.status)
        except urllib.error.HTTPError as e:
            detail, retryable = "HTTP {}".format(e.code), e.code >= 500
        except (urllib.error.URLError, OSError) as e:
            detail, retryable = str(getattr(e, "reason", e)), True
        if not retryable or attempt == retries:
            break
        time.sleep(BACKOFF * attempt)
    return False, detail


def notify(entries, retries, timeout):
    """Every mirror, in order, whatever the last one did. -> [Result]."""
    opener = urllib.request.build_opener(_NoRedirect)
    results = []
    for name, base_url in entries:
        url = sync_url(base_url)
        if url is None:
            results.append(Result(name, base_url, False, "refused: not an http(s) URL"))
            continue
        ok, detail = ping(url, retries, timeout, opener)
        results.append(Result(name, url, ok, detail))
    return results


def report(results):
    """One line per mirror, then the count. -> failures.

    All of it on stderr: the exit status is what a workflow reads, and the log is for the person who
    comes looking after one."""
    for r in results:
        print("  {} {:<16} {}  {}".format("ok  " if r.ok else "FAIL", r.name, r.url, r.detail),
              file=sys.stderr)
    bad = sum(not r.ok for r in results)
    if not results:
        print("notify-mirrors: no mirrors published — nothing to ping", file=sys.stderr)
    elif bad:
        print("notify-mirrors: {} mirror(s), {} pinged, {} FAILED — the release is published "
              "either way".format(len(results), len(results) - bad, bad), file=sys.stderr)
    else:
        print("notify-mirrors: {} mirror(s), all pinged".format(len(results)), file=sys.stderr)
    return bad


# --- selftest ---------------------------------------------------------------------------------------

def _fixture_server():
    """A stand-in for the mirror app: one server playing several mirrors, one per path prefix, so a
    single list can hold a good one, a flaky one and a broken one at once."""
    import http.server
    import threading

    class Fixture(http.server.HTTPServer):
        seen: list
        flaky: int

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.server.seen.append(self.path)
            if self.path == "/ok/sync":
                code = 202
            elif self.path == "/flaky/sync":
                # 500 once, then 202: the retry is what makes this mirror succeed.
                self.server.flaky += 1
                code = 500 if self.server.flaky == 1 else 202
            else:
                code = 404
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # Recorded too, so `seen` catches anything that arrives as something other than the POST it
        # was supposed to be.
        do_GET = do_POST

        def log_message(self, format, *args):
            pass

    srv = Fixture(("127.0.0.1", 0), Handler)     # 127.0.0.1: no firewall prompt
    srv.seen, srv.flaky = [], 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _closed_port():
    """A port nothing listens on. Bind-then-close rather than a guessed number: the OS names one it
    is not currently handing out, and the window before something else takes it is not a risk worth
    a fixed port that may well be in use."""
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _selftest():
    """The exit status is the contract, so every check runs the REAL CLI in a subprocess and reads
    its exit code — an in-process call would prove the helpers agree with each other and say nothing
    about what a workflow sees."""
    import subprocess
    import tempfile

    results = []

    def ok(name, fn):
        try:
            fn()
        except Exception as e:                      # noqa: BLE001 — any escape is the failure
            results.append((False, name, "{}: {}".format(type(e).__name__, e)))
        else:
            results.append((True, name, ""))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    srv = _fixture_server()
    base = "http://127.0.0.1:{}".format(srv.server_port)
    dead = "http://127.0.0.1:{}".format(_closed_port())
    me = os.path.abspath(__file__)

    try:
        with tempfile.TemporaryDirectory() as tmp:
            def write_list(fname, mirrors, doc=None):
                path = os.path.join(tmp, fname)
                body = doc if doc is not None else {
                    "format": 1, "payload_id": "mirrors", "serial": 7,
                    "mirrors": [{"base_url": u, "name": n, "country": "FI", "payloads": ["mod"]}
                                for n, u in mirrors]}
                with open(path, "w", encoding="utf-8", newline="\n") as fh:
                    json.dump(body, fh)
                return path

            def run(path, *extra):
                """-> (exit code, everything it printed)."""
                p = subprocess.run([sys.executable, me, "notify", "--list", path, *extra],
                                   capture_output=True)
                return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")

            def lines(out):
                return [ln for ln in out.splitlines()
                        if ln.startswith("  ok  ") or ln.startswith("  FAIL")]

            good = write_list("good.json", [("phx-ok", base + "/ok")])
            code, out = run(good)
            ok("a mirror answering 202 is a success, and the run exits 0",
               lambda: assert_(code == 0 and len(lines(out)) == 1 and lines(out)[0].startswith("  ok"),
                               "exit {}, out: {}".format(code, out)))
            ok("...and it arrived as a POST to <base_url>/sync",
               lambda: assert_(srv.seen == ["/ok/sync"], "the fixture saw {}".format(srv.seen)))

            flaky = write_list("flaky.json", [("phx-flaky", base + "/flaky")])
            ok("a 500 is retried, and the retry's 202 counts as a ping",
               lambda: assert_(run(flaky, "--retries", "3")[0] == 0, "the retry never happened"))
            ok("...and it took exactly the two attempts the fixture scripted",
               lambda: assert_(srv.seen.count("/flaky/sync") == 2,
                               "attempts: {}".format(srv.seen.count("/flaky/sync"))))

            missing = write_list("missing.json", [("phx-404", base + "/nope")])
            ok("a 404 is a reported failure, not a failed run",
               lambda: assert_(run(missing)[0] == 0, "a 404 failed the run"))
            ok("a 404 is not retried — it is the mirror's answer",
               lambda: assert_(srv.seen.count("/nope/sync") == 1,
                               "attempts: {}".format(srv.seen.count("/nope/sync"))))

            down = write_list("down.json", [("phx-down", dead)])
            ok("a mirror that is not listening is a reported failure, not a failed run",
               lambda: assert_(run(down, "--retries", "1")[0] == 0, "an unreachable host failed the run"))
            ok("--strict turns a failed mirror into a failed run",
               lambda: assert_(run(down, "--retries", "1", "--strict")[0] != 0, "--strict exited 0"))

            ftp = write_list("ftp.json", [("phx-ftp", "ftp://127.0.0.1:{}/ftp"
                                           .format(srv.server_port))])
            code, out = run(ftp)
            ok("an ftp:// entry is refused, and refused counts as a failed mirror",
               lambda: assert_(code == 0 and "FAIL" in out, "exit {}, out: {}".format(code, out)))
            ok("...without a request ever being made",
               lambda: assert_(not any(p.startswith("/ftp") for p in srv.seen),
                               "the fixture saw {}".format(srv.seen)))
            ok("a refused entry fails a --strict run",
               lambda: assert_(run(ftp, "--strict")[0] != 0, "--strict exited 0"))

            mixed = write_list("mixed.json", [("phx-404", base + "/nope"), ("phx-down", dead),
                                              ("phx-last", base + "/ok")])
            code, out = run(mixed, "--retries", "1")
            ok("every mirror is attempted, however the ones before it went",
               lambda: assert_(code == 0 and len(lines(out)) == 3,
                               "exit {}, {} report line(s)".format(code, len(lines(out)))))
            ok("...including the last one, after two failures",
               lambda: assert_(srv.seen.count("/ok/sync") >= 2, "the last mirror was never pinged"))

            empty = write_list("empty.json", [])
            code, out = run(empty)
            ok("an empty list is a success that says so",
               lambda: assert_(code == 0 and "no mirrors published" in out,
                               "exit {}, out: {}".format(code, out)))

            not_a_list = write_list("bogus.json", None, doc={"format": 1, "serial": 7})
            ok("a document that is not a mirror list fails the run even without --strict",
               lambda: assert_(run(not_a_list)[0] != 0, "a listless document exited 0"))
            broken = os.path.join(tmp, "broken.json")
            with open(broken, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            ok("a list that is not JSON fails the run",
               lambda: assert_(run(broken)[0] != 0, "unparseable JSON exited 0"))
            ok("a --list that does not exist fails the run",
               lambda: assert_(run(os.path.join(tmp, "no-such.json"))[0] != 0,
                               "a missing list exited 0"))

            ok("--retries 0 is a bad argument, not a mirror nobody pinged",
               lambda: assert_(run(good, "--retries", "0")[0] != 0, "--retries 0 was accepted"))
            ok("--list and --registry name two sources and are refused together",
               lambda: assert_(subprocess.run(
                   [sys.executable, me, "notify", "--list", good, "--registry", "a/b"],
                   capture_output=True).returncode != 0, "two sources were accepted"))
    finally:
        srv.shutdown()
        srv.server_close()

    for good_, name, detail in results:
        print("  {} {}".format("ok  " if good_ else "FAIL", name)
              + ("\n         " + detail if detail else ""))
    bad = sum(not g for g, _, _ in results)
    print("selftest: {} checks, all pass".format(len(results)) if not bad
          else "selftest: {} of {} checks FAILED".format(bad, len(results)))
    return bad


# --- CLI ------------------------------------------------------------------------------------------

def main():
    # BOTH streams: the report goes to stderr and carries names and URLs out of a document this
    # repo did not write, on a box whose default encoding is not UTF-8.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("notify", help="ping every published mirror")
    src = n.add_mutually_exclusive_group()
    src.add_argument("--registry", default=REGISTRY,
                     help="owner/name whose latest release carries {} (default: %(default)s)"
                          .format(LIST_ASSET))
    src.add_argument("--list", dest="list_path", metavar="PATH",
                     help="read the list from a local file instead of the registry")
    n.add_argument("--retries", type=int, default=3,
                   help="attempts per mirror, the first included (default: %(default)s)")
    n.add_argument("--timeout", type=float, default=TIMEOUT,
                   help="seconds per request (default: %(default)s)")
    n.add_argument("--strict", action="store_true",
                   help="exit non-zero if any mirror failed; for by-hand releases")
    n.add_argument("--token-env", default="GITHUB_TOKEN",
                   help="env var holding a GitHub token, used ONLY to read the registry's release "
                        "and only if set — the registry is public, so it buys nothing but the "
                        "authenticated rate limit (default: %(default)s)")

    sub.add_parser("selftest", help="check the exit-status contract against a local fixture")
    a = ap.parse_args()

    if a.cmd == "selftest":
        sys.exit(1 if _selftest() else 0)

    if a.retries < 1:
        die("--retries must be at least 1 — a mirror nobody attempts is one nobody reports on")
    if a.timeout <= 0:
        die("--timeout must be positive")

    try:
        doc = load_list(a.list_path) if a.list_path else fetch_list(
            a.registry, a.timeout, os.environ.get(a.token_env))
        entries = mirror_entries(doc)
    except NotifyError as e:
        # The one non-zero exit that is not about a mirror: nothing was pinged, and that is this
        # repo's problem rather than a host's.
        die(str(e))

    print("notify-mirrors: {} — serial {}, {} mirror(s)".format(
        a.list_path or a.registry, doc.get("serial", "?"), len(entries)), file=sys.stderr)
    bad = report(notify(entries, a.retries, a.timeout))
    sys.exit(1 if bad and a.strict else 0)


if __name__ == "__main__":
    main()
