#!/usr/bin/env python3
"""What serial does the next release of a payload carry? -- one more than the last PUBLISHED one.

`serial` is the sole ordering authority within a payload line (`version` is display text and is
never compared for ordering): a client keeps a per-payload high-water mark and refuses any manifest
whose serial is below it. This answers where the next number comes from, by reading the number that
is actually published rather than by counting alongside it: latest release -> its `manifest.json`
asset -> `serial` + 1. A counter that merely TRACKS what is published can lose its place -- the
`2000000 + github.run_number` this replaces resets to 2000001 the day the workflow file is renamed
-- while a number DERIVED from what is published cannot, because it holds no state to lose.

    python tools/next_serial.py --repo Pr0j3ctPh03nix/game-dist
    python tools/next_serial.py --repo Pr0j3ctPh03nix/client-dist-staging --token-env GH_TOKEN
    python tools/next_serial.py --file staging/manifest.json
    python tools/next_serial.py selftest

Stdout is the number and nothing else, so a CI step can capture it:
`SERIAL=$(python tools/next_serial.py --repo "$GITHUB_REPOSITORY")`.

THE ONE DISTINCTION THIS FILE EXISTS TO KEEP. "Nothing is published" and "I could not tell what is
published" are different answers and must never collapse into one. The first is a fact -- the
first-ever release of a new payload -- and its answer is `seed`, which must succeed or that payload
can never ship at all. The second is a network blip, a 500, a rate limit, an unparsable document, a
manifest with no `serial`: not a fact about the payload line, and its answer is a non-zero exit.
Collapse them and a run that merely failed to reach GitHub restarts numbering at the seed inside a
line already at 2000001 -- and every client that already has a release then refuses the new one.
Nothing reports an error: the update simply never appears, for everybody who already installed. The
launcher draws the same line in cmd/mod.rs between a definite answer and an unreachable source, and
for the same reason.

WHY A 404 IS NOT AN ANSWER BY ITSELF. GitHub answers a repository the caller cannot see with 404,
not 403 -- byte for byte what a visible repository with no releases answers. dist is private, so a
CI run whose token went missing would read "no releases" and mint the seed, which is precisely the
failure above. A 404 from `releases/latest` is therefore believed only after `GET /repos/<repo>`
proves the repository itself is visible; anything other than a clean 200 there raises.

"Latest" is GitHub's own notion: the newest release that is neither a draft nor a prerelease. That
suits this exactly -- dist's CI creates its release as a DRAFT and undrafts it only once every asset
is up, so the release being built right now is not something the run computing its serial can count
from.

Stdlib only (urllib, json), like manifest_schema.py and build_manifest.py: this runs in a CI shell
step before anything is installed, and `cryptography` -- the one dependency this repo's tooling has
-- lives on the signing path alone.

The token reaches api.github.com and nothing else. An asset download is answered with a 302 to
objects.githubusercontent.com, whose signed URL needs no credential and must not be handed one;
urllib copies every header onto a redirect by default, so see _DropAuthOnHostChange. It is read
from the ENVIRONMENT, never from argv, which every process on the box can read.
"""
import argparse
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"

# The asset name every payload publishes its manifest under; the reader finds the signature by
# appending .minisig to it (seal.py), so this exact name is part of the release layout, not a
# convention this tool is free to relax.
MANIFEST_ASSET = "manifest.json"

# The game's manifest is ~1.3 MB today and grows with the file count, so this is ample -- and it is
# the figure the rest of the project caps a read at. It exists because a response body is whatever
# the other end decides to send: a broken or hostile server that never stops writing would otherwise
# be read into memory until the runner dies.
READ_LIMIT = 16 << 20
TIMEOUT = 30

_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "phoenix-next-serial",
}
_DEFAULT_PORT = {"http": 80, "https": 443}


class SerialError(Exception):
    """Every way this tool can fail to produce a number, and the only exception it lets out.

    One type on purpose, and every one of them fatal: the whole point of this file is that a caller
    never gets to treat "could not tell" as "nothing published". A second, softer exception type is
    how that distinction would eventually be lost."""


class _NotFound(SerialError):
    """A 404 specifically -- still fatal unless something else proves what it means. GitHub says
    404 both for "no such release" and for "no such repository, as far as this token is concerned",
    so only _latest_release, which can ask the second question separately, may act on one."""


# --- HTTP: bounded reads, and a token that never leaves api.github.com ----------------------------

def _origin(url):
    """(scheme, host, port) -- what "the same host" means when deciding to carry a credential.

    Port and scheme are part of it: a redirect to another port is another server, and one to plain
    http is the same server listening in the clear. The default port is filled in so that
    `https://api.github.com` and `https://api.github.com:443` do not read as a host change."""
    u = urllib.parse.urlsplit(url)
    scheme = u.scheme.lower()
    return scheme, (u.hostname or "").lower(), u.port or _DEFAULT_PORT.get(scheme)


class _DropAuthOnHostChange(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never carry the Authorization header onto a different origin.

    urllib's own redirect_request copies every header except the content ones, so a token would ride
    along by default -- and the redirect that matters here leaves GitHub entirely: an asset download
    from api.github.com is answered with a 302 to objects.githubusercontent.com, whose URL is
    already signed and needs no credential. Handing our token to that host is a real leak, not a
    hypothetical one; the launcher enforces the identical rule in transport.rs.

    NOT urllib's add_unredirected_header, which is the built-in way to do this and drops the header
    on EVERY redirect, same host included: a renamed repository answers with a 301 to its new path
    ON api.github.com, and a token dropped there turns a private repo into a 404 -- "no such
    repository", the one answer this tool must never confuse with "nothing published yet"."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin(newurl) != _origin(req.full_url):
            new.headers = {k: v for k, v in new.headers.items() if k.lower() != "authorization"}
        return new


_OPENER = urllib.request.build_opener(_DropAuthOnHostChange())


def _read_capped(fp, what, limit=READ_LIMIT):
    """At most `limit` bytes, and a refusal rather than a truncation if there are more.

    Reads limit + 1 so "exactly at the cap" is still readable and one byte over is still detected;
    a Content-Length is not consulted because a body that lies about its length is exactly the case
    this defends against."""
    data = fp.read(limit + 1)
    if len(data) > limit:
        raise SerialError(f"{what}: response is larger than the {limit}-byte cap")
    return data


def _get(url, token=None, accept=None):
    """-> the response body, or SerialError/_NotFound. The token goes on the request only when the
    caller passes one; a public repository needs none, and dist needs one."""
    req = urllib.request.Request(url, headers=dict(_HEADERS))
    if accept:
        req.add_header("Accept", accept)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as resp:
            return _read_capped(resp, url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise _NotFound(f"GET {url}: HTTP 404 {e.reason}") from None
        hint = (" -- a token that cannot read this repository, or the unauthenticated rate limit "
                "(60 requests an hour)" if e.code in (401, 403, 429) else "")
        raise SerialError(f"GET {url}: HTTP {e.code} {e.reason}{hint}") from None
    except OSError as e:                    # URLError, timeouts, DNS, TLS -- all "could not tell"
        raise SerialError(f"GET {url}: {e}") from None


def _json(data, what):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise SerialError(f"{what}: not a JSON document ({e})") from None


# --- the rule ------------------------------------------------------------------------------------

def serial_of(doc):
    """The `serial` a manifest document carries, or SerialError.

    `bool` is checked before `int` because it is a subclass of it: a document carrying
    `"serial": true` would otherwise mint 2 out of a value that was never a serial at all -- the
    same trap manifest_schema.Int guards on the way out, met here on the way in. Negative is refused
    for the same reason it is there: the wire type is a u64, so a negative number came from
    arithmetic, not from a publisher counting."""
    if not isinstance(doc, dict):
        raise SerialError(f"not a manifest: the document is a {type(doc).__name__}, not an object")
    if "serial" not in doc:
        raise SerialError("the published manifest carries no `serial` -- refusing to guess where "
                          "this payload line has got to")
    value = doc["serial"]
    if isinstance(value, bool) or not isinstance(value, int):
        raise SerialError(f"`serial` is {value!r}, not a whole number")
    if value < 0:
        raise SerialError(f"`serial` is {value}, and a serial is a u64")
    return value


def _manifest_asset(release):
    """The API URL of the release's `manifest.json`, or None if it has none (a first release, or a
    release that is not a payload at all).

    The asset's own `url` -- not its `browser_download_url`: the browser URL is unauthenticated and
    simply 404s on a private repository, which dist is. This one redirects to a signed URL once the
    token has been accepted (see _DropAuthOnHostChange for what happens to the token there).

    An exact name match: `manifest.json.minisig` sits beside it in every release, and a prefix or
    suffix match would read the signature file as the document it signs."""
    if not isinstance(release, dict) or not isinstance(release.get("assets"), list):
        raise SerialError("the release document has no `assets` list -- this is not a GitHub "
                          "release object")
    for asset in release["assets"]:
        if isinstance(asset, dict) and asset.get("name") == MANIFEST_ASSET:
            url = asset.get("url")
            if not isinstance(url, str) or not url:
                raise SerialError(f"the {MANIFEST_ASSET} asset carries no download URL")
            return url
    return None


def _serial_after(release, fetch, seed):
    """The rule itself, with the network pushed out into `fetch(url) -> bytes`.

    `release` is the latest release document, or None for "the repository is visible and has no
    releases". That None is the ONLY seed path, and the "a fetch that failed is never a seed" path
    lives here too, which is exactly why both are reachable without a network: `fetch` raising
    propagates untouched.

    A latest release that carries no manifest.json does NOT seed. A release that EXISTS is not
    evidence that the payload line has not started -- it may have been published by hand, or be an
    older release from before this payload was signed, or be one whose asset upload failed halfway
    -- and seeding there restarts numbering below the ratchet every installed client already holds,
    which is the exact failure this module exists to prevent. Having no releases AT ALL is the only
    state that is a fact about the line, so it is the only one that mints a seed."""
    if release is None:
        return seed
    url = _manifest_asset(release)
    if url is None:
        raise SerialError(
            f"the latest release carries no {MANIFEST_ASSET} -- refusing to seed, because a "
            "release that exists is not evidence that this payload line has not started. Only a "
            "repository with no releases at all is that. If this really is a new line, publish the "
            "first release with an explicit serial.")
    return serial_of(_json(fetch(url), MANIFEST_ASSET)) + 1


def _repo_path(repo):
    """`owner/name`, percent-escaped a segment at a time -- so a malformed value fails here rather
    than becoming some other URL under api.github.com."""
    parts = repo.split("/")
    if len(parts) != 2 or not all(parts):
        raise SerialError(f"{repo!r} is not an owner/name repository")
    return "/".join(urllib.parse.quote(p, safe="") for p in parts)


def _latest_release(repo, token):
    """The repository's latest published release, or None when it is VISIBLE and has none.

    The None is the whole subtlety, and the docstring at the top of this file is where the reasoning
    lives: a 404 from releases/latest is not evidence of anything until `GET /repos/<repo>` has
    proved the repository can be seen at all."""
    path = _repo_path(repo)
    try:
        return _json(_get(f"{API}/repos/{path}/releases/latest", token), "the latest release")
    except _NotFound:
        pass
    try:
        _get(f"{API}/repos/{path}", token)
    except _NotFound:
        raise SerialError(
            f"{repo}: no such repository, or it is private and the token cannot see it -- GitHub "
            "answers both with 404. NOT read as 'nothing published yet': seeding a serial here "
            "would restart the payload line below the ratchet every installed client already "
            "holds, and no client would ever see the release again.") from None
    return None


def next_serial(repo, token=None, seed=1):
    """-> the serial the next release of `repo`'s payload should carry.

    `seed` for a repository that is visible and has published nothing at all; SerialError for
    everything else, including every way the question could not be answered, and including a latest
    release that carries no manifest.json. `token` is optional: a public repository needs none."""
    release = _latest_release(repo, token)
    return _serial_after(release, lambda url: _get(url, token, "application/octet-stream"), seed)


def next_serial_from_file(path):
    """serial + 1 from a manifest already on disk -- offline use, and what the selftest drives.

    No seed path: a path naming no readable manifest is a caller's mistake, never evidence that a
    payload line has not started."""
    try:
        with open(path, "rb") as fh:
            data = _read_capped(fh, path)
    except OSError as e:
        raise SerialError(f"{path}: {e.strerror or e}") from None
    return serial_of(_json(data, path)) + 1


# --- selftest ------------------------------------------------------------------------------------

def _selftest():
    """Every branch that decides between a number, a seed and a refusal -- with no network at all.

    The network is one function (`_get`), and the rule is written to take a `fetch` callable, so a
    fake one covers the paths that matter: the two seeds, and the failure that must NOT become a
    seed. The redirect rule is checked by calling redirect_request directly, which is where the
    decision is actually made -- no socket is involved in making it."""
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
        except SerialError as e:
            results.append((True, name, str(e)))
        except Exception as e:                        # noqa: BLE001
            results.append((False, name, f"raised {type(e).__name__}, not SerialError: {e}"))
        else:
            results.append((False, name, "ACCEPTED -- the check does not exist"))

    def assert_(cond, why):
        if not cond:
            raise AssertionError(why)

    import tempfile
    tmp_dir = tempfile.mkdtemp()

    def manifest_file(text):
        path = os.path.join(tmp_dir, f"manifest{len(os.listdir(tmp_dir))}.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return path

    def doc(serial):
        return manifest_file(json.dumps({"schema": 3, "payload_id": "game", "serial": serial,
                                         "version": "1805", "files": []}))

    # --- 1. a manifest on disk: the number is one more than the one published ------------------

    ok("serial + 1 from a manifest on disk",
       lambda: assert_(next_serial_from_file(doc(2000001)) == 2000002, "not serial + 1"))
    ok("a serial of 0 is a serial, not a missing one",
       lambda: assert_(next_serial_from_file(doc(0)) == 1, "0 must yield 1"))

    # --- 2. every way a document fails to answer the question -- each a refusal, never a seed --

    refused("a manifest with no `serial`",
            lambda: next_serial_from_file(manifest_file('{"payload_id": "game", "files": []}')))
    refused("a `serial` that is a string",
            lambda: next_serial_from_file(doc("2000001")))
    refused("a `serial` that is a float",
            lambda: next_serial_from_file(doc(2000001.0)))
    # JSON has a real boolean, so this is a document a server can genuinely serve; `true + 1` is 2.
    refused("a `serial` that is `true`", lambda: next_serial_from_file(doc(True)))
    refused("a negative `serial`", lambda: next_serial_from_file(doc(-1)))
    refused("a document that is a JSON array, not an object",
            lambda: next_serial_from_file(manifest_file("[2000001]")))
    refused("a document that is not JSON at all",
            lambda: next_serial_from_file(manifest_file("<html>504 Gateway Timeout</html>")))
    refused("a manifest path that does not exist",
            lambda: next_serial_from_file(os.path.join(tmp_dir, "absent.json")))

    # --- 3. the seed: published nothing yet. The fetch must not even be reached. ---------------

    def never_fetch(url):
        raise AssertionError(f"downloaded {url} -- there was nothing to download")

    ok("a repository with no releases at all yields the seed",
       lambda: assert_(_serial_after(None, never_fetch, 1) == 1, "not the seed"))
    ok("a non-default seed is what a first release gets",
       lambda: assert_(_serial_after(None, never_fetch, 2000001) == 2000001, "not the seed"))
    # A release that EXISTS but carries no manifest is NOT the seed: it may be a hand-made release,
    # or one from before this payload was signed, and seeding there restarts the line below every
    # installed client's ratchet. Only "no releases at all" is a fact about the line.
    refused("a latest release carrying no manifest.json refuses rather than seeding",
            lambda: _serial_after({"assets": [{"name": "phoenix-launcher.exe", "url": "u"}]},
                                  never_fetch, 7))
    # The signature sits beside the document in every release; a loose match would read one for the
    # other, and .minisig is not a JSON document at all. `never_fetch` is what proves the match was
    # not made: matching it would try to download, and that raises AssertionError, not SerialError.
    refused("manifest.json.minisig alone is not a manifest",
            lambda: _serial_after({"assets": [{"name": "manifest.json.minisig", "url": "u"}]},
                                  never_fetch, 7))

    # --- 4. a release that HAS a manifest: the right asset, by its API url ---------------------

    fetched = []

    def fetch(url):
        fetched.append(url)
        return json.dumps({"serial": 2000001}).encode()

    def picks_the_api_url():
        release = {"assets": [
            {"name": "pack-00.phxb", "url": f"{API}/repos/o/n/releases/assets/1"},
            {"name": MANIFEST_ASSET, "url": f"{API}/repos/o/n/releases/assets/2",
             "browser_download_url": "https://github.com/o/n/releases/download/v1/manifest.json"},
            {"name": "manifest.json.minisig", "url": f"{API}/repos/o/n/releases/assets/3"}]}
        assert_(_serial_after(release, fetch, 1) == 2000002, "not serial + 1")
        # The API url, never browser_download_url: the latter 404s on a private repository.
        assert_(fetched == [f"{API}/repos/o/n/releases/assets/2"], f"fetched {fetched}")

    ok("the manifest.json asset is picked out by name and fetched by its API url",
       picks_the_api_url)

    # --- 5. THE case: a fetch that failed is not "nothing published" ---------------------------

    def fetch_fails(url):
        raise SerialError("GET {}: HTTP 500 Internal Server Error".format(url))

    refused("a manifest.json that will not download -- must NEVER become the seed",
            lambda: _serial_after({"assets": [{"name": MANIFEST_ASSET, "url": "u"}]},
                                  fetch_fails, 1))
    refused("a release document that is not a release object",
            lambda: _serial_after({"message": "Not Found"}, never_fetch, 1))

    # --- 6. a malformed --repo never becomes some other URL ------------------------------------

    refused("a repo that is not owner/name", lambda: _repo_path("game-dist"))
    refused("a repo with an extra path segment", lambda: _repo_path("Pr0j3ctPh03nix/game-dist/x"))
    refused("a repo with an empty half", lambda: _repo_path("/game-dist"))
    ok("owner/name is escaped a segment at a time",
       lambda: assert_(_repo_path("Pr0j3ctPh03nix/game dist") == "Pr0j3ctPh03nix/game%20dist",
                       "not escaped per segment"))

    # --- 7. bounded reads ----------------------------------------------------------------------

    ok("a body exactly at the cap is read whole",
       lambda: assert_(_read_capped(io.BytesIO(b"abcd"), "x", limit=4) == b"abcd", "truncated"))
    refused("a body one byte over the cap",
            lambda: _read_capped(io.BytesIO(b"abcde"), "x", limit=4))
    ok("the shipped cap is 16 MiB", lambda: assert_(READ_LIMIT == 16 * 1024 * 1024, "not 16 MiB"))

    # --- 8. the token goes to api.github.com and nowhere else ----------------------------------

    def redirected(from_url, to_url):
        """The Request urllib would follow a 302 with -- the exact object whose headers go out."""
        import email.message
        req = urllib.request.Request(from_url, headers={"Authorization": "Bearer s3cret",
                                                        "Accept": "application/octet-stream"})
        new = _DropAuthOnHostChange().redirect_request(
            req, io.BytesIO(b""), 302, "Found", email.message.Message(), to_url)
        assert_(new is not None, "the redirect was not followed at all")
        return {k.lower(): v for k, v in new.headers.items()}

    asset = f"{API}/repos/o/n/releases/assets/2"
    ok("the token is dropped on the 302 to the asset host",
       lambda: assert_("authorization" not in redirected(
           asset, "https://objects.githubusercontent.com/github-production-release-asset/x?sig=y"),
           "the token followed the redirect off api.github.com"))
    ok("everything else survives that redirect",
       lambda: assert_(redirected(asset, "https://objects.githubusercontent.com/x").get("accept")
                       == "application/octet-stream", "an unrelated header was dropped too"))
    # A renamed repository 301s to its new path on the SAME host. Dropping the token there would
    # turn a private repo into a 404, which this tool reports as "no such repository" -- a failure
    # invented by the fix rather than by the server.
    ok("the token survives a same-host redirect",
       lambda: assert_("authorization" in redirected(asset, f"{API}/repos/o/renamed/releases/latest"),
                       "the token was dropped on a redirect that never left the host"))
    ok("a redirect to another port is another host",
       lambda: assert_("authorization" not in redirected("https://h:1/a", "https://h:2/a"),
                       "a port change carried the token"))
    ok("a redirect to plain http is another host",
       lambda: assert_("authorization" not in redirected("https://h/a", "http://h/a"),
                       "a downgrade to http carried the token"))
    ok("an explicit :443 is not a host change",
       lambda: assert_("authorization" in redirected("https://h/a", "https://h:443/b"),
                       "the default port read as a different host"))

    for good, name, detail in results:
        print(f"  {'ok  ' if good else 'FAIL'} {name}" + (f"\n         {detail}" if detail else ""))
    bad = sum(not good for good, _, _ in results)
    print(f"selftest: {len(results)} checks, all pass" if not bad
          else f"selftest: {bad} of {len(results)} checks FAILED")
    return bad


# --- CLI -------------------------------------------------------------------------------------------

def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) == 2 and sys.argv[1] == "selftest":
        sys.exit(1 if _selftest() else 0)

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo", metavar="OWNER/NAME",
                     help="the payload's repository; its latest release is read")
    src.add_argument("--file", metavar="PATH",
                     help="read a published manifest from disk instead of the network (offline)")
    ap.add_argument("--token-env", default="GITHUB_TOKEN", metavar="VAR",
                    help="env var holding the API token (default: %(default)s); unset means an "
                         "unauthenticated request, which is all a public repo needs. The token "
                         "itself is never an argument: argv is readable by every process here.")
    ap.add_argument("--seed", type=int, default=1,
                    help="the serial a payload's FIRST release gets, when nothing is published yet "
                         "(default: %(default)s)")
    a = ap.parse_args()

    try:
        if a.seed < 0:
            raise SerialError(f"--seed {a.seed}: a serial is a u64")
        value = (next_serial_from_file(a.file) if a.file
                 else next_serial(a.repo, os.environ.get(a.token_env) or None, a.seed))
    except SerialError as e:
        sys.exit(f"next_serial: {e}")
    print(value)


if __name__ == "__main__":
    main()
