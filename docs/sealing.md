# Sealing a payload — what a producer does now that the key lives here

The release signing key has left every producer repository. A producer builds and publishes; **this**
repository signs. Nobody holds a token for anybody else's repository, and the only credential that
crosses a boundary is a PAT that can ask for a signature and nothing else.

This document is the **producer-facing contract**. The workflow that implements it is
[`.github/workflows/seal.yml`](../.github/workflows/seal.yml) — read it for what the authority
checks and why; it is not restated here.

```
producer CI                         phoenix-release-tooling             branch `sealed`
───────────                         ───────────────────────             ───────────────
build → attest → upload DRAFT
pick a serial  ─────────────────────────────────────────────────────────► read (ledger)
dispatch {repo, tag, manifest} ───► ref · authorize · validate · ratchet
                                    seal.py + ping.py sign ────────────► commit + push
wait for the entry ◄────────────────────────────────────────────────────  read
verify locally → upload sidecar → undraft → notify mirrors
```

Three kinds of producer use it: the **mod** (from `client-dist-staging`, and from `client-dist` when
the public line goes live), the **launcher**, and the **mirror registry** — whose document is not a
manifest, and has its own section below. The **base game** does not: it is sealed by hand, offline
(see the last section).

## The request

`POST /repos/Pr0j3ctPh03nix/phoenix-release-tooling/actions/workflows/seal.yml/dispatches`, with a
fine-grained PAT:

```json
{"ref": "main",
 "inputs": {"repo": "Pr0j3ctPh03nix/client-dist-staging",
            "tag": "v1.2.3",
            "manifest": "<base64(gzip(the exact document bytes))>",
            "trusted_comment": "phoenix mod v1.2.3"}}
```

`ref` must be **`main`**. A workflow dispatch names the ref it runs and GitHub runs that ref's copy
of the workflow, so the workflow refuses to sign anywhere else: an older branch is an older, weaker
set of these rules holding the same key.

Exactly those four inputs, each a non-empty string. GitHub caps a whole `inputs` object at **65,535
characters** (and 25 top-level properties), which is what the gzip is for. `repo` must be the
repository that is asking; `tag` is `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. The input is called
`manifest` whatever kind of document it carries, for the same reason `seal.py`'s flag is: what gets
signed is a file's exact bytes.

**Send the body from a file.**

```sh
python - <<'PY' > "$RUNNER_TEMP/request.json"
import base64, gzip, json
raw = open("staging/manifest.json", "rb").read()
print(json.dumps({"ref": "main", "inputs": {
    "repo": "Pr0j3ctPh03nix/client-dist-staging", "tag": "v1.2.3",
    "manifest": base64.b64encode(gzip.compress(raw)).decode(),
    "trusted_comment": "phoenix mod v1.2.3"}}))
PY
gh api --method POST \
  repos/Pr0j3ctPh03nix/phoenix-release-tooling/actions/workflows/seal.yml/dispatches \
  --input "$RUNNER_TEMP/request.json"
```

**No leading slash on the endpoint.** Two of the three producers run this step under `shell: bash`
on a *Windows* runner, where bash is MSYS and rewrites any argument that looks like an absolute Unix
path into a Windows one: `/repos/…` reaches gh as `C:/Program Files/Git/repos/…`, which is refused
as an invalid endpoint — after the draft release is already up. gh accepts the path without the
slash on every platform, so write it that way rather than remembering which runner this is.

Never `gh api -f manifest=...`: that puts the whole base64 blob in the process's argv, and a Windows
runner's command line is capped at about 32,000 characters — a document well inside GitHub's own
limit then fails to be sent at all, with an error about the command line rather than about the
release.

The `manifest` is the **exact bytes** that are already uploaded to the draft release — the signature
covers bytes, so a re-serialisation on either side is a signature over a file nobody has. The
**serial is read from those bytes**, never from the request.

Which repository may seal which payload line is a fixed map in the workflow. A request naming a line
its repository is not listed for is refused; so is a manifest this repo's own builder would not have
produced (`python phx.py manifest validate <manifest.json>` asks the same question locally,
before dispatching).

## The answer

Branch **`sealed`**, world-readable, one commit per seal:

```
sealed/<owner>/<name>/<tag>/<document>.minisig
sealed/<owner>/<name>/<tag>/ping.json
```

`<document>` is the file that was sealed: `manifest.json` for a payload manifest, `mirrors.json` for
the mirror list. A signature in the ledger is therefore never separable from what it covers.

That branch is also the **ledger**: it is what the serial ratchet reads, and what a producer reads
to pick its next serial.

## What payload CI must do

**1. Build, attest, and upload the release as a DRAFT** — including `manifest.json` itself. Nothing
downstream is reachable by a client until the release is undrafted, which is the property that makes
waiting for a signature safe.

**2. Pick the serial:**

```
serial = max(highest sealed serial for this payload, serial in the latest published release) + 1
```

```sh
git -C .tooling fetch --quiet origin sealed
git -C .tooling worktree add --quiet "$RUNNER_TEMP/ledger" FETCH_HEAD     # or: git clone -b sealed
sealed=$(python .tooling/phx.py ping ledger --payload mod --sealed "$RUNNER_TEMP/ledger")
```

**`published + 1` alone is no longer safe.** Sealing and publishing are no longer the same job: a
payload job can be sealed at serial *N* and then die before it undrafts. Nothing is published, so
`published + 1` proposes *N* again — and the ratchet refuses it, forever, because *N* is spent. The
ledger is the only place that remembers a serial that was signed but never shipped. Taking the max
of the two also survives the other direction (a deleted release, which makes `releases/latest`
answer with an older one).

**3. Dispatch**, then **4. wait for the entry** — fetch `sealed` in a loop until both files exist,
giving up after ~10 minutes:

```sh
for i in $(seq 1 60); do
  git -C .tooling fetch --quiet origin sealed || true
  if git -C .tooling cat-file -e "FETCH_HEAD:sealed/$REPO/$TAG/ping.json" 2>/dev/null; then break; fi
  sleep 10
done
git -C .tooling show "FETCH_HEAD:sealed/$REPO/$TAG/manifest.json.minisig" > staging/manifest.json.minisig
git -C .tooling show "FETCH_HEAD:sealed/$REPO/$TAG/ping.json"             > staging/ping.json
```

**5. Prove it locally, against the pinned checkout's own keys.** This is the half of `seal.py` that
used to run in the producer's job, and it is the check that catches a signature made under a key
clients do not pin — whose only symptom otherwise is an update channel that has quietly died:

```sh
python .tooling/phx.py minisign verify staging/manifest.json \
    --pub .tooling/keys/phoenix-active.pub --sig staging/manifest.json.minisig
python .tooling/phx.py ping verify staging/ping.json --pub .tooling/keys/phoenix-active.pub
```

Also confirm the fetched `ping.json` carries **the serial you built with**. It is possible to fetch
an entry left by an *earlier* attempt at the same tag (see below); the signature check above fails
closed in that case, and comparing serials says why.

**6. Upload the sidecar to the draft, then undraft.** `manifest.json.minisig` is what every client
needs; the release must not become visible without it.

**7. Ping the mirrors** with the signed ping — after undrafting, since it announces a release a
mirror will immediately try to fetch:

```sh
python .tooling/phx.py notify notify --ping-file staging/ping.json
```

## The mirror registry, which seals a document that is not a manifest

`Pr0j3ctPh03nix/phoenix-mirror-registry` publishes `mirrors.json`, the signed list of hosts a
launcher may download releases from. It used to sign that document with the release key in its own
CI; it now asks here, like every other producer, and holds no key.

**What the authority checks for the `mirrors` kind, and deliberately nothing more:** the bytes parse
as one unambiguous JSON document (no duplicate keys, UTF-8, an object at the root); `payload_id` is
`"mirrors"`, which is *not* a manifest `payload_id` and never will be, so no reader can take a
signed mirror list for a payload manifest; the `serial` in the document is a whole number ≥ 1 within
a u64; and `mirrors` is a list. **Every rule about the list itself** — the URLs, the names, the
countries, the payload sets, the duplicates — is the registry's own `generate_mirror_list.py`,
enforced by its `validate.yml` on the pull request that adds a mirror, before anything can be merged
or published. Restating any of it here would be a second copy of a format this repo does not own.

The flow is the one above, with its own names:

1. build the list, and **upload it to a DRAFT release** — `mirrors.json`, tagged `v<serial>`;
2. the serial is `max(the ledger's highest sealed **mirrors** serial, the published one) + 1`
   (`python .tooling/phx.py ping ledger --payload mirrors --sealed <ledger>`); the published side
   is the `serial` in the latest release's `mirrors.json`, exactly as for a payload — a tag that
   was never sealed spent nothing, and one that was is in the ledger;
3. dispatch, with `trusted_comment` naming the list, e.g. `phoenix mirror list v2`;
4. wait for `sealed/Pr0j3ctPh03nix/phoenix-mirror-registry/<tag>/{mirrors.json.minisig,ping.json}`;
5. prove it locally — `phx.py minisign verify mirrors.json --pub .tooling/keys/phoenix-active.pub
   --sig mirrors.json.minisig` — and confirm the ping's serial is the one in the document;
6. upload `mirrors.json.minisig` to the draft, then undraft.

There is no step 7: the ping minted for a mirror list is never delivered. A mirror's registry entry
lists the payload *trees* it serves (`mod`, `launcher`, `game`) and never the list itself, so
`phx.py notify` would find no carrier and a mirror would answer `/sync/mirrors` with a 404. It
is minted anyway so that every ledger entry is the same two files — `ping.json` is where
`phx.py ping` reads a sealed serial from, and a kind that skipped it would be a kind the ratchet
cannot see.

## The dispatch PAT

Fine-grained, scoped to **`Pr0j3ctPh03nix/phoenix-release-tooling` only**, with **Actions: Read and
write**, issued from the owner's own account. That is the permission GitHub requires for the
[workflow-dispatch endpoint](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event):
*“The fine-grained token must have the following permission set: "Actions" repository permissions
(write)”*.

**What it can do:** ask this repository to run `seal.yml` — and whatever else Actions: write covers
here: re-running, cancelling and dispatching this repo's workflows, deleting their logs, and
disabling a workflow outright. Every one of those is a denial at worst; nothing it asks for skips a
gate, because the gates are in the file the run executes.

**What it cannot do:** write a byte of this repository. No push, no branch, no tag, no file, and no
secret (secrets are not readable through the API at all; the key exists only inside a job here, and
only in the step that signs).

That last point is the whole reason the trigger is a workflow dispatch. `repository_dispatch` needs
**Contents: write** — there is no narrower permission for `POST /repos/{owner}/{repo}/dispatches` —
which on a personal account is a token that can push to any unprotected branch of this repository,
including the one the signing workflow is read from. The transport credential is now *unable* to
rewrite what signs, rather than merely forbidden to; no machine account is needed, and the rulesets
below are hygiene rather than the boundary:

* **`main`** is the only ref this workflow signs on (the workflow refuses any other, and the PAT
  cannot create one). Requiring a PR to reach it keeps the rules that guard the key reviewable.
* **`sealed`** is the ratchet's memory: nothing in the ledger is signature-checked when the
  high-water mark is read (that read must stay stdlib-only, because it runs in producer CI before
  any dependency is installed), so its integrity is exactly "who may push to this branch". Block
  force-pushes and deletions there, with **GitHub Actions** as the bypass actor — the seal job's own
  `GITHUB_TOKEN` is what pushes it.

Give each producer its own token, so revoking one does not stop the others.

## Failure modes

**A dispatch on the wrong ref.** Refused by the first step, before the request is even read. Ask for
`"ref": "main"`.

**A tag that was already sealed.** Re-running a payload job that died *after* tooling had sealed it:
the producer recomputes a serial from the ledger, so it dispatches a *higher* one and gets a fresh
entry in the same directory. If it dispatches the *same* serial (an unchanged document, a re-run of
the request alone), the ratchet refuses it and the seal job goes red — while the producer's fetch
loop still succeeds, because the earlier run's files are still there. That is intended: the ledger
is untouched by a refusal, and step 5 is what decides whether the files it found actually cover the
document it holds.

**Two payloads sealing at once.** Serialised by the workflow's `concurrency` group: one seal at a
time, queued, never cancelled. A cancelled seal is one that may already have signed.

**A refused request** (bad authorization, a document the authority would not put a key to, a serial
that does not rise) leaves the ledger untouched and nothing signed. The producer's wait loop then
times out, and its draft release is still a draft — nothing a client can see.

**A signature that never arrives** is always recoverable: the draft is inert, and re-dispatching
with a serial above the ledger is a fresh, legal attempt.

## What this does not cover

* **The base game** (`game-dist`) is published by hand, by someone holding `active.key` offline —
  see `client-dist-staging/docs/release-keys.md`. It never dispatched anything and still does not.
  Whoever publishes it is the authority for that release and mints its ping themselves —
  `build_game_bundles.py` (in `client-dist-staging`) does it after the upload, with the same key it
  sealed with, and delivers it through `phx.py notify`. By hand, the same two steps are
  `python phx.py ping sign --sec active.key --payload game --serial <the sealed serial> --out
  ping.json`, then `phx.py notify notify --ping-file ping.json --strict`.
* **A recovery release** (`phoenix-recovery.pub`) is by hand by construction: RECOVERY never enters
  CI, here or anywhere.
