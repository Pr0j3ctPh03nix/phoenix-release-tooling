# Sealing a payload — what a producer does now that the key lives here

The release signing key has left every payload repository. A producer builds and publishes; **this**
repository signs. Nobody holds a token for anybody else's repository, and the only credential that
crosses a boundary is a dispatch PAT that can ask for a signature and nothing else.

This document is the **producer-facing contract**. The workflow that implements it is
[`.github/workflows/seal.yml`](../.github/workflows/seal.yml) — read it for what the authority
checks and why; it is not restated here.

```
payload CI                          phoenix-release-tooling             branch `sealed`
──────────                          ───────────────────────             ───────────────
build → attest → upload DRAFT
pick a serial  ─────────────────────────────────────────────────────────► read (ledger)
dispatch {repo, tag, manifest} ───► authorize · validate · ratchet
                                    seal.py + ping.py sign ────────────► commit + push
wait for the entry ◄────────────────────────────────────────────────────  read
verify locally → upload sidecar → undraft → notify mirrors
```

## The request

`POST /repos/Pr0j3ctPh03nix/phoenix-release-tooling/dispatches`, with a fine-grained PAT:

```json
{"event_type": "seal",
 "client_payload": {"repo": "Pr0j3ctPh03nix/client-dist-staging",
                    "tag": "v1.2.3",
                    "manifest": "<base64(gzip(the exact manifest.json bytes))>",
                    "trusted_comment": "phoenix mod v1.2.3"}}
```

Exactly those four fields, each a non-empty string. GitHub caps the whole `client_payload` at
**64 KB** of JSON (and 10 top-level properties), which is what the gzip is for. `repo` must be the
repository that is asking; `tag` is `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.

The `manifest` is the **exact bytes** that are already uploaded to the draft release — the signature
covers bytes, so a re-serialisation on either side is a signature over a file nobody has. The
**serial is read from those bytes**, never from the request.

Which repository may seal which `payload_id` is a fixed map in the workflow. A request naming a
payload its repository is not listed for is refused; so is a manifest this repo's own builder would
not have produced (`python tools/build_manifest.py validate <manifest.json>` asks the same question
locally, before dispatching).

## The answer

Branch **`sealed`**, world-readable, one commit per seal:

```
sealed/<owner>/<name>/<tag>/manifest.json.minisig
sealed/<owner>/<name>/<tag>/ping.json
```

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
sealed=$(python .tooling/tools/ping.py ledger --payload mod --sealed "$RUNNER_TEMP/ledger")
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
python .tooling/tools/phoenix_minisign.py verify staging/manifest.json \
    --pub .tooling/keys/phoenix-active.pub --sig staging/manifest.json.minisig
python .tooling/tools/ping.py verify staging/ping.json --pub .tooling/keys/phoenix-active.pub
```

Also confirm the fetched `ping.json` carries **the serial you built with**. It is possible to fetch
an entry left by an *earlier* attempt at the same tag (see below); the signature check above fails
closed in that case, and comparing serials says why.

**6. Upload the sidecar to the draft, then undraft.** `manifest.json.minisig` is what every client
needs; the release must not become visible without it.

**7. Ping the mirrors** with the signed ping — after undrafting, since it announces a release a
mirror will immediately try to fetch:

```sh
python .tooling/tools/notify_mirrors.py notify --ping-file staging/ping.json
```

## The dispatch PAT

Fine-grained, scoped to **`Pr0j3ctPh03nix/phoenix-release-tooling` only**, with **Contents: write** —
the [permission GitHub requires](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
for `POST /repos/{owner}/{repo}/dispatches`. There is no narrower permission for that endpoint;
"Contents: read" does not reach it.

**What it can do:** ask this repository to seal something, and — because Contents: write is what it
is — push to branches here that are not protected.

**What it cannot do:** read `PHOENIX_SIGNING_KEY`, or any secret. Secrets are not readable through
the API at all; the key exists only inside a job of this repository, and only in the two steps that
sign.

**Two consequences that must be handled where the repository is administered, not in a script:**

* `repository_dispatch` runs the workflow file on the **default branch**. A token with Contents:
  write that can push to `main` can therefore rewrite what signs. Protect `main` with a ruleset
  (no direct pushes, PR required) — that is what keeps the transport credential a transport
  credential.
* The same is true of `sealed`, which is the ratchet's memory: nothing in the ledger is
  signature-checked when the high-water mark is read (that read must stay stdlib-only, because it
  runs in producer CI before any dependency is installed), so its integrity is exactly "who may push
  to this branch". Restrict it to the workflow, and forbid force-pushes and deletions.

Give each producer its own token, so revoking one does not stop the others, and prefer a machine
account over a personal one.

## Failure modes

**A tag that was already sealed.** Re-running a payload job that died *after* tooling had sealed it:
the producer recomputes a serial from the ledger, so it dispatches a *higher* one and gets a fresh
entry in the same directory. If it dispatches the *same* serial (an unchanged manifest, a re-run of
the request alone), the ratchet refuses it and the seal job goes red — while the producer's fetch
loop still succeeds, because the earlier run's files are still there. That is intended: the ledger
is untouched by a refusal, and step 5 is what decides whether the files it found actually cover the
manifest it holds.

**Two payloads sealing at once.** Serialised by the workflow's `concurrency` group: one seal at a
time, queued, never cancelled. A cancelled seal is one that may already have signed.

**A refused request** (bad authorization, a document the builder would not produce, a serial that
does not rise) leaves the ledger untouched and nothing signed. The producer's wait loop then times
out, and its draft release is still a draft — nothing a client can see.

**A signature that never arrives** is always recoverable: the draft is inert, and re-dispatching
with a serial above the ledger is a fresh, legal attempt.

## What this does not cover

* **The base game** (`game-dist`) is published by hand, by someone holding `active.key` offline —
  see `client-dist-staging/docs/release-keys.md`. It never dispatched anything and still does not.
  Whoever publishes it is the authority for that release and mints its ping themselves:
  `python tools/ping.py sign --sec active.key --payload game --serial <the sealed serial> --out
  ping.json`, then `notify_mirrors.py notify --ping-file ping.json --strict`. Nothing builds that
  ping for them today — `build_game_bundles.py` seals but does not ping, and it lives in another
  repository.
* **The mirror registry** signs `mirrors.json` with the same key in its own CI. It is not a manifest
  and this authority only seals manifests, so that repository still holds the key.
* **A recovery release** (`phoenix-recovery.pub`) is by hand by construction: RECOVERY never enters
  CI, here or anywhere.
