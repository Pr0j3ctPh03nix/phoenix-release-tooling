# Sealing a payload — what a producer does now that the key lives here

The release signing key has left every producer repository. A producer builds and publishes; **this**
repository signs **and numbers**. Nobody holds a token for anybody else's repository, and the only
credential that crosses a boundary is a PAT that can ask for a signature and nothing else.

This document is the **producer-facing contract**. The workflow that implements it is
[`.github/workflows/seal.yml`](../.github/workflows/seal.yml) — read it for what the authority
checks and why; it is not restated here. The producer's two commands are
[`phoenix_tooling/dispatch.py`](../phoenix_tooling/dispatch.py).

```
producer CI                          phoenix-release-tooling            branch `sealed`
───────────                          ───────────────────────            ───────────────
build at serial 0 → upload DRAFT
phx dispatch send ────────────────►  ref · authorize · validate
                                     ASSIGN serial  ◄───────────────────  read (ledger)
                                     sign document + ping ─────────────►  commit + push
phx dispatch await ◄──────────────────────────────────────────────────── fetch + verify
upload the SEALED manifest + sidecar → undraft → notify mirrors
```

Three kinds of producer use it: the **mod** (from `client-dist-staging`, and from `client-dist` when
the public line goes live), the **launcher**, and the **mirror registry** — whose document is not a
manifest, and has its own section below. The **base game** does not: it is sealed by hand, offline
(see the last section).

## The serial is not a producer's business any more

A producer builds its document with **`serial: 0`**, which names no release: nothing anywhere
accepts a release at 0, so 0 already means "unnumbered". This job assigns the real number —
`highest serial ever sealed for that payload + 1`, from the ledger — writes it into the document,
and signs *those* bytes.

So there is no `max(ledger, published) + 1` in producer CI, no ledger fetch before dispatching, and
no way to propose a number that is already spent. **What a producer publishes is the document that
comes back**, not the one it sent.

## The request

`phx dispatch send` builds and sends it:

```sh
python .tooling/phx.py dispatch send \
    --repo Pr0j3ctPh03nix/client-dist-staging --tag v1.2.3 \
    --document staging/manifest.json --trusted-comment "phoenix mod v1.2.3"
```

with the PAT in `PHOENIX_TOOLING_DISPATCH` (`--token-env` names another variable). It refuses, before
anything is sent, a document that is not one this repo's own builder would produce and a document
that does not carry serial 0 — `--dry-run` runs both checks and sends nothing.

The wire form, for anyone who has to read a log:

```json
{"ref": "main",
 "inputs": {"repo": "Pr0j3ctPh03nix/client-dist-staging",
            "tag": "v1.2.3",
            "manifest": "<base64(gzip(the exact document bytes))>",
            "trusted_comment": "phoenix mod v1.2.3"}}
```

`ref` must be **`main`**: a workflow dispatch names the ref it runs and GitHub runs that ref's copy
of the workflow, so the workflow refuses to sign anywhere else — an older branch is an older, weaker
set of these rules holding the same key. Exactly those four inputs, each a non-empty string. GitHub
caps a whole `inputs` object at **65,535 characters**, which is what the gzip is for and what
`dispatch send` refuses to exceed. `repo` must be the repository that is asking; `tag` is
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. The input is called `manifest` whatever kind of document it
carries, for the same reason `seal.py`'s flag is: what gets signed is a file's exact bytes.

Do not hand-roll the POST with `gh`. Two traps cost a release each, and `dispatch send` has neither:
`gh api /repos/...` under `shell: bash` on a *Windows* runner is rewritten by MSYS into
`C:/Program Files/Git/repos/...`, and `gh api -f manifest=...` puts the base64 blob in a command
line Windows caps at about 32,000 characters.

Which repository may seal which payload line is a fixed map in the workflow. A request naming a line
its repository is not listed for is refused; so is a document this repo's own builder would not have
produced (`python phx.py manifest validate <manifest.json>` asks the same question locally).

## The answer

Branch **`sealed`**, world-readable, one commit per seal:

```
sealed/<owner>/<name>/<tag>/<document>            the document AS SEALED — the serial is in it
sealed/<owner>/<name>/<tag>/<document>.minisig    the signature over those exact bytes
sealed/<owner>/<name>/<tag>/ping.json             the signed mirror ping for that serial
```

`<document>` is the file that was sealed: `manifest.json` for a payload manifest, `mirrors.json` for
the mirror list. A signature in the ledger is therefore never separable from what it covers.

That branch is also the **ledger**: it is what the authority counts from. Nothing else reads it to
decide anything — `phx ping ledger --payload mod --sealed <checkout>` is for a person who wants to
know where a line stands.

## What payload CI must do

**1. Build at serial 0, attest, and upload the release as a DRAFT** — everything except
`manifest.json`, which does not exist in its final form yet. Nothing is reachable by a client until
the release is undrafted, which is the property that makes waiting for a signature safe.

**2. Dispatch** (`phx dispatch send`, above).

**3. Wait for the answer, and prove it:**

```sh
serial=$(python .tooling/phx.py dispatch await \
    --repo "$REPO" --tag "$TAG" --document staging/manifest.json --out staging | cut -d' ' -f2)
```

`await` polls branch `sealed` until the three files are there (10 minutes by default), then checks,
against **the pinned checkout's own `keys/phoenix-active.pub`**:

* **(a)** the `.minisig` verifies over the document's exact bytes;
* **(b)** `ping.json` is signed by that same key;
* **(c)** the ping names the payload the document does;
* **(d)** **the document is this request** at the serial the ping names — the request in
  `--document`, rendered again through the same `build_manifest.assign` the authority ran.

(d) is the one that cannot be dropped. A tag directory is a path, and an earlier attempt at the same
tag leaves an entry exactly where this run looks; it was genuinely sealed by the real key, so (a)
to (c) all pass over it. Only rebuilding the answer from the request in hand tells "sealed" from
"sealed for me". Any failure names its letter and exits non-zero.

It writes the three files into `--out` as fetched, and prints `serial <N>` on stdout — the number
this release turned out to have, for a workflow that wants to log or check it.

**4. Upload the sealed `manifest.json` and `manifest.json.minisig` to the draft, then undraft.**
Both are what every client needs; the release must not become visible without either, and the
manifest that goes up is the one `await` wrote — never the request.

**5. Ping the mirrors** with the signed ping — after undrafting, since it announces a release a
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
signed mirror list for a payload manifest; the `serial` is a whole number **0**, as every request's
is; and `mirrors` is a list. **Every rule about the list itself** — the URLs, the names, the
countries, the payload sets, the duplicates — is the registry's own `generate_mirror_list.py`,
enforced by its `validate.yml` on the pull request that adds a mirror, before anything can be merged
or published. Restating any of it here would be a second copy of a format this repo does not own.

The flow is the one above, with its own names: build the list at serial 0, upload it to a **draft**
release, `dispatch send` with a `trusted_comment` naming the list (e.g. `phoenix mirror list`),
`dispatch await` into the staging directory, upload the returned `mirrors.json` **and**
`mirrors.json.minisig`, undraft.

**The tag is the registry's to decide.** It used to be `v<serial>`, which is no longer possible: the
serial does not exist until the seal is done, and the tag names the ledger directory the request is
filed under. Anything matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` will do; that choice belongs to
that repository, not here.

There is no mirror ping to deliver: the ping minted for a mirror list is never sent. A mirror's
registry entry lists the payload *trees* it serves (`mod`, `launcher`, `game`) and never the list
itself, so `phx notify` would find no carrier and a mirror would answer `/sync/mirrors` with a 404.
It is minted anyway so that every ledger entry is the same three files — `ping.json` is where the
authority reads a sealed serial from, and a kind that skipped it would be a kind the counter cannot
see.

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
* **`sealed`** is the counter's memory: nothing in the ledger is signature-checked when the
  high-water mark is read (that read must stay stdlib-only, because it runs before the signing
  wheel is installed), so its integrity is exactly "who may push to this branch". Block force-pushes
  and deletions there, with **GitHub Actions** as the bypass actor — the seal job's own
  `GITHUB_TOKEN` is what pushes it.

Give each producer its own token, so revoking one does not stop the others.

## Failure modes

**A dispatch on the wrong ref.** Refused by the first step, before the request is even read. Ask for
`"ref": "main"` (`dispatch send` always does).

**A document that already carries a serial.** Refused — by `dispatch send` locally, and by the
authority if it arrives anyway. A producer that fills in a serial is a producer that believes it
still chooses one, and quietly renumbering it would publish something other than what it built.

**Re-running a payload job whose seal already happened.** The authority compares the ledger entry's
own document against this request rendered at that entry's serial: identical means *already sealed*,
and the run signs nothing, pushes nothing and spends no serial — `await` fetches the same three
files it would have. This is why a re-run is now free; it used to be a red seal job beside a green
producer.

**Re-running with a CHANGED document under the same tag.** A fresh seal at a fresh serial,
overwriting that tag's directory — a rebuilt tag has always behaved this way. Anything that fetched
the old entry before the overwrite fails check (d) rather than publishing it.

**Two payloads sealing at once.** Serialised by the workflow's `concurrency` group: one seal at a
time, queued, never cancelled. Read-then-add is now entirely inside that job, which is exactly why
the group must stay. A cancelled seal is one that may already have signed.

**A refused request** (bad authorization, a document the authority would not put a key to, a serial
that is not 0) leaves the ledger untouched and nothing signed. `await` then times out, and the draft
release is still a draft — nothing a client can see.

**A signature that never arrives** is always recoverable: the draft is inert, and re-dispatching is
a fresh, legal attempt that costs at most one serial.

## What this does not cover

* **The base game** (`game-dist`) is published by hand, by someone holding `active.key` offline —
  see `client-dist-staging/docs/release-keys.md`. It never dispatched anything and still does not,
  so it is also the one line that still picks its own serial: it never enters the ledger, and the
  only number it has to beat is its own published one. Whoever publishes it is the authority for
  that release and mints its ping themselves — `build_game_bundles.py` (in `client-dist-staging`)
  does it after the upload, with the same key it sealed with, and delivers it through
  `phx.py notify`. By hand, the same two steps are `python phx.py ping sign --sec active.key
  --payload game --serial <the sealed serial> --out ping.json`, then
  `phx.py notify notify --ping-file ping.json --strict`.
* **A recovery release** (`phoenix-recovery.pub`) is by hand by construction: RECOVERY never enters
  CI, here or anywhere.
