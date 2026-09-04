# Publishing a Phoenix payload

The release signing key exists in exactly one place — this repository's CI — and no producer holds
one. A producer builds; **this** repository **numbers, signs and answers on a public branch**. Nobody
holds a token for anybody else's repository, and the only credential that crosses a boundary is a
PAT that can ask for a signature and nothing else.

This is the **producer-facing contract**. Two files implement it and each is the authority on its
half: [`.github/workflows/seal.yml`](../.github/workflows/seal.yml) — what may be signed, for whom,
under which rules, including the map of which repository may seal which payload line — and
[`action.yml`](../action.yml), everything a producer does around it. Read those for the detail; none
of it is restated here.

```
producer CI                          phoenix-release-tooling            branch `sealed`
───────────                          ───────────────────────            ───────────────
build at serial 0
uses: …@v1  ─── draft ──┐
                        └─ send ──►  ref · authorize · validate
                                     ASSIGN serial  ◄───────────────────  read (ledger)
                                     sign document + ping ─────────────►  commit + push
            ◄── await ───────────────────────────────────────────────────  fetch + verify
        upload the SEALED document + sidecar → undraft → ping mirrors
```

## What a producer does

Build the payload, write the document at `serial: 0`, then one step:

```yaml
      - uses: Pr0j3ctPh03nix/phoenix-release-tooling@v1
        with:
          tag: ${{ github.ref_name }}
          document: staging/manifest.json
          assets: staging
          notes-file: release-notes.md
          token: ${{ github.token }}
          dispatch-token: ${{ secrets.PHOENIX_TOOLING_DISPATCH }}
```

It drafts the release, attaches every file in `assets`, asks for the seal, waits, **proves** the
answer against the public half every client pins, attaches the sealed document and its `.minisig`,
undrafts, and pings the mirrors. It outputs the `serial` the authority assigned and the
`release-url`. `dry-run: 'true'` validates the request and stops — the only part of this that can be
exercised without spending a serial, and what a producer's rehearsal should call.

That is the whole of it. What to build, what to attach and what the notes say are the producer's,
and none of them is anything this repository has an opinion about.

Underneath the action, `python phx.py dispatch send | await` are the same two halves as commands,
for a producer that is not a GitHub Actions job. `python phx.py --help` lists everything else.

## The request

A producer builds its document with **`serial: 0`**, which names no release — nothing anywhere
accepts a release at 0, so 0 already means "unnumbered". The authority assigns the real number,
`highest serial ever sealed for that payload + 1`, writes it into the document, and signs *those*
bytes.

So a producer does no arithmetic, reads no ledger, and cannot propose a number that is already
spent. **What a producer publishes is the document that comes back**, not the one it sent: the
serial exists only in the bytes the authority wrote it into, and only those bytes are signed.

The one field of a request that is a decision rather than a fact is `trusted-comment` — it is signed,
and therefore quotable. It defaults to `phoenix <payload_id> <tag>`.

## The answer

Branch **`sealed`**, world-readable, one commit per seal:

```
sealed/<owner>/<name>/<tag>/<document>            the document AS SEALED — the serial is in it
sealed/<owner>/<name>/<tag>/<document>.minisig    the signature over those exact bytes
sealed/<owner>/<name>/<tag>/ping.json             the signed mirror ping for that serial
```

`<document>` is the file that was sealed: `manifest.json` for a payload manifest, `mirrors.json` for
the mirror list. A signature in the ledger is therefore never separable from what it covers.

Before a byte of it is published, all of it is checked against the action's own
`keys/phoenix-active.pub`: **(a)** the signature covers the document's exact bytes; **(b)** the ping
is signed by that same key; **(c)** the ping names the payload the document does; **(d)** the
document **is this request** at the serial the ping names, re-rendered through the same function the
authority ran. (d) is the one that cannot be dropped — a tag directory is a path, and an earlier
attempt's entry sits exactly where this run looks and passes (a) to (c) perfectly, having been
genuinely sealed by the real key. [`phoenix_tooling/dispatch.py`](../phoenix_tooling/dispatch.py)
owns all four.

That branch is also the **ledger**: it is what the authority counts from. Nothing else reads it to
decide anything — `phx ping ledger --payload mod --sealed <checkout>` is for a person who wants to
know where a line stands.

## `@v1`

Consumers reference the moving major tag **`@v1`**. It is re-pointed at every green push to `main`
by [`.github/workflows/ci.yml`](../.github/workflows/ci.yml); `main` is PR-protected, so every merge
is a reviewed release of the tooling and there is no separate version step to forget. An
incompatible change to the action's inputs or outputs, or to the module names `phx.py` routes to, is
**`v2`** and a note here — never a silent change under `v1`.

The trade is deliberate and worth stating plainly: a moving `@v1` means a producer's next release
picks up changes here without a commit of its own — **including `keys/phoenix-active.pub`, the half
the answer is proven against**. A producer that wants the old "pinned commit SHA" property writes
`@<sha>` instead and updates it by hand, and then also stops receiving fixes. Both work; `@v1` is
what these producers use.

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
* **`v1`** is moved by this repo's own CI, so a tag-protection ruleset covering it needs **GitHub
  Actions** as a bypass actor too, or every push to `main` ends red.

Give each producer its own token, so revoking one does not stop the others.

## Failure modes

**A tag that is already released.** Refused before anything is created, uploaded or dispatched:
publishing into a finished release would change what clients have already been given, under a tag
they have already seen. Cut a new one.

**A document that already carries a serial**, or one this repository's own builder would not have
produced. Refused locally, before a draft exists — the same check the authority makes before it
reads the key, which is why a `dry-run` costs nothing and is worth having.

**A re-run of a producer's job.** Free, and the property the whole design rests on. The action
reuses its own draft, and the authority compares the ledger entry's document against this request
rendered at that entry's serial: identical means *already sealed*, so nothing is signed, nothing is
pushed and **no serial is spent**. A job that died between the seal and the undraft is therefore
recovered by pressing re-run.

**A re-run with a CHANGED document under the same tag.** A fresh seal at a fresh serial, overwriting
that tag's directory — a rebuilt tag has always behaved this way here. Anything that fetched the old
entry before the overwrite fails check (d) rather than publishing it.

**A refused request** (bad authorization, a document the authority would not put a key to, a serial
that is not 0) leaves the ledger untouched and nothing signed. `await` times out, and what is left
behind is an **inert draft** — invisible to every client. Read the seal run's log, fix, re-run; or
delete the draft.

**Two payloads sealing at once.** Serialised by the workflow's `concurrency` group: one seal at a
time, queued, never cancelled. Read-then-add is entirely inside that job, which is exactly why the
group must stay. A cancelled seal is one that may already have signed.

**A mirror that is down, or a registry that cannot be read.** A warning, never a failure. The
release is already published when the ping is delivered, and the ping is signed — anyone may deliver
it, later, so a missed one costs nothing a later delivery cannot redo.

## The mirror registry, which seals a document that is not a manifest

`Pr0j3ctPh03nix/phoenix-mirror-registry` publishes `mirrors.json`, the signed list of hosts a
launcher may download releases from. It used to sign that document with the release key in its own
CI; it now asks here, like every other producer, through the same action — its `document` is that
`mirrors.json` at serial 0.

**What the authority checks for the `mirrors` kind, and deliberately nothing more:** the bytes parse
as one unambiguous JSON document (no duplicate keys, UTF-8, an object at the root); `payload_id` is
`"mirrors"`, which is *not* a manifest `payload_id` and never will be, so no reader can take a
signed mirror list for a payload manifest; the `serial` is a whole number **0**, as every request's
is; and `mirrors` is a list. **Every rule about the list itself** — the URLs, the names, the
countries, the payload sets, the duplicates — is the registry's own `generate_mirror_list.py`,
enforced by its `validate.yml` on the pull request that adds a mirror, before anything can be merged
or published. Restating any of it here would be a second copy of a format this repo does not own.

**The tag is the registry's to decide.** It used to be `v<serial>`, which is no longer possible: the
serial does not exist until the seal is done, and the tag names the ledger directory the request is
filed under. Anything matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` will do; that choice belongs to
that repository, not here.

The ping minted for a mirror list is delivered like any other — the action does not special-case
it — but today it reaches nobody: a mirror's registry entry lists the payload *trees* it serves
(`mod`, `launcher`, `game`) and never the list itself, so `phx notify` finds no carrier, and a mirror
would answer `/sync/mirrors` with a 404. Teaching mirrors to carry the list is the mirror app's and
the registry's change to make; nothing here needs to change for it. The ping is minted regardless so
that every ledger entry is the same three files — `ping.json` is where the authority reads a sealed
serial from, and a kind that skipped it would be a kind the counter cannot see.

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
