# phoenix-release-tooling

The one thing every Phoenix producer shares — the mod, the launcher, the base game, the mirror
registry: the **manifest format**, the **signer**, the **signing authority** that holds the release
key, and the **mirror ping**. It belongs to none of them, so it is its own repository.

A producer builds its payload, then does one step:

```yaml
      - uses: Pr0j3ctPh03nix/phoenix-release-tooling@v1
        with:
          tag: ${{ github.ref_name }}
          document: staging/manifest.json
          assets: staging
          token: ${{ github.token }}
          dispatch-token: ${{ secrets.PHOENIX_TOOLING_DISPATCH }}
```

* [`docs/publishing.md`](docs/publishing.md) — the producer-facing contract. Start here.
* [`action.yml`](action.yml) — that step: its inputs, its outputs, and what it promises.
* [`.github/workflows/seal.yml`](.github/workflows/seal.yml) — the signing authority: the only copy
  of the release key, and every gate that runs before it is read.
* [`phx.py`](phx.py) — every tool here as one CLI. `python phx.py --help`.
* [`keys/`](keys) — the published public halves. **This path never moves**: the mirror app reads it
  live and the launcher compiles it in.
