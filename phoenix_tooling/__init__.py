"""The Phoenix release tooling — the manifest format, the signer, the sealer, the mirror ping.

THE PUBLIC SURFACE IS THESE MODULES, and nothing else in this package is one. A consumer imports
from here, or drives the same code through `phx.py` at the repo root; the file layout underneath a
name below is this repo's own business and may move without notice.

    manifest_schema   the manifest FORMAT, declared as data
    build_manifest    the one assembler, and the `validate` that reads a document back by rebuilding
    phxb              the `.phxb` bundle format — the settings and the writer
    minisign          `.minisig` signatures over release documents, both sides
    seal              sign -> prove: the one way a payload is sealed
    ping              the signed mirror ping, its wire contract, and the sealed-branch ledger reader
    notify            delivering a ping to every registered mirror that carries the payload
    wheels            proving `wheels/` holds the bytes `wheels/SHA256SUMS` claims
    rehearsal         running `.github/workflows/seal.yml`'s own gates off GitHub

NOTHING IS IMPORTED HERE, deliberately. `ping` and `notify` are read by producer CI before any wheel
is installed, and `build_manifest`/`manifest_schema` are the document-only path — none of them may
pull in `cryptography`, and importing this package must not make that decision for them. Only
`minisign` (and `seal`, through it) needs it, and only `phxb` needs `zstandard`.
"""
