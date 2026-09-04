#!/usr/bin/env python3
"""The one CLI over `phoenix_tooling` — `phx <module> <the module's own arguments>`.

    python phx.py manifest  selftest | validate <manifest.json>
    python phx.py minisign  keygen | sign | verify | selftest
    python phx.py seal      seal --manifest ... --pub ... --trusted-comment ...
    python phx.py ping      sign | verify | ledger | selftest
    python phx.py notify    notify --ping-file ping.json
    python phx.py dispatch  send | await | selftest
    python phx.py wheels    check | write
    python phx.py rehearsal selftest
    python phx.py selftest              # every module's selftest, in order

Every consumer of this repo used to name a FILE — `python tools/ping.py ledger`, or a
`sys.path.insert` and an import by module name — so a rename inside the package was a breaking
change for four other repositories. This is the stable surface instead: the module names below are
the contract, the layout underneath them is not.

Routing is deliberately thin. Each module owns its own argument parsing, so this hands the rest of
argv straight to that module's `main()` and does nothing else — there is no second place for a flag
to be spelled, defaulted or documented. `phxb` is absent because it has no CLI: it is the bundle
WRITER, called by the two producers as a library.

Modules are imported ONE AT A TIME, when routed to. `minisign` (and `seal`, through it) needs
`cryptography` and `phxb` needs `zstandard`, while `ping`, `notify`, `dispatch` and `manifest` run
in producer CI before any wheel is installed — importing the table eagerly would make every command
need what one of them needs.
"""
import importlib
import sys

# CLI name -> module in `phoenix_tooling`. The left column is what a workflow writes and what
# `prog` says; it is the thing that must not change under a consumer.
MODULES = {
    "manifest": "build_manifest",
    "minisign": "minisign",
    "seal": "seal",
    "ping": "ping",
    "notify": "notify",
    "dispatch": "dispatch",
    "wheels": "wheels",
    "rehearsal": "rehearsal",
}

# The modules that carry a `selftest` subcommand, in dependency order: the format before the
# builder that walks it, the signer before the ping that borrows its keys, the two that only speak
# to the outside world after both, and the rehearsal last because it drives the real workflow.
SELFTESTS = ("manifest", "minisign", "ping", "notify", "dispatch", "rehearsal")

USAGE = ("usage: phx {" + " | ".join(MODULES) + " | selftest} ...\n"
         "       phx <module> --help  for one module's own arguments")


def _run(name, argv):
    """-> the module's exit status. Its `main()` exits by raising SystemExit, which is the whole of
    its contract with a caller; catching it here is what lets `selftest` below run several in one
    process without the first one ending it."""
    main = importlib.import_module("phoenix_tooling." + MODULES[name]).main
    try:
        main(argv)
    except SystemExit as e:
        # `sys.exit("some message")` prints the message and means 1; `sys.exit(None)` means 0.
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr)
            return 1
        return e.code or 0
    return 0


def selftest():
    """Every module's selftest, in sequence, whatever the one before it did. -> failures.

    Not "stop at the first failure": each of these owns a different boundary, and knowing that two
    of them broke together is what tells a change from a coincidence."""
    failed = []
    for name in SELFTESTS:
        print(f"=== {name} ===")
        if _run(name, ["selftest"]):
            failed.append(name)
    print()
    if failed:
        print(f"phx selftest: {len(failed)} of {len(SELFTESTS)} FAILED — {', '.join(failed)}")
    else:
        print(f"phx selftest: {len(SELFTESTS)} modules, all pass")
    return len(failed)


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.exit(USAGE)
    if argv[0] == "selftest":
        if len(argv) != 1:
            sys.exit("usage: phx selftest    (it takes no arguments; ask one module directly)")
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.exit(1 if selftest() else 0)
    if argv[0] not in MODULES:
        sys.exit(f"phx: no such module {argv[0]!r}\n{USAGE}")
    sys.exit(_run(argv[0], argv[1:]))


if __name__ == "__main__":
    main()
