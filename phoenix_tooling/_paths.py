"""Where this package sits in the repo.

Two modules have to reach files this package does not own -- `wheels/` and
`.github/workflows/seal.yml` -- and the dirname arithmetic that finds them lives here rather than
once per module, so moving the package is one edit rather than a hunt.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
