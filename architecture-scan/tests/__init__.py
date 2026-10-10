"""Lets one module run alone (`python3 -m unittest tests.test_findings_renumber`).

The modules import their shared helpers as `test_architecture_scan`, which
`make test` (`unittest discover -s tests`) finds on its own.
"""
import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
