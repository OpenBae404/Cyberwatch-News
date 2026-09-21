"""CyberWatch test suite.

Present so `tests.negative_control` can be imported by name from the repo
root, which is what makes one definition of the negative control shared by
the control test and the mutation check instead of two copies that drift.

Entry point: `python3 tests/run.py` (add `--offline` to skip the live NVD
test). See that module's docstring for what is in the suite.
"""
