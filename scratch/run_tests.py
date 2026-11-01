"""Run all suites in isolated processes, propagating every failure to CI."""

import os
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"}
    failures = []
    for suite in sorted((root / "scratch").glob("test_*.py")):
        if suite.name == "test_support.py":
            continue
        print(f"\nRunning {suite.name}", flush=True)
        command = [sys.executable, "-B", "-m", "scratch." + suite.stem]
        if os.getenv("CYBERDASH_COVERAGE") == "1":
            command = [sys.executable, "-B", "-m", "coverage", "run", "--parallel-mode", "--source=app", "-m", "scratch." + suite.stem]
        result = subprocess.run(command, cwd=root, env=env)
        if result.returncode:
            failures.append(suite.name)
    if failures:
        print("Failed suites: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("All isolated suites passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
