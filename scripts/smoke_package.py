"""Offline isolated installation check; pass a wheel produced by pip wheel."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import venv


def run(command, cwd):
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True, timeout=60)


def main():
    wheel = Path(sys.argv[1]).resolve()
    root = Path(__file__).resolve().parents[1] / ".cache"
    root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="package-smoke-", dir=root) as directory:
        workspace = Path(directory)
        environment = workspace / "venv"
        venv.EnvBuilder(with_pip=False).create(environment)
        executable = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        run([sys.executable, "-m", "pip", "--python", str(executable), "install", "--no-index", "--no-deps", str(wheel)], workspace)
        # Attempt to shadow installed package. Isolated invocation must ignore this.
        hostile = workspace / "security_review"
        hostile.mkdir()
        (hostile / "__init__.py").write_text("raise RuntimeError('source package shadowed installation')")
        result = run([str(executable), "-I", "-m", "security_review", "backends", "list"], workspace)
        assert json.loads(result.stdout)["investigation"][0]["name"] == "claude-code"
        run([str(executable), "-I", "-c", "import importlib.util; assert importlib.util.find_spec('anthropic') is None"], workspace)
        run([str(executable), "-I", "-c", "from importlib.resources import files; import json; json.loads(files('security_review').joinpath('schemas/report-1.0.json').read_text())"], workspace)
        print("Offline isolated wheel installation, package-shadowing, optional-dependency and schema checks passed")


if __name__ == "__main__":
    main()
