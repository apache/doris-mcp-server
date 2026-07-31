"""Guard against runtime-only dependency gaps.

A missing transitive dependency does not fail any unit test that stubs the
import out — it fails at runtime, on the server, as an opaque
"Files present but failed to load".  These tests import the real modules.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REQUIREMENTS = REPO / "requirements.txt"


def _requirement_names() -> set[str]:
    names = set()
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split("[")[0]
        for sep in (">=", "<=", "==", "!=", "~=", ">", "<"):
            name = name.split(sep)[0]
        names.add(name.strip().replace("-", "_").lower())
    return names


class TestSemanticLayerImportable(unittest.TestCase):
    """The metricflow compile path must import with only declared deps."""

    def test_bootstrap_imports(self):
        """store.bootstrap pulls in the vendored metricflow.

        This is the module that fails when importlib_metadata is absent.
        """
        code = "from store.bootstrap import bootstrap, pre_validate_physical"
        r = subprocess.run(
            [sys.executable, "-c", code],
            cwd=REPO, env={"PYTHONPATH": "src", "PATH": ""},
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(
            r.returncode, 0,
            f"store.bootstrap failed to import — the semantic layer will not "
            f"compile at runtime:\n{r.stderr[-1500:]}",
        )

    def test_compiler_and_manifest_import(self):
        code = (
            "from store.compiler import MetricFlowCompiler\n"
            "from store.manifest import SemanticManifest"
        )
        r = subprocess.run(
            [sys.executable, "-c", code],
            cwd=REPO, env={"PYTHONPATH": "src", "PATH": ""},
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(r.returncode, 0, r.stderr[-1500:])


class TestRequirementsCoverage(unittest.TestCase):
    """Dependencies the vendored metricflow needs must be declared."""

    def test_importlib_metadata_declared(self):
        """src/metricflow imports it at module scope, so it is not optional."""
        self.assertIn(
            "importlib_metadata", _requirement_names(),
            "src/metricflow/semantic_interfaces/implementations/"
            "project_configuration.py does `from importlib_metadata import ...` "
            "at module scope. If it is not in requirements.txt the built "
            "package omits it and every workspace reports "
            "'Files present but failed to load'.",
        )

    def test_no_undeclared_top_level_imports_in_compile_path(self):
        """Every third-party module the compile path imports must be declared."""
        import ast

        targets = [
            REPO / "src" / "store" / "bootstrap.py",
            REPO / "src" / "store" / "compiler.py",
            REPO / "src" / "store" / "manifest.py",
        ]
        declared = _requirement_names()
        local = {p.stem for p in (REPO / "src").iterdir()} | {"metricflow"}
        stdlib = set(sys.stdlib_module_names)
        # Import name -> distribution name, where they differ.
        alias = {"yaml": "pyyaml", "dotenv": "python_dotenv", "jinja2": "jinja2",
                 "dateutil": "python_dateutil", "attr": "attrs"}

        undeclared = []
        for path in targets:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module.split(".")[0]] if node.module and node.level == 0 else []
                else:
                    continue
                for m in mods:
                    if m in stdlib or m in local or m.startswith("_"):
                        continue
                    key = alias.get(m, m).replace("-", "_").lower()
                    if key not in declared:
                        undeclared.append(f"{path.name}: {m}")

        self.assertEqual(
            undeclared, [],
            f"These modules are imported but not in requirements.txt, so the "
            f"built package will omit them: {undeclared}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
