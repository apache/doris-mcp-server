"""Offline unit tests for the provider registry and artifact store."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from providers.base import CompiledArtifact, ModelSource, ProviderError  # noqa: E402
from providers.registry import (  # noqa: E402
    detect_provider,
    get_provider,
    get_runtime,
    list_providers,
)
from store.artifacts import ArtifactStore, make_artifact_id  # noqa: E402


CUBE_YAML = "cubes:\n  - name: orders\n    sql_table: dw.orders\n    measures: [{name: c, type: count}]\n"
MF_YAML = "semantic_models:\n  - name: orders\n    measures: [{name: revenue}]\n"
LOOKML = "view: orders {\n  sql_table_name: dw.orders ;;\n  measure: c { type: count }\n}\n"


class TestRegistry(unittest.TestCase):
    def test_builtin_providers_registered(self):
        names = {p["name"] for p in list_providers()}
        self.assertIn("cube", names)
        self.assertIn("lookml", names)
        self.assertIn("metricflow", names)

    def test_get_provider_unknown(self):
        with self.assertRaises(ProviderError):
            get_provider("nope")

    def test_get_runtime_matches_provider(self):
        for name in ("cube", "lookml", "metricflow"):
            self.assertEqual(get_runtime(name).name, name)

    def test_detect_routes_cube(self):
        name, score = detect_provider(ModelSource("sales.yaml", CUBE_YAML))
        self.assertEqual(name, "cube")
        self.assertGreaterEqual(score, 0.5)

    def test_detect_routes_metricflow(self):
        name, _ = detect_provider(ModelSource("sem.yml", MF_YAML))
        self.assertEqual(name, "metricflow")

    def test_detect_routes_lookml(self):
        name, _ = detect_provider(ModelSource("orders.view.lkml", LOOKML))
        self.assertEqual(name, "lookml")

    def test_detect_unrecognized_raises(self):
        with self.assertRaises(ProviderError):
            detect_provider(ModelSource("notes.txt", "hello world"))


class TestArtifactStore(unittest.TestCase):
    def _artifact(self, provider: str = "cube", name: str = "orders") -> CompiledArtifact:
        return CompiledArtifact(
            provider=provider, name=name, payload={"cubes": {}}, source_digest="abc123"
        )

    def test_id_sanitization(self):
        self.assertEqual(make_artifact_id("cube", "sales cube/v2"), "cube__sales_cube_v2")
        self.assertTrue(make_artifact_id("cube", "!!!"))

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            store = ArtifactStore(d)
            aid = store.save(self._artifact(), source_filename="sales.yaml")
            loaded = store.load(aid)
            self.assertEqual(loaded.provider, "cube")
            self.assertEqual(loaded.name, "orders")
            self.assertEqual(loaded.source_digest, "abc123")
            meta = store.get_meta(aid)
            self.assertEqual(meta["source_filename"], "sales.yaml")
            self.assertEqual(meta["provider"], "cube")

    def test_list_and_delete(self):
        with tempfile.TemporaryDirectory() as d:
            store = ArtifactStore(d)
            self.assertEqual(store.list(), [])
            aid1 = store.save(self._artifact(name="a"))
            aid2 = store.save(self._artifact(name="b"))
            self.assertEqual({m["artifact_id"] for m in store.list()}, {aid1, aid2})
            self.assertTrue(store.delete(aid1))
            self.assertFalse(store.delete(aid1))
            self.assertEqual([m["artifact_id"] for m in store.list()], [aid2])

    def test_path_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            store = ArtifactStore(d)
            for bad in ("../x", "a/b", "..", "x\x00y"):
                with self.assertRaises(ProviderError):
                    store.load(bad)

    def test_load_missing(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ProviderError):
                ArtifactStore(d).load("cube__missing")

    def test_corrupt_entry_skipped_in_listing(self):
        with tempfile.TemporaryDirectory() as d:
            store = ArtifactStore(d)
            aid = store.save(self._artifact())
            (Path(d) / ".artifacts" / "broken.json").write_text("{not json", encoding="utf-8")
            listed = store.list()
            self.assertEqual([m["artifact_id"] for m in listed], [aid])

    def test_corrupt_artifact_load_raises(self):
        with tempfile.TemporaryDirectory() as d:
            store = ArtifactStore(d)
            aid = store.save(self._artifact())
            (Path(d) / ".artifacts" / f"{aid}.json").write_text("{not json", encoding="utf-8")
            with self.assertRaises(ProviderError):
                store.load(aid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
