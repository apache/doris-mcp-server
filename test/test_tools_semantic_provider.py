"""Offline unit tests for the provider-agnostic semantic tool functions."""

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from tools.semantic_provider import (  # noqa: E402
    compile_semantic_model,
    delete_semantic_artifact,
    generate_semantic_sql,
    get_semantic_metadata,
    list_semantic_artifacts,
    list_semantic_providers,
    query_semantic_model,
)

CUBE_YAML = """
cubes:
  - name: orders
    sql_table: dw.orders
    measures:
      - name: revenue
        type: sum
        sql: amount
    dimensions:
      - name: country
        sql: country
        type: string
"""


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def parse(resp: str) -> dict:
    return json.loads(resp)


class _FakePool:
    """Minimal ConnectionPool stand-in recording the executed SQL."""

    def __init__(self):
        self.executed: list[str] = []

    async def execute(self, sql, database=None, max_rows=None):
        self.executed.append(sql)
        return [{"revenue": 42}], ["revenue"]


class TestProviderTools(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws_dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _compile(self, **kwargs) -> dict:
        args = dict(workspace_dir=self.ws_dir, filename="sales.yaml", content=CUBE_YAML)
        args.update(kwargs)
        return parse(run(compile_semantic_model(**args)))

    def test_list_providers(self):
        resp = parse(run(list_semantic_providers()))
        self.assertTrue(resp["success"])
        names = {p["name"] for p in resp["data"]}
        self.assertIn("cube", names)

    def test_compile_auto_detect(self):
        resp = self._compile()
        self.assertTrue(resp["success"], resp)
        self.assertEqual(resp["data"]["provider"], "cube")
        self.assertEqual(resp["data"]["metrics"], ["revenue"])
        self.assertEqual(resp["data"]["dimensions"], ["country"])
        self.assertTrue(resp["data"]["artifact_id"])

    def test_compile_explicit_provider(self):
        resp = self._compile(provider="cube")
        self.assertTrue(resp["success"])

    def test_compile_unknown_provider(self):
        resp = self._compile(provider="nope")
        self.assertFalse(resp["success"])

    def test_compile_validation_failure(self):
        resp = self._compile(content="cubes: []\n")
        self.assertFalse(resp["success"])
        self.assertIn("problems", resp["error"]["details"])

    def test_artifact_lifecycle(self):
        artifact_id = self._compile()["data"]["artifact_id"]

        listed = parse(run(list_semantic_artifacts(self.ws_dir)))
        self.assertTrue(listed["success"])
        self.assertEqual([m["artifact_id"] for m in listed["data"]], [artifact_id])

        deleted = parse(run(delete_semantic_artifact(self.ws_dir, artifact_id)))
        self.assertTrue(deleted["success"])
        listed = parse(run(list_semantic_artifacts(self.ws_dir)))
        self.assertEqual(listed["data"], [])

    def test_metadata_discovery(self):
        artifact_id = self._compile()["data"]["artifact_id"]
        resp = parse(run(get_semantic_metadata(self.ws_dir, artifact_id)))
        self.assertTrue(resp["success"])
        self.assertEqual([m["name"] for m in resp["data"]["metrics"]], ["revenue"])
        self.assertEqual([d["name"] for d in resp["data"]["dimensions"]], ["country"])

    def test_metadata_missing_artifact(self):
        resp = parse(run(get_semantic_metadata(self.ws_dir, "cube__nope")))
        self.assertFalse(resp["success"])

    def test_generate_sql_dry_run(self):
        artifact_id = self._compile()["data"]["artifact_id"]
        resp = parse(run(generate_semantic_sql(
            self.ws_dir, artifact_id,
            metrics=["revenue"], dimensions=["country"],
            filters=[{"dimension": "country", "operator": "ne", "value": "US"}],
            order_by=["-revenue"], limit=5,
        )))
        self.assertTrue(resp["success"], resp)
        sql = resp["data"]["sql"]
        self.assertIn("GROUP BY", sql)
        self.assertIn("`orders`.`country` != 'US'", sql)
        self.assertIn("LIMIT 5", sql)

    def test_generate_sql_bad_filter_shape(self):
        artifact_id = self._compile()["data"]["artifact_id"]
        resp = parse(run(generate_semantic_sql(
            self.ws_dir, artifact_id, metrics=["revenue"],
            filters=[{"operator": "eq"}],  # missing dimension
        )))
        self.assertFalse(resp["success"])

    def test_generate_sql_no_metrics(self):
        artifact_id = self._compile()["data"]["artifact_id"]
        resp = parse(run(generate_semantic_sql(self.ws_dir, artifact_id, metrics=[])))
        self.assertFalse(resp["success"])

    def test_query_executes_generated_sql(self):
        artifact_id = self._compile()["data"]["artifact_id"]
        pool = _FakePool()
        resp = parse(run(query_semantic_model(
            self.ws_dir, pool, artifact_id,
            metrics=["revenue"], dimensions=["country"], limit=3,
        )))
        self.assertTrue(resp["success"], resp)
        self.assertEqual(resp["data"]["rows"], [{"revenue": 42}])
        self.assertEqual(len(pool.executed), 1)
        self.assertIn("LIMIT 3", pool.executed[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
