"""Compile every Sigma rule in detections/ to Elasticsearch and Splunk queries.

Usage: venv/bin/python tools/compile.py
Outputs: compiled/elasticsearch/<rule>.esql.txt, compiled/splunk/<rule>.spl.txt
"""
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.backends.splunk.splunk import SplunkBackend

BASE = Path(__file__).resolve().parent.parent
RULES = sorted((BASE / "detections").rglob("*.yml"))

OUT_ES = BASE / "compiled" / "elasticsearch"
OUT_SPLUNK = BASE / "compiled" / "splunk"
OUT_ES.mkdir(parents=True, exist_ok=True)
OUT_SPLUNK.mkdir(parents=True, exist_ok=True)

es_backend = EqlBackend()
splunk_backend = SplunkBackend()

CORRELATION_NOTE = (
    "\n# NOTE: pySigma backends do not translate Sigma correlations, so the\n"
    "# threshold logic (count/window/group-by) is NOT in the query above.\n"
    "# See the hand-authored threshold equivalents in\n"
    "# compiled/manual/ssh_brute_force.threshold.*.txt\n"
)

compiled = 0
for rule_path in RULES:
    name = rule_path.stem
    collection = SigmaCollection.from_yaml(rule_path.read_text())
    rule = collection.rules[0]
    has_correlation = bool(getattr(collection, "correlations", None))

    try:
        es_queries = es_backend.convert(collection)
    except Exception as e:  # noqa: BLE001 - backends vary in feature support
        es_queries = [f"# CONVERSION FAILED: {type(e).__name__}: {e}"]

    try:
        splunk_queries = splunk_backend.convert(collection)
    except Exception as e:  # noqa: BLE001
        splunk_queries = [f"# CONVERSION FAILED: {type(e).__name__}: {e}"]

    (OUT_ES / f"{name}.txt").write_text(
        f"# {rule.title}\n# Sigma: detections/{rule_path.relative_to(BASE/'detections').as_posix()}\n\n"
        + "\n\n".join(es_queries)
        + "\n"
    )
    (OUT_SPLUNK / f"{name}.txt").write_text(
        f"# {rule.title}\n# Sigma: detections/{rule_path.relative_to(BASE/'detections').as_posix()}\n\n"
        + "\n\n".join(splunk_queries)
        + "\n"
    )
    compiled += 1
    print(f"[ok] {name}: {len(es_queries)} ES query(ies), {len(splunk_queries)} Splunk query(ies)")

print(f"\nCompiled {compiled} rules -> {OUT_ES} and {OUT_SPLUNK}")
