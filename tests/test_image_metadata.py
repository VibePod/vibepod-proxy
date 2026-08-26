"""Proxy image capability metadata tests."""

from pathlib import Path


def test_dockerfile_exposes_policy_schema_2() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert 'LABEL io.vibepod.proxy.policy-schema="2"' in dockerfile
