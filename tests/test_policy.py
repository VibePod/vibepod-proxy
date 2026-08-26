"""Tests for the allow/deny filter policy."""

from __future__ import annotations

import json
import os
from pathlib import Path

from policy import FilterPolicy, PolicyStore

POLICY_ID = "4f4dbceea7034d198014979d8f2ca79b"


def _write(
    path: Path,
    mode: str,
    allow: list[str] | None = None,
    deny: list[str] | None = None,
) -> None:
    path.write_text(json.dumps({"mode": mode, "allow": allow or [], "deny": deny or []}))


def make_policy(
    tmp_path: Path,
    mode: str,
    allow: list[str] | None = None,
    deny: list[str] | None = None,
) -> FilterPolicy:
    filter_path = tmp_path / "filter.json"
    _write(filter_path, mode, allow, deny)
    return FilterPolicy(filter_path)


def test_open_mode_blocks_nothing(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "open", deny=["example.com"])
    assert not policy.is_blocked("example.com")


def test_deny_mode_blocks_listed_host_only(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "deny", deny=["example.com"])
    assert policy.is_blocked("example.com")
    assert not policy.is_blocked("other.com")


def test_allow_mode_blocks_unlisted_host(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "allow", allow=["api.anthropic.com"])
    assert not policy.is_blocked("api.anthropic.com")
    assert policy.is_blocked("example.com")


def test_wildcard_matches_subdomains_not_apex(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "deny", deny=["*.example.com"])
    assert policy.is_blocked("api.example.com")
    assert policy.is_blocked("a.b.example.com")
    assert not policy.is_blocked("example.com")
    assert not policy.is_blocked("notexample.com")


def test_exact_pattern_does_not_match_subdomains(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "deny", deny=["example.com"])
    assert not policy.is_blocked("api.example.com")


def test_matching_is_case_insensitive(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "deny", deny=["Example.COM"])
    assert policy.is_blocked("EXAMPLE.com")


def test_none_host_never_blocked(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "allow", allow=["api.anthropic.com"])
    assert not policy.is_blocked(None)


def test_trailing_dot_host_normalized(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "deny", deny=["example.com"])
    assert policy.is_blocked("example.com.")


def test_missing_file_fails_open(tmp_path: Path) -> None:
    policy = FilterPolicy(tmp_path / "does-not-exist.json")
    assert not policy.is_blocked("example.com")
    assert policy.mode == "open"


def test_malformed_json_fails_open(tmp_path: Path) -> None:
    filter_path = tmp_path / "filter.json"
    filter_path.write_text("{not json")
    policy = FilterPolicy(filter_path)
    assert not policy.is_blocked("example.com")


def test_unknown_mode_fails_open(tmp_path: Path) -> None:
    filter_path = tmp_path / "filter.json"
    filter_path.write_text(json.dumps({"mode": "strict", "deny": ["example.com"]}))
    policy = FilterPolicy(filter_path)
    assert not policy.is_blocked("example.com")


def test_block_reason_none_in_open_mode(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "open", deny=["example.com"])
    assert policy.block_reason("example.com") is None


def test_block_reason_deny_match(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "deny", deny=["example.com"])
    assert policy.block_reason("example.com") == "deny-match"
    assert policy.block_reason("other.com") is None


def test_block_reason_allow_miss(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "allow", allow=["api.anthropic.com"])
    assert policy.block_reason("example.com") == "allow-miss"
    assert policy.block_reason("api.anthropic.com") is None


def test_block_reason_none_host(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "allow", allow=["api.anthropic.com"])
    assert policy.block_reason(None) is None


def test_hot_reload_picks_up_changes(tmp_path: Path) -> None:
    filter_path = tmp_path / "filter.json"
    _write(filter_path, "open")
    policy = FilterPolicy(filter_path)
    assert not policy.is_blocked("example.com")

    _write(filter_path, "deny", deny=["example.com"])
    # mtime resolution can swallow rapid rewrites; force a distinct mtime.
    os.utime(filter_path, (0, 12345.0))
    assert policy.is_blocked("example.com")


def test_recovers_after_file_restored(tmp_path: Path) -> None:
    filter_path = tmp_path / "filter.json"
    _write(filter_path, "deny", deny=["example.com"])
    policy = FilterPolicy(filter_path)
    assert policy.is_blocked("example.com")

    filter_path.unlink()
    assert not policy.is_blocked("example.com")

    _write(filter_path, "deny", deny=["example.com"])
    os.utime(filter_path, (0, 12345.0))
    assert policy.is_blocked("example.com")


def test_reload_when_mtime_unchanged_but_content_differs(tmp_path: Path) -> None:
    """Coarse-mtime filesystems can swallow rapid rewrites; size must gate too."""
    filter_path = tmp_path / "filter.json"
    _write(filter_path, "open")
    policy = FilterPolicy(filter_path)
    assert not policy.is_blocked("example.com")

    st = os.stat(filter_path)
    _write(filter_path, "deny", deny=["example.com"])
    os.utime(filter_path, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert policy.is_blocked("example.com")


def test_file_with_zero_mtime_loads(tmp_path: Path) -> None:
    filter_path = tmp_path / "filter.json"
    _write(filter_path, "deny", deny=["example.com"])
    os.utime(filter_path, (0, 0))
    policy = FilterPolicy(filter_path)
    assert policy.is_blocked("example.com")


def test_non_utf8_file_fails_open(tmp_path: Path) -> None:
    filter_path = tmp_path / "filter.json"
    filter_path.write_bytes(b"\xff\xfe{bad}")
    policy = FilterPolicy(filter_path)
    assert not policy.is_blocked("example.com")


def test_reload_on_atomic_replace_with_same_size_and_mtime(tmp_path: Path) -> None:
    """os.replace gives a new inode even when size and mtime match."""
    filter_path = tmp_path / "filter.json"
    _write(filter_path, "deny", deny=["old-host.com"])
    policy = FilterPolicy(filter_path)
    assert policy.is_blocked("old-host.com")

    st = os.stat(filter_path)
    replacement = tmp_path / "filter.json.new"
    _write(replacement, "deny", deny=["new-host.com"])  # same byte length
    os.utime(replacement, ns=(st.st_atime_ns, st.st_mtime_ns))
    os.replace(replacement, filter_path)

    assert policy.is_blocked("new-host.com")
    assert not policy.is_blocked("old-host.com")


def test_evaluate_returns_mode_and_reason_together(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "deny", deny=["example.com"])
    decision = policy.evaluate("example.com")
    assert decision.mode == "deny"
    assert decision.reason == "deny-match"
    assert decision.blocked

    decision = policy.evaluate("other.com")
    assert decision.mode == "deny"
    assert decision.reason is None
    assert not decision.blocked


def test_evaluate_allow_miss(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, "allow", allow=["api.anthropic.com"])
    assert policy.evaluate("example.com").reason == "allow-miss"
    assert policy.evaluate("api.anthropic.com").reason is None


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_container_policy(
    tmp_path: Path,
    *,
    profile: str = "work",
    project_filter: dict[str, object] | None = None,
    env_mode: str | None = None,
) -> None:
    _write_json(
        tmp_path / "policies" / "containers" / f"{POLICY_ID}.json",
        {
            "version": 2,
            "policy_id": POLICY_ID,
            "profile": profile,
            "project_filter": project_filter,
            "env_mode": env_mode,
        },
    )


def test_policy_store_uses_global_policy_for_unidentified_client(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "filter.json",
        {"version": 2, "mode": "deny", "allow": [], "deny": ["example.com"]},
    )
    store = PolicyStore(tmp_path)

    decision = store.evaluate("example.com", policy_id=None)

    assert (decision.mode, decision.reason) == ("deny", "deny-match")


def test_policy_store_explicit_profile_replaces_project_filter(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "filter.json",
        {"version": 2, "mode": "open", "allow": [], "deny": []},
    )
    _write_json(
        tmp_path / "policies" / "profiles" / "work.json",
        {
            "version": 2,
            "profile": "work",
            "mode": "allow",
            "allow": ["api.anthropic.com"],
            "deny": [],
        },
    )
    _write_container_policy(
        tmp_path,
        project_filter={"mode": "deny", "deny": ["example.com"]},
    )
    store = PolicyStore(tmp_path)

    assert store.evaluate("example.com", policy_id=POLICY_ID).reason == "allow-miss"
    assert store.evaluate("api.anthropic.com", policy_id=POLICY_ID).reason is None


def test_policy_store_inherited_profile_applies_project_then_environment(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "filter.json",
        {
            "version": 2,
            "mode": "allow",
            "allow": ["api.anthropic.com"],
            "deny": [],
        },
    )
    _write_container_policy(
        tmp_path,
        project_filter={"deny": ["example.com"]},
        env_mode="deny",
    )
    store = PolicyStore(tmp_path)

    decision = store.evaluate("example.com", policy_id=POLICY_ID)

    assert (decision.mode, decision.reason) == ("deny", "deny-match")
    assert store.evaluate("other.com", policy_id=POLICY_ID).reason is None


def test_policy_store_missing_identified_policy_fails_closed(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "filter.json",
        {"version": 2, "mode": "open", "allow": [], "deny": []},
    )
    store = PolicyStore(tmp_path)

    decision = store.evaluate("example.com", policy_id=POLICY_ID)

    assert (decision.mode, decision.reason) == ("unavailable", "policy-unavailable")
    assert decision.blocked


def test_policy_store_reloads_referenced_profile_after_atomic_replace(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "filter.json",
        {"version": 2, "mode": "open", "allow": [], "deny": []},
    )
    profile_path = tmp_path / "policies" / "profiles" / "work.json"
    _write_json(
        profile_path,
        {"version": 2, "profile": "work", "mode": "open", "allow": [], "deny": []},
    )
    _write_container_policy(tmp_path)
    store = PolicyStore(tmp_path)
    assert store.evaluate("example.com", policy_id=POLICY_ID).reason is None

    replacement = profile_path.with_suffix(".new")
    _write_json(
        replacement,
        {
            "version": 2,
            "profile": "work",
            "mode": "deny",
            "allow": [],
            "deny": ["example.com"],
        },
    )
    os.replace(replacement, profile_path)

    decision = store.evaluate("example.com", policy_id=POLICY_ID)
    assert (decision.mode, decision.reason) == ("deny", "deny-match")
