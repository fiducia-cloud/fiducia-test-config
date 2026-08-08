#!/usr/bin/env python3
"""Verify immutable release manifests and sanitized evidence bundles."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\blin_api_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def secret_findings(value: Any) -> list[str]:
    return sorted({pattern.pattern for text in strings(value) for pattern in SECRET_PATTERNS if pattern.search(text)})


def validate_release(release: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if release.get("schema") != "fiducia.release-manifest/v1":
        errors.append("release.schema")
    source = release.get("source", {})
    if not isinstance(source, dict) or not SHA.fullmatch(str(source.get("commit_sha", ""))):
        errors.append("release.source.commit_sha")
    if not isinstance(source, dict) or not isinstance(source.get("repository"), str) or "/" not in source["repository"]:
        errors.append("release.source.repository")
    artifacts = release.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("release.artifacts")
    else:
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                errors.append(f"release.artifacts[{index}]")
                continue
            if not all(isinstance(artifact.get(key), str) and artifact[key] for key in ("kind", "name")):
                errors.append(f"release.artifacts[{index}].identity")
            if not DIGEST.fullmatch(str(artifact.get("digest", ""))):
                errors.append(f"release.artifacts[{index}].digest")
            locator = " ".join(str(artifact.get(key, "")) for key in ("name", "source", "version")).lower()
            if ":latest" in locator or locator.endswith("@main") or locator.endswith("@master"):
                errors.append(f"release.artifacts[{index}].mutable_locator")
    if not isinstance(release.get("interfaces"), dict) or not release["interfaces"]:
        errors.append("release.interfaces")
    if not isinstance(release.get("topology"), dict) or not release["topology"]:
        errors.append("release.topology")
    if not isinstance(release.get("migrations"), list):
        errors.append("release.migrations")
    if not isinstance(release.get("feature_gates"), dict):
        errors.append("release.feature_gates")
    if secret_findings(release):
        errors.append("release.secret_shaped_content")
    return sorted(set(errors))


def validate_evidence(release: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if evidence.get("schema") != "fiducia.evidence-bundle/v1":
        errors.append("evidence.schema")
    if evidence.get("release_manifest_sha256") != sha256(release):
        errors.append("evidence.release_manifest_sha256")
    outcome = evidence.get("outcome")
    if outcome not in {"passed", "failed", "blocked"}:
        errors.append("evidence.outcome")
    assertions = evidence.get("assertions", {})
    if not isinstance(assertions, dict) or any(not isinstance(assertions.get(key), int) or assertions[key] < 0 for key in ("passed", "failed", "skipped")):
        errors.append("evidence.assertions")
    elif outcome == "passed" and (assertions["failed"] or assertions["skipped"]):
        errors.append("evidence.clean_pass_required")
    if evidence.get("requires_credentials") is True and outcome != "blocked":
        errors.append("evidence.credential_lane_must_be_blocked")
    if outcome == "blocked" and not evidence.get("blocked_reason"):
        errors.append("evidence.blocked_reason")
    cleanup = evidence.get("cleanup", {})
    if not isinstance(cleanup, dict) or cleanup.get("status") not in {"clean", "failed", "quarantined"} or not cleanup.get("completed_at"):
        errors.append("evidence.cleanup")
    elif outcome == "passed" and cleanup.get("status") != "clean":
        errors.append("evidence.clean_cleanup_required")
    for key in ("environment_hash", "config_hash"):
        if not DIGEST.fullmatch(str(evidence.get(key, ""))):
            errors.append(f"evidence.{key}")
    for key in ("run_id", "deterministic_seed", "junit", "timeline", "trace_ids", "metrics", "failure_classification"):
        if key not in evidence:
            errors.append(f"evidence.{key}")
    signature = evidence.get("signature", {})
    unsigned = copy.deepcopy(evidence)
    unsigned.pop("signature", None)
    expected = f"sha256:{sha256(unsigned)}"
    if not isinstance(signature, dict) or not signature.get("algorithm") or not signature.get("key_id") or signature.get("signed_digest") != expected:
        errors.append("evidence.signature_envelope")
    if secret_findings(evidence):
        errors.append("evidence.secret_shaped_content")
    return sorted(set(errors))


def fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    release = {
        "schema": "fiducia.release-manifest/v1",
        "release_id": "fixture-1",
        "source": {"repository": "fiducia-cloud/fiducia-node.rs", "commit_sha": "a" * 40},
        "artifacts": [{"kind": "oci", "name": "ghcr.io/fiducia-cloud/node", "digest": "sha256:" + "b" * 64, "version": "1.0.0"}],
        "interfaces": {"fiducia-api": "1.0.0"},
        "migrations": ["0001_initial"],
        "feature_gates": {"leases": True},
        "topology": {"nodes": 3},
    }
    evidence = {
        "schema": "fiducia.evidence-bundle/v1",
        "run_id": "fixture-run-1",
        "outcome": "passed",
        "release_manifest_sha256": sha256(release),
        "deterministic_seed": 7,
        "environment_hash": "sha256:" + "c" * 64,
        "config_hash": "sha256:" + "d" * 64,
        "assertions": {"passed": 4, "failed": 0, "skipped": 0},
        "junit": [], "timeline": [], "trace_ids": [], "metrics": [],
        "failure_classification": None,
        "cleanup": {"status": "clean", "completed_at": "2026-08-08T00:00:00Z"},
        "requires_credentials": False,
    }
    evidence["signature"] = {"algorithm": "cosign-placeholder", "key_id": "fixture", "signed_digest": f"sha256:{sha256(evidence)}"}
    return release, evidence


def self_test() -> None:
    release, evidence = fixture()
    assert not validate_release(release)
    assert not validate_evidence(release, evidence)
    tampered = copy.deepcopy(release)
    tampered["topology"]["nodes"] = 5
    assert "evidence.release_manifest_sha256" in validate_evidence(tampered, evidence)
    leaked = copy.deepcopy(evidence)
    leaked["timeline"] = [{"message": "ghp_" + "x" * 30}]
    assert "evidence.secret_shaped_content" in validate_evidence(release, leaked)
    mutable = copy.deepcopy(release)
    mutable["artifacts"][0]["name"] += ":latest"
    assert "release.artifacts[0].mutable_locator" in validate_release(mutable)
    print("release evidence self-test: ok")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.release or not args.evidence:
        parser.error("--release and --evidence are required")
    release = json.loads(args.release.read_text(encoding="utf-8"))
    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    errors = validate_release(release) + validate_evidence(release, evidence)
    json.dump({"ok": not errors, "errors": sorted(set(errors))}, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
