#!/usr/bin/env python3
"""Verify sanitized Kibana contract fixture structure and optional OpenAPI schemas."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

VERSIONS = ("v9.2.0", "v9.4.2")
FORBIDDEN_PATHS = {
    "/api/fleet/epm/packages/{pkgName}",
}
REQUIRED_OPERATIONS = {
    ("GET", "/api/fleet/epm/packages/installed"),
    ("GET", "/api/fleet/epm/packages/{pkgName}/{pkgVersion}"),
    ("POST", "/api/fleet/epm/packages/{pkgName}/{pkgVersion}"),
    ("GET", "/api/fleet/agent_policies"),
    ("POST", "/api/fleet/agent_policies"),
    ("GET", "/api/fleet/agent_policies/{agentPolicyId}"),
    ("PUT", "/api/fleet/agent_policies/{agentPolicyId}"),
    ("POST", "/api/fleet/agent_policies/delete"),
    ("GET", "/api/fleet/package_policies"),
    ("POST", "/api/fleet/package_policies"),
    ("GET", "/api/fleet/package_policies/{packagePolicyId}"),
    ("PUT", "/api/fleet/package_policies/{packagePolicyId}"),
    ("DELETE", "/api/fleet/package_policies/{packagePolicyId}"),
    ("GET", "/api/detection_engine/rules/_find"),
    ("GET", "/api/detection_engine/rules?rule_id={ruleId}"),
    ("POST", "/api/detection_engine/rules"),
    ("PUT", "/api/detection_engine/rules"),
    ("DELETE", "/api/detection_engine/rules?rule_id={ruleId}"),
    ("GET", "/api/detection_engine/rules/prepackaged/_status"),
    ("PUT", "/api/detection_engine/rules/prepackaged"),
}
SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "api-key",
    "authorization",
    "cookie",
    "id_token",
    "access_token",
    "refresh_token",
    "password",
    "private_key",
    "secret",
}
SENSITIVE_TEXT = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"\bAuthorization\s*:\s*(?:ApiKey|Bearer)\s+\S+", re.I),
    re.compile(r"\b(?:ApiKey|Bearer)\s+[A-Za-z0-9_+./=-]{12,}", re.I),
)
PAGE_TWO_TO_FIRST = {
    "installed-packages-page-2.json": "installed-packages-page-1.json",
    "agent-policies-page-2.json": "agent-policies-page-1.json",
    "package-policies-page-2.json": "package-policies-page-1.json",
    "detection-rules-page-2.json": "detection-rules-page-1.json",
}


def fail(message: str) -> None:
    raise ValueError(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{path}: invalid JSON: {exc}")


def scan_sensitive(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if key.lower() in SENSITIVE_KEYS or normalized in SENSITIVE_KEYS:
                fail(f"{location}: sensitive key is forbidden: {key}")
            scan_sensitive(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_sensitive(child, f"{location}[{index}]")
    elif isinstance(value, str):
        for pattern in SENSITIVE_TEXT:
            if pattern.search(value):
                fail(f"{location}: credential-like text is forbidden")


def fixture_index(root: Path) -> dict[str, tuple[Path, dict[str, Any]]]:
    manifests: dict[str, tuple[Path, dict[str, Any]]] = {}
    expected_operations: set[tuple[str, str]] | None = None

    for version in VERSIONS:
        directory = root / version
        manifest_path = directory / "contract.json"
        manifest = load_json(manifest_path)
        if manifest.get("kibanaVersion") != version.removeprefix("v"):
            fail(f"{manifest_path}: kibanaVersion does not match directory")

        source = manifest.get("source", {})
        if not re.fullmatch(r"[0-9a-f]{64}", source.get("sha256", "")):
            fail(f"{manifest_path}: source SHA-256 is missing or malformed")
        expected_suffix = f"/{version}/oas_docs/output/kibana.yaml"
        if not source.get("url", "").endswith(expected_suffix):
            fail(f"{manifest_path}: source URL is not pinned to {version}")

        operations: set[tuple[str, str]] = set()
        responses: set[str] = set()
        for operation in manifest.get("operations", []):
            identity = (operation.get("method", ""), operation.get("path", ""))
            if identity in operations:
                fail(f"{manifest_path}: duplicate operation: {identity}")
            operations.add(identity)
            response = operation.get("response", "")
            if not response or Path(response).name != response:
                fail(f"{manifest_path}: unsafe response fixture path: {response}")
            if not (directory / response).is_file():
                fail(f"{manifest_path}: missing response fixture: {response}")
            responses.add(response)

        if operations != REQUIRED_OPERATIONS:
            missing = sorted(REQUIRED_OPERATIONS - operations)
            extra = sorted(operations - REQUIRED_OPERATIONS)
            fail(f"{manifest_path}: operation mismatch; missing={missing}, extra={extra}")
        if any(path.split("?", 1)[0] in FORBIDDEN_PATHS for _, path in operations):
            fail(f"{manifest_path}: contains the Kibana-9.2-incompatible unversioned EPM path")
        if expected_operations is not None and operations != expected_operations:
            fail(f"{manifest_path}: operation set differs across pinned versions")
        expected_operations = operations

        for error_name in manifest.get("errorFixtures", []):
            if not (directory / error_name).is_file():
                fail(f"{manifest_path}: missing error fixture: {error_name}")
            responses.add(error_name)

        for path in sorted(directory.glob("*.json")):
            value = load_json(path)
            scan_sensitive(value, str(path))
            if path.name != "contract.json" and path.name not in responses and path.name not in PAGE_TWO_TO_FIRST:
                fail(f"{path}: fixture is not referenced by the contract manifest or pagination map")

        manifests[version] = (directory, manifest)

    return manifests


def validate_openapi(
    manifests: dict[str, tuple[Path, dict[str, Any]]], openapi_dir: Path
) -> int:
    try:
        import yaml  # type: ignore[import-not-found]
        import jsonschema  # type: ignore[import-not-found]
    except ImportError as exc:
        fail(f"OpenAPI validation requires PyYAML and jsonschema: {exc}")

    validated = 0
    for version, (directory, manifest) in manifests.items():
        spec_path = openapi_dir / f"{version}.yaml"
        try:
            raw = spec_path.read_bytes()
        except OSError as exc:
            fail(f"{spec_path}: cannot read pinned OpenAPI document: {exc}")
        expected_sha = manifest["source"]["sha256"]
        actual_sha = hashlib.sha256(raw).hexdigest()
        if actual_sha != expected_sha:
            fail(f"{spec_path}: SHA-256 mismatch: expected {expected_sha}, got {actual_sha}")

        spec = yaml.safe_load(raw)
        resolver = jsonschema.RefResolver.from_schema(spec)
        response_operations: dict[str, dict[str, Any]] = {}
        for operation in manifest["operations"]:
            response_operations[operation["response"]] = operation

        for fixture_name, operation in response_operations.items():
            api_path = operation["path"].split("?", 1)[0]
            response = spec["paths"][api_path][operation["method"].lower()]["responses"]["200"]
            schema = response.get("content", {}).get("application/json", {}).get("schema")
            if schema is None:
                continue
            jsonschema.validate(load_json(directory / fixture_name), schema, resolver=resolver)
            validated += 1

        for second_name, first_name in PAGE_TWO_TO_FIRST.items():
            operation = response_operations[first_name]
            api_path = operation["path"].split("?", 1)[0]
            schema = spec["paths"][api_path][operation["method"].lower()]["responses"]["200"]["content"]["application/json"]["schema"]
            jsonschema.validate(load_json(directory / second_name), schema, resolver=resolver)
            validated += 1

    return validated


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path("testdata/contracts/kibana"),
        help="contract fixture root",
    )
    parser.add_argument(
        "--openapi-dir",
        type=Path,
        help="optional directory containing v9.2.0.yaml and v9.4.2.yaml",
    )
    args = parser.parse_args()

    try:
        manifests = fixture_index(args.fixtures)
        validated = 0
        if args.openapi_dir is not None:
            validated = validate_openapi(manifests, args.openapi_dir)
    except (ValueError, KeyError, TypeError) as exc:
        print(f"contract verification failed: {exc}", file=sys.stderr)
        return 1

    fixture_count = sum(1 for path in args.fixtures.rglob("*.json"))
    suffix = f"; {validated} responses validated against pinned OpenAPI schemas" if args.openapi_dir else ""
    print(f"contract verification passed: {len(manifests)} versions, {fixture_count} JSON files{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
