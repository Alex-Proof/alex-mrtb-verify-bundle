#!/usr/bin/env python3
"""Independent devtask.execution@1.0 Evidence Package verifier.

JSON/evidence checks are implemented here, independently of the TypeScript verifier.
Ed25519 is delegated to the system OpenSSL binary; no Python packages are required.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

HEX64 = re.compile(r"^[a-f0-9]{64}$")
PREFIXES = {
    "contract": "devtask_contract_bound:", "attempt": "devtask_attempt_started:",
    "context": "devtask_execution_context:", "validation": "devtask_validation:",
    "approval": "devtask_human_approval:", "outcome": "devtask_outcome:",
    "diff": "devtask_diff_evidence:", "ci": "devtask_ci_result:",
}


def compact(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def canonical_evidence_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def key_id(pem: str) -> str:
    return "ed25519:" + sha256_text(pem)


def openssl_verify(public_key: str, payload: bytes, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        with tempfile.TemporaryDirectory(prefix="alex_verify_") as directory:
            key_path = os.path.join(directory, "key.pem")
            payload_path = os.path.join(directory, "payload.bin")
            signature_path = os.path.join(directory, "signature.bin")
            with open(key_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(public_key)
            with open(payload_path, "wb") as handle:
                handle.write(payload)
            with open(signature_path, "wb") as handle:
                handle.write(signature)
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", key_path,
                 "-rawin", "-in", payload_path, "-sigfile", signature_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
            return result.returncode == 0
    except (OSError, ValueError):
        return False


def event(events: list[str], name: str) -> dict[str, Any] | None:
    prefix = PREFIXES[name]
    for raw in events:
        if raw.startswith(prefix):
            try:
                parsed = json.loads(raw[len(prefix):])
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def protected_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return bool(re.search(r"(^|/)(__tests__|tests?|specs?)(/|$)", normalized) or
                re.search(r"\.(test|spec)\.[^/]+$", normalized) or
                re.search(r"(^|/)(vitest|jest|playwright|cypress)\.config\.[^/]+$", normalized))


def valid_repository(repository: Any, base_commit: Any) -> bool:
    if not isinstance(repository, dict) or repository.get("schema_version") != "repository-state@1.0":
        return False
    if repository.get("base_commit") != base_commit or not repository.get("result_commit"):
        return False
    before, after = repository.get("tree_before_sha256"), repository.get("tree_after_sha256")
    if not isinstance(before, str) or not HEX64.fullmatch(before) or not isinstance(after, str) or not HEX64.fullmatch(after) or before == after:
        return False
    files = repository.get("changed_files")
    if not isinstance(files, list) or not files:
        return False
    for item in files:
        if not isinstance(item, dict) or not item.get("path") or item.get("status") not in ("A", "M", "D"):
            return False
        status, old, new = item["status"], item.get("before_sha256"), item.get("after_sha256")
        if old is not None and (not isinstance(old, str) or not HEX64.fullmatch(old)):
            return False
        if new is not None and (not isinstance(new, str) or not HEX64.fullmatch(new)):
            return False
        if (status == "A" and old is not None) or (status == "D" and new is not None):
            return False
        if (status != "A" and old is None) or (status != "D" and new is None):
            return False
    return True


def derive(bundle: dict[str, Any]) -> str:
    events, controller = bundle.get("trace_events"), bundle.get("controller_evidence")
    if not isinstance(events, list) or not all(isinstance(item, str) for item in events) or not isinstance(controller, dict):
        return "inconclusive"
    values = {name: event(events, name) for name in PREFIXES}
    contract, attempt, outcome = values["contract"], values["attempt"], values["outcome"]
    if not contract or not attempt or not outcome:
        return "inconclusive"
    present = [item for item in values.values() if item]
    if any(item.get("task_id") != contract.get("task_id") or item.get("attempt_number") != contract.get("attempt_number") for item in present):
        return "failed"
    if controller.get("task_id") != contract.get("task_id") or controller.get("attempt_number") != contract.get("attempt_number"):
        return "failed"
    completed = outcome.get("outcome") == "COMPLETED"
    if completed and not values["approval"]:
        return "failed"
    validation = values["validation"]
    if completed and validation and validation.get("validation_status") not in ("passed", "passed_override"):
        return "failed"
    context, diff, approval = values["context"], values["diff"], values["approval"]
    if not context or controller.get("execution_reference") != context.get("execution_reference"):
        return "failed"
    if not validation or controller.get("validation_reference") != validation.get("validation_reference"):
        return "failed"
    if not diff or controller.get("diff_stat_sha256") != diff.get("diff_stat_sha256") or controller.get("diff_full_sha256") != diff.get("diff_full_sha256"):
        return "failed"
    full_diff, full_hash = controller.get("diff_full"), controller.get("diff_full_sha256")
    if not isinstance(full_diff, str) or not isinstance(full_hash, str) or sha256_text(full_diff) != full_hash:
        return "failed"
    if completed and controller.get("approval_reference") != approval.get("approval_reference"):
        return "failed"
    repository = controller.get("repository_state")
    if repository is not None and not valid_repository(repository, controller.get("base_commit")):
        return "failed"
    ci = values["ci"]
    if completed and ci:
        if (ci.get("task_id") != controller.get("task_id") or ci.get("attempt_number") != controller.get("attempt_number") or
                ci.get("result_commit") != (repository or {}).get("result_commit") or ci.get("source") != "github_checks_and_statuses"):
            return "failed"
        if ci.get("conclusion") == "failure":
            return "failed"
        if ci.get("conclusion") != "success":
            return "inconclusive"
    if contract.get("protect_existing_tests") is True:
        if not isinstance(repository, dict):
            return "inconclusive"
        violating = sorted(item["path"] for item in repository["changed_files"] if item.get("status") != "A" and protected_test_path(item["path"]))
        expected = {"schema_version": "test-integrity-policy@1.0", "policy": "protect_existing_tests",
                    "protected": True, "status": "failed" if violating else "passed", "violating_files": violating}
        if controller.get("test_integrity_policy") != expected or violating:
            return "failed"
    required = ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full"]
    if completed:
        required += ["human_approval", "result_reference", "ci_result"]
    if repository is not None:
        required.append("repository_state")
    if contract.get("protect_existing_tests") is True:
        required.append("test_integrity_policy")
    if bundle.get("required_evidence") != required:
        return "inconclusive"
    basics = [controller.get("base_commit"), controller.get("diff_full"), context, validation, outcome]
    if completed:
        basics += [controller.get("result_reference"), approval, ci]
    return "verified" if all(basics) else "inconclusive"


DEVTASK_V2_SCHEMA_VERSIONS = ("evidence-package@2.0", "evidence-package@2.1", "evidence-package@2.2")
DEVTASK_EVIDENCE_SPEC_VERSION = "devtask.execution@1.0"


def validate_spec_v1(bundle: dict[str, Any]) -> str | None:
    required = (
        "schema_version", "spec_version", "bundle_id", "capability", "run_id", "claim_ladder",
        "executed_at", "trace_events", "trace_hash_chain", "outcome", "signature", "public_key",
        "signer_key_id", "controller_evidence", "required_evidence", "approval_attestation_required",
    )
    for field in required:
        if field not in bundle or bundle[field] is None:
            return f"spec_validation_failed:missing_required_field:{field}"
    allowed = set(required) | {"customer_evidence", "rfc3161_timestamp", "approval_attestation", "observer_receipt"}
    if bundle.get("spec_version") != DEVTASK_EVIDENCE_SPEC_VERSION:
        return "spec_validation_failed:unsupported_spec_version"
    if bundle.get("capability") != DEVTASK_EVIDENCE_SPEC_VERSION:
        return "spec_validation_failed:capability_mismatch"
    if bundle.get("claim_ladder") not in ("L0", "L1", "L2"):
        return "spec_validation_failed:claim_ladder_out_of_range"
    controller = bundle.get("controller_evidence")
    controller_required = (
        "producer", "task_id", "attempt_number", "base_commit", "result_reference",
        "diff_stat_sha256", "diff_full", "diff_full_sha256", "execution_reference",
        "validation_reference", "approval_reference", "sandbox_reference",
        "sandbox_attestation", "agent_run_id",
    )
    if not isinstance(controller, dict):
        return "spec_validation_failed:missing_required_field:controller_evidence"
    for field in controller_required:
        if field not in controller:
            return f"spec_validation_failed:missing_controller_field:{field}"
    return None



NEGATIVE_CLAIM_PREFIX = "devtask_negative_claim:"


def claim_evidence_ref_assessments(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    base_events = [event for event in bundle.get("trace_events", []) if not event.startswith(NEGATIVE_CLAIM_PREFIX)]
    assessments: list[dict[str, Any]] = []
    for event in bundle.get("trace_events", []):
        if not event.startswith(NEGATIVE_CLAIM_PREFIX):
            continue
        try:
            claim = json.loads(event[len(NEGATIVE_CLAIM_PREFIX):])
        except (TypeError, json.JSONDecodeError):
            continue
        ref = claim.get("evidence_ref")
        required = claim.get("strength") in ("observed", "attested")
        if not isinstance(ref, dict):
            assessments.append({"claim": claim.get("claim"), "supported": False, "required": False, "reason": "missing_evidence_ref"})
            continue
        artifact = None
        if ref.get("artifact") == "attestation" and ref.get("id") == "controller_evidence.sandbox_attestation":
            artifact = (bundle.get("controller_evidence") or {}).get("sandbox_attestation")
        elif ref.get("artifact") == "runtime_trace" and ref.get("id") == "trace_events:without_negative_claims":
            artifact = base_events
        if artifact is None:
            assessments.append({"claim": claim.get("claim"), "supported": False, "required": required, "reason": "unresolved_evidence_ref"})
            continue
        expected = "sha256:" + sha256_bytes(canonical_evidence_bytes(artifact))
        if ref.get("digest") != expected:
            assessments.append({"claim": claim.get("claim"), "supported": False, "required": required, "reason": "digest_mismatch"})
            continue
        assessments.append({"claim": claim.get("claim"), "supported": True, "required": required})
    return assessments

def verify(bundle: dict[str, Any], trusted_key: str, approval_key: str | None) -> tuple[bool, str]:
    if bundle.get("schema_version") not in DEVTASK_V2_SCHEMA_VERSIONS or bundle.get("capability") != "devtask.execution@1.0":
        return False, "unsupported_schema_or_capability"
    if bundle.get("schema_version") == "evidence-package@2.2":
        spec_error = validate_spec_v1(bundle)
        if spec_error:
            return False, spec_error
    if shutil.which("openssl") is None:
        return False, "openssl_unavailable"
    embedded = bundle.get("public_key")
    if embedded != trusted_key or bundle.get("signer_key_id") != key_id(trusted_key):
        return False, "untrusted_signer"
    payload = {key: value for key, value in bundle.items() if key not in ("signature", "public_key", "rfc3161_timestamp", "approval_attestation", "observer_receipt")}
    signed_payload = canonical_evidence_bytes(payload) if bundle.get("schema_version") == "evidence-package@2.2" else compact(payload)
    if not openssl_verify(trusted_key, signed_payload, str(bundle.get("signature", ""))):
        return False, "invalid_signature"
    events, chain = bundle.get("trace_events", []), bundle.get("trace_hash_chain", [])
    previous, expected_chain = "genesis", []
    for raw in events:
        previous = sha256_text(previous + raw)
        expected_chain.append(previous)
    if chain != expected_chain:
        return False, "invalid_hash_chain"
    unsupported_required = next((claim for claim in claim_evidence_ref_assessments(bundle) if not claim["supported"] and claim["required"]), None)
    if unsupported_required:
        return False, "unsupported_required_claim:" + str(unsupported_required["claim"])
    derived = derive(bundle)
    if bundle.get("outcome") != derived:
        return False, f"trace_outcome_mismatch:declared={bundle.get('outcome')}:derived={derived}"
    if derived != "verified":
        return False, f"non_verified_outcome:{derived}"
    attestation = bundle.get("approval_attestation")
    if bundle.get("approval_attestation_required") is True:
        if not approval_key:
            return False, "missing_approval_trust_anchor"
        if not isinstance(attestation, dict) or attestation.get("public_key") != approval_key or attestation.get("signer_key_id") != key_id(approval_key):
            return False, "untrusted_approval_signer"
        approval_payload = {key: value for key, value in attestation.items() if key not in ("signature", "public_key", "signer_key_id")}
        if not openssl_verify(approval_key, compact(approval_payload), str(attestation.get("signature", ""))):
            return False, "invalid_approval_signature"
        # 06.09.2026 (identischer Fix wie verify.ts/evidenceBundle.server.ts): observer_receipt wird
        # in der Produktions-Pipeline immer erst NACH attachApprovalAttestation() angehaengt --
        # bundle_sha256 wurde ohne dieses Feld berechnet und muss hier ebenso ausgeschlossen werden.
        without_approval = {key: value for key, value in bundle.items() if key not in ("approval_attestation", "observer_receipt")}
        if attestation.get("bundle_sha256") != sha256_bytes(compact(without_approval)):
            return False, "approval_scope_mismatch"
    return True, "verified"


# Bauanleitung Evidence-Standard, Punkt 3 (06.09.2026): "Proof Policies" -- Mindestbeweislage vor
# einer als "gated" markierten Aktion. Format/Begruendung: spec/policies/README.md. Identische
# Kopie (Logik, nicht Code) in verify.ts und evidenceBundle.server.ts. Dieser Python-Verifier
# fuehrt NIE eine Live-Netzwerkpruefung durch (kein GitHub-Diff-, RFC-3161-Chain- oder
# Observer-Cross-Check wie in verify.ts) -- verifier_checks bleibt deshalb hier immer auf das
# offline Nachrechenbare beschraenkt. Eine Policy, die "independent_witness" verlangt, bleibt
# mit diesem Verifier folgerichtig IMMER blockiert (spec/INVARIANTS.md Invariante 2: unknown ist
# niemals gleichbedeutend mit pass) -- das ist keine Einschraenkung dieses Skripts, sondern die
# ehrliche Aussage, dass ein unabhaengiger Zeugennachweis offline nicht bestaetigt werden kann.
CLAIM_LADDER_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4}


def evaluate_proof_policy(policy: dict[str, Any], bundle: dict[str, Any], effective_claim_ladder: str,
                           verifier_checks: dict[str, str]) -> dict[str, Any]:
    evaluated: dict[str, Any] = {}
    blocked_by: list[str] = []

    def record(name: str, required: Any, satisfied: bool) -> None:
        evaluated[name] = {"required": required, "satisfied": satisfied}
        if not satisfied:
            blocked_by.append(name)

    requires = policy.get("requires", {})
    if "outcome" in requires:
        record("outcome", requires["outcome"], bundle.get("outcome") == requires["outcome"])
    if "claim_ladder_min" in requires:
        record("claim_ladder_min", requires["claim_ladder_min"],
                CLAIM_LADDER_RANK.get(effective_claim_ladder, -1) >= CLAIM_LADDER_RANK.get(requires["claim_ladder_min"], 99))
    if requires.get("human_approval") == "required":
        record("human_approval", "required", bundle.get("approval_attestation_required") is True)
    if requires.get("no_unsupported_required_claims") is True:
        unsupported = any(claim["required"] and not claim["supported"] for claim in claim_evidence_ref_assessments(bundle))
        record("no_unsupported_required_claims", True, not unsupported)
    if requires.get("independent_witness") == "required":
        record("independent_witness", "required", verifier_checks.get("observer_inclusion") == "ok")

    return {
        "policy_id": policy.get("policy_id"), "gates_action": policy.get("gates_action"),
        "allowed": len(blocked_by) == 0, "blocked_by": blocked_by, "evaluated": evaluated,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent Python verifier for ALEX dev-task Evidence Packages")
    parser.add_argument("bundle")
    parser.add_argument("trusted_key")
    parser.add_argument("approval_key", nargs="?")
    parser.add_argument("--policy", help="Pfad zu einer Proof-Policy-Datei (spec/policies/*.json) -- optionales Gate nach erfolgreicher Verifikation.")
    args = parser.parse_args()
    try:
        with open(args.bundle, encoding="utf-8") as handle:
            bundle = json.load(handle)
        with open(args.trusted_key, encoding="utf-8") as handle:
            trusted = handle.read()
        approval = None
        if args.approval_key:
            with open(args.approval_key, encoding="utf-8") as handle:
                approval = handle.read()
        ok, reason = verify(bundle, trusted, approval)
        print("VERIFIED" if ok else f"REJECTED: {reason}")
        if not ok:
            return 2
        if args.policy:
            with open(args.policy, encoding="utf-8") as handle:
                policy = json.load(handle)
            verifier_checks = {"signature": "ok", "hash_chain": "ok"}
            evaluation = evaluate_proof_policy(policy, bundle, bundle.get("claim_ladder", ""), verifier_checks)
            if evaluation["allowed"]:
                print(f"PROOF POLICY '{evaluation['policy_id']}' SATISFIED -- gated action '{evaluation['gates_action']}' allowed.")
            else:
                print(f"PROOF POLICY '{evaluation['policy_id']}' BLOCKED -- gated action '{evaluation['gates_action']}' denied. "
                      f"Missing: {', '.join(evaluation['blocked_by'])}")
                return 6
        return 0
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
