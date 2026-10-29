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

# Gepinnte FreeTSA Root CA (https://freetsa.org/files/cacert.pem), bytegleich mit verify.ts.
FREETSA_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----"""


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


def verify_rfc3161_binding(bundle: dict[str, Any]) -> tuple[bool, str | None]:
    timestamp = bundle.get("rfc3161_timestamp")
    if not isinstance(timestamp, dict):
        return False, "no_timestamp_present"
    # Diese vier Felder werden erst nach dem Zeitstempel angehaengt. Signatur und Public Key
    # gehoeren dagegen zur gehashten Nutzlast (identisch zu verifyRfc3161Binding() in verify.ts).
    payload = {
        key: value for key, value in bundle.items()
        if key not in ("rfc3161_timestamp", "approval_attestation", "observer_receipt", "epistemic_gate")
    }
    if sha256_bytes(compact(payload)) != timestamp.get("timestamped_sha256"):
        return False, "timestamp_hash_mismatch"
    return True, None


def verify_rfc3161_tsa_chain(timestamp: dict[str, Any]) -> tuple[bool, str | None]:
    digest = timestamp.get("timestamped_sha256")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        return False, "invalid_timestamped_sha256"
    try:
        token = base64.b64decode(str(timestamp.get("token_der_base64", "")), validate=True)
    except (ValueError, TypeError):
        return False, "invalid_token_base64"
    try:
        with tempfile.TemporaryDirectory(prefix="alex_verify_ts_") as directory:
            token_path = os.path.join(directory, "token.der")
            root_path = os.path.join(directory, "freetsa-root.pem")
            with open(token_path, "wb") as handle:
                handle.write(token)
            with open(root_path, "w", encoding="ascii", newline="\n") as handle:
                handle.write(FREETSA_ROOT_CA_PEM)
            result = subprocess.run(
                ["openssl", "ts", "-verify", "-in", token_path, "-token_in",
                 "-digest", digest, "-CAfile", root_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
            return (True, None) if result.returncode == 0 else (False, "tsa_chain_verification_failed")
    except OSError:
        return False, "openssl_unavailable"


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


_MISSING = object()  # modelliert JS `undefined` (vs. None = JS `null`) fuer byte-genaue !==-Paritaet

# Run 01 / "Code-Pruefstand": vier Sandbox-Policy-Profile fuer die policy_sha256-Nachrechnung. Flache
# Objekte; policy_sha256 = sha256 der sortiert-kompakt serialisierten Policy (bytegleich zu
# JSON.stringify(policy, Object.keys(policy).sort()) in verify.ts / core/mrtb/evidenceBundle.server.ts).
SANDBOX_ATTESTATION_POLICY_NO_NETWORK = {
    "schema_version": "sandbox-attestation@2.0", "filesystem": "snapshot_without_git_or_symlinks",
    "network": "bubblewrap_unshare_net_fail_closed", "environment": "bubblewrap_clearenv",
    "process": "systemd_scope_limits_and_kill", "handoff": "regular_files_only_filtered",
}
SANDBOX_ATTESTATION_POLICY_NETWORK_CAPTURE = {**SANDBOX_ATTESTATION_POLICY_NO_NETWORK, "network": "netns_egress_logged_v1"}
SANDBOX_ATTESTATION_POLICY_NETWORK_ENFORCED = {**SANDBOX_ATTESTATION_POLICY_NO_NETWORK, "network": "netns_egress_allowlisted_v1"}
SANDBOX_ATTESTATION_POLICY_NETWORK_PROXY_ONLY = {**SANDBOX_ATTESTATION_POLICY_NO_NETWORK, "network": "netns_egress_proxy_only_v1"}
SANDBOX_NETWORK_POLICIES = (
    "bubblewrap_unshare_net_fail_closed", "netns_egress_logged_v1",
    "netns_egress_allowlisted_v1", "netns_egress_proxy_only_v1",
)
EXECUTOR_ALLOWLIST = ("deepseek", "hermes", "opencode", "aider", "cline", "buzz")


def risk_rank(risk_class: Any) -> int:
    match = re.fullmatch(r"R([0-4])", risk_class) if isinstance(risk_class, str) else None
    return int(match.group(1)) if match else 4


def _policy_sha256(policy: dict[str, Any]) -> str:
    return sha256_bytes(json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _event_payload(raw: str, prefix: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw[len(prefix):])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


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
    # Basis-Gate (deriveOutcomeFromTrace, capability devtask): scope_violation, unabhaengige
    # negative_claim (result=False, strength != "policy_derived") und ungeloeste contradiction
    # blockieren "verified" -> "failed". Byte-genau zu deriveOutcomeFromTrace() in verify.ts.
    tid, anum = contract.get("task_id"), contract.get("attempt_number")
    for raw in events:
        if raw.startswith("devtask_scope_violation:"):
            v = _event_payload(raw, "devtask_scope_violation:")
            if v is not None and v.get("task_id") == tid and v.get("attempt_number") == anum:
                return "failed"
        elif raw.startswith("devtask_negative_claim:"):
            v = _event_payload(raw, "devtask_negative_claim:")
            if (v is not None and v.get("task_id") == tid and v.get("attempt_number") == anum
                    and v.get("strength") != "policy_derived" and v.get("result") is False):
                return "failed"
        elif raw.startswith("devtask_contradiction:"):
            v = _event_payload(raw, "devtask_contradiction:")
            if v is not None and v.get("resolved") is False:
                return "failed"
    context, diff, approval = values["context"], values["diff"], values["approval"]
    if not context or controller.get("execution_reference") != context.get("execution_reference"):
        return "failed"
    # Executor-Provenance: wenn behauptet (irgendeines der Felder gesetzt), muss sie vollstaendig
    # gueltig sein -- bekannter Executor, harness_id/adapter_version im erlaubten Muster,
    # adapter_version_sha256 == sha256(adapter_version). Spiegel zu deriveDevTaskV2Outcome() in
    # verify.ts; fehlende Einzelfelder werden sauber als ungueltig gewertet (kein Crash).
    executor, harness_id = context.get("executor"), context.get("harness_id")
    adapter_version, adapter_version_sha256 = context.get("adapter_version"), context.get("adapter_version_sha256")
    if (executor or harness_id or adapter_version or adapter_version_sha256) and (
            executor not in EXECUTOR_ALLOWLIST
            or not isinstance(harness_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", harness_id)
            or not isinstance(adapter_version, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._@/-]*", adapter_version)
            or adapter_version_sha256 != sha256_text(adapter_version)):
        return "failed"
    if not validation or controller.get("validation_reference") != validation.get("validation_reference"):
        return "failed"
    if not diff or controller.get("diff_stat_sha256") != diff.get("diff_stat_sha256") or controller.get("diff_full_sha256") != diff.get("diff_full_sha256"):
        return "failed"
    # diff_full===null -> ueberspringen (faellt ueber basics auf "inconclusive"), NICHT "failed":
    # byte-genau zu verify.ts (controller.diff_full !== null && diff_full_sha256 !== null && mismatch).
    full_diff, full_hash = controller.get("diff_full"), controller.get("diff_full_sha256")
    if full_diff is not None and full_hash is not None and (not isinstance(full_diff, str) or sha256_text(full_diff) != full_hash):
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
    # Sandbox-Attestation (Run 01 / "Code-Pruefstand", 4 Profile inkl. proxy_only): sandbox_reference
    # muss zu context UND zum berechneten Attestation-Hash passen; policy_sha256 haengt am behaupteten
    # network_policy-Profil, network_capture muss dazu konsistent sein (nur bei den netns_egress_*-
    # Profilen befuellt, sonst exakt null). Byte-genau zu deriveDevTaskV2Outcome() in verify.ts; JS
    # undefined/null via _MISSING modelliert, damit der "Feld fehlt ganz"-Fall (undefined !== null ->
    # failed) exakt wie in TS entscheidet.
    attestation = controller.get("sandbox_attestation")
    attestation_hash = ("sandbox-attestation:sha256:" + sha256_bytes(compact(attestation))) if attestation else None
    sandbox_ref = controller.get("sandbox_reference", _MISSING)
    if sandbox_ref != context.get("sandbox_reference", _MISSING) or sandbox_ref != attestation_hash:
        return "failed"
    network_policy = attestation.get("network_policy") if isinstance(attestation, dict) else None
    enforced_like = network_policy in ("netns_egress_logged_v1", "netns_egress_allowlisted_v1", "netns_egress_proxy_only_v1")
    expected_policy = (
        SANDBOX_ATTESTATION_POLICY_NETWORK_CAPTURE if network_policy == "netns_egress_logged_v1"
        else SANDBOX_ATTESTATION_POLICY_NETWORK_ENFORCED if network_policy == "netns_egress_allowlisted_v1"
        else SANDBOX_ATTESTATION_POLICY_NETWORK_PROXY_ONLY if network_policy == "netns_egress_proxy_only_v1"
        else SANDBOX_ATTESTATION_POLICY_NO_NETWORK)
    capture = attestation.get("network_capture", _MISSING) if isinstance(attestation, dict) else _MISSING
    if not attestation:
        network_capture_consistent = False
    elif enforced_like:
        network_capture_consistent = bool(
            isinstance(capture, dict)
            and capture.get("schema_version") == "egress-capture@1.0"
            and isinstance(capture.get("dns_queries_sha256"), str) and HEX64.fullmatch(capture["dns_queries_sha256"])
            and isinstance(capture.get("connections_sha256"), str) and HEX64.fullmatch(capture["connections_sha256"]))
    else:
        network_capture_consistent = capture is None
    sandbox_hashes = ([attestation.get(name) for name in ("snapshot_sha256", "policy_sha256", "handoff_manifest_sha256", "rejected_manifest_sha256")]
                      if isinstance(attestation, dict) else [])
    sandbox_valid = bool(
        isinstance(attestation, dict)
        and attestation.get("schema_version") == "sandbox-attestation@2.0"
        and attestation.get("os_isolation_available") and attestation.get("git_metadata_absent")
        and attestation.get("controller_checkout_separated")
        and network_policy in SANDBOX_NETWORK_POLICIES
        and network_capture_consistent
        and attestation.get("environment_policy") == "bubblewrap_clearenv"
        and attestation.get("process_policy") == "systemd_scope_limits_and_kill"
        and attestation.get("agent_id") == controller.get("agent_run_id")
        and attestation.get("policy_sha256") == _policy_sha256(expected_policy)
        and all(isinstance(h, str) and HEX64.fullmatch(h) for h in sandbox_hashes))
    rank = risk_rank(contract.get("risk_class"))
    required = ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full"]
    if completed:
        required += ["human_approval", "result_reference", "ci_result"]
    if rank >= 3:
        required.append("sandbox_attestation")
    if repository is not None:
        required.append("repository_state")
    if contract.get("protect_existing_tests") is True:
        required.append("test_integrity_policy")
    if bundle.get("required_evidence") != required:
        return "inconclusive"
    basics = [controller.get("base_commit"), controller.get("diff_full"), context, validation, outcome]
    if completed:
        basics += [controller.get("result_reference"), approval, ci]
    if rank >= 3:
        basics.append(sandbox_valid)
    return "verified" if all(basics) else "inconclusive"


# 28.09.2026: "evidence-package@2.3" ergaenzt (Iman/EMILIA-Feedback, SCITT-Mailingliste) -- Parity
# zu DEVTASK_V2_SCHEMA_VERSIONS in evidenceBundle.server.ts/verify.ts. 2.3 erzwingt zusaetzlich ein
# gueltiges epistemic_gate, siehe EPISTEMIC_GATE_REQUIRED_SCHEMA_VERSIONS unten.
DEVTASK_V2_SCHEMA_VERSIONS = ("evidence-package@2.0", "evidence-package@2.1", "evidence-package@2.2", "evidence-package@2.3")
EPISTEMIC_GATE_REQUIRED_SCHEMA_VERSIONS = ("evidence-package@2.3",)
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
    allowed = set(required) | {"customer_evidence", "rfc3161_timestamp", "approval_attestation", "observer_receipt", "epistemic_gate"}
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



# 01.10.2026 (vNext 4.18 Claim-Zerlegung): identische Logik zu validateClaimDecomposition() in
# core/claimDecomposition.server.ts / verify.ts -- unabhaengig gehaltener Spiegel. claim_decomposition
# ist, wenn vorhanden, Teil der signierten Nutzlast, wird aber zusaetzlich VOR der Signaturpruefung
# strukturell re-validiert. Bewusst OHNE die server-exklusive review.accepted_claim_ids-Pruefung --
# der Offline-Verifier re-validiert nur die signierte Kernstruktur, bytegleich zum TS-Spiegel.
CLAIM_DECOMPOSER_VERSION = "claim-decomposer@1.0"
CLAIM_ROUTING_RULE_VERSION = "claim-routing-rules@1.0"
CLAIM_ROUTE_BY_TYPE = {
    "fact": "retrieval", "logical_constraint": "formal_solver", "numeric": "calculation_engine",
    "recommendation": "human_review", "mixed": "none", "unknown": "none",
}
ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _claim_id(output_hash: str, start: int, end: int, claim_type: str) -> str:
    return "claim:sha256:" + sha256_text(f"{CLAIM_DECOMPOSER_VERSION}\0{output_hash}\0{start}\0{end}\0{claim_type}")


def validate_claim_decomposition(artifact: dict[str, Any], original_output: str, require_review: bool = False) -> str | None:
    """Re-validiert ein Artefakt ohne dem Erzeuger zu vertrauen -- identische Logik zu
    validateClaimDecomposition() in core/claimDecomposition.server.ts / verify.ts."""
    if artifact.get("schema_version") != "claim-decomposition@1.0":
        return "unsupported_schema_version"
    if artifact.get("transformer_version") != CLAIM_DECOMPOSER_VERSION:
        return "unsupported_transformer_version"
    if artifact.get("routing_rule_version") != CLAIM_ROUTING_RULE_VERSION:
        return "unsupported_routing_rule_version"
    if artifact.get("original_output_sha256") != "sha256:" + sha256_text(original_output):
        return "original_output_hash_mismatch"
    review = artifact.get("review") or {}
    if review.get("proposal_source") != "untrusted":
        return "invalid_proposal_source"
    if require_review and review.get("status") != "reviewed":
        return "review_required"
    if review.get("status") == "reviewed":
        reviewed_at = review.get("reviewed_at")
        if not review.get("reviewed_by") or not isinstance(reviewed_at, str) or not ISO8601_RE.match(reviewed_at):
            return "invalid_review_metadata"
    elif review.get("status") != "unreviewed" or review.get("reviewed_by") is not None or review.get("reviewed_at") is not None:
        return "invalid_review_metadata"
    claims = artifact.get("claims")
    if not isinstance(claims, list) or len(claims) == 0:
        return "missing_claims"

    cursor = 0
    for claim in claims:
        start, end = claim.get("source_start"), claim.get("source_end")
        if (not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool)
                or start < cursor or end <= start or end > len(original_output)):
            return "invalid_claim_offsets"
        if original_output[cursor:start].strip():
            return "uncovered_source_text"
        if claim.get("source_text") != original_output[start:end]:
            return "source_text_mismatch"
        claim_type = claim.get("type")
        if claim_type not in CLAIM_ROUTE_BY_TYPE or claim.get("route") != CLAIM_ROUTE_BY_TYPE[claim_type]:
            return "routing_mismatch"
        if claim.get("claim_id") != _claim_id(artifact["original_output_sha256"], start, end, claim_type):
            return "claim_id_mismatch"
        dependencies = claim.get("dependencies")
        if not isinstance(dependencies, list) or any(not isinstance(dep, str) or not dep for dep in dependencies):
            return "invalid_claim_dependency"
        if claim_type == "recommendation" and claim.get("status") != "human_review_required":
            return "recommendation_status_mismatch"
        if claim_type in ("mixed", "unknown") and claim.get("status") != "not_verifiable":
            return "unverifiable_status_mismatch"
        cursor = end
    if original_output[cursor:].strip():
        return "uncovered_source_text"
    return None


NEGATIVE_CLAIM_PREFIX = "devtask_negative_claim:"


def _has_complete_policy_kernel_file_observation(bundle: dict[str, Any]) -> bool:
    controller = bundle.get("controller_evidence")
    attestation = controller.get("sandbox_attestation") if isinstance(controller, dict) else None
    observation = attestation.get("file_observation") if isinstance(attestation, dict) else None
    return (
        isinstance(observation, dict)
        and observation.get("schema_version") == "policy-kernel-file-observation@1.0"
        and observation.get("observer") == "policy_kernel_process"
        and isinstance(observation.get("kernel_pid"), int) and observation["kernel_pid"] > 0
        and isinstance(observation.get("allowed_write_paths"), list)
        and isinstance(observation.get("inspected_entry_count"), int) and observation["inspected_entry_count"] >= 0
        and observation.get("blocked_attempt_count") == 0
        and isinstance(observation.get("completed_at"), str) and len(observation["completed_at"]) > 0
    )


def effective_negative_claim_strengths(bundle: dict[str, Any], verifier_checks: dict[str, str]) -> dict[str, str]:
    """Verifier-derived view only; never mutates signed claims or their outcome."""
    result: dict[str, str] = {}
    for raw in bundle.get("trace_events", []):
        if not isinstance(raw, str) or not raw.startswith(NEGATIVE_CLAIM_PREFIX):
            continue
        try:
            claim = json.loads(raw[len(NEGATIVE_CLAIM_PREFIX):])
        except (TypeError, json.JSONDecodeError):
            continue
        strength = claim.get("strength")
        if (
            claim.get("claim") == "no_write_outside_allowlist"
            and claim.get("result") is True
            and strength == "observed"
            and _has_complete_policy_kernel_file_observation(bundle)
            and verifier_checks.get("policy_kernel_witness") == "ok"
        ):
            strength = "independently_witnessed"
        if isinstance(claim.get("claim"), str) and isinstance(strength, str):
            result[claim["claim"]] = strength
    return result

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
    # 2.3 ist "2.2 + Pflicht-Gate": erbt dieselbe Spec-Validierung/Kanonisierung wie 2.2, keine
    # eigene, dritte Nutzlastform (Parity zu verifyBundleObject() in verify.ts).
    if bundle.get("schema_version") in ("evidence-package@2.2", "evidence-package@2.3"):
        spec_error = validate_spec_v1(bundle)
        if spec_error:
            return False, spec_error
    claim_decomposition = bundle.get("claim_decomposition")
    if claim_decomposition is not None:
        decomposition_error = validate_claim_decomposition(claim_decomposition, claim_decomposition.get("original_output", ""), True)
        if decomposition_error:
            return False, f"claim_decomposition_{decomposition_error}"
    if shutil.which("openssl") is None:
        return False, "openssl_unavailable"
    embedded = bundle.get("public_key")
    if embedded != trusted_key or bundle.get("signer_key_id") != key_id(trusted_key):
        return False, "untrusted_signer"
    payload = {key: value for key, value in bundle.items() if key not in ("signature", "public_key", "rfc3161_timestamp", "approval_attestation", "observer_receipt", "epistemic_gate")}
    signed_payload = canonical_evidence_bytes(payload) if bundle.get("schema_version") in ("evidence-package@2.2", "evidence-package@2.3") else compact(payload)
    if not openssl_verify(trusted_key, signed_payload, str(bundle.get("signature", ""))):
        return False, "invalid_signature"
    # 28.09.2026 (Iman/EMILIA-Feedback): fuer evidence-package@2.3 ist epistemic_gate PFLICHT, nicht
    # nur additiv-optional wie fuer 2.0-2.2 (Parity zu verifyBundleObject() in verify.ts). Laeuft im
    # blossen Bundle-Check, nicht nur im Verdict-Artefakt-Pfad.
    if bundle.get("schema_version") in EPISTEMIC_GATE_REQUIRED_SCHEMA_VERSIONS:
        gate_ok, gate_reason = verify_epistemic_gate_binding(bundle, trusted_key)
        if not gate_ok:
            return False, f"epistemic_gate_{gate_reason or 'invalid'}"
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
        # 26.09.2026: epistemic_gate haengt noch spaeter an (nach observer_receipt), gleicher Grund.
        without_approval = {key: value for key, value in bundle.items() if key not in ("approval_attestation", "observer_receipt", "epistemic_gate")}
        if attestation.get("bundle_sha256") != sha256_bytes(compact(without_approval)):
            return False, "approval_scope_mismatch"
    return True, "verified"


# 26.09.2026 (Iman/EMILIA-Protocol, SCITT-Mailingliste): Python-Parity zu
# verifyEpistemicGateBinding() in host/receipts.server.ts / verify.ts. verify() oben ruft diese
# Funktion NICHT selbst auf -- identisches Muster wie die TS-Seite: eine separate, explizit
# aufzurufende Pruefung, kein Teil der Kernsignaturpruefung. compact() reproduziert JS' schlichtes
# JSON.stringify() bytegleich (keine Schluessel-Sortierung, kein ASCII-Escaping), deshalb matcht
# der hier neu berechnete Hash exakt den serverseitig zum Anhaengezeitpunkt berechneten.
def verify_epistemic_gate_binding(bundle: dict[str, Any], trusted_key: str) -> tuple[bool, str | None]:
    attestation = bundle.get("epistemic_gate")
    if not attestation:
        return False, "epistemic_gate_not_attached"
    public_key = attestation.get("public_key")
    if public_key != trusted_key or attestation.get("signer_key_id") != key_id(trusted_key):
        return False, "untrusted_epistemic_gate_signer"
    without_gate = {key: value for key, value in bundle.items() if key != "epistemic_gate"}
    if attestation.get("bundle_sha256") != sha256_bytes(compact(without_gate)):
        return False, "epistemic_gate_hash_mismatch"
    payload = {key: value for key, value in attestation.items() if key not in ("signature", "public_key", "signer_key_id")}
    if not openssl_verify(public_key, compact(payload), str(attestation.get("signature", ""))):
        return False, "invalid_epistemic_gate_signature"
    return True, None


# Bauanleitung Evidence-Standard, Punkt 3 (06.09.2026): "Proof Policies" -- Mindestbeweislage vor
# einer als "gated" markierten Aktion. Format/Begruendung: spec/policies/README.md. Identische
# Kopie (Logik, nicht Code) in verify.ts und evidenceBundle.server.ts. Dieser Python-Verifier
# fuehrt NIE eine Live-Netzwerkpruefung durch (kein GitHub-Diff- oder Observer-Cross-Check wie in
# verify.ts); die RFC-3161-Kette wird rein offline gegen die gepinnte FreeTSA-Root geprueft.
# verifier_checks bleibt auf das offline Nachrechenbare beschraenkt. Eine Policy, die "independent_witness" verlangt, bleibt
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


def verify_agent_passport_card_v1(artifact: dict[str, Any], trusted_key: str) -> tuple[bool, str | None]:
    """Spiegel zu verifyAgentPassportCardV1() in verify.ts (kein Shared Import). identity_line_id,
    barcode (AXP-<identity[:20].upper>), qr-Payload und Signatur werden offline nachgerechnet. canonical
    == canonicalEvidenceJson fuer JSON-geparste Daten (kein undefined) -> canonical_evidence_bytes."""
    if artifact.get("schema_version") != "agent-passport-card@1.0":
        return False, "unsupported_schema_version"
    if artifact.get("public_key") != trusted_key or artifact.get("signer_key_id") != key_id(trusted_key):
        return False, "untrusted_signer"
    passport = artifact.get("passport") if isinstance(artifact.get("passport"), dict) else {}
    identity = sha256_bytes(canonical_evidence_bytes({
        "adapter_binary_hash": passport.get("adapter_binary_hash"),
        "model_version": passport.get("model_version"),
        "tool_manifest": passport.get("tool_manifest"),
        "enforcement_class": passport.get("enforcement_class"),
    }))
    if artifact.get("identity_line_id") != identity:
        return False, "identity_line_id_mismatch"
    barcode = artifact.get("barcode") if isinstance(artifact.get("barcode"), dict) else {}
    if barcode.get("format") != "code128" or barcode.get("value") != f"AXP-{identity[:20].upper()}":
        return False, "barcode_projection_mismatch"
    qr = artifact.get("qr") if isinstance(artifact.get("qr"), dict) else {}
    qr_payload = f"alex:agent-passport:v1?identity={identity}&receipt={artifact.get('receipt_content_sha256')}"
    if qr.get("format") != "qrcode" or qr.get("payload") != qr_payload:
        return False, "qr_projection_mismatch"
    payload = {key: value for key, value in artifact.items() if key != "signature"}
    if openssl_verify(trusted_key, canonical_evidence_bytes(payload), str(artifact.get("signature", ""))):
        return True, None
    return False, "invalid_signature"


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
        # CLI-Dispatch nach schema_version (Spiegel zu main() in verify.ts): Hilfsartefakte laufen
        # ueber ihren eigenen Verifier, Evidence-Bundles fallen in den verify()-Pfad unten.
        if bundle.get("schema_version") == "agent-passport-card@1.0":
            ok, reason = verify_agent_passport_card_v1(bundle, trusted)
            if ok:
                print(f"Agent passport card {bundle.get('identity_line_id')} for receipt {bundle.get('receipt_id')} verified offline.")
                return 0
            print(f"Agent passport card verification failed: {reason}", file=sys.stderr)
            return 2
        approval = None
        if args.approval_key:
            with open(args.approval_key, encoding="utf-8") as handle:
                approval = handle.read()
        ok, reason = verify(bundle, trusted, approval)
        print("VERIFIED" if ok else f"REJECTED: {reason}")
        if not ok:
            return 2
        checks = {"signature": "ok", "hash_chain": "ok"}
        timestamp = bundle.get("rfc3161_timestamp")
        if isinstance(timestamp, dict):
            binding_ok, binding_reason = verify_rfc3161_binding(bundle)
            checks["rfc3161_binding"] = "ok" if binding_ok else (binding_reason or "failed")
            if binding_ok:
                chain_ok, chain_reason = verify_rfc3161_tsa_chain(timestamp)
                checks["rfc3161_chain"] = "ok" if chain_ok else (chain_reason or "failed")
        else:
            checks["rfc3161_binding"] = "not_applicable_no_timestamp"
        print(json.dumps({"checks": checks}, indent=2))
        if args.policy:
            with open(args.policy, encoding="utf-8") as handle:
                policy = json.load(handle)
            verifier_checks = {**checks, "policy_kernel_witness": "not_checked_offline"}
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
