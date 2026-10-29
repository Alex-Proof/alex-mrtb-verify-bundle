import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { deriveDevTaskV2Outcome, requiredDevTaskEvidenceV2 } from "../dist/verify.js";

// Phase 1 (29.10.2026): umfassender TS<->Python-Paritaetstest fuer die devtask-Ableitung
// (deriveDevTaskV2Outcome in verify.ts vs. derive() in verify.py). Deckt die bis dahin nur in TS
// vorhandene Sandbox-Attestation-Ableitung (4 network_policy-Profile inkl. netns_egress_proxy_only_v1,
// policy_sha256, network_capture, sandbox_reference) und Executor-Provenance ab, dazu die Basis-Gate-
// Checks (scope_violation / unabhaengige negative_claim / ungeloeste contradiction) und die diff_full-
// Behandlung. Verglichen wird auf derive-Ebene: dieselbe (events, controller) -> dasselbe Verdikt.
// required_evidence wird pro Fall auf requiredDevTaskEvidenceV2() gesetzt, damit die Python-seitige
// required_evidence-Pruefung nicht stoert (sie ist in verify.ts an anderer Stelle, nicht in derive()).
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const sha256 = value => createHash("sha256").update(value).digest("hex");
const hex = char => char.repeat(64);
const ev = (prefix, obj) => prefix + JSON.stringify(obj);

const BASE_POLICY = {
  schema_version: "sandbox-attestation@2.0", filesystem: "snapshot_without_git_or_symlinks",
  network: "bubblewrap_unshare_net_fail_closed", environment: "bubblewrap_clearenv",
  process: "systemd_scope_limits_and_kill", handoff: "regular_files_only_filtered",
};
function policyHash(network) {
  const policy = { ...BASE_POLICY, network };
  return sha256(JSON.stringify(policy, Object.keys(policy).sort()));
}
const ENFORCED_LIKE = ["netns_egress_logged_v1", "netns_egress_allowlisted_v1", "netns_egress_proxy_only_v1"];

function sandboxAttestation(network_policy, overrides = {}) {
  const att = {
    schema_version: "sandbox-attestation@2.0",
    os_isolation_available: true, git_metadata_absent: true, controller_checkout_separated: true,
    network_policy,
    network_capture: ENFORCED_LIKE.includes(network_policy)
      ? { schema_version: "egress-capture@1.0", dns_queries_sha256: hex("a"), connections_sha256: hex("b") }
      : null,
    environment_policy: "bubblewrap_clearenv", process_policy: "systemd_scope_limits_and_kill",
    agent_id: "agent-1",
    policy_sha256: policyHash(network_policy),
    snapshot_sha256: hex("c"), handoff_manifest_sha256: hex("d"), rejected_manifest_sha256: hex("e"),
    ...overrides,
  };
  return att;
}

// Baut ein VERIFIED, COMPLETED devtask-v2-Bundle (events + controller). Standardmaessig High-Risk (R4)
// mit gueltigem proxy-only-Sandbox-Attestat. extraEvents werden angehaengt.
function baseInputs({ network_policy = "netns_egress_proxy_only_v1", risk_class = "R4", withSandbox = true,
  attestationOverrides = {}, contextOverrides = {}, extraEvents = [], diffFull = "diff text here" } = {}) {
  const tid = "t1", an = 1;
  const diff_full_sha256 = diffFull === null ? null : sha256(diffFull);
  const att = withSandbox ? sandboxAttestation(network_policy, attestationOverrides) : null;
  const sandbox_reference = withSandbox ? `sandbox-attestation:sha256:${sha256(JSON.stringify(att))}` : null;
  const context = {
    task_id: tid, attempt_number: an, execution_reference: "exec-1", sandbox_reference,
    executor: "cline", harness_id: "h1", adapter_version: "v1@1.0", adapter_version_sha256: sha256("v1@1.0"),
    ...contextOverrides,
  };
  const repository_state = {
    schema_version: "repository-state@1.0", base_commit: "base-commit", result_commit: "result-commit",
    tree_before_sha256: hex("a"), tree_after_sha256: hex("b"),
    changed_files: [{ path: "src/x.ts", status: "M", before_sha256: hex("c"), after_sha256: hex("d") }],
  };
  const controller = {
    producer: "privileged_controller", task_id: tid, attempt_number: an, base_commit: "base-commit",
    execution_reference: "exec-1", validation_reference: "val-1", diff_stat_sha256: hex("a"),
    diff_full: diffFull, diff_full_sha256, result_reference: "res-1", approval_reference: "appr-1",
    agent_run_id: "agent-1", sandbox_reference, sandbox_attestation: att, repository_state,
  };
  const events = [
    ev("devtask_contract_bound:", { task_id: tid, attempt_number: an, risk_class, protect_existing_tests: false }),
    ev("devtask_attempt_started:", { task_id: tid, attempt_number: an }),
    ev("devtask_execution_context:", context),
    ev("devtask_validation:", { task_id: tid, attempt_number: an, validation_reference: "val-1", validation_status: "passed" }),
    ev("devtask_human_approval:", { task_id: tid, attempt_number: an, approval_reference: "appr-1" }),
    ev("devtask_diff_evidence:", { task_id: tid, attempt_number: an, diff_stat_sha256: hex("a"), diff_full_sha256 }),
    ev("devtask_ci_result:", { task_id: tid, attempt_number: an, result_commit: "result-commit", source: "github_checks_and_statuses", checked_at: "2026-10-29T00:00:00.000Z", conclusion: "success" }),
    ev("devtask_outcome:", { task_id: tid, attempt_number: an, outcome: "COMPLETED" }),
    ...extraEvents,
  ];
  return { events, controller };
}

function pythonDerive(events, controller) {
  const dir = mkdtempSync(join(tmpdir(), "devtask-"));
  const inputPath = join(dir, "bundle.json");
  const bundle = { trace_events: events, controller_evidence: controller, required_evidence: requiredDevTaskEvidenceV2(events, controller) };
  writeFileSync(inputPath, JSON.stringify(bundle), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "b=json.load(open(sys.argv[2],encoding='utf-8'))",
    "print(m.derive(b))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

// Jeder Fall: Build-Funktion -> erwartetes Verdikt. Geprueft wird (1) TS liefert das Erwartete und
// (2) Python liefert byte-gleich dasselbe wie TS.
const cases = {
  "proxy_only valid (R4)": [() => baseInputs({ network_policy: "netns_egress_proxy_only_v1" }), "verified"],
  "logged valid (R4)": [() => baseInputs({ network_policy: "netns_egress_logged_v1" }), "verified"],
  "allowlisted valid (R4)": [() => baseInputs({ network_policy: "netns_egress_allowlisted_v1" }), "verified"],
  "no-network valid, capture null (R4)": [() => baseInputs({ network_policy: "bubblewrap_unshare_net_fail_closed" }), "verified"],
  "no-network but capture NOT null -> sandbox invalid": [
    () => baseInputs({ network_policy: "bubblewrap_unshare_net_fail_closed", attestationOverrides: { network_capture: { schema_version: "egress-capture@1.0", dns_queries_sha256: hex("a"), connections_sha256: hex("b") } } }), "inconclusive"],
  "enforced profile but capture null -> sandbox invalid": [
    () => baseInputs({ network_policy: "netns_egress_proxy_only_v1", attestationOverrides: { network_capture: null } }), "inconclusive"],
  "wrong policy_sha256 -> sandbox invalid": [
    () => baseInputs({ attestationOverrides: { policy_sha256: hex("f") } }), "inconclusive"],
  "unknown network_policy -> sandbox invalid": [
    () => baseInputs({ network_policy: "something_else" }), "inconclusive"],
  "bad snapshot_sha256 (not hex) -> sandbox invalid": [
    () => baseInputs({ attestationOverrides: { snapshot_sha256: "nope" } }), "inconclusive"],
  "agent_id != agent_run_id -> sandbox invalid": [
    () => baseInputs({ attestationOverrides: { agent_id: "other" } }), "inconclusive"],
  "controller.sandbox_reference mismatch -> failed": [
    () => { const b = baseInputs(); b.controller.sandbox_reference = "sandbox-attestation:sha256:" + hex("0"); return b; }, "failed"],
  "context.sandbox_reference mismatch -> failed": [
    () => { const b = baseInputs(); b.events[2] = ev("devtask_execution_context:", { task_id: "t1", attempt_number: 1, execution_reference: "exec-1", sandbox_reference: "sandbox-attestation:sha256:" + hex("0"), executor: "cline", harness_id: "h1", adapter_version: "v1@1.0", adapter_version_sha256: sha256("v1@1.0") }); return b; }, "failed"],
  "low-risk R2, no sandbox (all null) -> verified": [
    () => baseInputs({ risk_class: "R2", withSandbox: false }), "verified"],
  "low-risk R2 with valid sandbox -> verified": [
    () => baseInputs({ risk_class: "R2" }), "verified"],
  "executor invalid name -> failed": [
    () => baseInputs({ contextOverrides: { executor: "evil" } }), "failed"],
  "executor absent (no provenance) -> verified": [
    () => baseInputs({ contextOverrides: { executor: undefined, harness_id: undefined, adapter_version: undefined, adapter_version_sha256: undefined } }), "verified"],
  "harness_id bad pattern -> failed": [
    () => baseInputs({ contextOverrides: { harness_id: "BAD ID" } }), "failed"],
  "adapter_version_sha256 wrong -> failed": [
    () => baseInputs({ contextOverrides: { adapter_version_sha256: hex("0") } }), "failed"],
  "scope_violation event -> failed": [
    () => baseInputs({ extraEvents: [ev("devtask_scope_violation:", { task_id: "t1", attempt_number: 1, violation_type: "scope_violation" })] }), "failed"],
  "negative_claim result=false (observed) -> failed": [
    () => baseInputs({ extraEvents: [ev("devtask_negative_claim:", { task_id: "t1", attempt_number: 1, strength: "observed", result: false })] }), "failed"],
  "negative_claim result=false (policy_derived) -> verified": [
    () => baseInputs({ extraEvents: [ev("devtask_negative_claim:", { task_id: "t1", attempt_number: 1, strength: "policy_derived", result: false })] }), "verified"],
  "contradiction unresolved -> failed": [
    () => baseInputs({ extraEvents: [ev("devtask_contradiction:", { task_id: "t1", attempt_number: 1, resolved: false })] }), "failed"],
  "diff_full null -> inconclusive": [
    () => baseInputs({ diffFull: null }), "inconclusive"],
  "validation_status not passed (completed) -> failed": [
    () => { const b = baseInputs(); b.events[3] = ev("devtask_validation:", { task_id: "t1", attempt_number: 1, validation_reference: "val-1", validation_status: "failed" }); return b; }, "failed"],
};

test("devtask derive(): TS and Python agree across the full branch matrix", () => {
  for (const [name, [build, expected]] of Object.entries(cases)) {
    const { events, controller } = build();
    const ts = deriveDevTaskV2Outcome(events, controller);
    const py = pythonDerive(events, controller);
    assert.equal(ts, expected, `TS verdict for "${name}"`);
    assert.equal(py, ts, `parity TS<->Python for "${name}"`);
  }
});
