import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildVerifierBindingManifestV1, verifyVerifierBindingManifestV1 } from "../dist/verify.js";

// 31.10.2026: TS<->Python-Paritaet fuer verifier-binding-manifest@1.0 (sechs Anker, Begruendung
// siehe Kommentar bei VerifierBindingManifestV1 in verify.ts). Gleiches Fixture-/Vergleichsmuster
// wie test/python-verdict.test.mjs: ein echtes, per raw Ed25519 signiertes Quell-Bundle, beide
// Verifier leiten dasselbe Manifest unabhaengig ab und muessen byte-gleich zustimmen.
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const sha256 = v => createHash("sha256").update(v).digest("hex");

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().filter(k => value[k] !== undefined).map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}
const sha256Canonical = value => "sha256:" + sha256(canonical(value));

function sourceBundle({ withCiResult = true, withApproval = true } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const run = { task_id: "manifest-src", attempt_number: 1 };
  const contract_snapshot = { rawText: "Testauftrag fuer verifier-binding-manifest.", acceptanceCriteria: ["ok"], protectExistingTests: false };
  const contractHash = sha256(JSON.stringify(contract_snapshot));
  const repositoryState = {
    schema_version: "repository-state@1.0", base_commit: "a".repeat(40), result_commit: "b".repeat(40),
    tree_before_sha256: sha256("before"), tree_after_sha256: sha256("after"), changed_files: [],
  };
  const traceEvents = [
    `devtask_contract_bound:${JSON.stringify({ ...run, contract_hash: contractHash, risk_class: "R1" })}`,
    `devtask_attempt_started:${JSON.stringify({ ...run, started_at: "2026-10-31T00:00:00Z" })}`,
    `devtask_execution_context:${JSON.stringify({ ...run, execution_reference: "attempt:1", sandbox_reference: null })}`,
    `devtask_validation:${JSON.stringify({ ...run, validation_status: "passed", validation_reference: "validation:1" })}`,
    `devtask_diff_evidence:${JSON.stringify({ ...run, diff_stat_sha256: sha256("stat"), diff_full_sha256: sha256("diff"), scope: "diff_stat_and_full" })}`,
    `devtask_outcome:${JSON.stringify({ ...run, outcome: "ABORTED", completed_at: "2026-10-31T00:01:00Z" })}`,
  ];
  if (withCiResult) {
    traceEvents.push(`devtask_ci_result:${JSON.stringify({
      ...run, result_commit: repositoryState.result_commit, conclusion: "success",
      checked_at: "2026-10-31T00:00:45Z", source: "github_checks_and_statuses",
      checks: [{ name: "build", conclusion: "success" }],
    })}`);
  }
  let prev = "genesis";
  const trace_hash_chain = traceEvents.map(e => (prev = sha256(prev + e)));
  const controller_evidence = {
    producer: "privileged_controller", ...run, base_commit: repositoryState.base_commit, result_reference: null,
    policy_snapshot_sha256: sha256("policy-snapshot"), diff_stat_sha256: sha256("stat"), diff_full: "diff",
    diff_full_sha256: sha256("diff"), execution_reference: "attempt:1", validation_reference: "validation:1",
    approval_reference: null, sandbox_reference: null, sandbox_attestation: null, agent_run_id: null,
    contract_snapshot, repository_state: repositoryState,
  };
  const payload = {
    schema_version: "evidence-package@2.2", spec_version: "devtask.execution@1.0", bundle_id: "manifest-src", capability: "devtask.execution@1.0",
    run_id: "manifest-src:1", claim_ladder: "L0", executed_at: "2026-10-31T00:01:00Z",
    trace_events: traceEvents, trace_hash_chain, outcome: "failed",
    signer_key_id: `ed25519:${sha256(pem)}`, controller_evidence,
    required_evidence: ["contract", "attempt", "execution_context", "validation", "outcome", "base_commit", "diff_full", "repository_state"],
    approval_attestation_required: false,
  };
  // evidence-package@2.2 signiert kanonisches JSON (sortierte Keys), nicht JSON.stringify() --
  // anders als das 2.0-Fixture-Muster in test/python-verdict.test.mjs.
  const signature = sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64");
  let bundle = { ...payload, signature, public_key: pem };

  if (withApproval) {
    const approvalKeys = generateKeyPairSync("ed25519");
    const approvalPem = approvalKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
    const approvalPayload = { schema_version: "approval-attestation@1.0", actor_id: "andre", approved_at: "2026-10-31T00:00:30Z", bundle_sha256: sha256(JSON.stringify(bundle)) };
    const approvalSignature = sign(null, Buffer.from(JSON.stringify(approvalPayload), "utf8"), approvalKeys.privateKey).toString("base64");
    bundle = { ...bundle, approval_attestation: { ...approvalPayload, signer_key_id: `ed25519:${sha256(approvalPem)}`, public_key: approvalPem, signature: approvalSignature } };
    return { bundle, pem, approvalPem };
  }
  return { bundle, pem, approvalPem: null };
}

const PYTHON_MANIFEST_DRIVER = [
  "import importlib.util, json, sys",
  "spec = importlib.util.spec_from_file_location('verify_py', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
  "d = json.load(open(sys.argv[2], encoding='utf-8'))",
  "try:",
  "    manifest = m.build_verifier_binding_manifest_v1(d['bundle'])",
  "    print(json.dumps({'manifest': manifest}))",
  "except ValueError as e:",
  "    print(json.dumps({'error': str(e)}))",
  "",
].join("\n");

function pythonManifest(bundle) {
  const dir = mkdtempSync(join(tmpdir(), "manifest-"));
  const inputPath = join(dir, "input.json");
  const driverPath = join(dir, "driver.py");
  writeFileSync(inputPath, JSON.stringify({ bundle }), "utf8");
  writeFileSync(driverPath, PYTHON_MANIFEST_DRIVER, "utf8");
  const result = spawnSync(process.env.PYTHON ?? "python", [driverPath, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim());
}

function pythonVerify(manifest, bundle, trustedKey, approvalKey) {
  const dir = mkdtempSync(join(tmpdir(), "manifest-verify-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ manifest, bundle, trustedKey, approvalKey }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify_verifier_binding_manifest_v1(d['manifest'],d['bundle'],d['trustedKey'],d.get('approvalKey'))",
    "print('ok' if ok else reason)",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test("verifier-binding-manifest: TS and Python derive an identical manifest for a valid bundle", () => {
  const { bundle } = sourceBundle();
  const tsManifest = buildVerifierBindingManifestV1(bundle);
  const py = pythonManifest(bundle);
  assert.deepEqual(py.manifest, tsManifest);
});

test("verifier-binding-manifest: honest null anchors when ci_result/approval are absent, not fabricated", () => {
  const { bundle } = sourceBundle({ withCiResult: false, withApproval: false });
  const tsManifest = buildVerifierBindingManifestV1(bundle);
  assert.equal(tsManifest.test_result_hash, null);
  assert.equal(tsManifest.approval_event_hash, null);
  const py = pythonManifest(bundle);
  assert.deepEqual(py.manifest, tsManifest);
});

test("verifier-binding-manifest: TS and Python agree on verification, including a forged diff_hash", () => {
  const { bundle, pem, approvalPem } = sourceBundle();
  const manifest = buildVerifierBindingManifestV1(bundle);

  const tsValid = verifyVerifierBindingManifestV1(manifest, bundle, pem, approvalPem);
  assert.deepEqual(tsValid, { ok: true });
  assert.equal(pythonVerify(manifest, bundle, pem, approvalPem), "ok");

  const forged = { ...manifest, diff_hash: sha256("anderer-diff") };
  const tsForged = verifyVerifierBindingManifestV1(forged, bundle, pem, approvalPem);
  assert.equal(tsForged.reason, "manifest_derivation_mismatch");
  assert.equal(pythonVerify(forged, bundle, pem, approvalPem), "manifest_derivation_mismatch");
});

test("verifier-binding-manifest: a tampered approval signature is rejected even though the manifest hash still matches", () => {
  const { bundle, pem, approvalPem } = sourceBundle();
  const tampered = { ...bundle, approval_attestation: { ...bundle.approval_attestation, signature: Buffer.from("not-a-real-signature").toString("base64") } };
  const manifest = buildVerifierBindingManifestV1(tampered);

  const tsResult = verifyVerifierBindingManifestV1(manifest, tampered, pem, approvalPem);
  assert.equal(tsResult.reason, "invalid_approval_signature");
  assert.equal(pythonVerify(manifest, tampered, pem, approvalPem), "invalid_approval_signature");
});
