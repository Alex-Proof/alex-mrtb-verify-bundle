import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildVerifierBindingManifestV1, verifyVerifierBindingManifestV1 } from "../dist/verify.js";

// 31.10.2026 (externer Haertungsvorschlag, SaSame @sasame-mcp.bsky.social, auf Bluesky): "after
// RFC3161 issuance, mutate one manifest field while keeping the token, then separately keep the
// manifest and mutate the bundle. Both should fail verification. That tests whether the timestamp
// binds the exact evidence, not just the run."
//
// Nutzt independence/demo-pr-38.json -- ein ECHTES, bei FreeTSA bezogenes Zeitstempel-Token, kein
// Mock. Beide Faelle laufen in TS UND Python, gegen dasselbe reale Bundle.
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const fixturePath = fileURLToPath(new URL("../independence/demo-pr-38.json", import.meta.url));
const bundle = JSON.parse(readFileSync(fixturePath, "utf8"));
const trustedKey = bundle.public_key;
const trustedApprovalKey = bundle.approval_attestation.public_key;

function pythonVerify(manifest, bundleArg) {
  const dir = mkdtempSync(join(tmpdir(), "rfc3161-adversarial-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ manifest, bundle: bundleArg, trustedKey, trustedApprovalKey }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify_verifier_binding_manifest_v1(d['manifest'],d['bundle'],d['trustedKey'],d['trustedApprovalKey'])",
    "print('ok' if ok else reason)",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test("verifier-binding-manifest + real RFC3161 token: the untouched baseline verifies ok", () => {
  const manifest = buildVerifierBindingManifestV1(bundle);
  assert.ok(manifest.repo_state_timestamp, "fixture must carry a real rfc3161_timestamp");
  const ts = verifyVerifierBindingManifestV1(manifest, bundle, trustedKey, trustedApprovalKey);
  assert.deepEqual(ts, { ok: true });
  assert.equal(pythonVerify(manifest, bundle), "ok");
});

test("adversarial check 1: one manifest field forged, repo_state_timestamp (the token) left byte-identical -> rejected", () => {
  const manifest = buildVerifierBindingManifestV1(bundle);
  const forged = { ...manifest, diff_hash: "0".repeat(64) };
  assert.deepEqual(forged.repo_state_timestamp, manifest.repo_state_timestamp, "token must stay untouched for this check to be meaningful");

  const ts = verifyVerifierBindingManifestV1(forged, bundle, trustedKey, trustedApprovalKey);
  assert.equal(ts.ok, false);
  assert.equal(pythonVerify(forged, bundle), ts.reason);
});

test("adversarial check 2: manifest left byte-identical, bundle mutated underneath it -> rejected", () => {
  const manifest = buildVerifierBindingManifestV1(bundle);
  const mutatedBundle = JSON.parse(JSON.stringify(bundle));
  mutatedBundle.controller_evidence.diff_full += "\n// injected line";

  const ts = verifyVerifierBindingManifestV1(manifest, mutatedBundle, trustedKey, trustedApprovalKey);
  assert.equal(ts.ok, false);
  assert.equal(pythonVerify(manifest, mutatedBundle), ts.reason);
});
