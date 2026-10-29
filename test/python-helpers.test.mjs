import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verifyAgentPassportHistoryV1, verifyChallengeResponseArtifactV1, verifyPhpExposureEvidenceArtifactV1 } from "../dist/verify.js";

// Phase 3 (29.10.2026): TS<->Python-Paritaet fuer die drei self-contained Hilfsverifier
// (agent-passport-history, challenge-response, php-exposure-evidence). Jeder bekommt einen valide
// signierten Artefakt-Build + Mutationen ueber die reason-codes; Verdikt muss byte-gleich sein.
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const sha256 = v => createHash("sha256").update(v).digest("hex");
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`
    : JSON.stringify(value);

// Generischer Python-Aufruf: m.<func>(artifact, trusted_key) -> (ok, reason)
function pythonVerify(func, artifact, trustedKey) {
  const dir = mkdtempSync(join(tmpdir(), "helpers-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ func, artifact, trusted_key: trustedKey }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=getattr(m,d['func'])(d['artifact'],d['trusted_key'])",
    "print('ok' if ok else reason)",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pem: publicKey.export({ type: "spki", format: "pem" }).toString(), privateKey };
}

// ---------- agent-passport-history ----------
function historyEntry(id, seq, prevHash, { outcome = "verified", claimLadder = "L1", policyProfileHash, recordedAt }) {
  const body = {
    identity_line_id: id, sequence: seq, receipt_hash: null, verdict_hash: null,
    outcome, claim_ladder: claimLadder, policy_profile_hash: policyProfileHash, recorded_at: recordedAt,
  };
  const entryHash = sha256(prevHash + canonical(body));
  return { identityLineId: id, sequence: seq, receiptHash: null, verdictHash: null, outcome, claimLadder, policyProfileHash, recordedAt, prevHash, entryHash };
}
function signedHistory() {
  const { pem, privateKey } = keypair();
  const id = "identity-line-1";
  const e0 = historyEntry(id, 0, "0".repeat(64), { policyProfileHash: sha256("p0"), recordedAt: "2026-10-29T00:00:00.000Z" });
  const e1 = historyEntry(id, 1, e0.entryHash, { policyProfileHash: sha256("p1"), recordedAt: "2026-10-29T01:00:00.000Z", outcome: "failed", claimLadder: "L0" });
  const entries = [e0, e1];
  const signature = sign(null, Buffer.from(canonical({ identity_line_id: id, entries }), "utf8"), privateKey).toString("base64");
  return { bundle: { schema_version: "agent-passport-history@1.0", identity_line_id: id, entries, signer_key_id: `ed25519:${sha256(pem)}`, public_key: pem, signature }, pem };
}

test("agent-passport-history: TS and Python agree on a valid chain and every reason-code", () => {
  const cases = [];
  { const { bundle, pem } = signedHistory(); cases.push(["valid", bundle, pem, "ok"]); }
  { const { bundle, pem } = signedHistory(); cases.push(["unsupported_schema_version", { ...bundle, schema_version: "agent-passport-history@2.0" }, pem, "unsupported_schema_version"]); }
  { const { bundle } = signedHistory(); const other = keypair().pem; cases.push(["untrusted_signer", bundle, other, "untrusted_signer"]); }
  { const { bundle, pem } = signedHistory(); const entries = bundle.entries.map(e => ({ ...e })); entries[1] = { ...entries[1], outcome: "verified" }; cases.push(["entry_hash_mismatch:1", { ...bundle, entries }, pem, "entry_hash_mismatch:1"]); }
  { const { bundle, pem } = signedHistory(); const entries = bundle.entries.map(e => ({ ...e })); entries[1] = { ...entries[1], sequence: 5 }; cases.push(["sequence_gap:5", { ...bundle, entries }, pem, "sequence_gap:5"]); }
  { const { bundle, pem } = signedHistory(); const entries = bundle.entries.map(e => ({ ...e })); entries[1] = { ...entries[1], prevHash: "f".repeat(64) }; cases.push(["chain_broken:1", { ...bundle, entries }, pem, "chain_broken:1"]); }
  { const { bundle, pem } = signedHistory(); cases.push(["invalid_signature", { ...bundle, signature: Buffer.from("x".repeat(64)).toString("base64") }, pem, "invalid_signature"]); }
  for (const [name, bundle, key, expected] of cases) {
    const ts = verifyAgentPassportHistoryV1(bundle, key); const tsv = ts.ok ? "ok" : ts.reason;
    assert.equal(tsv, expected, `TS history "${name}"`);
    assert.equal(pythonVerify("verify_agent_passport_history_v1", bundle, key), tsv, `parity history "${name}"`);
  }
});

// ---------- challenge-response ----------
function signedChallenge({ outcome = "SUPPORTED", superseding_receipt = null } = {}) {
  const { pem, privateKey } = keypair();
  const base = {
    schema_version: "challenge-response@1.0", challenge_id: "C-1", receipt_id: "R-1",
    receipt_content_sha256: sha256("rc"), evidence_package_sha256: sha256("ep"), reason_code: "completeness",
    claim_pointer: "/claims/0", raised_statement: "Statement.", raised_at: "2026-10-29T00:00:00.000Z",
    outcome, response_statement: "Response.", response_evidence_pointers: ["/evidence/0"],
    responded_at: "2026-10-29T01:00:00.000Z", superseding_receipt,
    signer_key_id: `ed25519:${sha256(pem)}`, public_key: pem,
  };
  const signPayload = { ...base }; delete signPayload.signer_key_id; delete signPayload.public_key;
  const signature = sign(null, Buffer.from(canonical(signPayload), "utf8"), privateKey).toString("base64");
  return { artifact: { ...base, signature }, pem };
}

test("challenge-response: TS and Python agree on valid artifacts and every reason-code", () => {
  const cases = [];
  { const { artifact, pem } = signedChallenge(); cases.push(["valid SUPPORTED", artifact, pem, "ok"]); }
  { const { artifact, pem } = signedChallenge({ outcome: "CONTRADICTED", superseding_receipt: { receipt_id: "S-1", supersedes: "R-1" } }); cases.push(["valid CONTRADICTED", artifact, pem, "ok"]); }
  { const { artifact, pem } = signedChallenge(); cases.push(["unsupported_schema_version", { ...artifact, schema_version: "challenge-response@2.0" }, pem, "unsupported_schema_version"]); }
  { const { artifact } = signedChallenge(); cases.push(["untrusted_signer", artifact, keypair().pem, "untrusted_signer"]); }
  { const { artifact, pem } = signedChallenge({ outcome: "SUPPORTED", superseding_receipt: { receipt_id: "S-1", supersedes: "R-1" } }); cases.push(["superseding_receipt_outcome_mismatch", artifact, pem, "superseding_receipt_outcome_mismatch"]); }
  { const { artifact, pem } = signedChallenge({ outcome: "CONTRADICTED", superseding_receipt: { receipt_id: "S-1", supersedes: "OTHER" } }); cases.push(["superseding_receipt_does_not_reference_original", artifact, pem, "superseding_receipt_does_not_reference_original"]); }
  { const { artifact, pem } = signedChallenge(); cases.push(["invalid_signature", { ...artifact, response_statement: "tampered" }, pem, "invalid_signature"]); }
  for (const [name, artifact, key, expected] of cases) {
    const ts = verifyChallengeResponseArtifactV1(artifact, key); const tsv = ts.ok ? "ok" : ts.reason;
    assert.equal(tsv, expected, `TS challenge "${name}"`);
    assert.equal(pythonVerify("verify_challenge_response_artifact_v1", artifact, key), tsv, `parity challenge "${name}"`);
  }
});

// ---------- php-exposure-evidence ----------
const PHP_RULE = "php-exposure-rules@2026-10-22.1";
function signedPhp() {
  const { pem, privateKey } = keypair();
  const phpOut = "PHP 8.3.40 (cli) (built: ...)";
  const osOut = "PRETTY_NAME=\"Debian GNU/Linux 12\"";
  const pkgOut = "";
  const phpSha = `sha256:${sha256(phpOut)}`;
  const raw = {
    php_version_output: phpOut, php_version_output_sha256: phpSha,
    os_release_output: osOut, os_release_output_sha256: `sha256:${sha256(osOut)}`,
    package_manager: "none", package_query_output: pkgOut, package_query_output_sha256: `sha256:${sha256(pkgOut)}`,
    distro_changelog_note: null, distro_changelog_note_sha256: null,
    collected_at: "2026-10-29T00:00:00.000Z", hostname: "host-1",
  };
  // 8.3.40, kein Paketmanager -> Fix-Version 8.3.36, 40>=36 -> PATCHED (Reasoning char-genau zu verify.ts)
  const assessment = {
    verdict: "PATCHED", rule_version: PHP_RULE, parsed_php_version: "8.3.40", distro_sourced: false,
    evidence_refs: [phpSha],
    reasoning: `PHP 8.3.40 (kein Paketmanager-Treffer) gegen Fix-Version 8.3.36 verglichen (php_version_output ${phpSha}).`,
  };
  const base = { schema_version: "php-exposure-evidence@1.0", raw_evidence: raw, assessment, signer_key_id: `ed25519:${sha256(pem)}`, public_key: pem };
  const signPayload = { ...base }; delete signPayload.signer_key_id; delete signPayload.public_key;
  const signature = sign(null, Buffer.from(canonical(signPayload), "utf8"), privateKey).toString("base64");
  return { artifact: { ...base, signature }, pem };
}

test("php-exposure-evidence: TS and Python agree on a valid artifact and every reason-code", () => {
  const cases = [];
  { const { artifact, pem } = signedPhp(); cases.push(["valid PATCHED", artifact, pem, "ok"]); }
  { const { artifact, pem } = signedPhp(); cases.push(["unsupported_schema_version", { ...artifact, schema_version: "php-exposure-evidence@2.0" }, pem, "unsupported_schema_version"]); }
  { const { artifact } = signedPhp(); cases.push(["untrusted_signer", artifact, keypair().pem, "untrusted_signer"]); }
  { const { artifact, pem } = signedPhp(); cases.push(["raw_evidence_hash_mismatch", { ...artifact, raw_evidence: { ...artifact.raw_evidence, php_version_output_sha256: `sha256:${"0".repeat(64)}` } }, pem, "raw_evidence_hash_mismatch"]); }
  { const { artifact, pem } = signedPhp(); cases.push(["unsupported_rule_version", { ...artifact, assessment: { ...artifact.assessment, rule_version: "php-exposure-rules@1999.1" } }, pem, "unsupported_rule_version"]); }
  { const { artifact, pem } = signedPhp(); cases.push(["assessment_mismatch", { ...artifact, assessment: { ...artifact.assessment, verdict: "VULNERABLE" } }, pem, "assessment_mismatch"]); }
  { const { artifact, pem } = signedPhp(); cases.push(["invalid_signature", { ...artifact, assessment: { ...artifact.assessment, reasoning: artifact.assessment.reasoning } , signature: Buffer.from("y".repeat(64)).toString("base64") }, pem, "invalid_signature"]); }
  for (const [name, artifact, key, expected] of cases) {
    const ts = verifyPhpExposureEvidenceArtifactV1(artifact, key); const tsv = ts.ok ? "ok" : ts.reason;
    assert.equal(tsv, expected, `TS php "${name}"`);
    assert.equal(pythonVerify("verify_php_exposure_evidence_artifact_v1", artifact, key), tsv, `parity php "${name}"`);
  }
});
