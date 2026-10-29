import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verifyAgentPassportCardV1 } from "../dist/verify.js";

// Phase 2 (29.10.2026): TS<->Python-Paritaetstest fuer agent-passport-card@1.0 (verifyAgentPassportCardV1
// in verify.ts vs. verify_agent_passport_card_v1 in verify.py). identity_line_id = sha256(canonical(
// {adapter_binary_hash, model_version, tool_manifest, enforcement_class})), barcode/qr sind Projektionen,
// Signatur ueber canonical(payload ohne signature). canonical == canonicalEvidenceJson fuer JSON-Daten.
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const sha256 = v => createHash("sha256").update(v).digest("hex");
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`
    : JSON.stringify(value);

function signedCard(passportOverrides = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const passport = {
    model_version: "claude-opus-4-8", tool_manifest: ["read", "write"], enforcement_class: "strict",
    adapter_binary_hash: `sha256:${sha256("adapter")}`, ...passportOverrides,
  };
  const identity = sha256(canonical({
    adapter_binary_hash: passport.adapter_binary_hash ?? null, model_version: passport.model_version,
    tool_manifest: passport.tool_manifest, enforcement_class: passport.enforcement_class,
  }));
  const receipt_content_sha256 = sha256("receipt-content");
  const payload = {
    schema_version: "agent-passport-card@1.0", passport, identity_line_id: identity,
    receipt_id: "R-20261029-001", receipt_content_sha256, outcome: "verified", claim_ladder: "L1",
    policy_profile_hash: sha256("policy"),
    barcode: { format: "code128", value: `AXP-${identity.slice(0, 20).toUpperCase()}` },
    qr: { format: "qrcode", payload: `alex:agent-passport:v1?identity=${identity}&receipt=${receipt_content_sha256}` },
    signer_key_id: `ed25519:${sha256(pem)}`, public_key: pem,
  };
  const signature = sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64");
  return { card: { ...payload, signature }, pem };
}

function pythonVerify(card, trustedKey) {
  const dir = mkdtempSync(join(tmpdir(), "passcard-"));
  const inputPath = join(dir, "input.json");
  writeFileSync(inputPath, JSON.stringify({ artifact: card, trusted_key: trustedKey }), "utf8");
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "d=json.load(open(sys.argv[2],encoding='utf-8'))",
    "ok,reason=m.verify_agent_passport_card_v1(d['artifact'],d['trusted_key'])",
    "print('ok' if ok else reason)",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, inputPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function tsVerify(card, trustedKey) {
  const r = verifyAgentPassportCardV1(card, trustedKey);
  return r.ok ? "ok" : r.reason;
}

test("agent-passport-card: TS and Python agree on a valid card and every reason-code", () => {
  const cases = [];
  // valid
  { const { card, pem } = signedCard(); cases.push(["valid", card, pem, "ok"]); }
  // null adapter_binary_hash variant (?? null Pfad) -- muss weiterhin gueltig sein
  { const { card, pem } = signedCard({ adapter_binary_hash: null }); cases.push(["valid null adapter", card, pem, "ok"]); }
  // unsupported_schema_version
  { const { card, pem } = signedCard(); cases.push(["unsupported_schema_version", { ...card, schema_version: "agent-passport-card@2.0" }, pem, "unsupported_schema_version"]); }
  // untrusted_signer (gegen fremden Schluessel pruefen)
  { const { card } = signedCard(); const other = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString(); cases.push(["untrusted_signer", card, other, "untrusted_signer"]); }
  // identity_line_id_mismatch
  { const { card, pem } = signedCard(); cases.push(["identity_line_id_mismatch", { ...card, identity_line_id: sha256("wrong") }, pem, "identity_line_id_mismatch"]); }
  // barcode_projection_mismatch
  { const { card, pem } = signedCard(); cases.push(["barcode_projection_mismatch", { ...card, barcode: { format: "code128", value: "AXP-WRONG" } }, pem, "barcode_projection_mismatch"]); }
  // qr_projection_mismatch
  { const { card, pem } = signedCard(); cases.push(["qr_projection_mismatch", { ...card, qr: { format: "qrcode", payload: "alex:wrong" } }, pem, "qr_projection_mismatch"]); }
  // invalid_signature (Nutzlast nach Signatur veraendert, Projektionen bleiben gueltig)
  { const { card, pem } = signedCard(); cases.push(["invalid_signature", { ...card, outcome: "failed" }, pem, "invalid_signature"]); }

  for (const [name, card, trustedKey, expected] of cases) {
    const ts = tsVerify(card, trustedKey);
    assert.equal(ts, expected, `TS verdict for "${name}"`);
    assert.equal(pythonVerify(card, trustedKey), ts, `parity TS<->Python for "${name}"`);
  }
});
