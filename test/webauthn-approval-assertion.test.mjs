import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verifyWebauthnApprovalAssertionV1 } from "../dist/verify.js";

// spec/webauthn-approval-assertion@1.0.md G4: echte, aus einer realen Browser-Ceremony stammende
// Assertion (echter Chromium + echter virtueller CDP-WebAuthn-Authenticator, siehe
// alex-core/.local-tools/gen-webauthn-fixture.ts), keine handgebastelten Fake-Bytes fuer den
// Erfolgsfall. "tampered" ist eine bewusste Bit-Manipulation der echten Signatur (negativer Pfad,
// kein Vorfuehr-Erfolg).
const verifierDir = fileURLToPath(new URL("..", import.meta.url));
const fixturePath = fileURLToPath(new URL("../fixtures/webauthn-approval-assertion.json", import.meta.url));
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

function pythonCheck(assertion) {
  const script = [
    "import importlib.util,json,sys",
    "s=importlib.util.spec_from_file_location('verify_py',sys.argv[1])",
    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
    "a=json.loads(sys.argv[2])",
    "ok,reason=m.verify_webauthn_approval_assertion_v1(a)",
    "print(json.dumps({'ok':ok,'reason':reason}))",
  ].join(";");
  const result = spawnSync(process.env.PYTHON ?? "python", ["-c", script, `${verifierDir}/verify.py`, JSON.stringify(assertion)], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("G2/G4: echte Assertion verifiziert in TS und Python identisch", () => {
  const tsResult = verifyWebauthnApprovalAssertionV1(fixture.valid);
  assert.equal(tsResult.ok, true, tsResult.reason);
  const pyResult = pythonCheck(fixture.valid);
  assert.deepEqual(pyResult, { ok: true, reason: null });
});

test("G3/G4: manipulierte Signatur scheitert in TS und Python identisch", () => {
  const tsResult = verifyWebauthnApprovalAssertionV1(fixture.tampered);
  assert.equal(tsResult.ok, false);
  assert.equal(tsResult.reason, "invalid_webauthn_assertion");
  const pyResult = pythonCheck(fixture.tampered);
  assert.deepEqual(pyResult, { ok: false, reason: "invalid_webauthn_assertion" });
});

test("G5: unbekannter COSE-Algorithmus ist kein impliziter Pass (Invariante 2)", () => {
  // Kein echter Authenticator nutzt dieses COSE-Key-Format -- bewusst konstruiert, um den
  // Negativpfad fuer eine unbekannte Algorithmus-ID zu pruefen (INVARIANTS.md #2: Unknown ist
  // niemals gleichbedeutend mit Pass). Kein Vorfuehr-ERFOLG, also kein no-demo-theater-Verstoss.
  // COSE map { 1: 1 (kty=OKP), 3: -9 (unbekannter alg), -1: 6 (crv=Ed25519), -2: <32 bytes x> }:
  // a4 01 01 03 28 20 06 21 58 20 <32 bytes x>
  const x = Buffer.from(fixture.valid.public_key, "base64").subarray(-32);
  const coseBuf = Buffer.concat([
    Buffer.from([0xa4, 0x01, 0x01, 0x03, 0x28, 0x20, 0x06, 0x21, 0x58, 0x20]),
    x,
  ]);
  const assertion = { ...fixture.valid, public_key: coseBuf.toString("base64") };
  const tsResult = verifyWebauthnApprovalAssertionV1(assertion);
  assert.equal(tsResult.ok, false);
  assert.equal(tsResult.reason, "cose_unsupported_algorithm");
  const pyResult = pythonCheck(assertion);
  assert.deepEqual(pyResult, { ok: false, reason: "cose_unsupported_algorithm" });
});
