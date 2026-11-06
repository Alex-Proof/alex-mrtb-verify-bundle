import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { crossCheckTrustAnchor } from "../dist/verify.js";

// 06.11.2026 (externe Gegenkritik, Evidence-Forgery-Challenge-Nachtrag): crossCheckTrustAnchor()
// zaehlte key_id-Strings pro Kanal und nahm dann results.find(r => r.key_id === agreedKeyId)
// ?.public_key_pem -- den PEM des ERSTEN Treffers -- OHNE je zu pruefen, ob dieser Kanal ueberhaupt
// den PASSENDEN PEM zur behaupteten key_id liefert. Ein kompromittierter/vorgezogener Kanal konnte
// die ECHTE key_id mit einem FREMDEN PEM melden und wurde ungeprueft als "agreed" durchgereicht
// (trustedPublicKey = consensus.agreed_public_key_pem direkt in main()/runManifestSubcommand()).

function keyIdOf(pem) {
  return `ed25519:${createHash("sha256").update(pem).digest("hex")}`;
}

function startServer(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, () => resolve(server));
  });
}

test("crossCheckTrustAnchor lehnt einen Kanal ab, der die ECHTE key_id mit einem FREMDEN PEM meldet", async () => {
  const { publicKey: realPub } = generateKeyPairSync("ed25519");
  const realPem = realPub.export({ type: "spki", format: "pem" });
  const realKeyId = keyIdOf(realPem);

  const { publicKey: attackerPub } = generateKeyPairSync("ed25519");
  const attackerPem = attackerPub.export({ type: "spki", format: "pem" });

  const server = await startServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    // Kompromittierter/vorgezogener Kanal: behauptet die ECHTE key_id, liefert aber einen FREMDEN PEM.
    res.end(JSON.stringify({ key_id: realKeyId, public_key_pem: attackerPem }));
  });
  try {
    const url = `http://127.0.0.1:${server.address().port}/.well-known/alex-pubkey.json`;
    const consensus = await crossCheckTrustAnchor("evidence_package", [url]);
    assert.equal(consensus.agreed_key_id, null, "eine key_id/PEM-Fehlpaarung darf nie als 'agreed' durchgehen");
    assert.equal(consensus.agreed_public_key_pem, null);
    assert.equal(consensus.channels[0].error, "key_id_pem_mismatch");
  } finally {
    server.close();
  }
});

test("crossCheckTrustAnchor akzeptiert einen Kanal, dessen key_id wirklich zum PEM passt", async () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" });
  const id = keyIdOf(pem);
  const server = await startServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ key_id: id, public_key_pem: pem }));
  });
  try {
    const url = `http://127.0.0.1:${server.address().port}/.well-known/alex-pubkey.json`;
    const consensus = await crossCheckTrustAnchor("evidence_package", [url]);
    assert.equal(consensus.agreed_key_id, id);
    assert.equal(consensus.agreed_public_key_pem, pem);
  } finally {
    server.close();
  }
});
