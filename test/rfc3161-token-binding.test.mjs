import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { AsnSerializer, OctetString } from "@peculiar/asn1-schema";
import { TSTInfo, MessageImprint } from "@peculiar/asn1-tsp";
import { AlgorithmIdentifier, Name } from "@peculiar/asn1-x509";
import {
  ContentInfo, SignedData, EncapsulatedContentInfo, EncapsulatedContent, SignerInfo, SignerInfos,
  IssuerAndSerialNumber, SignerIdentifier, DigestAlgorithmIdentifiers,
} from "@peculiar/asn1-cms";
import { verifyRfc3161Binding } from "../dist/verify.js";

// 06.11.2026 (externe Gegenkritik, Evidence-Forgery-Challenge-Nachtrag): verifyRfc3161Binding()
// verglich bisher NUR das selbst-deklarierte JSON-Feld `timestamped_sha256` gegen den Bundle-Hash --
// nie gegen den kryptografisch im Token signierten Hash (TSTInfo.messageImprint.hashedMessage). Ein
// Angreifer konnte einen ECHTEN, gueltig signierten Token fuer Hash A nehmen, ihn an ein FREMDES
// Bundle mit Hash B haengen und `timestamped_sha256` auf B setzen -- dieser Check war dafuer blind.
// Identischer Fix wie adapters/mrtb/rfc3161Timestamp.server.ts (kein Shared Import, siehe Datei-Header
// dort). Python war davon nicht betroffen (openssl ts -verify -digest erzwingt die Bindung schon).

function sha256(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

/** Baut einen strukturell gueltigen, aber unsignierten RFC-3161-Token mit genau dem uebergebenen
 *  Hash im TSTInfo.messageImprint -- fuer verifyRfc3161Binding() reicht das, sie prueft nur den
 *  Hash-Inhalt, nie Signatur/Kette (das deckt verifyRfc3161TsaChain() separat ab). */
function buildTokenForHash(hash) {
  const tstInfo = new TSTInfo({
    version: 1, policy: "1.2.3.4",
    messageImprint: new MessageImprint({
      hashAlgorithm: new AlgorithmIdentifier({ algorithm: "2.16.840.1.101.3.4.2.1" }),
      hashedMessage: new OctetString(hash),
    }),
    serialNumber: new Uint8Array([1]),
    genTime: new Date("2026-09-05T09:32:37.000Z"),
  });
  const tstInfoBytes = Buffer.from(AsnSerializer.serialize(tstInfo));
  const dummySigner = new SignerInfo({
    version: 1,
    sid: new SignerIdentifier({ issuerAndSerialNumber: new IssuerAndSerialNumber({ issuer: new Name(), serialNumber: new Uint8Array([1]) }) }),
    digestAlgorithm: new AlgorithmIdentifier({ algorithm: "2.16.840.1.101.3.4.2.1" }),
    signatureAlgorithm: new AlgorithmIdentifier({ algorithm: "1.2.840.10045.4.3.2" }),
    signature: new OctetString(new Uint8Array([0])),
  });
  const signedData = new SignedData({
    version: 3,
    digestAlgorithms: new DigestAlgorithmIdentifiers([new AlgorithmIdentifier({ algorithm: "2.16.840.1.101.3.4.2.1" })]),
    encapContentInfo: new EncapsulatedContentInfo({ eContentType: "1.2.840.113549.1.9.16.1.4", eContent: new EncapsulatedContent({ single: new OctetString(tstInfoBytes) }) }),
    signerInfos: new SignerInfos([dummySigner]),
  });
  const contentInfo = new ContentInfo({
    contentType: "1.2.840.113549.1.7.2",
    content: new Uint8Array(Buffer.from(AsnSerializer.serialize(signedData))),
  });
  return Buffer.from(AsnSerializer.serialize(contentInfo)).toString("base64");
}

test("verifyRfc3161Binding akzeptiert einen Token, dessen signierter Hash zum deklarierten Feld passt", () => {
  const bundle = { schema_version: "evidence-package@2.0", capability: "devtask.execution@1.0", outcome: "verified" };
  const declaredHashHex = sha256(bundle);
  const finalBundle = {
    ...bundle,
    rfc3161_timestamp: {
      schema_version: "rfc3161-timestamp@1.0", tsa_url: "https://freetsa.org/tsr",
      timestamped_sha256: declaredHashHex, gen_time: "2026-09-05T09:32:37.000Z",
      token_der_base64: buildTokenForHash(Buffer.from(declaredHashHex, "hex")),
    },
  };
  assert.deepEqual(verifyRfc3161Binding(finalBundle), { ok: true });
});

test("verifyRfc3161Binding lehnt einen ECHTEN Token ab, der an ein FREMDES Bundle gehaengt wurde (Replay)", () => {
  const forgedBundle = { schema_version: "evidence-package@2.0", capability: "devtask.execution@1.0", outcome: "forged-by-attacker" };
  const forgedHashHex = sha256(forgedBundle);
  const realTokenHash = createHash("sha256").update("originales-anderes-bundle").digest();
  const bundle = {
    ...forgedBundle,
    rfc3161_timestamp: {
      schema_version: "rfc3161-timestamp@1.0", tsa_url: "https://freetsa.org/tsr",
      timestamped_sha256: forgedHashHex, gen_time: "2026-09-05T09:32:37.000Z",
      token_der_base64: buildTokenForHash(realTokenHash),
    },
  };
  assert.deepEqual(verifyRfc3161Binding(bundle), { ok: false, reason: "token_hash_mismatch" });
});
