# Evidence-Invarianten und Trust Model

Diese Regeln sind der stabile Massstab fuer jede Evidence-Spezifikation und jeden Verifier.
Eine Implementierung, die ihnen widerspricht, darf nicht freigegeben werden.

## Unveraenderliche Invarianten

1. Evidence kann vom Verifier nicht verstärkt werden — der Verifier leitet nie aus einem schwächeren Signal einen stärkeren Claim ab.
2. Unknown ist niemals gleichbedeutend mit Pass.
3. Fehlende Provenance kann keinen Claim stützen.
4. Verifikation ist immer an eine konkrete Spec-Version gebunden.
5. Alte Packages bleiben unabhängig von neueren Spec-Versionen prüfbar.
6. Widerruf (`revoked`) verändert niemals rückwirkend historische Evidence.
7. Die Verfügbarkeit von ALEX ist keine Voraussetzung für offline Verifikation.
8. Die `strength` eines Claims muss aus der Evidence ableitbar sein, nicht vom Erzeuger behauptet werden.

## Trust Model

Die Stufen sind strikt geordnet. Eine Quelle darf nur die Stufe tragen, die ihr eigenes, aufloesbares Artefakt belegt.

1. `policy_derived` — aus einer deklarierten Policy oder Konfiguration abgeleitet; kein Laufzeitbeleg.
2. `observed` — durch ein konkretes Laufzeitartefakt beobachtet.
3. `attested` — durch eine signierte Attestation eines benannten Erzeugers belegt.
4. `independently_witnessed` — durch ein eigenstaendiges Artefakt einer unabhaengigen Instanz belegt.
5. `cryptographically_verified` — kryptographische Bindung, Signatur und zugehoerige Vertrauenskette wurden vom Verifier selbst geprueft.

Cryptographic verification proves authenticity/integrity of the referenced evidence artifact; it does not by itself increase the semantic trust level of the underlying claim. A higher trust level requires evidence that independently satisfies the requirements of that level.

Mehrere Artefakte unterhalb einer geforderten Stufe ergeben zusammen niemals diese hoehere Stufe.
Jede Hochstufung braucht mindestens ein eigenstaendiges, aufloesbares Artefakt, das die Zielstufe selbst erreicht.
Unbekannte Stufen, fehlende Artefakte und nicht aufloesbare Provenance sind nicht bestanden.

## Aenderungsregel

Diese Datei steht vor der Evidence Package Spec. Eine spaetere Spec darf die Regeln konkretisieren,
aber nicht abschwaechen. Eine notwendige Abweichung wird vor der Umsetzung an Andre eskaliert.
