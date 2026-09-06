# Independence Test Kit

**Zuletzt bearbeitet:** 2026-09-06
**Von:** MERIDIAN

Dieses Verzeichnis enthaelt den eingefrorenen Werkzeugsatz und drei reale Pruefprotokolle
desselben Evidence Package ohne Vertrauen in eine laufende ALEX-Instanz. Das veroeffentlichbare
Paket entsteht mit `npm pack`.

## Eingefrorener Testgegenstand

- Evidence Package: `demo-pr-38.json`
- Trust-Anchor-Snapshot: `trust-anchor-20260906.json`, vor Test C separat bezogen
- daraus aufgeloeste Schluessel: `trusted-evidence.pem`, `trusted-approval.pem`
- Verifier: `../verify.py`, getesteter Quellstand `b3d11484041ae6579baec694a75de404d682c2cc`
- normative Unterlagen: `../spec/`

## Tatsaechlich notwendige Bestandteile

| Bestandteil | Ausfuehrung | Rolle |
|---|---:|---|
| `verify.py` | ja | Prueft Schema, Signaturen, Hash-Kette, Ableitungen und Bindungen |
| Python 3 | ja | Nur Standardbibliothek |
| OpenSSL | ja | Ed25519-Signaturpruefung; keine Python-Pakete |
| Evidence Package | ja | Portabler Pruefgegenstand |
| Evidence-PEM | ja | Separater Anker der Bundle-Signatur |
| Approval-PEM | fuer PR 38 ja | Separater Anker der Freigabe-Signatur |
| Trust-Anchor-JSON | ja, als Herkunftsnachweis | Eingefrorene Quelle der PEMs; kein Live-Endpunkt |
| `spec/` inkl. Invarianten | normativ ja, technisch nein | Auditierbare Definition; wird nicht vom Programm eingelesen |
| Node.js/npm/ALEX-Code/DB/API | nein | Nicht verwendet |

Reproduktion aus dem Paket-Root:

```bash
sha256sum -c independence/SHA256SUMS
python3 verify.py independence/demo-pr-38.json \
  independence/trusted-evidence.pem independence/trusted-approval.pem
```

Die Protokolle belegen getrennt: offline, fremde Umgebung und gestoppte ALEX-Runtime.
Coverage-Kennzahl und Lifecycle sind ausdruecklich nicht Teil dieser Pruefung.
