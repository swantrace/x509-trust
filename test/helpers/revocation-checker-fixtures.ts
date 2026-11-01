import assert from "node:assert/strict";
import { inlinePkiEngine } from "../../src/engine/pki-engine.ts";
import { compileValidationProfile } from "../../src/profile/profile.ts";
import { fixtureTime, readCertificateDer, readCrl } from "./fixtures.ts";

export const certificateDer = readCertificateDer("leaf");
export const issuerDer = readCertificateDer("intermediate");

export const crl = readCrl("intermediate-revoked");
export const profile = compileValidationProfile();
export const path = await inlinePkiEngine.preparePath({
  certificateChain: [certificateDer, issuerDer],
  trustAnchors: [readCertificateDer("root")],
  checkDateMs: fixtureTime
});
assert.ok(path.pathValid);
export const prepared = path.certificates[0];
export const crlOptions = {
  prepared: {
    ...prepared,
    crlUrls: ["http://crl.example.test/intermediate.crl"],
    ocspUrls: []
  },
  certificateIndex: 0
};
export const ocspOptions = {
  prepared: {
    ...prepared,
    crlUrls: [],
    ocspUrls: ["http://ocsp.example.test/status"]
  },
  certificateIndex: 0
};
