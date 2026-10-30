import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decideRevocationEvidence,
  type EvidenceAttempt,
  type EvidenceSummary,
  requiredMechanisms
} from "../src/evidence/evidence.ts";
import type {
  RequiredEvidence,
  RevocationMechanism
} from "../src/profile/profile.ts";

function summary(
  mechanism: RevocationMechanism,
  status: "good" | "revoked",
  certificateIndex = 0
): EvidenceSummary {
  return {
    certificateIndex,
    mechanism,
    status,
    authenticated: true,
    fresh: true,
    thisUpdateMs: 1,
    nextUpdateMs: 2,
    checkedAtMs: 1
  };
}

function attempt(
  mechanism: RevocationMechanism,
  status: "good" | "revoked" | "unknown",
  certificateIndex = 0
): EvidenceAttempt {
  return {
    certificateIndex,
    mechanism,
    status,
    ...(status === "unknown" ? {} : { evidence: summary(mechanism, status) }),
    message: status
  };
}

test("any evidence accepts the first authenticated good and never downgrades revoked", () => {
  assert.deepEqual(
    decideRevocationEvidence("any", [
      attempt("ocsp", "unknown"),
      attempt("crl", "good")
    ]),
    { status: "good", evidence: [summary("crl", "good")] }
  );
  assert.deepEqual(
    decideRevocationEvidence("any", [
      attempt("crl", "good"),
      attempt("ocsp", "revoked")
    ]),
    { status: "revoked", evidence: summary("ocsp", "revoked") }
  );
});

test("required CRL or OCSP evidence cannot be satisfied by the other mechanism", () => {
  assert.equal(
    decideRevocationEvidence("crl", [attempt("ocsp", "good")]).status,
    "unknown"
  );
  assert.equal(
    decideRevocationEvidence("ocsp", [attempt("crl", "good")]).status,
    "unknown"
  );
  assert.deepEqual(
    decideRevocationEvidence("crl", [
      attempt("ocsp", "good"),
      attempt("crl", "good")
    ]),
    { status: "good", evidence: [summary("crl", "good")] }
  );
});

test("both evidence requires a good result from each mechanism", () => {
  assert.equal(
    decideRevocationEvidence("both", [attempt("ocsp", "good")]).status,
    "unknown"
  );
  assert.equal(
    decideRevocationEvidence("both", [attempt("crl", "good")]).status,
    "unknown"
  );
  assert.deepEqual(
    decideRevocationEvidence("both", [
      attempt("ocsp", "good"),
      attempt("crl", "good")
    ]),
    {
      status: "good",
      evidence: [summary("ocsp", "good"), summary("crl", "good")]
    }
  );
});

test("authenticated revoked always wins, including under both", () => {
  for (const required of ["any", "crl", "ocsp", "both"] as RequiredEvidence[]) {
    const decision = decideRevocationEvidence(required, [
      attempt("crl", "good"),
      attempt("ocsp", "revoked")
    ]);
    assert.equal(decision.status, "revoked");
  }
});

test("unknown and unauthenticated evidence cannot establish good", () => {
  const unauthenticated: EvidenceAttempt = {
    certificateIndex: 0,
    mechanism: "crl",
    status: "good",
    evidence: { ...summary("crl", "good"), authenticated: false as never },
    message: "unauthenticated"
  };
  assert.equal(
    decideRevocationEvidence("any", [attempt("ocsp", "unknown")]).status,
    "unknown"
  );
  assert.equal(
    decideRevocationEvidence("any", [unauthenticated]).status,
    "unknown"
  );
});

test("required mechanism lists are independent of source order", () => {
  assert.deepEqual([...requiredMechanisms("any")], ["crl", "ocsp"]);
  assert.deepEqual([...requiredMechanisms("crl")], ["crl"]);
  assert.deepEqual([...requiredMechanisms("ocsp")], ["ocsp"]);
  assert.deepEqual([...requiredMechanisms("both")], ["crl", "ocsp"]);
});
