import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  RequiredEvidence,
  RevocationMechanism
} from "../src/profile/profile.ts";
import {
  decideRevocation,
  type RevocationAttempt,
  type RevocationSummary,
  requiredMechanisms
} from "../src/revocation/revocation.ts";

function summary(
  mechanism: RevocationMechanism,
  status: "good" | "revoked",
  certificateIndex = 0
): RevocationSummary {
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
): RevocationAttempt {
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
    decideRevocation("any", [
      attempt("ocsp", "unknown"),
      attempt("crl", "good")
    ]),
    { status: "good", evidence: [summary("crl", "good")] }
  );
  assert.deepEqual(
    decideRevocation("any", [
      attempt("crl", "good"),
      attempt("ocsp", "revoked")
    ]),
    { status: "revoked", evidence: summary("ocsp", "revoked") }
  );
});

test("required CRL or OCSP evidence cannot be satisfied by the other mechanism", () => {
  assert.equal(
    decideRevocation("crl", [attempt("ocsp", "good")]).status,
    "unknown"
  );
  assert.equal(
    decideRevocation("ocsp", [attempt("crl", "good")]).status,
    "unknown"
  );
  assert.deepEqual(
    decideRevocation("crl", [attempt("ocsp", "good"), attempt("crl", "good")]),
    { status: "good", evidence: [summary("crl", "good")] }
  );
});

test("both evidence requires a good result from each mechanism", () => {
  assert.equal(
    decideRevocation("both", [attempt("ocsp", "good")]).status,
    "unknown"
  );
  assert.equal(
    decideRevocation("both", [attempt("crl", "good")]).status,
    "unknown"
  );
  assert.deepEqual(
    decideRevocation("both", [attempt("ocsp", "good"), attempt("crl", "good")]),
    {
      status: "good",
      evidence: [summary("ocsp", "good"), summary("crl", "good")]
    }
  );
});

test("authenticated revoked always wins, including under both", () => {
  for (const required of ["any", "crl", "ocsp", "both"] as RequiredEvidence[]) {
    const decision = decideRevocation(required, [
      attempt("crl", "good"),
      attempt("ocsp", "revoked")
    ]);
    assert.equal(decision.status, "revoked");
  }
});

test("unknown and unauthenticated evidence cannot establish good", () => {
  const unauthenticated: RevocationAttempt = {
    certificateIndex: 0,
    mechanism: "crl",
    status: "good",
    evidence: { ...summary("crl", "good"), authenticated: false as never },
    message: "unauthenticated"
  };
  assert.equal(
    decideRevocation("any", [attempt("ocsp", "unknown")]).status,
    "unknown"
  );
  assert.equal(decideRevocation("any", [unauthenticated]).status, "unknown");
});

test("required mechanism lists are independent of source order", () => {
  assert.deepEqual([...requiredMechanisms("any")], ["crl", "ocsp"]);
  assert.deepEqual([...requiredMechanisms("crl")], ["crl"]);
  assert.deepEqual([...requiredMechanisms("ocsp")], ["ocsp"]);
  assert.deepEqual([...requiredMechanisms("both")], ["crl", "ocsp"]);
});
