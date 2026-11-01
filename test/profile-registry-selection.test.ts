import assert from "node:assert/strict";
import { test } from "node:test";
import { ProfileError } from "../src/index.ts";
import {
  base,
  inputFor,
  makeRegistry,
  profileFor,
  sameSan,
  second
} from "./helpers/profile-registry-fixtures.ts";

test("selects anchors per profile even when leaves share a SAN", async () => {
  const { registry } = makeRegistry([
    { profileId: "profile-a", chain: base },
    { profileId: "profile-b", chain: second }
  ]);
  const first = await registry.verify({
    profileId: "profile-a",
    certificateChain: inputFor(base)
  });
  const other = await registry.verify({
    profileId: "profile-b",
    certificateChain: inputFor(second)
  });
  assert.equal(first.valid, true);
  assert.equal(other.valid, true);
  assert.equal(first.valid && first.profileId, "profile-a");
  assert.equal(other.valid && other.profileId, "profile-b");
  assert.deepEqual(
    first.valid && first.leafCertificate.uriSubjectAlternativeNames,
    [sameSan]
  );
  assert.deepEqual(
    other.valid && other.leafCertificate.uriSubjectAlternativeNames,
    [sameSan]
  );

  const cross = await registry.verify({
    profileId: "profile-a",
    certificateChain: inputFor(second)
  });
  assert.equal(cross.valid, false);
  assert.equal(cross.code, "INVALID_CERTIFICATE_PATH");
});

test("unknown profiles and versions fail without any evidence I/O", async () => {
  const { registry, calls } = makeRegistry([
    { profileId: "known", chain: base }
  ]);
  const unknown = await registry.verify({
    profileId: "unknown",
    certificateChain: inputFor(base)
  });
  assert.equal(unknown.valid, false);
  assert.equal(unknown.code, "UNKNOWN_PROFILE");
  assert.equal(calls.crl.length, 0);

  const unknownVersion = await registry.verify({
    profileId: "known",
    profileVersion: 99,
    certificateChain: inputFor(base)
  });
  assert.equal(unknownVersion.valid, false);
  assert.equal(unknownVersion.code, "UNKNOWN_PROFILE_VERSION");
  assert.equal(calls.crl.length, 0);
});

test("selects the latest profile version unless an exact version is requested", async () => {
  const { registry } = makeRegistry([
    {
      profileId: "versioned",
      chain: base,
      profile: profileFor("versioned:v1", { version: 1 })
    },
    {
      profileId: "versioned",
      chain: base,
      profile: profileFor("versioned:v2", {
        version: 2,
        rules: { leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.9"] }
      })
    }
  ]);
  const latest = await registry.verify({
    profileId: "versioned",
    certificateChain: inputFor(base)
  });
  assert.equal(latest.valid, false);
  assert.equal(latest.code, "PROFILE_REJECTED");
  assert.equal(latest.profileVersion, 2);

  const pinned = await registry.verify({
    profileId: "versioned",
    profileVersion: 1,
    certificateChain: inputFor(base)
  });
  assert.equal(pinned.valid, true);
  assert.equal(pinned.valid && pinned.profileVersion, 1);
});

test("selects string profile versions using explicit versionOrder", async () => {
  const v1 = {
    id: "versions:string:v1",
    version: "2025-01",
    versionOrder: 10,
    source: { uri: "https://profile.example/profile/2025-01" },
    anchorSetId: "synthetic:root",
    revocation: {
      requiredEvidence: "crl" as const,
      sourceOrder: ["crl"] as const
    }
  };
  const v2 = {
    id: "versions:string:v2",
    version: "2026-01",
    versionOrder: 20,
    source: { uri: "https://profile.example/profile/2026-01" },
    anchorSetId: "synthetic:root",
    revocation: {
      requiredEvidence: "crl" as const,
      sourceOrder: ["crl"] as const
    },
    rules: { leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.9"] }
  };
  const { registry } = makeRegistry([
    { profileId: "string-versions", chain: base, profile: v1 },
    { profileId: "string-versions", chain: base, profile: v2 }
  ]);
  const latest = await registry.verify({
    profileId: "string-versions",
    certificateChain: inputFor(base)
  });
  assert.equal(latest.valid, false);
  assert.equal(latest.code, "PROFILE_REJECTED");
  assert.equal(latest.profileVersion, "2026-01");

  const pinned = await registry.verify({
    profileId: "string-versions",
    profileVersion: "2025-01",
    certificateChain: inputFor(base)
  });
  assert.equal(pinned.valid, true);
  assert.equal(pinned.valid && pinned.profileVersion, "2025-01");

  assert.throws(
    () =>
      registry.register({
        profileId: "string-versions",
        trustAnchors: [base.root.der],
        profile: { ...v1, version: "2025-02", versionOrder: 10 }
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "INVALID_PROFILE");
      return true;
    }
  );
  const missing = await registry.verify({
    profileId: "string-versions",
    profileVersion: "2024-01",
    certificateChain: inputFor(base)
  });
  assert.equal(missing.valid, false);
  assert.equal(missing.code, "UNKNOWN_PROFILE_VERSION");
});
