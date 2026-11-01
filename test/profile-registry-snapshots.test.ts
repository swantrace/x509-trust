import assert from "node:assert/strict";
import { test } from "node:test";
import {
  base,
  baseLeafCrlUrl,
  crlByUrl,
  inputFor,
  makeRegistry,
  profileFor
} from "./helpers/profile-registry-fixtures.ts";

test("a version registered during a pending request does not affect that request", async () => {
  let release!: () => void;
  let started!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const startedSignal = new Promise<void>((resolve) => {
    started = resolve;
  });
  const { registry } = makeRegistry(
    [
      {
        profileId: "pending",
        chain: base,
        profile: profileFor("pending:v1", { version: 1 })
      }
    ],
    async (url) => {
      if (url === baseLeafCrlUrl) {
        started();
        await gate;
      }
      const response = crlByUrl.get(url);
      if (!response) throw new Error(`No CRL for ${url}`);
      return response;
    }
  );
  const pending = registry.verify({
    profileId: "pending",
    certificateChain: inputFor(base)
  });
  await startedSignal;
  registry.register({
    trustAnchors: [base.root.der],
    profile: {
      ...profileFor("pending:v2", {
        version: 2,
        rules: { leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.9"] }
      }),
      id: "pending"
    }
  });
  release();
  const result = await pending;
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.profileVersion, 1);
});

test("registration snapshots resist later caller mutation", async () => {
  const anchor = Uint8Array.from(base.root.der);
  const profile = profileFor("mutable");
  const { registry } = makeRegistry([]);
  registry.register({
    trustAnchors: [anchor],
    profile: { ...profile, id: "mutable" }
  });
  anchor.fill(0);
  (profile.revocation as { sourceOrder: string[] }).sourceOrder = ["ocsp"];
  profile.id = "changed";
  const result = await registry.verify({
    profileId: "mutable",
    certificateChain: inputFor(base)
  });
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.profileId, "mutable");
});
