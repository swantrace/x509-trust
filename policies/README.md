# Local trust policies

Community policies are **local, reviewed, versioned data**. They are not
downloaded from request-supplied URIs and are not automatically trusted.

Recommended layout:

```text
policies/
├── default/
│   └── policy.json
└── <community-id>/
    ├── policy.json
    └── anchors/          # optional public trust bundle, host-approved
```

- `default/policy.json` mirrors the built-in strict default. The code constant
  `DEFAULT_TRUST_POLICY` remains authoritative; the JSON is for review/export.
- Each community directory is registered explicitly by the host:

```typescript
const policy = JSON.parse(
  readFileSync("policies/community-a/policy.json", "utf8")
);

registry.register({
  communityId: "community-a",
  trustAnchors: loadApprovedPublicAnchors("policies/community-a/anchors"),
  policy
});
```

- `anchorSetId` names the local anchor set used by the hosting application;
  anchors are supplied separately, never by the request.
- `version` may be a number or a string. String versions require a positive
  `versionOrder`; the registry selects the highest order as latest.
- `requiredCapabilities` must use names from `POLICY_CAPABILITIES`; unsupported
  capabilities are rejected before certificate I/O.
- Do not put private keys in this tree. Only public certificate fixtures or
  host-approved public trust bundles belong in `anchors/`.
- A community directory is configuration, not a statement of compliance. Do not
  label a policy as compliant with a real community without its current
  requirements and local approval.
