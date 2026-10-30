# Local validation profiles

Validation profiles are **local, reviewed, versioned data**. They are not
downloaded from request-supplied URIs and are not automatically trusted.

Recommended layout:

```text
profiles/
├── default/
│   └── profile.json
└── <profile-id>/
    ├── profile.json
    └── anchors/          # optional public trust bundle, host-approved
```

- `default/profile.json` mirrors the built-in strict default. The code constant
  `DEFAULT_VALIDATION_PROFILE` remains authoritative; the JSON is for
  review/export.
- Each profile directory is registered explicitly by the host. The `profile.id`
  is the registry key:

```typescript
const profile = JSON.parse(
  readFileSync("profiles/example/profile.json", "utf8")
);

registry.register({
  trustAnchors: loadApprovedPublicAnchors("profiles/example/anchors"),
  profile
});
```

- `anchorSetId` names the local anchor set used by the hosting application;
  anchors are supplied separately, never by the request.
- `version` may be a number or a string. String versions require a positive
  `versionOrder`; the registry selects the highest order as latest.
- `requiredCapabilities` must use names from `PROFILE_CAPABILITIES`;
  unsupported capabilities are rejected before certificate I/O.
- Do not put private keys in this tree. Only public certificate fixtures or
  host-approved public trust bundles belong in `anchors/`.
- A profile directory is configuration, not a statement of compliance. Do not
  label a profile as compliant with a real external framework or community
  without its current requirements and local approval.
