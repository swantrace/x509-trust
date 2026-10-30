# FHIR UDAP integration

The core package has no built-in UDAP or community vocabulary. A UDAP host maps
its external trust-framework identifier to a local `profileId` before calling
the registry:

```typescript
import {
  createValidationProfileRegistry,
  type ValidationProfileInput
} from "x509-trust";

const registry = createValidationProfileRegistry({
  loadCrl,
  loadOcsp
});

function udapProfileId(frameworkIdentifier: string): string {
  return `udap:${frameworkIdentifier}`;
}

const frameworkIdentifier = "https://example.org/udap/trust-framework";
const profile: ValidationProfileInput = {
  id: udapProfileId(frameworkIdentifier),
  version: "2026-01",
  versionOrder: 1,
  source: { uri: frameworkIdentifier },
  anchorSetId: "udap:approved-roots",
  requiredCapabilities: ["revocation:both"],
  revocation: {
    requiredEvidence: "both",
    sourceOrder: ["crl", "ocsp"]
  }
};

registry.register({
  trustAnchors: approvedUdapAnchors,
  profile,
  rules: udapRules
});

const result = await registry.verify({
  profileId: udapProfileId(frameworkIdentifier),
  certificateChain: [leafCertificate, intermediateCertificate]
});
```

- The framework identifier is an external UDAP input, not an X.509 field.
- Anchors and rules must come from the host's approved local configuration.
- Do not fetch anchors or profiles from a request-supplied URI.
- JWT `x5c`, `iss`/`aud`, OAuth, and replay protection remain application
  responsibilities; this library only validates the certificate path, configured
  revocation evidence, and profile rules.
