# FHIR UDAP integration

[Back to README](../../README.md)

UDAP JWTs carry the signer's certificate chain in the `x5c` header.
`x509-trust` validates that chain against approved local trust anchors,
checks validity and revocation, and applies the selected profile's rules.
JWT signatures, claims, issuer/SAN matching, replay protection, and OAuth
behavior remain application responsibilities. Accept a request only after
both certificate validation and the workflow's JWT validation succeed.

The package has no built-in UDAP vocabulary. The host maps an external trust
community URI to a locally registered `profileId`:

```text
community URI -> profileId -> profile and approved anchors -> registry.verify()
```

## Register approved community configuration

Create the registry once. Supply `approvedUdapAnchors` from reviewed deployment
configuration as PEM strings or DER byte arrays. The profile below illustrates
an application policy; it does not claim compliance with a specific community.

```typescript
import {
  createValidationProfileRegistry,
  type ValidationProfileInput
} from "x509-trust";

const registry = createValidationProfileRegistry();

const communityUri = "https://community.example.org";
const profileId = `udap:${communityUri}`;

const profile: ValidationProfileInput = {
  id: profileId,
  version: "2026-01",
  versionOrder: 1,
  source: { uri: communityUri },
  anchorSetId: "udap:approved-roots",
  revocation: {
    requiredEvidence: "both",
    sourceOrder: ["crl", "ocsp"]
  }
};

registry.register({
  trustAnchors: approvedUdapAnchors,
  profile
});
```

| Configuration | Purpose |
| --- | --- |
| `profile.id` | Local identifier selected by the application. |
| `profile.version` / `versionOrder` | Policy revision and its ordering; string versions require a positive `versionOrder`. |
| `source.uri` | Configuration provenance, not a URL to fetch during verification. |
| `anchorSetId` | Application label for the approved anchor bundle. |
| `registry.register({ trustAnchors, profile })` | Binds approved anchors and rules before processing requests. |

Anchors may come from reviewed files, configuration, or a database. Request
data must never supply or replace them. The registry does not trust system
roots or download anchors from a request-supplied URI. See
[local validation profiles](../../profiles/README.md) for configuration layout
and versioning.

## Select the community before validating the chain

The [UDAP discovery guide](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/discovery.html#multiple-trust-communities)
describes selecting community-specific metadata with a `community` query
parameter:

```http
GET /.well-known/udap?community=https%3A%2F%2Fcommunity.example.org
```

A host may expose a community-specific registration URL in that metadata,
for example:

```json
{
  "registration_endpoint": "https://as.example.org/register?community=https%3A%2F%2Fcommunity.example.org"
}
```

That registration URL shape is an application routing choice. The client uses
the returned URL, and the host resolves its community selector against approved
local configuration before choosing a `profileId`. An unknown selector must
not create a new profile or fall back to another community's anchors.

Do not infer the community by trying profiles until one succeeds. Communities
can share a trust anchor, so the same chain may pass more than one profile.
The application must establish the intended community from its routing and
registration context.

## Convert and validate the JWT certificate chain

After checking that the JWT header contains a nonempty `x5c` array of strings,
decode each Base64 DER certificate. Raw `x5c` strings are not PEM certificate
inputs. Preserve their leaf-first order:

```typescript
import { Buffer } from "node:buffer";

const certificateChain = jwtHeader.x5c.map((certificate: string) =>
  Buffer.from(certificate, "base64")
);

const result = await registry.verify({
  profileId,
  certificateChain
});
```

Decoding `x5c` does not validate the JWT. The host must also verify its signature
and applicable claims, including `iss`, `sub`, `aud`, time limits, and `jti`, as
required by the workflow. A successful certificate result exposes
`leafCertificate` for those application checks. The registry accepts the
selected profile identifier and certificate chain; requests cannot change its
configured trust anchors.

## Registration and token requests

For registration, resolve the approved community and expected registration
endpoint first. Check the software statement's certificate chain and JWT,
including its audience against that endpoint. Reject a failed check without
retrying under another community's profile.

In a host supporting multiple communities, scope registration records by
community and issuer, for example `(communityUri, iss)`, and store the selected
`profileId` with the assigned `client_id`. Updating one registration must not
overwrite a record for another community. See the
[UDAP registration guide](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/registration.html#modifying-and-cancelling-registrations)
for the protocol's registration update requirements.

For a token request, use the registration associated with `client_id` to select
the stored `profileId`. Validate the authentication JWT's `x5c` chain using the
same conversion above, together with the workflow's signature, claims, and
replay checks. A caller-supplied community or profile identifier must not
override the stored registration.

The library implements certificate validation, not discovery, registration,
or token endpoints. Its [capability matrix](../../docs/capabilities.md) lists
the supported certificate and revocation mechanisms.

## Protocol references

- [FHIR UDAP Security IG](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/)
- [JWT validation](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/general.html#jwt-validation)
- [UDAP Dynamic Client Registration](https://www.udap.org/udap-dynamic-client-registration-stu1.html)
