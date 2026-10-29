use std::time::Duration;

use napi::bindgen_prelude::{AsyncTask, Uint8Array};
use napi::{Env, Error, Result, Status, Task};
use napi_derive::napi;
use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{ExtendedKeyUsageValidator, KeyPurposeIdIter, VerifiedPath};
use x509_parser::oid_registry::{
    OID_X509_EXT_INHIBIT_ANY_POLICY, OID_X509_EXT_POLICY_CONSTRAINTS, OID_X509_EXT_POLICY_MAPPINGS,
};

use crate::{
    decode_certificate, get_revocation_endpoints, get_uri_subject_alternative_names, ocsp,
    parse_certificate,
};

// This API validates trust without imposing an application-specific EKU.
// Consume every OID so malformed EKU data is still rejected.
struct AnyPurpose;

impl ExtendedKeyUsageValidator for AnyPurpose {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> std::result::Result<(), webpki::Error> {
        for purpose in iter {
            purpose?;
        }
        Ok(())
    }
}

fn check_certificate(
    der: &[u8],
    check_date_ms: f64,
    is_ca: bool,
) -> std::result::Result<(), webpki::Error> {
    let certificate = parse_certificate(der).map_err(|_| webpki::Error::BadDer)?;
    let validity = certificate.validity();
    if check_date_ms < validity.not_before.timestamp() as f64 * 1000.0
        || check_date_ms > validity.not_after.timestamp() as f64 * 1000.0
    {
        return Err(webpki::Error::InvalidCertValidity);
    }

    // webpki does not enforce CA keyCertSign or trust-anchor CA constraints.
    if is_ca {
        if !certificate
            .basic_constraints()
            .map_err(|_| webpki::Error::ExtensionValueInvalid)?
            .is_some_and(|constraints| constraints.value.ca)
        {
            return Err(webpki::Error::EndEntityUsedAsCa);
        }
        if certificate
            .key_usage()
            .map_err(|_| webpki::Error::ExtensionValueInvalid)?
            .is_some_and(|usage| !usage.value.key_cert_sign())
        {
            return Err(webpki::Error::ExtensionValueInvalid);
        }
    }

    certificate
        .extensions_map()
        .map_err(|_| webpki::Error::MalformedExtensions)?;
    for extension in certificate.extensions() {
        // Policy-tree processing is not implemented by webpki. Reject these
        // extensions even when noncritical rather than ignore their constraints.
        if extension.oid == OID_X509_EXT_POLICY_MAPPINGS
            || extension.oid == OID_X509_EXT_POLICY_CONSTRAINTS
            || extension.oid == OID_X509_EXT_INHIBIT_ANY_POLICY
        {
            return Err(webpki::Error::ExtensionValueInvalid);
        }
        if extension.parsed_extension().error().is_some()
            || (extension.critical && extension.parsed_extension().unsupported())
        {
            return Err(webpki::Error::UnsupportedCriticalExtension);
        }
    }
    Ok(())
}

#[napi(object)]
pub struct NativeValidatedPath {
    pub certificate_path: Vec<Uint8Array>,
    pub trust_anchor_index: u32,
    pub trust_anchor_fingerprint256: String,
    pub leaf_uri_subject_alternative_names: Vec<String>,
    pub revocation_targets: Vec<NativeRevocationTarget>,
}

#[napi(object)]
pub struct NativeRevocationTarget {
    pub certificate_index: u32,
    pub crl_urls: Vec<String>,
    pub ocsp_urls: Vec<String>,
    pub ocsp_request: Option<Uint8Array>,
}

struct RevocationTarget {
    certificate_index: u32,
    crl_urls: Vec<String>,
    ocsp_urls: Vec<String>,
    ocsp_request: Option<Vec<u8>>,
}

pub struct ValidatedPath {
    certificates: Vec<Vec<u8>>,
    anchor_index: u32,
    anchor_fingerprint256: String,
    leaf_uris: Vec<String>,
    targets: Vec<RevocationTarget>,
}

pub struct ValidatePathTask {
    chain: Vec<Vec<u8>>,
    anchors: Vec<Vec<u8>>,
    check_date_ms: f64,
}

#[napi]
impl Task for ValidatePathTask {
    type Output = ValidatedPath;
    type JsValue = NativeValidatedPath;

    fn compute(&mut self) -> Result<Self::Output> {
        let failure = |error: webpki::Error| Error::new(Status::GenericFailure, error.to_string());
        if !self.check_date_ms.is_finite() || self.check_date_ms < 0.0 {
            return Err(Error::new(
                Status::GenericFailure,
                "Path validation requires a date on or after the Unix epoch",
            ));
        }
        if self.chain.is_empty() || self.anchors.is_empty() {
            return Err(Error::new(
                Status::InvalidArg,
                "Certificates and trust anchors are required",
            ));
        }
        // Decode and check every candidate within this worker, including unused ones.
        self.chain = self
            .chain
            .iter()
            .map(|input| decode_certificate(input))
            .collect::<Result<_>>()?;
        self.anchors = self
            .anchors
            .iter()
            .map(|input| decode_certificate(input))
            .collect::<Result<_>>()?;
        let chain: Vec<_> = self
            .chain
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        let anchor_certs: Vec<_> = self
            .anchors
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        let anchors = anchor_certs
            .iter()
            .map(webpki::anchor_from_trusted_cert)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(failure)?;
        let end_entity = webpki::EndEntityCert::try_from(&chain[0]).map_err(failure)?;

        let check_path = |path: &VerifiedPath<'_>| {
            // Identify the exact configured certificate, including when two
            // anchors share a subject and public key but differ in validity.
            let index = anchors
                .iter()
                .position(|anchor| std::ptr::eq(anchor, path.anchor()))
                .ok_or(webpki::Error::UnknownIssuer)?;
            check_certificate(anchor_certs[index].as_ref(), self.check_date_ms, true)?;
            check_certificate(path.end_entity().der().as_ref(), self.check_date_ms, false)?;
            for intermediate in path.intermediate_certificates() {
                check_certificate(intermediate.der().as_ref(), self.check_date_ms, true)?;
            }
            Ok(())
        };
        let path = end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &chain[1..],
                UnixTime::since_unix_epoch(Duration::from_millis(self.check_date_ms as u64)),
                AnyPurpose,
                None, // Revocation remains a separate fail-closed step in TypeScript.
                Some(&check_path),
            )
            .map_err(failure)?;
        let anchor_index = anchors
            .iter()
            .position(|anchor| std::ptr::eq(anchor, path.anchor()))
            .ok_or_else(|| failure(webpki::Error::UnknownIssuer))?;
        let mut certificates = vec![self.chain[0].clone()];
        certificates.extend(
            path.intermediate_certificates()
                .map(|cert| cert.der().as_ref().to_vec()),
        );
        certificates.push(self.anchors[anchor_index].clone());
        let leaf_uris = get_uri_subject_alternative_names(&certificates[0])?;
        let targets = certificates
            .windows(2)
            .enumerate()
            .map(|(index, pair)| {
                let endpoints = get_revocation_endpoints(&pair[0])?;
                let request = if endpoints.ocsp_urls.is_empty() {
                    None
                } else {
                    // Encoding failures must still allow CRL/custom-loader fallback.
                    ocsp::build_request(&pair[0], &pair[1]).ok()
                };
                Ok(RevocationTarget {
                    certificate_index: index as u32,
                    crl_urls: endpoints.crl_urls,
                    ocsp_urls: endpoints.ocsp_urls,
                    ocsp_request: request,
                })
            })
            .collect::<Result<_>>()?;
        Ok(ValidatedPath {
            certificates,
            leaf_uris,
            targets,
            anchor_index: anchor_index as u32,
            anchor_fingerprint256: ring::digest::digest(
                &ring::digest::SHA256,
                &self.anchors[anchor_index],
            )
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
        })
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(NativeValidatedPath {
            certificate_path: output
                .certificates
                .into_iter()
                .map(Uint8Array::from)
                .collect(),
            trust_anchor_index: output.anchor_index,
            trust_anchor_fingerprint256: output.anchor_fingerprint256,
            leaf_uri_subject_alternative_names: output.leaf_uris,
            revocation_targets: output
                .targets
                .into_iter()
                .map(|target| NativeRevocationTarget {
                    certificate_index: target.certificate_index,
                    crl_urls: target.crl_urls,
                    ocsp_urls: target.ocsp_urls,
                    ocsp_request: target.ocsp_request.map(Uint8Array::from),
                })
                .collect(),
        })
    }
}

#[napi]
pub fn validate_certificate_path(
    chain: Vec<Uint8Array>,
    anchors: Vec<Uint8Array>,
    check_date_ms: f64,
) -> AsyncTask<ValidatePathTask> {
    AsyncTask::new(ValidatePathTask {
        // Own a snapshot before leaving the JS thread: callers can mutate their
        // typed arrays as soon as this function returns a Promise.
        chain: chain.iter().map(|der| der.to_vec()).collect(),
        anchors: anchors.iter().map(|der| der.to_vec()).collect(),
        check_date_ms,
    })
}
