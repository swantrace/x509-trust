use der::asn1::{AnyRef, ContextSpecific, IntRef, Null, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Reader, SliceReader, TagNumber};
use napi::bindgen_prelude::{AsyncTask, Uint8Array};
use napi::{Env, Result, Task};
use napi_derive::napi;
use ring::digest;
use x509_cert::{serial_number::SerialNumber, spki::AlgorithmIdentifierOwned};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request,
    ResponderId, TbsRequest,
};
use x509_parser::asn1_rs::BitString;
use x509_parser::prelude::*;

use crate::{crl::names_equal, invalid, parse_certificate};

const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const BASIC_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

#[napi(string_enum = "lowercase")]
pub enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

#[napi(string_enum = "UPPER_SNAKE")]
pub enum OcspFailureCode {
    InvalidOcspResponse,
    OcspResponderError,
    UnsupportedOcspResponse,
    OcspIssuerMismatch,
    OcspCertificateMismatch,
    InvalidOcspSignature,
    OcspResponderVerificationFailed,
    OcspNotYetValid,
    OcspExpired,
    OcspMissingNextUpdate,
    OcspStatusUnknown,
}

#[napi(object)]
pub struct NativeOcspResult {
    pub status: OcspStatus,
    pub this_update_ms: Option<f64>,
    pub next_update_ms: Option<f64>,
    pub code: Option<OcspFailureCode>,
    pub message: Option<String>,
}

fn unknown(code: OcspFailureCode, message: &str) -> NativeOcspResult {
    NativeOcspResult {
        status: OcspStatus::Unknown,
        this_update_ms: None,
        next_update_ms: None,
        code: Some(code),
        message: Some(message.to_owned()),
    }
}

fn hash_algorithm(oid: ObjectIdentifier) -> Option<&'static digest::Algorithm> {
    match oid.to_string().as_str() {
        // SHA-1 here identifies certificates, rather than authenticating responses.
        "1.3.14.3.2.26" => Some(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        "2.16.840.1.101.3.4.2.1" => Some(&digest::SHA256),
        "2.16.840.1.101.3.4.2.2" => Some(&digest::SHA384),
        "2.16.840.1.101.3.4.2.3" => Some(&digest::SHA512),
        _ => None,
    }
}

fn matches_certificate(
    id: &CertId,
    certificate: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Option<bool> {
    let algorithm = hash_algorithm(id.hash_algorithm.oid)?;
    if id
        .hash_algorithm
        .parameters
        .as_ref()
        .is_some_and(|parameters| parameters != &Null.into())
    {
        return None;
    }
    Some(
        // RustCrypto serials retain the INTEGER sign-padding byte. Both DER
        // encodings must identify the same signed serial, including that byte.
        id.serial_number.as_bytes() == certificate.raw_serial()
            && id.issuer_name_hash.as_bytes()
                == digest::digest(algorithm, issuer.subject().as_raw()).as_ref()
            && id.issuer_key_hash.as_bytes()
                == digest::digest(algorithm, &issuer.public_key().subject_public_key.data).as_ref(),
    )
}

fn responder_is_issuer(responder: &ResponderId, issuer: &X509Certificate<'_>) -> bool {
    match responder {
        ResponderId::ByName(name) => name.to_der().ok().is_some_and(|der| {
            matches!(X509Name::from_der(&der), Ok(([], name)) if names_equal(&name, issuer.subject()))
        }),
        ResponderId::ByKey(hash) => {
            hash.as_bytes()
                == digest::digest(
                    &digest::SHA1_FOR_LEGACY_USE_ONLY,
                    &issuer.public_key().subject_public_key.data,
                )
                .as_ref()
        }
    }
}

#[derive(der::Sequence)]
struct RsaPssParameters {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    salt_length: Option<u32>,
    #[asn1(context_specific = "3", optional = "true", tag_mode = "EXPLICIT")]
    trailer_field: Option<u32>,
}

fn null_or_absent(algorithm: &AlgorithmIdentifierOwned) -> bool {
    algorithm
        .parameters
        .as_ref()
        .is_none_or(|value| value == &Null.into())
}

fn supported_signature_parameters(algorithm: &AlgorithmIdentifierOwned) -> bool {
    match algorithm.oid.to_string().as_str() {
        "1.2.840.113549.1.1.5"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13" => null_or_absent(algorithm),
        "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" | "1.3.101.112" => {
            algorithm.parameters.is_none()
        }
        "1.2.840.113549.1.1.10" => {
            let Some(parameters) = algorithm
                .parameters
                .as_ref()
                .and_then(|value| value.decode_as::<RsaPssParameters>().ok())
            else {
                return false;
            };
            let (Some(hash), Some(mask_gen)) = (parameters.hash, parameters.mask_gen) else {
                return false;
            };
            let Some(digest) = hash_algorithm(hash.oid) else {
                return false;
            };
            let Some(mask_hash) = mask_gen
                .parameters
                .as_ref()
                .and_then(|value| value.decode_as::<AlgorithmIdentifierOwned>().ok())
            else {
                return false;
            };
            // ring's PSS algorithms require MGF1 with the signature digest,
            // a digest-sized salt and trailer field 1. Check all declared
            // parameters: x509-parser's verifier dispatches on the hash alone.
            hash.oid != SHA1
                && null_or_absent(&hash)
                && mask_gen.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8")
                && mask_hash.oid == hash.oid
                && null_or_absent(&mask_hash)
                && parameters.salt_length.unwrap_or(20) as usize == digest.output_len()
                && parameters.trailer_field.unwrap_or(1) == 1
        }
        _ => false,
    }
}

// Extract the exact ResponseData TLV, including its original tag and length.
// Re-encoding decoded data could change the message that was actually signed.
fn signed_response_data(basic_der: &[u8]) -> der::Result<(&[u8], u32)> {
    let basic = AnyRef::from_der(basic_der)?;
    let mut reader = SliceReader::new(basic.value())?;
    let data = reader.tlv_bytes()?;
    let response_data = AnyRef::from_der(data)?;
    let mut reader = SliceReader::new(response_data.value())?;
    let version = ContextSpecific::<u32>::decode_explicit(&mut reader, TagNumber::N0)?
        .map_or(0, |version| version.value);
    Ok((data, version))
}

pub struct ValidateOcspTask {
    certificate: Vec<u8>,
    issuer: Vec<u8>,
    response: Vec<u8>,
    check_date_ms: f64,
}

impl ValidateOcspTask {
    fn validate(&self) -> NativeOcspResult {
        use OcspFailureCode::*;
        let certificate = match parse_certificate(&self.certificate) {
            Ok(certificate) => certificate,
            Err(_) => return unknown(InvalidOcspResponse, "Unable to parse the DER certificate"),
        };
        let issuer = match parse_certificate(&self.issuer) {
            Ok(issuer) => issuer,
            Err(_) => return unknown(OcspIssuerMismatch, "Unable to parse the DER issuer"),
        };
        if !names_equal(certificate.issuer(), issuer.subject()) {
            return unknown(
                OcspIssuerMismatch,
                "Certificate does not have the supplied issuer",
            );
        }
        let outer = match OcspResponse::from_der(&self.response) {
            Ok(outer) => outer,
            Err(_) => return unknown(InvalidOcspResponse, "Unable to parse the DER OCSP response"),
        };
        if outer.response_status != OcspResponseStatus::Successful {
            return unknown(
                OcspResponderError,
                "OCSP responder did not return a successful response",
            );
        }
        let Some(bytes) = outer.response_bytes else {
            return unknown(InvalidOcspResponse, "OCSP response has no response bytes");
        };
        if bytes.response_type != BASIC_OCSP {
            return unknown(
                UnsupportedOcspResponse,
                "Only BasicOCSPResponse is supported",
            );
        }
        let (signed_data, version) = match signed_response_data(bytes.response.as_bytes()) {
            Ok(data) => data,
            Err(_) => return unknown(InvalidOcspResponse, "Invalid OCSP response data"),
        };
        if version != 0 {
            return unknown(UnsupportedOcspResponse, "Unsupported OCSP response version");
        }
        let basic = match BasicOcspResponse::from_der(bytes.response.as_bytes()) {
            Ok(basic) => basic,
            Err(_) => return unknown(InvalidOcspResponse, "Unable to parse the BasicOCSPResponse"),
        };
        let mut matches = Vec::new();
        for single in &basic.tbs_response_data.responses {
            match matches_certificate(&single.cert_id, &certificate, &issuer) {
                Some(true) => matches.push(single),
                Some(false) => (),
                None => {
                    return unknown(
                        InvalidOcspResponse,
                        "Invalid or unsupported CertID hash algorithm",
                    )
                }
            }
        }
        if matches.len() != 1 {
            return unknown(
                OcspCertificateMismatch,
                "OCSP response must contain exactly one matching certificate status",
            );
        }
        let single = matches[0];
        if basic
            .tbs_response_data
            .response_extensions
            .iter()
            .flatten()
            .any(|extension| extension.critical)
            || single
                .single_extensions
                .iter()
                .flatten()
                .any(|extension| extension.critical)
        {
            return unknown(
                UnsupportedOcspResponse,
                "Unsupported critical OCSP extension",
            );
        }
        let Some(next_update) = single.next_update else {
            return unknown(
                OcspMissingNextUpdate,
                "This verifier requires nextUpdate to bound response freshness",
            );
        };
        let produced_at_ms = basic
            .tbs_response_data
            .produced_at
            .0
            .to_unix_duration()
            .as_secs_f64()
            * 1000.0;
        let this_update_ms = single.this_update.0.to_unix_duration().as_secs_f64() * 1000.0;
        let next_update_ms = next_update.0.to_unix_duration().as_secs_f64() * 1000.0;
        if next_update_ms <= this_update_ms {
            return unknown(InvalidOcspResponse, "Invalid OCSP response time interval");
        }
        if produced_at_ms > self.check_date_ms || this_update_ms > self.check_date_ms {
            return unknown(
                OcspNotYetValid,
                "OCSP response was produced or updated in the future",
            );
        }
        if next_update_ms <= self.check_date_ms {
            return unknown(OcspExpired, "OCSP nextUpdate has been reached");
        }
        // Embedded certificates never establish trust. Delegation is not supported.
        if !responder_is_issuer(&basic.tbs_response_data.responder_id, &issuer) {
            return unknown(
                OcspResponderVerificationFailed,
                "Unable to authenticate a direct-issuer OCSP response",
            );
        }
        let Some(signature) = basic.signature.as_bytes() else {
            return unknown(InvalidOcspSignature, "OCSP signature must be byte-aligned");
        };
        if !supported_signature_parameters(&basic.signature_algorithm) {
            return unknown(
                InvalidOcspSignature,
                "Unsupported OCSP signature algorithm parameters",
            );
        }
        let Ok(algorithm_der) = basic.signature_algorithm.to_der() else {
            return unknown(InvalidOcspSignature, "Invalid OCSP signature algorithm");
        };
        let Ok(([], algorithm)) = AlgorithmIdentifier::from_der(&algorithm_der) else {
            return unknown(InvalidOcspSignature, "Invalid OCSP signature algorithm");
        };
        if x509_parser::verify::verify_signature(
            issuer.public_key(),
            &algorithm,
            &BitString::new(0, signature),
            signed_data,
        )
        .is_err()
        {
            return unknown(
                InvalidOcspSignature,
                "OCSP signature is invalid or unsupported",
            );
        }
        let status = match single.cert_status {
            CertStatus::Good(_) => OcspStatus::Good,
            CertStatus::Revoked(_) => OcspStatus::Revoked,
            CertStatus::Unknown(_) => {
                return unknown(
                    OcspStatusUnknown,
                    "OCSP responder reports unknown certificate status",
                )
            }
        };
        NativeOcspResult {
            status,
            this_update_ms: Some(this_update_ms),
            next_update_ms: Some(next_update_ms),
            code: None,
            message: None,
        }
    }
}

#[napi]
impl Task for ValidateOcspTask {
    type Output = NativeOcspResult;
    type JsValue = NativeOcspResult;

    fn compute(&mut self) -> Result<Self::Output> {
        if !self.check_date_ms.is_finite() {
            return Err(invalid("checkDate must be a valid date"));
        }
        Ok(self.validate())
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Certificate and issuer must belong to a previously validated path.
#[napi]
pub fn validate_ocsp(
    certificate: Uint8Array,
    issuer_certificate: Uint8Array,
    response: Uint8Array,
    check_date_ms: f64,
) -> AsyncTask<ValidateOcspTask> {
    AsyncTask::new(ValidateOcspTask {
        certificate: certificate.to_vec(),
        issuer: issuer_certificate.to_vec(),
        response: response.to_vec(),
        check_date_ms,
    })
}

pub struct CreateOcspRequestTask {
    certificate: Vec<u8>,
    issuer: Vec<u8>,
}

impl CreateOcspRequestTask {
    fn encode(&self) -> Result<Vec<u8>> {
        let certificate = parse_certificate(&self.certificate)?;
        let issuer = parse_certificate(&self.issuer)?;
        if !names_equal(certificate.issuer(), issuer.subject()) {
            return Err(invalid("Certificate does not have the supplied issuer"));
        }
        let encode = || -> der::Result<Vec<u8>> {
            OcspRequest {
                tbs_request: TbsRequest {
                    request_list: vec![Request {
                        req_cert: CertId {
                            hash_algorithm: AlgorithmIdentifierOwned {
                                oid: SHA1,
                                parameters: Some(Null.into()),
                            },
                            issuer_name_hash: OctetString::new(
                                digest::digest(
                                    &digest::SHA1_FOR_LEGACY_USE_ONLY,
                                    issuer.subject().as_raw(),
                                )
                                .as_ref(),
                            )?,
                            issuer_key_hash: OctetString::new(
                                digest::digest(
                                    &digest::SHA1_FOR_LEGACY_USE_ONLY,
                                    &issuer.public_key().subject_public_key.data,
                                )
                                .as_ref(),
                            )?,
                            serial_number: SerialNumber::from_der(
                                &IntRef::new(certificate.raw_serial())?.to_der()?,
                            )?,
                        },
                        single_request_extensions: None,
                    }],
                    ..TbsRequest::default()
                },
                optional_signature: None,
            }
            .to_der()
        };
        encode().map_err(|_| invalid("Unable to encode the DER OCSP request"))
    }
}

#[napi]
impl Task for CreateOcspRequestTask {
    type Output = Vec<u8>;
    type JsValue = Uint8Array;

    fn compute(&mut self) -> Result<Self::Output> {
        self.encode()
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

/// Unsigned, single-certificate request without a nonce, using SHA-1 CertID hashes.
#[napi]
pub fn create_ocsp_request(
    certificate: Uint8Array,
    issuer_certificate: Uint8Array,
) -> AsyncTask<CreateOcspRequestTask> {
    AsyncTask::new(CreateOcspRequestTask {
        certificate: certificate.to_vec(),
        issuer: issuer_certificate.to_vec(),
    })
}
