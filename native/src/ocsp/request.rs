use der::asn1::{IntRef, Null, OctetString};
use der::{Decode, Encode};
use napi::Result;
use ring::digest;
use x509_cert::{serial_number::SerialNumber, spki::AlgorithmIdentifierOwned};
use x509_ocsp::{CertId, OcspRequest, Request, TbsRequest};

use super::identity::SHA1;
use crate::{invalid, names::names_equal, parse_certificate};

pub(crate) fn build_request(certificate_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>> {
    let certificate = parse_certificate(certificate_der)?;
    let issuer = parse_certificate(issuer_der)?;
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
