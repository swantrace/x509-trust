use der::asn1::{Null, ObjectIdentifier};
use der::Encode;
use ring::digest;
use x509_ocsp::{CertId, ResponderId};
use x509_parser::prelude::*;

use crate::names::names_equal;

pub(super) const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

pub(super) fn hash_algorithm(oid: ObjectIdentifier) -> Option<&'static digest::Algorithm> {
    match oid.to_string().as_str() {
        // SHA-1 here identifies certificates, rather than authenticating responses.
        "1.3.14.3.2.26" => Some(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        "2.16.840.1.101.3.4.2.1" => Some(&digest::SHA256),
        "2.16.840.1.101.3.4.2.2" => Some(&digest::SHA384),
        "2.16.840.1.101.3.4.2.3" => Some(&digest::SHA512),
        _ => None,
    }
}

pub(super) fn matches_certificate(
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

pub(super) fn responder_is_issuer(responder: &ResponderId, issuer: &X509Certificate<'_>) -> bool {
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
