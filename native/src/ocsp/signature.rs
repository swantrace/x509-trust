use der::asn1::Null;
use der::asn1::ObjectIdentifier;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::identity::{hash_algorithm, SHA1};

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

pub(super) fn supported_signature_parameters(algorithm: &AlgorithmIdentifierOwned) -> bool {
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
