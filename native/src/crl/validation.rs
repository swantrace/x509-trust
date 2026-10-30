use napi::Result;
use x509_parser::oid_registry::{
    OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_CRL_NUMBER,
    OID_X509_EXT_DELTA_CRL_INDICATOR, OID_X509_EXT_ISSUER, OID_X509_EXT_ISSUER_DISTRIBUTION_POINT,
};
use x509_parser::prelude::*;

use super::{unknown, CrlFailureCode, NativeCrlResult};
use crate::{invalid, names::names_equal, parse_certificate, RevocationStatus};

fn issuer_can_sign_crl(issuer: &X509Certificate<'_>) -> bool {
    if issuer.extensions_map().is_err()
        || !matches!(issuer.basic_constraints(), Ok(Some(constraints)) if constraints.value.ca)
    {
        return false;
    }
    match issuer.key_usage() {
        Ok(None) => true,
        Ok(Some(usage)) => usage.value.crl_sign(),
        Err(_) => false,
    }
}

fn has_unsupported_extensions(crl: &CertificateRevocationList<'_>) -> bool {
    crl.extensions().iter().any(|extension| {
        extension.oid == OID_X509_EXT_DELTA_CRL_INDICATOR
            || extension.oid == OID_X509_EXT_ISSUER_DISTRIBUTION_POINT
            || (extension.critical
                && extension.oid != OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
                && extension.oid != OID_X509_EXT_CRL_NUMBER)
    }) || crl.iter_revoked_certificates().any(|entry| {
        entry
            .extensions()
            .iter()
            .any(|extension| extension.oid == OID_X509_EXT_ISSUER || extension.critical)
    })
}

pub(super) fn validate(
    certificate_der: &[u8],
    issuer_der: &[u8],
    crl_der: &[u8],
    check_date_ms: f64,
) -> Result<NativeCrlResult> {
    use CrlFailureCode::*;
    if !check_date_ms.is_finite() {
        return Err(invalid("checkDate must be a valid date"));
    }
    let certificate = match parse_certificate(certificate_der) {
        Ok(certificate) => certificate,
        Err(_) => return Ok(unknown(InvalidCrl, "Unable to parse the DER certificate")),
    };
    let issuer = match parse_certificate(issuer_der) {
        Ok(issuer) => issuer,
        Err(_) => {
            return Ok(unknown(
                CrlIssuerNotAuthorized,
                "Unable to parse the DER issuer certificate",
            ))
        }
    };
    let crl = match parse_x509_crl(crl_der) {
        Ok(([], crl)) => crl,
        _ => return Ok(unknown(InvalidCrl, "Unable to parse the DER CRL")),
    };
    if !names_equal(certificate.issuer(), issuer.subject())
        || !names_equal(crl.issuer(), issuer.subject())
    {
        return Ok(unknown(
            CrlIssuerMismatch,
            "Certificate and CRL must have the supplied issuer",
        ));
    }
    if !issuer_can_sign_crl(&issuer) {
        return Ok(unknown(
            CrlIssuerNotAuthorized,
            "The issuer must be a CA permitted to sign CRLs",
        ));
    }
    if has_unsupported_extensions(&crl) {
        return Ok(unknown(
            UnsupportedCrl,
            "Only direct, complete CRLs without scope restrictions are supported",
        ));
    }
    if crl.tbs_cert_list.extensions_map().is_err()
        || crl
            .extensions()
            .iter()
            .any(|extension| extension.parsed_extension().error().is_some())
        || crl.iter_revoked_certificates().any(|entry| {
            entry.extensions_map().is_err()
                || entry
                    .extensions()
                    .iter()
                    .any(|extension| extension.parsed_extension().error().is_some())
        })
    {
        return Ok(unknown(InvalidCrl, "Invalid or duplicate CRL extensions"));
    }
    let this_update_ms = crl.last_update().timestamp() as f64 * 1000.0;
    let Some(next_update) = crl.next_update() else {
        return Ok(unknown(CrlMissingNextUpdate, "CRL nextUpdate is required"));
    };
    let next_update_ms = next_update.timestamp() as f64 * 1000.0;
    if next_update_ms <= this_update_ms {
        return Ok(unknown(InvalidCrl, "Invalid CRL validity interval"));
    }
    if this_update_ms > check_date_ms {
        return Ok(unknown(CrlNotYetValid, "CRL thisUpdate is in the future"));
    }
    if next_update_ms <= check_date_ms {
        return Ok(unknown(CrlExpired, "CRL nextUpdate has been reached"));
    }
    if crl.tbs_cert_list.signature != crl.signature_algorithm {
        return Ok(unknown(
            InvalidCrlSignature,
            "CRL signature algorithm identifiers do not match",
        ));
    }
    if crl.signature_value.unused_bits != 0 {
        return Ok(unknown(
            InvalidCrlSignature,
            "CRL signature must be byte-aligned",
        ));
    }
    if crl.verify_signature(issuer.public_key()).is_err() {
        return Ok(unknown(
            InvalidCrlSignature,
            "CRL signature is invalid or unsupported",
        ));
    }
    let revoked = crl
        .iter_revoked_certificates()
        .any(|entry| entry.serial() == &certificate.serial);
    Ok(NativeCrlResult {
        status: if revoked {
            RevocationStatus::Revoked
        } else {
            RevocationStatus::Good
        },
        this_update_ms: Some(this_update_ms),
        next_update_ms: Some(next_update_ms),
        code: None,
        message: None,
    })
}
