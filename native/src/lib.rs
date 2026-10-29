use napi::{Error, Result, Status};
use napi_derive::napi;
use x509_parser::oid_registry::{
    OID_PKIX_ACCESS_DESCRIPTOR_OCSP, OID_PKIX_AUTHORITY_INFO_ACCESS,
    OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
};
use x509_parser::prelude::*;

// napi-rs omits task implementations and registration in Rust test builds.
#[cfg_attr(test, allow(dead_code))]
mod certificate_path;
#[cfg_attr(test, allow(dead_code))]
mod crl;

/// Minimal native entry point used to verify the mixed Rust/TypeScript setup.
#[napi]
pub fn native_ready() -> bool {
    true
}

fn invalid(message: &str) -> Error {
    Error::new(Status::InvalidArg, message)
}

fn parse_certificate(der: &[u8]) -> Result<X509Certificate<'_>> {
    let (remaining, certificate) =
        parse_x509_certificate(der).map_err(|_| invalid("Unable to parse the DER certificate"))?;
    if !remaining.is_empty() {
        return Err(invalid("Unexpected bytes after the DER certificate"));
    }
    Ok(certificate)
}

fn uri_name(name: &GeneralName<'_>) -> Result<Option<String>> {
    match name {
        GeneralName::URI(uri) => Ok(Some((*uri).to_owned())),
        GeneralName::Invalid(_, _) => Err(invalid("Invalid general name in certificate extension")),
        _ => Ok(None),
    }
}

#[napi]
pub fn get_uri_subject_alternative_names(der: &[u8]) -> Result<Vec<String>> {
    let certificate = parse_certificate(der)?;
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| invalid("Invalid subject alternative name extension"))?;
    let mut uris = Vec::new();
    if let Some(san) = san {
        for name in &san.value.general_names {
            if let Some(uri) = uri_name(name)? {
                uris.push(uri);
            }
        }
    }
    Ok(uris)
}

#[napi(object)]
pub struct RevocationEndpoints {
    pub crl_urls: Vec<String>,
    pub ocsp_urls: Vec<String>,
}

#[napi]
pub fn get_revocation_endpoints(der: &[u8]) -> Result<RevocationEndpoints> {
    let certificate = parse_certificate(der)?;
    let mut endpoints = RevocationEndpoints {
        crl_urls: Vec::new(),
        ocsp_urls: Vec::new(),
    };

    if let Some(extension) = certificate
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .map_err(|_| invalid("Duplicate CRL distribution points extension"))?
    {
        let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() else {
            return Err(invalid("Invalid CRL distribution points extension"));
        };
        for point in &points.points {
            if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                for name in names {
                    if let Some(uri) = uri_name(name)? {
                        endpoints.crl_urls.push(uri);
                    }
                }
            }
        }
    }

    if let Some(extension) = certificate
        .get_extension_unique(&OID_PKIX_AUTHORITY_INFO_ACCESS)
        .map_err(|_| invalid("Duplicate authority information access extension"))?
    {
        let ParsedExtension::AuthorityInfoAccess(access) = extension.parsed_extension() else {
            return Err(invalid("Invalid authority information access extension"));
        };
        for description in &access.accessdescs {
            let uri = uri_name(&description.access_location)?;
            if description.access_method == OID_PKIX_ACCESS_DESCRIPTOR_OCSP {
                if let Some(uri) = uri {
                    endpoints.ocsp_urls.push(uri);
                }
            }
        }
    }

    Ok(endpoints)
}
