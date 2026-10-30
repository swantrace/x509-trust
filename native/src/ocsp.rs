use napi::bindgen_prelude::{AsyncTask, Uint8Array};
use napi::{Env, Result, Task};
use napi_derive::napi;

use crate::{invalid, RevocationStatus};

mod identity;
mod request;
mod response;
mod signature;

pub(crate) use request::build_request;

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
    pub status: RevocationStatus,
    pub this_update_ms: Option<f64>,
    pub next_update_ms: Option<f64>,
    pub code: Option<OcspFailureCode>,
    pub message: Option<String>,
}

fn unknown(code: OcspFailureCode, message: &str) -> NativeOcspResult {
    NativeOcspResult {
        status: RevocationStatus::Unknown,
        this_update_ms: None,
        next_update_ms: None,
        code: Some(code),
        message: Some(message.to_owned()),
    }
}

pub struct ValidateOcspTask {
    certificate: Vec<u8>,
    issuer: Vec<u8>,
    response: Vec<u8>,
    check_date_ms: f64,
}

#[napi]
impl Task for ValidateOcspTask {
    type Output = NativeOcspResult;
    type JsValue = NativeOcspResult;

    fn compute(&mut self) -> Result<Self::Output> {
        if !self.check_date_ms.is_finite() {
            return Err(invalid("checkDate must be a valid date"));
        }
        Ok(response::validate(
            &self.certificate,
            &self.issuer,
            &self.response,
            self.check_date_ms,
        ))
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

#[napi]
impl Task for CreateOcspRequestTask {
    type Output = Vec<u8>;
    type JsValue = Uint8Array;

    fn compute(&mut self) -> Result<Self::Output> {
        build_request(&self.certificate, &self.issuer)
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
