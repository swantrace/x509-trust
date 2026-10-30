use napi::bindgen_prelude::{AsyncTask, Uint8Array};
use napi::{Env, Result, Task};
use napi_derive::napi;

use crate::RevocationStatus;

mod validation;

#[napi(string_enum = "UPPER_SNAKE")]
pub enum CrlFailureCode {
    InvalidCrl,
    CrlIssuerMismatch,
    CrlIssuerNotAuthorized,
    InvalidCrlSignature,
    CrlNotYetValid,
    CrlExpired,
    CrlMissingNextUpdate,
    UnsupportedCrl,
}

#[napi(object)]
pub struct NativeCrlResult {
    pub status: RevocationStatus,
    pub this_update_ms: Option<f64>,
    pub next_update_ms: Option<f64>,
    pub code: Option<CrlFailureCode>,
    pub message: Option<String>,
}

fn unknown(code: CrlFailureCode, message: &str) -> NativeCrlResult {
    NativeCrlResult {
        status: RevocationStatus::Unknown,
        this_update_ms: None,
        next_update_ms: None,
        code: Some(code),
        message: Some(message.to_owned()),
    }
}

pub struct ValidateCrlTask {
    certificate: Vec<u8>,
    issuer: Vec<u8>,
    crl: Vec<u8>,
    check_date_ms: f64,
}

#[napi]
impl Task for ValidateCrlTask {
    type Output = NativeCrlResult;
    type JsValue = NativeCrlResult;

    fn compute(&mut self) -> Result<Self::Output> {
        validation::validate(
            &self.certificate,
            &self.issuer,
            &self.crl,
            self.check_date_ms,
        )
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Certificate and issuer must belong to a previously validated path.
#[napi]
pub fn validate_crl(
    certificate: Uint8Array,
    issuer_certificate: Uint8Array,
    crl: Uint8Array,
    check_date_ms: f64,
) -> AsyncTask<ValidateCrlTask> {
    AsyncTask::new(ValidateCrlTask {
        certificate: certificate.to_vec(),
        issuer: issuer_certificate.to_vec(),
        crl: crl.to_vec(),
        check_date_ms,
    })
}
